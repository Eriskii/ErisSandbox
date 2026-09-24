//! Commands outside the supervisor's namespaces. After [`crate::bootstrap`] the program runs as
//! root of its own user namespace; whatever should run as the invoking user, exactly as if
//! there were no sandboxes (a shell for a person, an agent working directly on this
//! machine), is started by the bootstrap parent, which never left the original namespaces.
//! The supervisor asks over a socket; the parent forks, execs, reaps, and reports exits.

use crate::process::{ExitStatus, KILLED, Killer, Process};
use crate::sandbox::proto;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::unix::AsyncFd;
use tokio::sync::oneshot;

/// A command for [`crate::Host::spawn_outside`]. It runs in a new session, as the invoking
/// user, with exactly `env`.
pub struct OutsideCommand {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub env: Vec<(String, String)>,
    /// A terminal to run on, such as a pseudoterminal's peer: it becomes the command's
    /// standard streams and controlling terminal, and the process's output reaches the
    /// terminal instead. Without one, standard input is empty and output is combined.
    pub terminal: Option<OwnedFd>,
}

#[derive(Debug, Serialize, Deserialize)]
enum Request {
    Spawn { argv: Vec<String>, cwd: PathBuf, env: Vec<(String, String)>, terminal: bool },
}

#[derive(Debug, Serialize, Deserialize)]
enum Reply {
    Spawned { pid: i32 },
    Failed { error: String },
    Exited { pid: i32, code: Option<i32>, signal: Option<i32> },
}

/// The supervisor's end of the channel to the bootstrap parent.
pub(crate) struct Outside {
    socket: Mutex<Option<OwnedFd>>,
    launcher: OnceLock<Arc<Launcher>>,
}

impl Outside {
    pub(crate) fn new(socket: OwnedFd) -> Self {
        Self { socket: Mutex::new(Some(socket)), launcher: OnceLock::new() }
    }

    fn launcher(&self) -> Result<Arc<Launcher>> {
        if let Some(launcher) = self.launcher.get() {
            return Ok(launcher.clone());
        }
        let socket = self.socket.lock().unwrap().take();
        if let Some(socket) = socket {
            crate::process::set_nonblocking(&socket)?;
            let launcher = Arc::new(Launcher {
                socket: AsyncFd::new(socket)?,
                send: tokio::sync::Mutex::new(()),
                replies: Mutex::default(),
                exits: Mutex::default(),
            });
            tokio::spawn(launcher.clone().read());
            let _ = self.launcher.set(launcher);
        }
        self.launcher.get().cloned().context("the bootstrap parent is gone")
    }

    pub(crate) async fn spawn(&self, command: OutsideCommand) -> Result<Process> {
        let launcher = self.launcher()?;
        let (output, input) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
        let terminal = command.terminal.is_some();
        let fd = command.terminal.as_ref().map_or(input.as_raw_fd(), AsRawFd::as_raw_fd);
        let request = Request::Spawn { argv: command.argv, cwd: command.cwd, env: command.env, terminal };
        let pid = launcher.spawn(&request, fd).await?;
        drop(input);
        drop(command.terminal);
        let exit = launcher.expect_exit(pid);
        let exited = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let killer = Killer::new({
            let exited = exited.clone();
            move || {
                if !exited.load(std::sync::atomic::Ordering::Acquire) {
                    // SAFETY: signalling the process group of a command we started.
                    unsafe { libc::kill(-pid, libc::SIGKILL) };
                }
                Box::pin(async {})
            }
        });
        let (status_tx, status_rx) = oneshot::channel();
        tokio::spawn(async move {
            let status = exit.await.unwrap_or(KILLED);
            exited.store(true, std::sync::atomic::Ordering::Release);
            let _ = status_tx.send(status);
        });
        Ok(Process::new(output, status_rx, killer, None)?)
    }
}

struct Launcher {
    socket: AsyncFd<OwnedFd>,
    /// Keeps each request and the queueing of its reply together, so replies match in order.
    send: tokio::sync::Mutex<()>,
    replies: Mutex<VecDeque<oneshot::Sender<Result<i32, String>>>>,
    exits: Mutex<HashMap<i32, Exit>>,
}

enum Exit {
    Waiting(oneshot::Sender<ExitStatus>),
    Done(ExitStatus),
}

impl Launcher {
    async fn spawn(&self, request: &Request, fd: RawFd) -> Result<i32> {
        let (tx, rx) = oneshot::channel();
        {
            let _order = self.send.lock().await;
            self.replies.lock().unwrap().push_back(tx);
            loop {
                let mut ready = self.socket.writable().await?;
                match ready.try_io(|s| proto::send(s.get_ref().as_fd(), request, &[fd])) {
                    Ok(result) => break result?,
                    Err(_would_block) => continue,
                }
            }
        }
        rx.await.map_err(|_| anyhow!("the bootstrap parent is gone"))?.map_err(|e| anyhow!(e))
    }

    fn expect_exit(&self, pid: i32) -> oneshot::Receiver<ExitStatus> {
        let (tx, rx) = oneshot::channel();
        let mut exits = self.exits.lock().unwrap();
        match exits.remove(&pid) {
            Some(Exit::Done(status)) => {
                let _ = tx.send(status);
            }
            _ => {
                exits.insert(pid, Exit::Waiting(tx));
            }
        }
        rx
    }

    async fn read(self: Arc<Self>) {
        loop {
            let Ok(mut ready) = self.socket.readable().await else { break };
            let message = match ready.try_io(|s| proto::recv::<Reply>(s.get_ref().as_fd())) {
                Ok(Ok(Some((message, _)))) => message,
                Ok(_) => break,
                Err(_would_block) => continue,
            };
            match message {
                Reply::Spawned { pid } => self.answer(Ok(pid)),
                Reply::Failed { error } => self.answer(Err(error)),
                Reply::Exited { pid, code, signal } => {
                    let status = ExitStatus { code, signal };
                    let mut exits = self.exits.lock().unwrap();
                    match exits.remove(&pid) {
                        Some(Exit::Waiting(tx)) => {
                            let _ = tx.send(status);
                        }
                        _ => {
                            exits.insert(pid, Exit::Done(status));
                        }
                    }
                }
            }
        }
        self.replies.lock().unwrap().clear();
        self.exits.lock().unwrap().clear();
    }

    fn answer(&self, result: Result<i32, String>) {
        if let Some(tx) = self.replies.lock().unwrap().pop_front() {
            let _ = tx.send(result);
        }
    }
}

/// The bootstrap parent's loop: serves spawn requests on `socket` and reaps, until the
/// supervisor `child` exits. Returns the supervisor's wait status.
pub(crate) fn serve(socket: OwnedFd, child: libc::pid_t) -> nix::Result<nix::sys::wait::WaitStatus> {
    use nix::sys::signal::{SigSet, Signal};
    use nix::sys::signalfd::{SfdFlags, SignalFd};
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    let mut chld = SigSet::empty();
    chld.add(Signal::SIGCHLD);
    chld.thread_block()?;
    let signals = SignalFd::with_flags(&chld, SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC)?;
    let mut socket = Some(socket);
    let mut running: Vec<libc::pid_t> = Vec::new();
    loop {
        // Children, the supervisor included, may have exited before the signal was blocked.
        loop {
            match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) | Err(_) => break,
                Ok(status @ (WaitStatus::Exited(..) | WaitStatus::Signaled(..))) => {
                    let pid = status.pid().unwrap().as_raw();
                    if pid == child {
                        for pid in running {
                            // SAFETY: ending the sessions of commands we started.
                            unsafe { libc::kill(-pid, libc::SIGKILL) };
                        }
                        return Ok(status);
                    }
                    running.retain(|p| *p != pid);
                    let (code, signal) = match status {
                        WaitStatus::Exited(_, code) => (Some(code), None),
                        WaitStatus::Signaled(_, signal, _) => (None, Some(signal as i32)),
                        _ => unreachable!(),
                    };
                    if let Some(socket) = &socket {
                        let _ = proto::send(socket.as_fd(), &Reply::Exited { pid, code, signal }, &[]);
                    }
                }
                Ok(_) => {}
            }
        }
        let mut fds = vec![nix::poll::PollFd::new(signals.as_fd(), nix::poll::PollFlags::POLLIN)];
        if let Some(socket) = &socket {
            fds.push(nix::poll::PollFd::new(socket.as_fd(), nix::poll::PollFlags::POLLIN));
        }
        match nix::poll::poll(&mut fds, nix::poll::PollTimeout::NONE) {
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(error),
            Ok(_) => {}
        }
        let request = fds.get(1).and_then(|f| f.revents()).is_some_and(|r| !r.is_empty());
        while signals.read_signal().ok().flatten().is_some() {}
        if !request {
            continue;
        }
        let received = socket.as_ref().map(|s| proto::recv::<Request>(s.as_fd()));
        match received {
            Some(Ok(Some((Request::Spawn { argv, cwd, env, terminal }, fds)))) => {
                let reply = match fds.first() {
                    Some(fd) => match launch(&argv, &cwd, &env, fd, terminal) {
                        Ok(pid) => {
                            running.push(pid);
                            Reply::Spawned { pid }
                        }
                        Err(error) => Reply::Failed { error },
                    },
                    None => Reply::Failed { error: "no output descriptor".into() },
                };
                if let Some(socket) = &socket {
                    let _ = proto::send(socket.as_fd(), &reply, &[]);
                }
            }
            Some(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted => {}
            _ => socket = None,
        }
    }
}

/// `program` as `execve` needs it: itself if it names a path, else found through `PATH`.
fn resolve(program: &str, env: &[(String, String)]) -> Option<PathBuf> {
    if program.contains('/') {
        return Some(PathBuf::from(program));
    }
    let path = env.iter().find(|(k, _)| k == "PATH").map_or("/usr/bin:/bin", |(_, v)| v.as_str());
    path.split(':').filter(|d| !d.is_empty()).map(|d| Path::new(d).join(program)).find(|candidate| {
        let c = CString::new(candidate.as_os_str().as_bytes()).unwrap_or_default();
        // SAFETY: access on a NUL-terminated path.
        unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 }
    })
}

fn launch(argv: &[String], cwd: &Path, env: &[(String, String)], fd: &OwnedFd, terminal: bool) -> Result<i32, String> {
    let program = argv.first().ok_or("an empty command")?;
    let path = resolve(program, env).ok_or_else(|| format!("{program}: command not found"))?;
    let cstring = |s: &[u8]| CString::new(s).map_err(|_| format!("{program}: argument contains NUL"));
    let path_c = cstring(path.as_os_str().as_bytes())?;
    let cwd_c = cstring(cwd.as_os_str().as_bytes())?;
    let args: Vec<CString> = argv.iter().map(|a| cstring(a.as_bytes())).collect::<Result<_, _>>()?;
    let envs: Vec<CString> =
        env.iter().map(|(k, v)| cstring(format!("{k}={v}").as_bytes())).collect::<Result<_, _>>()?;
    let mut arg_ptrs: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    arg_ptrs.push(std::ptr::null());
    let mut env_ptrs: Vec<*const libc::c_char> = envs.iter().map(|e| e.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());
    let (errors, error_pipe) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(|e| e.to_string())?;
    let null = c"/dev/null";
    let fd = fd.as_raw_fd();
    let error_fd = error_pipe.as_raw_fd();
    // SAFETY: the bootstrap parent is single-threaded; the child only makes raw syscalls on
    // memory prepared above, then execs or exits.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
            let fail = |step: i32| -> ! {
                let errno = *libc::__errno_location();
                let report = [step, errno];
                libc::write(error_fd, report.as_ptr().cast(), 8);
                libc::_exit(127)
            };
            if libc::setsid() < 0 {
                fail(0);
            }
            if terminal {
                if libc::ioctl(fd, libc::TIOCSCTTY, 0) < 0 {
                    fail(1);
                }
                for target in 0..3 {
                    libc::dup2(fd, target);
                }
            } else {
                let input = libc::open(null.as_ptr(), libc::O_RDONLY);
                libc::dup2(input, 0);
                libc::dup2(fd, 1);
                libc::dup2(fd, 2);
            }
            if libc::chdir(cwd_c.as_ptr()) < 0 {
                fail(2);
            }
            libc::syscall(libc::SYS_close_range, 3, u32::MAX, libc::CLOSE_RANGE_CLOEXEC);
            libc::execve(path_c.as_ptr(), arg_ptrs.as_ptr(), env_ptrs.as_ptr());
            fail(3);
        }
    }
    drop(error_pipe);
    if pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    let mut report = [0u8; 8];
    let read = nix::unistd::read(&errors, &mut report).unwrap_or(0);
    if read == 8 {
        let step = i32::from_ne_bytes(report[..4].try_into().unwrap());
        let errno = std::io::Error::from_raw_os_error(i32::from_ne_bytes(report[4..].try_into().unwrap()));
        let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None);
        return Err(match step {
            2 => format!("working directory {}: {errno}", cwd.display()),
            3 => format!("{program}: {errno}"),
            _ => format!("starting {program}: {errno}"),
        });
    }
    Ok(pid)
}

pub(crate) fn channel() -> Result<(OwnedFd, OwnedFd)> {
    let (supervisor, parent) = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::SeqPacket,
        None,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC,
    )?;
    Ok((supervisor, parent))
}
