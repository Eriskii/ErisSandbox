//! Processes run by a sandbox, or by anything else that hands out the same primitives: a
//! running [`Process`] with combined output, its [`ExitStatus`], a [`Killer`] for its process
//! group, and [`OpenMode`] for opening files as the process's machine sees them.

use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::io::unix::AsyncFd;
use tokio::sync::oneshot;

/// How a file is opened for a process's machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpenMode {
    Read,
    /// Create or truncate, optionally creating missing parent directories.
    Write {
        create_parents: bool,
    },
    /// Read and write an existing file without truncating it.
    Update,
}

/// Opens a path in the calling process's view of the filesystem. A sandbox's init calls this
/// from inside the sandbox.
pub fn open_path(path: &str, mode: OpenMode) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    // Non-blocking so opening a FIFO cannot hang; the flag is cleared before returning.
    options.custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK);
    match mode {
        OpenMode::Read => {
            options.read(true);
        }
        OpenMode::Write { create_parents } => {
            if create_parents && let Some(parent) = Path::new(path).parent() {
                fs::create_dir_all(parent)?;
            }
            options.write(true).create(true).truncate(true).mode(0o644);
        }
        OpenMode::Update => {
            options.read(true).write(true);
        }
    }
    let file = options.open(path)?;
    // SAFETY: F_GETFL/F_SETFL on a descriptor we own.
    unsafe {
        let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }
    Ok(file)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitStatus {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

impl ExitStatus {
    /// The shell convention: the exit code, or 128 plus the terminating signal.
    pub fn code(&self) -> i32 {
        self.code.unwrap_or_else(|| 128 + self.signal.unwrap_or(0))
    }

    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

pub const KILLED: ExitStatus = ExitStatus { code: None, signal: Some(libc::SIGKILL) };

/// How long output is still collected after a command exits.
pub const DRAIN_GRACE: Duration = Duration::from_millis(100);

/// Combined stdout and stderr of a finished command.
#[derive(Clone, Debug)]
pub struct Output {
    pub bytes: Vec<u8>,
    pub status: ExitStatus,
}

impl Output {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

type KillFn = dyn Fn() -> BoxFuture<'static, ()> + Send + Sync;

/// Kills a command's whole process group.
#[derive(Clone)]
pub struct Killer(Arc<KillFn>);

impl Killer {
    pub fn new(kill: impl Fn() -> BoxFuture<'static, ()> + Send + Sync + 'static) -> Self {
        Self(Arc::new(kill))
    }

    pub async fn kill(&self) {
        (self.0)().await
    }
}

/// A running command. Dropping it leaves the command running.
pub struct Process {
    output: Option<tokio::net::unix::pipe::Receiver>,
    exit: oneshot::Receiver<ExitStatus>,
    killer: Killer,
    /// Whatever must live as long as the command, such as a sandbox's activity count.
    _keep: Option<Box<dyn Send + Sync>>,
}

impl Process {
    /// A process whose combined output arrives on `output`, whose exit status arrives on
    /// `exit`, and which `killer` kills. `keep` lives as long as the process handle.
    pub fn new(
        output: OwnedFd,
        exit: oneshot::Receiver<ExitStatus>,
        killer: Killer,
        keep: Option<Box<dyn Send + Sync>>,
    ) -> io::Result<Self> {
        set_nonblocking(&output)?;
        let output = tokio::net::unix::pipe::Receiver::from_owned_fd(output)?;
        Ok(Self { output: Some(output), exit, killer, _keep: keep })
    }

    /// Combined stdout and stderr. Reaches end of file once every process holding it exits.
    pub fn take_output(&mut self) -> tokio::net::unix::pipe::Receiver {
        self.output.take().expect("output already taken")
    }

    pub async fn kill(&self) {
        self.killer.kill().await;
    }

    /// A handle that kills this command, usable while [`Process::wait`] owns the process.
    pub fn killer(&self) -> Killer {
        self.killer.clone()
    }

    pub async fn wait(self) -> ExitStatus {
        self.exit.await.unwrap_or(KILLED)
    }

    /// Feeds output to `sink` until the command exits, then for at most [`DRAIN_GRACE`]
    /// longer. Background processes it started may keep the pipe open indefinitely; they
    /// are not waited for.
    pub async fn drain(mut self, mut sink: impl FnMut(&[u8])) -> ExitStatus {
        let mut output = self.take_output();
        let mut buffer = vec![0u8; 16 * 1024];
        let mut open = true;
        let status = loop {
            tokio::select! {
                exit = &mut self.exit => break exit.unwrap_or(KILLED),
                read = output.read(&mut buffer), if open => match read {
                    Ok(n) if n > 0 => sink(&buffer[..n]),
                    _ => open = false,
                },
            }
        };
        let grace = tokio::time::Instant::now() + DRAIN_GRACE;
        while open {
            match tokio::time::timeout_at(grace, output.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => sink(&buffer[..n]),
                _ => open = false,
            }
        }
        status
    }
}

/// Tokio drives these descriptors; a blocking read would stall a runtime worker.
pub fn set_nonblocking(fd: &impl AsRawFd) -> io::Result<()> {
    // SAFETY: F_GETFL/F_SETFL on a valid descriptor.
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Waits for the process behind a pidfd to exit and reaps it. Reaping through the pidfd
/// needs no thread per child. Repeating it is harmless: a reaped pidfd stays readable.
pub async fn reap(pidfd: &AsyncFd<OwnedFd>) -> ExitStatus {
    let _ = pidfd.readable().await;
    wait_exited(pidfd.as_raw_fd())
}

/// Reaps an exited child by pidfd.
pub fn wait_exited(pidfd: i32) -> ExitStatus {
    // SAFETY: waitid on a pidfd we own, into a zeroed siginfo.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::waitid(libc::P_PIDFD, pidfd as libc::id_t, &mut info, libc::WEXITED) };
    if result < 0 {
        return KILLED;
    }
    // SAFETY: waitid filled a SIGCHLD siginfo.
    let status = unsafe { info.si_status() };
    if info.si_code == libc::CLD_EXITED {
        ExitStatus { code: Some(status), signal: None }
    } else {
        ExitStatus { code: None, signal: Some(status) }
    }
}
