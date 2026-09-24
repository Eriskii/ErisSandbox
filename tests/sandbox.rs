//! Isolation contract for sandboxes. Runs inside the supervisor user namespace, so it uses
//! its own `main` that bootstraps before any thread starts.

mod common;

use common::{Fixture, block_on};
use erissandbox::{Bind, Forward, Layer, Limits, Output, OutsideCommand};
use libtest_mimic::Failed;
use std::fs;

fn main() {
    common::run(&[
        ("commands_run_as_root_with_a_private_hostname", identity),
        ("host_files_are_unreachable", host_files_are_unreachable),
        ("writes_stay_in_each_sandboxes_layer", writes_stay_in_each_sandboxes_layer),
        ("workspace_layer_is_copy_on_write", workspace_layer_is_copy_on_write),
        ("read_only_bind_is_live_and_immutable", read_only_bind_is_live_and_immutable),
        ("sandboxes_cannot_see_other_processes", sandboxes_cannot_see_other_processes),
        ("each_sandbox_has_its_own_loopback_network", each_sandbox_has_its_own_loopback_network),
        ("memory_limit_kills_the_runaway_process", memory_limit_kills_the_runaway_process),
        ("pid_limit_bounds_process_creation", pid_limit_bounds_process_creation),
        ("namespace_and_mount_escapes_are_denied", namespace_and_mount_escapes_are_denied),
        ("background_processes_keep_the_sandbox_alive", background_processes_keep_the_sandbox_alive),
        ("files_open_inside_the_sandbox_view", files_open_inside_the_sandbox_view),
        ("filesystem_persists_across_hibernation", filesystem_persists_across_hibernation),
        ("missing_working_directory_is_reported", missing_working_directory_is_reported),
        ("kill_stops_the_whole_command", kill_stops_the_whole_command),
        ("forwarded_ports_reach_host_sockets", forwarded_ports_reach_host_sockets),
        ("devices_are_passed_through", devices_are_passed_through),
        ("destroy_stops_and_deletes_a_sandbox", destroy_stops_and_deletes_a_sandbox),
        ("outside_commands_run_as_the_invoking_user", outside_commands_run_as_the_invoking_user),
        ("outside_commands_stop_with_their_process_group", outside_commands_stop_with_their_process_group),
        ("outside_commands_can_own_a_terminal", outside_commands_can_own_a_terminal),
        ("directories_can_be_renamed_like_on_any_filesystem", directories_can_be_renamed_like_on_any_filesystem),
    ]);
}

/// Counts `sleep` processes visible in the sandbox; Debian slim has no procps.
const SLEEPERS: &str = "grep -l '^sleep' /proc/[0-9]*/cmdline 2>/dev/null | wc -l";

fn sh(fixture: &Fixture, sandbox: &std::sync::Arc<erissandbox::Sandbox>, script: &str) -> Output {
    block_on(fixture.run(sandbox, script))
}

fn check(condition: bool, message: impl Into<String>) -> Result<(), Failed> {
    if condition { Ok(()) } else { Err(message.into().into()) }
}

fn identity(f: &Fixture) -> Result<(), Failed> {
    let sandbox = f.sandbox("identity", f.spec());
    let out = sh(f, &sandbox, "id -u; hostname; echo $HOME; pwd");
    check(out.text() == "0\nsandbox-identity\n/root\n/root\n", format!("{out:?}"))
}

fn host_files_are_unreachable(f: &Fixture) -> Result<(), Failed> {
    let secret = f.host_dir("secret").join("key");
    fs::write(&secret, "host secret").unwrap();
    let sandbox = f.sandbox("host-files", f.spec());
    let script = format!(
        "cat {0} 2>/dev/null; test -e {0} && echo visible; ls /home; test -e /nix && echo nix; test -e /run/current-system && echo system; true",
        secret.display()
    );
    let out = sh(f, &sandbox, &script);
    check(out.text().is_empty(), format!("host content leaked: {out:?}"))
}

fn writes_stay_in_each_sandboxes_layer(f: &Fixture) -> Result<(), Failed> {
    let a = f.sandbox("layer-a", f.spec());
    let b = f.sandbox("layer-b", f.spec());
    sh(f, &a, "echo a > /etc/marker && mkdir -p /usr/local/x && touch /usr/local/x/y");
    sh(f, &b, "echo b > /etc/marker");
    check(sh(f, &a, "cat /etc/marker").text() == "a\n", "sandbox a lost its file")?;
    check(
        sh(f, &b, "cat /etc/marker; test -e /usr/local/x/y || echo absent").text() == "b\nabsent\n",
        "sandbox b saw sandbox a",
    )?;
    check(!f.rootfs().join("etc/marker").exists(), "image was modified")
}

fn workspace_layer_is_copy_on_write(f: &Fixture) -> Result<(), Failed> {
    let project = f.host_dir("project");
    fs::write(project.join("main.rs"), "fn main() {}\n").unwrap();
    let mut spec = f.spec();
    spec.layers.push(Layer { lower: project.clone(), target: "/workspace".into() });
    spec.cwd = "/workspace".into();
    let sandbox = f.sandbox("workspace", spec);
    let out = sh(f, &sandbox, "cat main.rs; echo changed > main.rs; echo new > added; cat main.rs");
    check(out.text() == "fn main() {}\nchanged\n", format!("{out:?}"))?;
    check(fs::read_to_string(project.join("main.rs")).unwrap() == "fn main() {}\n", "project changed")?;
    check(!project.join("added").exists(), "project gained a file")?;
    let upper = sandbox.layer_upper(0);
    check(fs::read_to_string(upper.join("added")).unwrap() == "new\n", "change missing from the layer")
}

fn read_only_bind_is_live_and_immutable(f: &Fixture) -> Result<(), Failed> {
    let records = f.host_dir("records");
    fs::write(records.join("transcript.jsonl"), "one\n").unwrap();
    let mut spec = f.spec();
    spec.binds.push(Bind { source: records.clone(), target: "/workspace/.ae".into(), writable: false });
    let sandbox = f.sandbox("bind", spec);
    check(sh(f, &sandbox, "cat /workspace/.ae/transcript.jsonl").text() == "one\n", "bind not visible")?;
    fs::write(records.join("transcript.jsonl"), "one\ntwo\n").unwrap();
    let out = sh(
        f,
        &sandbox,
        "cat /workspace/.ae/transcript.jsonl; (echo x > /workspace/.ae/new) 2>/dev/null || echo denied",
    );
    check(out.text() == "one\ntwo\ndenied\n", format!("{out:?}"))?;
    check(!records.join("new").exists(), "bind was writable")
}

fn sandboxes_cannot_see_other_processes(f: &Fixture) -> Result<(), Failed> {
    let a = f.sandbox("pids-a", f.spec());
    let b = f.sandbox("pids-b", f.spec());
    sh(f, &a, "sleep 300 >/dev/null 2>&1 &");
    let out = sh(f, &b, &format!("{SLEEPERS}; ls /proc | grep -cE '^[0-9]+$'"));
    let text = out.text();
    let lines: Vec<&str> = text.lines().collect();
    let visible: usize = lines.get(1).and_then(|n| n.parse().ok()).unwrap_or(usize::MAX);
    let result = check(lines.first() == Some(&"0") && visible < 8, format!("visible processes: {out:?}"));
    block_on(a.shutdown(true));
    result
}

fn each_sandbox_has_its_own_loopback_network(f: &Fixture) -> Result<(), Failed> {
    let a = f.sandbox("net-a", f.spec());
    let b = f.sandbox("net-b", f.spec());
    let interfaces = sh(f, &a, "tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' '");
    check(interfaces.text() == "lo\n", format!("interfaces: {interfaces:?}"))?;
    let up = sh(
        f,
        &a,
        "cat /sys/class/net/lo/operstate; (exec 3<>/dev/tcp/1.1.1.1/53) 2>/dev/null && echo online || echo offline",
    );
    check(up.text() == "unknown\noffline\n", format!("{up:?}"))?;
    let ns = |s| sh(f, s, "readlink /proc/self/ns/net").text();
    check(ns(&a) != ns(&b), "sandboxes share a network namespace")
}

fn memory_limit_kills_the_runaway_process(f: &Fixture) -> Result<(), Failed> {
    let mut spec = f.spec();
    spec.limits = Limits { memory_bytes: Some(64 << 20), ..spec.limits };
    let sandbox = f.sandbox("memory", spec);
    // The shell running the pipeline may be an OOM victim too, so judge the command itself.
    let out = sh(f, &sandbox, "head -c 512M /dev/zero | tail > /dev/null && echo completed");
    check(!out.text().contains("completed") && out.status.code() == 137, format!("{out:?}"))?;
    check(sh(f, &sandbox, "echo alive").text() == "alive\n", "sandbox died with the process")
}

fn pid_limit_bounds_process_creation(f: &Fixture) -> Result<(), Failed> {
    let mut spec = f.spec();
    spec.limits = Limits { pids: Some(16), ..spec.limits };
    let sandbox = f.sandbox("pids-limit", spec);
    // The kernel counts every fork the limit refuses in pids.events. timeout kills the
    // whole process group, so bash's fork retries end quickly.
    let out = sh(
        f,
        &sandbox,
        "cat /sys/fs/cgroup/pids.max; { timeout -s KILL 1 bash -c 'for i in $(seq 40); do sleep 30 & done'; } 2>/dev/null; \
         grep -c '^max [1-9]' /sys/fs/cgroup/pids.events",
    );
    block_on(sandbox.shutdown(true));
    check(out.text() == "16\n1\n", format!("{out:?}"))
}

fn namespace_and_mount_escapes_are_denied(f: &Fixture) -> Result<(), Failed> {
    let sandbox = f.sandbox("escapes", f.spec());
    let out = sh(
        f,
        &sandbox,
        "unshare -U true 2>/dev/null && echo userns; unshare -n true 2>/dev/null && echo netns; \
         mount -t tmpfs t /mnt 2>/dev/null && echo mount; \
         (echo 1 > /sys/fs/cgroup/memory.max) 2>/dev/null && echo cgroup; grep CapEff /proc/self/status",
    );
    // Docker's default capability set: no SYS_ADMIN, NET_ADMIN, SYS_PTRACE or SYS_MODULE.
    check(out.text() == "CapEff:\t00000000a80425fb\n", format!("escape succeeded: {out:?}"))
}

fn background_processes_keep_the_sandbox_alive(f: &Fixture) -> Result<(), Failed> {
    let sandbox = f.sandbox("background", f.spec());
    sh(f, &sandbox, "(sleep 300 &) ; echo started");
    check(!block_on(sandbox.shutdown(false)), "idle shutdown stopped a background process")?;
    check(sh(f, &sandbox, SLEEPERS).text() == "1\n", "background process vanished")?;
    check(block_on(sandbox.shutdown(true)), "forced shutdown failed")?;
    check(sh(f, &sandbox, SLEEPERS).text() == "0\n", "forced shutdown left processes")
}

fn files_open_inside_the_sandbox_view(f: &Fixture) -> Result<(), Failed> {
    use erissandbox::OpenMode;
    use std::io::{Read, Write};
    let sandbox = f.sandbox("open", f.spec());
    let mut file: fs::File = block_on(sandbox.open("/root/deep/note.txt", OpenMode::Write { create_parents: true }))
        .map_err(|e| e.to_string())?
        .into();
    file.write_all(b"from outside").unwrap();
    drop(file);
    check(sh(f, &sandbox, "cat /root/deep/note.txt").text() == "from outside", "write not visible")?;
    let mut text = String::new();
    fs::File::from(block_on(sandbox.open("/etc/debian_version", OpenMode::Read)).map_err(|e| e.to_string())?)
        .read_to_string(&mut text)
        .unwrap();
    check(!text.is_empty(), "read failed")?;
    let err = block_on(sandbox.open("/nope/missing", OpenMode::Read)).unwrap_err();
    check(err.raw_os_error() == Some(libc::ENOENT), format!("{err:?}"))?;
    sh(f, &sandbox, "ln -s /../../../../etc/shadow /root/escape");
    let escaped = block_on(sandbox.open("/root/escape", OpenMode::Read)).map(fs::File::from);
    let mut contents = String::new();
    if let Ok(mut file) = escaped {
        file.read_to_string(&mut contents).unwrap();
    }
    check(!contents.contains("eriskii"), "symlink escaped to the host")
}

fn filesystem_persists_across_hibernation(f: &Fixture) -> Result<(), Failed> {
    let sandbox = f.sandbox("hibernate", f.spec());
    sh(f, &sandbox, "echo kept > /root/state");
    check(block_on(sandbox.shutdown(false)), "idle sandbox refused shutdown")?;
    check(!sandbox.is_live(), "sandbox still live")?;
    check(sh(f, &sandbox, "cat /root/state").text() == "kept\n", "state lost")
}

fn missing_working_directory_is_reported(f: &Fixture) -> Result<(), Failed> {
    let mut spec = f.spec();
    spec.cwd = "/does/not/exist".into();
    let sandbox = f.sandbox("cwd", spec);
    let err = block_on(sandbox.spawn(&["true".into()], None)).err().map(|e| e.to_string()).unwrap_or_default();
    check(err.contains("Working directory does not exist: /does/not/exist"), err)
}

fn kill_stops_the_whole_command(f: &Fixture) -> Result<(), Failed> {
    let sandbox = f.sandbox("kill", f.spec());
    let started = std::time::Instant::now();
    let process =
        block_on(sandbox.spawn(&["/bin/bash".into(), "-c".into(), "sleep 100 | cat; sleep 100".into()], None)).unwrap();
    block_on(async {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        process.kill().await;
    });
    let status = block_on(process.wait());
    check(status.signal == Some(libc::SIGKILL), format!("{status:?}"))?;
    check(started.elapsed().as_secs() < 5, "kill did not stop the command")?;
    check(sh(f, &sandbox, SLEEPERS).text() == "0\n", "pipeline members survived")
}

fn forwarded_ports_reach_host_sockets(f: &Fixture) -> Result<(), Failed> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let socket = f.host_dir("forward").join("service.sock");
    let listener = block_on(async { tokio::net::UnixListener::bind(&socket) }).unwrap();
    common::runtime().spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (read, mut write) = stream.into_split();
                let mut lines = BufReader::new(read).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = write.write_all(format!("host saw {line}\n").as_bytes()).await;
                }
            });
        }
    });
    let mut spec = f.spec();
    spec.forwards.push(Forward { port: 3128, socket: socket.clone() });
    let sandbox = f.sandbox("forward", spec);
    let talk = "exec 3<>/dev/tcp/127.0.0.1/3128; echo hello >&3; head -n1 <&3";
    check(sh(f, &sandbox, talk).text() == "host saw hello\n", "first connection")?;
    check(block_on(sandbox.shutdown(false)), "idle shutdown refused")?;
    check(sh(f, &sandbox, talk).text() == "host saw hello\n", "forward after hibernation")?;
    let other = f.sandbox("no-forward", f.spec());
    let closed = sh(f, &other, "(exec 3<>/dev/tcp/127.0.0.1/3128) 2>/dev/null && echo open || echo closed");
    check(closed.text() == "closed\n", format!("{closed:?}"))
}

fn devices_are_passed_through(f: &Fixture) -> Result<(), Failed> {
    let mut spec = f.spec();
    spec.devices.push("/dev/fuse".into());
    let sandbox = f.sandbox("devices", spec);
    let out = sh(f, &sandbox, "stat -c '%F %t:%T' /dev/fuse; exec 3<>/dev/fuse && echo opened");
    check(out.text() == "character special file a:e5\nopened\n", format!("{out:?}"))?;
    let plain = f.sandbox("no-devices", f.spec());
    check(sh(f, &plain, "test -e /dev/fuse || echo absent").text() == "absent\n", "device leaked")
}

fn destroy_stops_and_deletes_a_sandbox(f: &Fixture) -> Result<(), Failed> {
    let sandbox = f.sandbox("destroy", f.spec());
    sh(f, &sandbox, "echo data > /root/file; (sleep 300 &)");
    check(sandbox.is_live(), "background process should keep it live")?;
    block_on(f.sandboxes.destroy("destroy")).map_err(|e| e.to_string())?;
    check(!sandbox.is_live(), "destroyed sandbox is live")?;
    let again = f.sandbox("destroy", f.spec());
    check(sh(f, &again, "cat /root/file 2>/dev/null || echo gone").text() == "gone\n", "filesystem survived")
}

fn outside(dir: &std::path::Path, script: &str) -> OutsideCommand {
    OutsideCommand {
        argv: vec!["sh".into(), "-c".into(), script.into()],
        cwd: dir.to_owned(),
        env: vec![("PATH".into(), std::env::var("PATH").unwrap()), ("MARK".into(), "set".into())],
        terminal: None,
    }
}

fn outside_commands_run_as_the_invoking_user(f: &Fixture) -> Result<(), Failed> {
    let dir = f.host_dir("outside");
    let inside = fs::read_to_string("/proc/self/uid_map").unwrap();
    let mut bytes = Vec::new();
    let status = block_on(async {
        let process = f.host.spawn_outside(outside(&dir, "cat /proc/self/uid_map; echo $MARK; pwd; exit 7")).await?;
        anyhow::Ok(process.drain(|chunk| bytes.extend_from_slice(chunk)).await)
    })
    .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    let lines: Vec<&str> = text.lines().collect();
    check(lines.len() == 3, format!("{text:?}"))?;
    let map: Vec<&str> = lines[0].split_whitespace().collect();
    check(map == ["0", "0", "4294967295"], format!("not the initial user namespace: {text:?}"))?;
    check(inside.split_whitespace().nth(2) != Some("4294967295"), "the test itself runs outside")?;
    check(lines[1] == "set" && lines[2] == dir.to_str().unwrap(), format!("{text:?}"))?;
    check(status.code == Some(7), format!("{status:?}"))?;
    let missing =
        block_on(f.host.spawn_outside(OutsideCommand { argv: vec!["/no/such/program".into()], ..outside(&dir, "") }));
    check(missing.is_err_and(|e| e.to_string().contains("/no/such/program")), "missing program was not reported")
}

fn outside_commands_stop_with_their_process_group(f: &Fixture) -> Result<(), Failed> {
    let dir = f.host_dir("outside-kill");
    let marker = format!("60.{}", std::process::id());
    let script = format!("sleep {marker} | cat");
    let started = std::time::Instant::now();
    let status = block_on(async {
        let mut command = outside(&dir, &script);
        command.argv[0] = "bash".into();
        let process = f.host.spawn_outside(command).await?;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        process.kill().await;
        anyhow::Ok(process.wait().await)
    })
    .map_err(|e| e.to_string())?;
    check(status.signal == Some(libc::SIGKILL), format!("{status:?}"))?;
    check(started.elapsed().as_secs() < 5, "kill did not stop it")?;
    std::thread::sleep(std::time::Duration::from_millis(200));
    let survivors = fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|e| fs::read(e.path().join("cmdline")).ok())
        .filter(|c| String::from_utf8_lossy(c).contains(&marker))
        .count();
    check(survivors == 0, "the pipeline outlived the kill")
}

fn outside_commands_can_own_a_terminal(f: &Fixture) -> Result<(), Failed> {
    use std::io::Read;
    let dir = f.host_dir("outside-tty");
    let pty = nix::pty::openpty(None, None).unwrap();
    let command = OutsideCommand { terminal: Some(pty.slave), ..outside(&dir, "tty; test -t 0 && echo interactive") };
    let status = block_on(async {
        let process = f.host.spawn_outside(command).await?;
        anyhow::Ok(process.wait().await)
    })
    .map_err(|e| e.to_string())?;
    let mut master = fs::File::from(pty.master);
    let mut buffer = [0u8; 4096];
    let read = master.read(&mut buffer).unwrap_or(0);
    let text = String::from_utf8_lossy(&buffer[..read]).to_string();
    check(status.success(), format!("{status:?}"))?;
    check(text.starts_with("/dev/pts/") && text.contains("interactive"), format!("{text:?}"))
}

/// Package managers install directories by renaming them into place, including over
/// directories from the image.
fn directories_can_be_renamed_like_on_any_filesystem(f: &Fixture) -> Result<(), Failed> {
    let sandbox = f.sandbox("rename", f.spec());
    let out = sh(
        f,
        &sandbox,
        "mkdir -p /etc/fresh.new && touch /etc/fresh.new/a && mv /etc/fresh.new /etc/fresh && echo fresh; \
         mv /etc/apt /etc/apt.moved && mv /etc/apt.moved /etc/apt && ls /etc/apt | head -1 && echo image",
    );
    check(out.text().starts_with("fresh\n") && out.text().ends_with("image\n"), format!("{out:?}"))
}
