# ErisSandbox

Rootless Linux sandboxes for running untrusted commands, cheap enough to keep thousands on
one machine. Each sandbox is:

- a copy-on-write overlay over a shared image, plus optional copy-on-write layers and live
  bind mounts;
- private user, mount, PID, network (loopback only), IPC, UTS and cgroup namespaces;
- a cgroup with memory, process and CPU limits;
- Docker's default capabilities, no new privileges, and a seccomp filter against namespace
  and mount escapes, BPF, io_uring, keyrings, userfaultfd and module loading.

A sandbox exists as processes only while something runs in it. Its filesystem persists
between runs; an idle one costs nothing but disk.

## Use

```rust
fn main() -> anyhow::Result<()> {
    // First thing in main, before any thread exists.
    let host = erissandbox::bootstrap()?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let sandboxes = erissandbox::Sandboxes::new(&host, "/var/lib/myapp/sandboxes")?;
        let spec = erissandbox::SandboxSpec {
            rootfs: "/var/lib/myapp/images/debian".into(),
            layers: vec![erissandbox::Layer { lower: "/srv/project".into(), target: "/workspace".into() }],
            binds: Vec::new(),
            limits: erissandbox::Limits { memory_bytes: Some(512 << 20), pids: Some(256), cpus: Some(1.0) },
            hostname: "worker".into(),
            cwd: "/workspace".into(),
            env: erissandbox::SandboxSpec::default_env(),
        };
        let sandbox = sandboxes.sandbox("worker-1", spec)?;
        let output = sandbox.run(&["sh".into(), "-c".into(), "cargo test".into()]).await?;
        println!("{} ({:?})", output.text(), output.status);
        sandbox.shutdown(true).await;
        anyhow::Ok(())
    })
}
```

- `Sandboxes::sandbox(id, spec)` returns the sandbox with that id. Its writes collect under
  the state directory and persist across runs and restarts.
- `Sandbox::spawn` starts a command and returns a `Process`. You must read its combined
  output. `Process::drain` does that until exit, then briefly more, without waiting on
  background processes that keep the pipe open.
- `Sandbox::open` opens a path as the sandbox sees it and returns the file descriptor.
  Symlinks resolve inside the sandbox, so they cannot point a caller at host files.
- `Sandbox::shutdown(false)` stops an idle sandbox and refuses while processes run.
  `shutdown(true)` kills everything. An idle sandbox also hibernates by itself after
  `Sandboxes::idle_grace`.
- `Sandbox::layer_upper(i)` is where writes to layer `i` accumulate, for callers that turn
  them into something (a diff, a commit).
- `rootfs::import` unpacks an image tarball, such as `docker export` output, with ownership
  intact.

## How it works

**Bootstrap.** `bootstrap()` claims a delegated cgroup subtree and forks. The child becomes
the *supervisor*: it continues `main` inside a new user and mount namespace, where the
invoking user is root and the user's `/etc/subuid` range backs ids 1–65536 (through
`newuidmap`). No root is needed. The parent only forwards signals, cleans up the cgroups, and
exits with the supervisor's status. Re-executed with a private argument, the same binary
becomes a sandbox's init instead.

**Starting a sandbox.** The first request `clone3`s an init directly into its namespaces and
cgroup. The init:

1. mounts the overlays and binds, then fresh `/proc`, read-only `/sys`, a read-only view of
   its own cgroup, and a minimal `/dev`;
2. calls `pivot_root`, which detaches the host filesystem entirely;
3. drops to Docker's capability set, sets no-new-privs, makes itself non-dumpable, and
   installs the seccomp filter;
4. serves spawn, kill, open and shutdown requests over a `SOCK_SEQPACKET` socket, passing
   file descriptors with `SCM_RIGHTS`.

Commands raise their OOM score so the kernel kills them before the init.

**Cgroups.**

```text
<delegated>/erissandbox-<pid>/     controllers enabled for children
    supervisor/                    the process that called bootstrap
    sandboxes/<sandbox id>/        one leaf per live sandbox, with its limits
```

`<delegated>` is the process's own cgroup when it is alone there (a systemd unit with
`Delegate=yes`). Otherwise it is the nearest ancestor the user owns with the memory, pids and
cpu controllers available, such as `user@<uid>.service`. Subtrees left by killed supervisors
are swept at startup.

**What a sandboxed process can still see:** the kernel version, CPU and memory totals, and
timing. Sandboxes share the host kernel, so a kernel exploit escapes, as with any container.

## Requirements

- Linux with cgroup v2, with memory, pids and cpu delegated to the user (as systemd's
  `user@.service` does).
- Unprivileged user namespaces.
- A range of at least 65536 ids for the user in `/etc/subuid` and `/etc/subgid`, and
  `newuidmap`/`newgidmap`.
- Images are plain directory trees.

## Verification

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test          # needs Docker once, to export debian:bookworm-slim as the test image
```
