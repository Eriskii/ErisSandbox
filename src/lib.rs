//! ErisSandbox: rootless Linux sandboxes. Each sandbox is a copy-on-write filesystem over a
//! shared image, private user, mount, PID, network, IPC, UTS and cgroup namespaces, cgroup
//! limits, Docker's default capabilities and a seccomp filter. It exists as processes only
//! while something runs in it.
//!
//! Call [`bootstrap`] first in `main`, then create [`Sandboxes`] and run commands in them.

mod bootstrap;
mod cgroup;
mod outside;
mod process;
pub mod rootfs;
mod sandbox;

pub use bootstrap::{Host, bootstrap};
pub use cgroup::Limits;
pub use outside::OutsideCommand;
pub use process::{
    DRAIN_GRACE, ExitStatus, KILLED, Killer, OpenMode, Output, Process, open_path, reap, set_nonblocking, wait_exited,
};
pub use sandbox::{Bind, Forward, Layer, Sandbox, SandboxSpec, Sandboxes};
