//! Images are plain directory trees. [`import`] unpacks an image tarball, such as the
//! output of `docker export`, with its ownership intact. It must run inside the supervisor
//! namespace so ids beyond the invoking user map onto the subordinate range.

use anyhow::{Context, Result, bail};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

pub fn import(mut tar: impl Read, dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    // Device nodes cannot be created in a user namespace; sandboxes mount their own /dev.
    let mut child = Command::new("tar")
        .args(["-x", "-p", "--numeric-owner", "--exclude=dev/*", "--exclude=.dockerenv", "-C"])
        .arg(dir)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running tar")?;
    let mut stderr = child.stderr.take().unwrap();
    let errors = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let copied = std::io::copy(&mut tar, child.stdin.as_mut().unwrap());
    drop(child.stdin.take());
    let status = child.wait()?;
    let errors = errors.join().unwrap_or_default();
    let tail: Vec<&str> = errors.lines().rev().take(10).collect::<Vec<_>>().into_iter().rev().collect();
    if !status.success() {
        bail!("tar exited with {status}: {}", tail.join("\n"));
    }
    match copied {
        // tar stops reading at the end-of-archive marker, leaving the record's padding unread.
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => other.map(drop).with_context(|| format!("feeding tar: {}", tail.join("\n"))),
    }
}
