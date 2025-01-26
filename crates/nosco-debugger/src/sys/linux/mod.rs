mod error;
pub mod mem;
mod session;
pub mod thread;

use std::io;
use std::process::Stdio;

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use tokio::process::{Child, Command};

pub use self::error::{Error, Result};
pub use self::session::Session;
pub use crate::common::binary::MappedBinary;

/// Spawns a new child process.
///
/// # Note
///
/// The process is spawned in debug-mode.
pub async fn spawn_debuggee(command: &mut Command) -> crate::sys::Result<(u64, Child)> {
    // On Linux, if a `pre_exec` closure is specified, `rust-std` will
    // spawn the process with `fork`+`exec`, otherwise `posix_spawn` is used.
    unsafe {
        command.pre_exec(|| ptrace::traceme().map_err(|e| io::Error::from_raw_os_error(e as i32)))
    };

    let child = command
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let Some(pid) = child.id().map(|id| Pid::from_raw(id as i32)) else {
        unreachable!("debuggee should not have completed");
    };

    wait_for_thread_ready(pid)?;

    Ok((pid.as_raw() as u64, child))
}

fn wait_for_thread_ready(pid: Pid) -> crate::sys::Result<()> {
    // FIXME: this call blocks the async runtime
    let status = waitpid(pid, None)?;

    if !matches!(status, WaitStatus::Stopped(_, Signal::SIGTRAP)) {
        return Err(crate::sys::Error::BadChildWait(status));
    }

    ptrace::setoptions(
        pid,
        ptrace::Options::PTRACE_O_TRACECLONE | ptrace::Options::PTRACE_O_TRACEEXIT,
    )?;

    Ok(())
}
