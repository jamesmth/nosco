use std::os::fd::{AsRawFd, OwnedFd};

use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::unistd::Pid;

/// OS-specific process handle.
pub struct TracedProcessHandle {
    pidfd: OwnedFd,
    pid: Pid,
    kill_on_drop: bool,
}

impl TracedProcessHandle {
    /// Creates a new `ProcessHandle` from the given process ID.
    pub const fn new(pidfd: OwnedFd, pid: Pid, kill_on_drop: bool) -> Self {
        Self {
            pidfd,
            pid,
            kill_on_drop,
        }
    }

    /// Returns the process ID of the process associated with this handle.
    pub const fn id(&self) -> Pid {
        self.pid
    }

    /// Returns the process ID of the process associated with this handle.
    pub const fn raw_id(&self) -> u64 {
        self.pid.as_raw() as u64
    }
}

impl Drop for TracedProcessHandle {
    fn drop(&mut self) {
        if self.kill_on_drop {
            let res = unsafe {
                Errno::result(nix::libc::syscall(
                    nix::libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    Signal::SIGKILL,
                    Option::<()>::None,
                    0,
                ))
            };

            match res {
                Ok(_) => tracing::debug!(pid = self.pid.as_raw(), "process killed"),
                Err(Errno::ESRCH) => (),
                Err(e) => {
                    tracing::error!(error = %e, pidfd = self.pidfd.as_raw_fd(), "pidfd_send_signal")
                }
            }
        }
    }
}
