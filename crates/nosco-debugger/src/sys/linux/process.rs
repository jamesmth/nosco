use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

/// OS-specific process handle.
pub struct TracedProcessHandle {
    pid: Pid,
    kill_on_drop: bool,
}

impl TracedProcessHandle {
    /// Creates a new `ProcessHandle` from the given process ID.
    pub const fn new(pid: Pid, kill_on_drop: bool) -> Self {
        Self { pid, kill_on_drop }
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
            let _ = kill(self.pid, Signal::SIGKILL);
        }
    }
}
