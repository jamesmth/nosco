mod error;
pub mod mem;
pub mod process;
mod session;
pub mod thread;

use std::ffi::{CString, NulError};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;

use nix::fcntl::OFlag;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::unistd::{ForkResult, chdir, dup2, execvp, fork, pipe2};
use nosco_tracer::Command;
use nosco_tracer::tracer::TracedProcessStdio;

pub use self::error::{Error, Result};
use self::process::TracedProcessHandle;
pub use self::session::Session;

/// Spawns a new child process.
///
/// # Note
///
/// The process is spawned in debug-mode.
pub async fn spawn_debuggee(
    command: Command,
) -> crate::sys::Result<(TracedProcessHandle, TracedProcessStdio)> {
    let args = Some(CString::new(command.program.into_os_string().into_vec()))
        .into_iter()
        .chain(
            command
                .args
                .into_iter()
                .map(|arg| CString::new(arg.into_bytes())),
        )
        .collect::<std::result::Result<Vec<_>, NulError>>()?;

    let env = command
        .env
        .captured()
        .map(|env| {
            env.into_iter()
                .map(|(k, v)| CString::new(format!("{k}={v}")))
                .collect::<std::result::Result<Vec<_>, NulError>>()
        })
        .transpose()?;

    let envp = env.map(|env| {
        env.iter()
            .map(|s| s.as_ptr())
            .chain(Some(std::ptr::null()))
            .collect::<Vec<_>>()
    });

    let (child_stdin, parent_stdin) = pipe2(OFlag::O_CLOEXEC)?;
    let (parent_stdout, child_stdout) = pipe2(OFlag::O_CLOEXEC)?;
    let (parent_stderr, child_stderr) = pipe2(OFlag::O_CLOEXEC)?;

    // TODO just before forking:
    // - call `std::panic::always_abort` (once stabilized)
    // - use locking mechanism (RwLock) to make sure no other thread is accessing
    // the environment

    let pid = match unsafe { fork()? } {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            dup2(child_stdin.as_raw_fd(), nix::libc::STDIN_FILENO)?;
            dup2(child_stdout.as_raw_fd(), nix::libc::STDOUT_FILENO)?;
            dup2(child_stderr.as_raw_fd(), nix::libc::STDERR_FILENO)?;

            if let Some(cwd) = command.current_dir {
                chdir(&cwd)?;
            }

            ptrace::traceme()?;

            // Although we're performing an exec here we may also return with an
            // error from this function (without actually exec'ing) in which case we
            // want to be sure to restore the global environment back to what it
            // once was, ensuring that our temporary override, when free'd, doesn't
            // corrupt our process's environment.
            let mut _reset_env = None;
            if let Some(envp) = envp {
                unsafe {
                    _reset_env = Some(imp::ResetEnv(*imp::environ()));
                    *imp::environ() = envp.as_ptr();
                }
            }

            let Err(e) = execvp(&args[0], &args);

            unsafe { nix::libc::exit(e as i32) }
        }
    };

    imp::wait_for_thread_ready(pid)?;

    let handle = TracedProcessHandle::new(pid, true);

    let stdio = TracedProcessStdio {
        stdin: parent_stdin.into(),
        stdout: parent_stdout.into(),
        stderr: parent_stderr.into(),
    };

    Ok((handle, stdio))
}

/// Exception happening within the debuggee.
pub struct Exception(pub Signal);

impl Exception {
    pub(crate) fn is_breakpoint_or_singlestep(&self) -> bool {
        matches!(self.0, Signal::SIGTRAP)
    }
}

mod imp {
    use nix::sys::ptrace;
    use nix::sys::signal::Signal;
    use nix::sys::wait::{WaitStatus, waitpid};
    use nix::unistd::Pid;

    pub(super) fn wait_for_thread_ready(pid: Pid) -> crate::sys::Result<()> {
        // FIXME: this call blocks the async runtime
        let status = waitpid(pid, None)?;

        match status {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => (),
            WaitStatus::Exited(_, code) => {
                return Err(crate::sys::Error::ChildExec(
                    std::io::Error::from_raw_os_error(code),
                ));
            }
            _ => return Err(crate::sys::Error::BadChildWait(status)),
        }

        ptrace::setoptions(
            pid,
            ptrace::Options::PTRACE_O_TRACECLONE | ptrace::Options::PTRACE_O_TRACEEXIT,
        )?;

        Ok(())
    }

    pub(super) unsafe fn environ() -> *mut *const *const std::ffi::c_char {
        unsafe extern "C" {
            static mut environ: *const *const std::ffi::c_char;
        }

        &raw mut environ
    }

    pub(super) struct ResetEnv(pub *const *const std::ffi::c_char);

    impl Drop for ResetEnv {
        fn drop(&mut self) {
            unsafe {
                *environ() = self.0;
            }
        }
    }
}
