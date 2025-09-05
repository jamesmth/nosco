pub mod breakpoint;
pub mod debugger;
pub mod session;
pub mod thread;

use nosco_tracer::debugger::ExitStatus;

pub enum DebugStop {
    Exception {
        thread_id: u64,
        exception: crate::sys::Exception,
    },

    #[allow(dead_code)] // to be used when multithreading is supported
    ThreadCreated {
        thread_id: u64,
        new_thread_id: u64,
    },

    ThreadExited {
        thread_id: u64,
        exit_code: i32,
    },

    Exited(ExitStatus<crate::sys::Exception>),
}
