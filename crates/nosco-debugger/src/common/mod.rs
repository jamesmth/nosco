pub mod binary;
pub mod breakpoint;
pub mod debugger;
pub mod session;
pub mod thread;

pub enum DebugStop {
    Trap {
        thread_id: u64,
    },

    #[allow(dead_code)] // to be used when multithreading is supported
    ThreadCreated {
        thread_id: u64,
    },

    ThreadExited {
        thread_id: u64,
        exit_code: i32,
    },

    Exited {
        exit_code: i32,
    },
}
