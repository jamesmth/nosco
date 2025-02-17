use std::collections::{HashMap, HashSet};

use super::breakpoint::Breakpoint;

pub struct ThreadManager {
    threads: HashMap<u64, ThreadState>,
    breakpoints: HashSet<u64>,
}

impl ThreadManager {
    pub fn new() -> Self {
        Self {
            threads: HashMap::new(),
            breakpoints: HashSet::new(),
        }
    }

    pub fn register_thread_create(&mut self, thread_id: u64) -> StoppedThread {
        let state = self
            .threads
            .entry(thread_id)
            .or_insert_with(|| ThreadState {
                single_step: false,
                stepping_over: None,
                breakpoints: HashSet::new(),
            });

        StoppedThread {
            id: thread_id,
            instr_addr: 0,
            single_step: state.single_step,
            stepped_over: state.stepping_over.clone(),
            stopped_by: None,
        }
    }

    pub fn register_thread_exit(&mut self, thread_id: u64) {
        self.threads.remove(&thread_id);
    }

    pub fn register_add_breakpoint(&mut self, thread_id: Option<u64>, addr: u64) {
        if let Some(id) = thread_id {
            if let Some(state) = self.threads.get_mut(&id) {
                state.breakpoints.insert(addr);
            }
        } else {
            self.breakpoints.insert(addr);
        }
    }

    pub fn register_remove_breakpoint(&mut self, thread_id: Option<u64>, addr: u64) {
        if let Some(id) = thread_id {
            if let Some(state) = self.threads.get_mut(&id) {
                state.breakpoints.remove(&addr);
            }
        } else {
            self.breakpoints.remove(&addr);
        }
    }

    pub fn register_thread_stop(
        &mut self,
        thread_id: u64,
        stopped_by: Option<Breakpoint>,
    ) -> Option<StoppedThread> {
        self.threads.get(&thread_id).map(|state| StoppedThread {
            id: thread_id,
            instr_addr: 0,
            single_step: state.single_step,
            stepped_over: state.stepping_over.clone(),
            stopped_by: stopped_by.map(|bk| {
                let is_breakpoint_of_thread =
                    self.breakpoints.contains(&bk.addr) || state.breakpoints.contains(&bk.addr);
                (is_breakpoint_of_thread, bk)
            }),
        })
    }

    pub fn register_thread_resume(
        &mut self,
        thread_id: u64,
        single_step_mode: bool,
        stepping_over: Option<Breakpoint>,
    ) {
        if let Some(state) = self.threads.get_mut(&thread_id) {
            state.single_step = single_step_mode;
            state.stepping_over = stepping_over;
        }
    }
}

struct ThreadState {
    /// Whether the thread is in single-step mode.
    single_step: bool,

    /// The optional breakpoint the thread is stepping over.
    stepping_over: Option<Breakpoint>,

    /// Breakpoints registered for this thread.
    breakpoints: HashSet<u64>,
}

/// Stopped thread of the tracee.
pub struct StoppedThread {
    /// ID of the thread.
    id: u64,

    /// Thread's instruction address.
    pub(super) instr_addr: u64,

    /// Whether the thread is in single-step mode.
    pub(super) single_step: bool,

    /// The optional breakpoint the thread has stepped over.
    ///
    /// Once the thread has stepped over this breakpoint, it needs to be
    /// enabled again.
    pub(super) stepped_over: Option<Breakpoint>,

    /// The optional breakpoint that stopped the thread.
    ///
    /// The boolean specifies whether the breakpoint is in effect for this
    /// thread.
    pub(super) stopped_by: Option<(bool, Breakpoint)>,
}

impl nosco_tracer::debugger::Thread for StoppedThread {
    type Error = crate::Error;

    fn id(&self) -> u64 {
        self.id
    }

    fn instr_addr(&self) -> u64 {
        self.instr_addr
    }

    fn single_step_mut(&mut self) -> &mut bool {
        &mut self.single_step
    }
}
