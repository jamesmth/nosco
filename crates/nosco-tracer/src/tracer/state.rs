use std::collections::HashMap;

//use super::binary::MappedBinaries;
use crate::debugger::{BinaryInformation, BinaryView, DebugSession};
use crate::error::DebuggerError;
use crate::handler::EventHandler;

type BinaryName = String;
type BinaryAddr = u64;

type SymbolName = String;
type SymbolAddr = u64;

type ThreadId = u64;

type UnresolvedScope = HashMap<SymbolName, usize>;

/// Scoped tracing configuration.
pub struct ScopedTraceConfig {
    pub(super) scopes: HashMap<BinaryName, UnresolvedScope>,
}

/// State of scoped tracing.
pub struct ScopedTraceState {
    traced_functions_unresolved: HashMap<BinaryName, UnresolvedScope>,
    traced_functions: HashMap<BinaryAddr, Vec<SymbolAddr>>,

    traced_functions_depth: HashMap<SymbolAddr, usize>,

    cur_scopes: HashMap<ThreadId, Vec<(SymbolAddr, usize)>>,
}

impl ScopedTraceState {
    /// Creates a new [ScopedTraceState] with the given configuration.
    pub fn new(config: ScopedTraceConfig) -> Self {
        let cap = config.scopes.len();

        Self {
            traced_functions_unresolved: config.scopes,
            traced_functions: HashMap::with_capacity(cap),
            traced_functions_depth: HashMap::new(),
            cur_scopes: HashMap::new(),
        }
    }

    /// Updates the state with the given binary mapped by the tracee.
    pub async fn register_mapped_binary<S: DebugSession, H: EventHandler>(
        &mut self,
        session: &mut S,
        binary: S::MappedBinary,
    ) -> crate::Result<(), S::Error, H::Error> {
        let Some(unresolved) = self.traced_functions_unresolved.get(binary.file_name()) else {
            return Ok(());
        };

        let binary_view = binary
            .to_view()
            .await
            .map_err(|e| DebuggerError(e.into()))?;

        let mut resolved_addrs = Vec::with_capacity(unresolved.len());

        for (symbol, trace_depth) in unresolved.iter() {
            let span = tracing::info_span!("ResolveSymbol", binary = binary.file_name(), symbol);
            let _guard = span.enter();

            let addr = binary_view
                .addr_of_symbol(symbol)
                .map_err(|e| DebuggerError(e.into().into()))?
                .ok_or_else(|| {
                    crate::Error::SymbolNotFound(binary.file_name().to_owned(), symbol.clone())
                })?;

            tracing::info!(addr = format_args!("{addr:#x}"), "resolved");

            self.traced_functions_depth.insert(addr, *trace_depth);
            resolved_addrs.push(addr);

            session.add_breakpoint(None, addr).map_err(DebuggerError)?;
        }

        self.traced_functions
            .insert(binary.addr_range().start, resolved_addrs);

        Ok(())
    }

    /// Updates the state with the given binary unmapped by the tracee.
    pub fn register_unmapped_binary<S: DebugSession, H: EventHandler>(
        &mut self,
        session: &mut S,
        binary_addr: BinaryAddr,
    ) -> crate::Result<(), S::Error, H::Error> {
        let Some(addrs) = self.traced_functions.remove(&binary_addr) else {
            return Ok(());
        };

        for addr in addrs {
            self.traced_functions_depth.remove(&addr);
            session
                .remove_breakpoint(None, addr)
                .map_err(DebuggerError)?;
        }

        Ok(())
    }

    /// Updates the state with the given thread created by the tracee.
    pub fn register_thread_created(&mut self, thread_id: ThreadId) {
        self.cur_scopes.insert(thread_id, Vec::new());
    }

    /// Updates the state with the given thread exited by the tracee.
    pub fn register_thread_exited(&mut self, thread_id: ThreadId) {
        self.cur_scopes.remove(&thread_id);
    }

    /// Returns whether the given address (tracee) is the start of some function to trace.
    pub fn is_function_to_trace(&self, addr: SymbolAddr) -> bool {
        self.traced_functions_depth.contains_key(&addr)
    }

    /// Updates the state with a new function call made by the tracee.
    ///
    /// It returns whether the maximum function call depth was exceeded.
    pub fn register_function_call(&mut self, thread_id: ThreadId, addr: SymbolAddr) -> bool {
        let Some(thread_scopes) = self.cur_scopes.get_mut(&thread_id) else {
            unreachable!("thread {thread_id} not registered")
        };

        if let Some(max_depth) = self.traced_functions_depth.get(&addr).copied() {
            // this is a function to trace, we initialize a new scope with initial depth

            let cur_depth = 1;
            thread_scopes.push((addr, cur_depth));

            cur_depth > max_depth
        } else if let Some((addr, cur_depth)) = thread_scopes.last_mut() {
            // this is a nested function, we increment the current depth

            let Some(max_depth) = self.traced_functions_depth.get(addr).copied() else {
                unreachable!("lookup of function to trace should not fail");
            };

            *cur_depth = cur_depth.saturating_add(1);
            *cur_depth > max_depth
        } else {
            unreachable!("unexpected nested function before function to trace");
        }
    }

    /// Updates the state with a function return made by the tracee.
    ///
    /// It returns whether the new current depth is 0.
    pub fn register_function_return(&mut self, thread_id: ThreadId) -> bool {
        let Some(thread_scopes) = self.cur_scopes.get_mut(&thread_id) else {
            unreachable!("thread {thread_id} not registered")
        };

        let Some((_, cur_depth)) = thread_scopes.last_mut() else {
            unreachable!("return before call");
        };

        *cur_depth = cur_depth.saturating_sub(1);

        if *cur_depth == 0 {
            thread_scopes.pop();
            true
        } else {
            false
        }
    }
}

/// State of full tracing.
pub struct FullTraceState {
    /// Maximum reachable function call depth.
    max_depth: usize,

    /// Current function call depth, per thread.
    cur_depths: HashMap<ThreadId, usize>,
}

impl FullTraceState {
    /// Creates a new [FullTraceState] with the given maximum reachable depth.
    pub fn new(max_depth: usize) -> Self {
        Self {
            max_depth,
            cur_depths: HashMap::new(),
        }
    }

    /// Updates the state with a new function call made by the tracee.
    ///
    /// It returns whether the maximum function call depth was exceeded.
    pub fn register_function_call(&mut self, thread_id: ThreadId) -> bool {
        let Some(cur_depth) = self.cur_depths.get_mut(&thread_id) else {
            unreachable!("thread {thread_id} not registered")
        };

        *cur_depth = cur_depth.saturating_add(1);
        *cur_depth > self.max_depth
    }

    /// Updates the state with a function return made by the tracee.
    ///
    /// It returns whether the new current depth is 0.
    pub fn register_function_return(&mut self, thread_id: ThreadId) -> bool {
        let Some(cur_depth) = self.cur_depths.get_mut(&thread_id) else {
            unreachable!("thread {thread_id} not registered")
        };

        *cur_depth = cur_depth.saturating_sub(1);
        *cur_depth == 0
    }

    /// Updates the state with the given thread created by the tracee.
    pub fn register_thread_created(&mut self, thread_id: u64) {
        self.cur_depths.insert(thread_id, 0);
    }

    /// Updates the state with the given thread exited by the tracee.
    pub fn register_thread_exited(&mut self, thread_id: u64) {
        self.cur_depths.remove(&thread_id);
    }
}
