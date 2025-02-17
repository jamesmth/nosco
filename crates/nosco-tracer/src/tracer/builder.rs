use std::collections::HashMap;

use super::state::ScopedTraceConfig;
use super::{TraceModeConfig, Tracer};
use crate::{debugger::Debugger, handler::EventHandler};

/// Builder for [Tracer].
///
/// It is usually created by calling [Tracer::builder], and allows to
/// specify which debugger and event handler to use for spawning and tracing a
/// process.
pub struct Builder<S> {
    state: S,
}

impl Builder<NeedsDebugger> {
    pub(super) const fn new() -> Self {
        Self {
            state: NeedsDebugger,
        }
    }
}

impl Builder<NeedsDebugger> {
    /// Specifies the debugger to use for spawning and tracing a process.
    pub const fn with_debugger<D: Debugger>(self, debugger: D) -> Builder<NeedsHandler<D>> {
        Builder {
            state: NeedsHandler { debugger },
        }
    }
}

impl<D: Debugger> Builder<NeedsHandler<D>> {
    /// Specifies the handler of execution events from the traced process.
    pub fn with_event_handler<H>(self, handler: H) -> Builder<NeedsFlavor<D, H>>
    where
        H: EventHandler<Session = <D as Debugger>::Session>,
    {
        Builder {
            state: NeedsFlavor {
                debugger: self.state.debugger,
                handler,
            },
        }
    }
}

impl<D, H> Builder<NeedsFlavor<D, H>> {
    /// Specifies to use a global trace scope, which traces **all**
    /// instructions executed by the tracee.
    ///
    /// `depth` specifies the maximum function call depth to reach before
    /// pausing the tracer (until the last called function returns).
    ///
    /// # Warning
    ///
    /// This can lead to a significant performance drop for the traced
    /// process.
    pub fn trace_all(self, depth: usize) -> Builder<TraceAll<D, H>> {
        Builder {
            state: TraceAll {
                debugger: self.state.debugger,
                handler: self.state.handler,
                depth,
            },
        }
    }

    /// Specifies to use one or many trace scopes, which only trace
    /// instructions executed by the tracee **within** these scopes.
    ///
    /// # Note
    ///
    /// Unlike [trace_all](Self::trace_all), this function allows to
    /// minimize the performance penalties for the traced process (provided
    /// you carefully selected the trace scopes).
    pub fn trace_scopes(self) -> Builder<TraceWithScopes<D, H>> {
        Builder {
            state: TraceWithScopes {
                debugger: self.state.debugger,
                handler: self.state.handler,
                scopes_to_trace: HashMap::new(),
            },
        }
    }
}

impl<D, H> Builder<TraceWithScopes<D, H>> {
    /// Specifies a trace scope.
    ///
    /// - `binary` is the name of the loaded binary containing `symbol`.
    /// - `symbol` is the name of the function starting the trace scope
    /// - `depth` is the maximum function call depth to reach (in this scope)
    ///   before pausing the tracer (until the last called function returns)
    ///
    /// The trace scope starts when the specified function is called by the
    /// tracee, and stops when the function returns.
    pub fn scope(
        mut self,
        binary: impl Into<String>,
        symbol: impl Into<String>,
        depth: usize,
    ) -> Self {
        self.state
            .scopes_to_trace
            .entry(binary.into())
            .or_default()
            .insert(symbol.into(), depth);
        self
    }
}

impl<D, H> ReadyToBuild for TraceAll<D, H> {
    type Debugger = D;
    type Handler = H;

    fn build(self) -> Tracer<Self::Debugger, Self::Handler> {
        Tracer {
            debugger: self.debugger,
            handler: self.handler,
            trace_mode: TraceModeConfig::Full { depth: self.depth },
        }
    }
}

impl<D, H> ReadyToBuild for TraceWithScopes<D, H> {
    type Debugger = D;
    type Handler = H;

    fn build(self) -> Tracer<Self::Debugger, Self::Handler> {
        Tracer {
            debugger: self.debugger,
            handler: self.handler,
            trace_mode: TraceModeConfig::Scoped(ScopedTraceConfig {
                scopes: self.scopes_to_trace,
            }),
        }
    }
}

impl<S: ReadyToBuild> Builder<S> {
    /// Builds the tracer.
    pub fn build(self) -> Tracer<S::Debugger, S::Handler> {
        self.state.build()
    }
}

pub struct NeedsDebugger;

pub struct NeedsHandler<D> {
    pub(super) debugger: D,
}

pub struct NeedsFlavor<D, H> {
    debugger: D,
    handler: H,
}

pub struct TraceAll<D, H> {
    debugger: D,
    handler: H,
    depth: usize,
}

pub struct TraceWithScopes<D, H> {
    debugger: D,
    handler: H,
    scopes_to_trace: HashMap<String, HashMap<String, usize>>,
}

pub trait ReadyToBuild {
    type Debugger;
    type Handler;

    fn build(self) -> Tracer<Self::Debugger, Self::Handler>;
}
