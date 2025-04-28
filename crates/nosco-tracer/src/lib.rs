//! This crate allows to spawn a process and trace its execution.
//!
//! Two main components are provided:
//! - A trait to implement a custom trace handler, allowing to implement
//!   arbitrary logic to consume process execution events (e.g., executed
//!   instructions, spawned threads).
//! - A few traits to implement a custom debugger, responsible for spawning a
//!   process and instrumenting it.
//!
//! # Consuming trace events
//!
//! This is the main use case of this crate.
//!
//! The [EventHandler](self::handler::EventHandler) trait allows define custom
//! logic for handling execution events from a spawned process.
//!
//! ```no_run
//! use nosco_debugger::{Debugger, Session};
//!
//! use nosco_tracer::Command;
//! use nosco_tracer::debugger::DebugSession;
//! use nosco_tracer::handler::EventHandler;
//! use nosco_tracer::tracer::Tracer;
//!
//! #[tokio::main]
//! async fn main() {
//!     // initialize the tracer
//!     let tracer = Tracer::builder()
//!         .with_debugger(Debugger::default())
//!         .with_event_handler(CustomHandler)
//!         .trace_all(3)
//!         .build();
//!
//!     // spawn the process to trace
//!     let (process, _) = tracer.spawn(Command::new("ls").arg("/")).await.unwrap();
//!
//!     // wait for the traced process to exit
//!     let (exit_code, _) = process.resume_and_trace().await.unwrap();
//! }
//!
//! struct CustomHandler;
//!
//! impl EventHandler for CustomHandler {
//!     type Session = Session;
//!     type Error = std::io::Error;
//!
//!     async fn instruction_executed(
//!         &mut self,
//!         _session: &mut Self::Session,
//!         _thread: &<Self::Session as DebugSession>::StoppedThread,
//!         _opcodes_addr: u64,
//!         _opcodes: Vec<u8>,
//!     ) -> Result<(), Self::Error> {
//!         //
//!         // do some action with the executed instruction
//!         //
//!
//!         Ok(())
//!     }
//! }
//! ```
//!
//! # Implementing a custom debugger
//!
//! This is the advanced use case of this crate.
//!
//! The [Debugger](self::debugger::Debugger)/[DebugSession](self::debugger::DebugSession)
//! traits allows to implement the inner debugging logic used for tracing a
//! process. For instance, an application could spawn and trace a process by
//! leveraging **Remote Debugging** (e.g., `gdb`, `lldb`) or **Virtual Machine
//! Introspection** under the hood. The possibilities are endless.
//!
//! Most of the time, you won't need to go this far. If you simply need to trace
//! a process running on the same machine as the tracer, you can use the
//! default debugger provided by `nosco-debugger`.

/// Module containing traits for implementing a custom debugger.
pub mod debugger;

mod command;
mod error;

/// Module containing traits for handling trace events.
pub mod handler;

/// Module implementing the process tracer.
pub mod tracer;

pub use self::command::{Command, CommandEnv};
pub use self::error::{Error, Result};
