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
//! # Implementing a custom debugger
//!
//! This is the advanced use case of this crate.
//!
//! The [Debugger](self::debugger::Debugger)/[DebugSession](self::debugger::DebugSession)
//! traits allows to implement the inner debugging logic used for tracing a
//! process. For instance, an application could spawn and trace a process by
//! leveraging **Remote Debugging** (e.g., `gdb`, `lldb`) or **Virtual Machine
//! Introspection** under the hood. The possibilities are endless.

/// Module containing traits for implementing a custom debugger.
pub mod debugger;

mod error;

/// Module containing traits for handling trace events.
pub mod handler;

/// Module implementing the process tracer.
pub mod tracer;

pub use self::error::{Error, Result};
