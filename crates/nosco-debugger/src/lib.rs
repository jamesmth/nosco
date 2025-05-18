//! This crate provides a default implementation of a debugger (to be used with
//! `nosco-tracer`).
//!
//! The debugger is able to spawn a process (on the **same host machine**) as
//! a child and debug it.
//!
//! <div class="warning">
//!
//! *This crate is not meant to be used on its own! It merely implements the
//! interface (traits) provided by `nosco-tracer`, so that the debugger can
//! be used by that crate for tracing processes.*
//!
//! </div>
//!
//! # Supported Platforms
//!
//! <table>
//!     <thead>
//!         <tr>
//!             <th>Host Machine</th>
//!             <th>Debuggee Platform</th>
//!         </tr>
//!     </thead>
//!     <tbody>
//!         <tr>
//!             <td rowspan="2">Linux <code>x86_64</code></td>
//!             <td><code>x86_64</code></td>
//!         </tr>
//!         <tr>
//!             <td><code>i386</code></td>
//!         </tr>
//!     </tbody>
//! </table>

mod common;
mod error;
mod sys;

pub use self::common::debugger::Debugger;
pub use self::common::session::Session;
pub use self::error::{Error, Result};
pub use self::sys::Exception;
