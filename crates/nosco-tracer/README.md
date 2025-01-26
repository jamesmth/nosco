nosco-tracer
============

[<img alt="version" src="https://img.shields.io/crates/v/nosco-tracer.svg?style=for-the-badge&color=fc8d62&logo=rust" height="18">](https://crates.io/crates/nosco-tracer)
[<img alt="doc" src="https://img.shields.io/badge/docs.rs-nosco--tracer-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="18">](https://docs.rs/nosco-tracer)
[<img alt="msrv" src="https://img.shields.io/crates/msrv/nosco-tracer.svg?style=for-the-badge&color=lightgray" height="18">](https://blog.rust-lang.org/2024/08/08/Rust-1.80.1.html)

This crate allows to spawn a process and trace its execution.

Two main components are provided:
- A trait to implement a custom trace handler, allowing to implement
  arbitrary logic to consume process execution events (e.g., executed
  instructions, spawned threads).
- A few traits to implement a custom debugger, responsible for spawning a
  process and instrumenting it.

# Basic Usage

```rust
use std::process::Command;

use nosco_debugger::{Debugger, Session};

use nosco_tracer::debugger::DebugSession;
use nosco_tracer::handler::EventHandler;
use nosco_tracer::tracer::Tracer;

#[tokio::main]
async fn main() {
    // initialize the tracer
    let tracer = Tracer::builder()
        .with_debugger(Debugger::default())
        .with_event_handler(CustomHandler)
        .trace_all(3)
        .build();

    // initialize the process to trace
    let mut cmd = Command::new("ls");
    cmd.arg("/");

    // spawn the process to trace
    let process = tracer.spawn(cmd).await.unwrap();

    // wait for the traced process to exit
    let exit_code = process.resume_and_trace().await.unwrap();
}

struct CustomHandler;

impl EventHandler for CustomHandler {
    type Session = Session;
    type Error = std::io::Error;

    async fn instruction_executed(
        &mut self,
        _session: &mut Self::Session,
        _thread: &<Self::Session as DebugSession>::StoppedThread,
        _opcodes_addr: u64,
        _opcodes: Vec<u8>,
    ) -> Result<(), Self::Error> {
        //
        // do some action with the executed instruction
        //

        Ok(())
    }
}
```

# Implementing a custom debugger

Some traits are also provided to implement the inner debugging logic used for
tracing a process. For instance, an application could spawn and trace a process
by leveraging **Remote Debugging** (e.g., *gdb*, *lldb*) or **Virtual Machine
Introspection** under the hood. The possibilities are endless.

Most of the time, you won't need to go this far. If you simply need to trace
a process running on the same machine as the tracer, you can use the
default debugger provided by the [nosco-debugger] crate.

[nosco-debugger]: https://crates.io/crates/nosco-debugger
