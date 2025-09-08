<div align="center">

# nosco

[<img alt="version" src="https://img.shields.io/crates/v/nosco-cli.svg?style=for-the-badge&color=fc8d62&logo=rust" height="18">](https://crates.io/crates/nosco-cli)
[<img alt="msrv" src="https://img.shields.io/crates/msrv/nosco-cli.svg?style=for-the-badge&color=lightgray" height="18">](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/)

**An easy-to-use process execution tracer.**

[Getting started](#getting-started) •
[Installation](#installation) •
[Roadmap](#roadmap)

</div>

> [!WARNING]
> This is a work in progress! You can [try it right now](#installation) if you are curious,
> but you will probably find bugs. Also, your platform may not be supported at the moment (checkout
> the [roadmap](#roadmap) for more details).

Whether you are a reverse engineer, or just curious about how software runs on your OS, `nosco`
is a tool that allows you to easily capture and analyze an execution trace of a process. 

## Getting started

![Tutorial](https://github.com/user-attachments/assets/3aa3c37a-b314-44ff-a11c-d63d663a0e79)

```sh
# run a process and capture a full trace (can be very slow, so a maximum call depth is specified)
nosco run -c 'call-depth 3' -o echo.trace -- echo 'hello'

# run a process and capture a scoped trace (here, the function `main`)
nosco run -c 'trace "main" binary="echo"' -o echo.trace -- echo 'hello'

# dump all the created/exited threads in a trace session (also reveals the root call IDs of the trace)
nosco dump -i echo.trace thread-info

# dump a call trace of a particular call
nosco dump -i echo.trace call-trace --depth 2 <CALL_ID>

# dump the executed instructions of a particular call
nosco dump -i echo.trace exec-trace <CALL_ID>

# dump all the loaded/unloaded libraries/images in a trace session
nosco dump -i echo.trace binary-info
```

> [!NOTE]
> The `-c` flag can be used with an inline configuration ([KDL format](https://kdl.dev/)), and also
> accepts a path to a configuration file. The output of the `dump` command is also KDL-formatted.
> Why KDL? In short: [it is human-friendly, flexible](https://kdl.dev/#faq), and has
> [multi-language support](https://kdl.dev/#implementations) for further processing.

*A proper documentation of `nosco` is not available yet.*

## Installation

If you have a [Rust](https://rustup.rs/) toolchain installed, you can install a development version:
```sh
cargo install --git https://github.com/jamesmth/nosco --locked
```

## Why use it?

There are already a few mature tools out there that can do the same thing and more (think
debuggers, profilers, fuzzers), so why another one?  In a few words, `nosco` is:
- Straightforward to install (single binary, no external dependencies)
- Easy to use, easy to configure
- **Not** a debugger/profiler/fuzzer, just a control flow tracer
- Developer-friendly (e.g, adding a tracing backend is a matter of implementing a few Rust traits)

In the future, `nosco` aims to be:
- Multi-platform for tracing local processes (only Linux right now)
- Extensible at runtime via WASM-based plugins (e.g., customize the tracing behavior, interact with
the traced process)

## Roadmap

Here is an overview of the direction this project is heading.

### Major features
  
| Feature                                                  | Release   | Dev |
|----------------------------------------------------------|-----------|-----|
| CLI command `run` to trace new processes                 | 🔜 (v0.1) | ✅ |
| CLI command `dump` to inspect trace session files        | 🔜 (v0.1) | ✅ |
| Tracing backend (**x86** Linux): `ptrace`                | 🔜 (v0.1) | ✅ |
| CLI command `dump`: symbolication of dumped addresses    | 🔜 (v0.1) | ✅ |
| Tracing backend (**x86** Windows): `debugapi`            | ❓(TBD)   |    |
| Tracing backend (**ARM** Linux): `ptrace`                | ❓(TBD)   |    |
| Tracing backend (**ARM** MacOS): mach ports              | ❓(TBD)   |    |
| Tracing backend (**ARM** Windows): `debugapi`            | ❓(TBD)   |    |
| WASM-based plugin system ([wasmtime?])                   | ❓(TBD)   |    |
| CLI command `attach` to trace existing processes         | ❓(TBD)   |    |
| **x86** Hardware-accelerated tracing (Intel PT)          | ❓(TBD)   |    |
| **ARM** Hardware-accelerated tracing (ARM Coresight ETM) | ❓(TBD)   |    |
| UI to inspect trace session files                        | ❓(TBD)   |    |
| Tracing backend: GDB Remote Protocol                     | ❓(TBD)   |    |
| Tracing backend: Virtual Machine Introspection           | ❓(TBD)   |    |

[wasmtime?]: https://component-model.bytecodealliance.org/runtimes/wasmtime.html

### Other features
  
| Feature                       | Release    | 
|-------------------------------|------------|
| Extended documentation (Wiki) | 🔜 (v0.1) |
