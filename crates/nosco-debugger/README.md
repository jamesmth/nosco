nosco-debugger
==============

[<img alt="version" src="https://img.shields.io/crates/v/nosco-debugger.svg?style=for-the-badge&color=fc8d62&logo=rust" height="18">](https://crates.io/crates/nosco-debugger)
[<img alt="doc" src="https://img.shields.io/badge/docs.rs-nosco--debugger-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="18">](https://docs.rs/nosco-debugger)
[<img alt="msrv" src="https://img.shields.io/crates/msrv/nosco-debugger.svg?style=for-the-badge&color=lightgray" height="18">](https://blog.rust-lang.org/2024/08/08/Rust-1.80.1.html)

This crate provides a default implementation of a debugger (to be used with
[nosco-tracer]).

The debugger is able to spawn a process (on the **same host machine**) as
a child and debug it.

> :warning: This crate is not meant to be used on its own! It merely implements
> the interface (traits) provided by [nosco-tracer], so that the debugger can
> be used by that crate for tracing processes.

[nosco-tracer]: ../nosco-tracer/README.md

# Supported Platforms

<table>
    <thead>
        <tr>
            <th>Host Machine</th>
            <th>Debuggee Platform</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td rowspan="2">Linux <code>x86_64</code></td>
            <td><code>x86_64</code></td>
        </tr>
        <tr>
            <td><code>i386</code></td>
        </tr>
    </tbody>
</table>
