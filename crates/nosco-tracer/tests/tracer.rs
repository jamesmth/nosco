// Once clippy takes `clippy.toml` into account (for `tests` targets),
// we can remove these.
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::print_stdout)]
#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]

#[cfg(target_os = "linux")]
mod linux;

mod common;
