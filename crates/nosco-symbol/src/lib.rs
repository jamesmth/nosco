//! This crate provides helpers to perform symbol resolution over multiple
//! binary formats (only ELF for now).

#![cfg_attr(
    feature = "elf",
    doc = r##"
# Example

```no_run
use std::sync::Arc;

use nosco_symbol::elf::MappedElf;
use nosco_tracer::debugger::MappedBinary;
use wholesym::{SymbolManager, SymbolManagerConfig};

#[tokio::main]
async fn main() {
    let symbol_manager = SymbolManager::with_config(SymbolManagerConfig::default());
    let symbol_manager = Arc::new(symbol_manager);

    let mut binary = MappedElf::new(0x400000..0x4fccd8, "/bin/sh".into(), symbol_manager);

    // retrieve the symbol associated with a given address
    let (symbol, offset) = binary.symbol_of_addr(0x41e3a0).await.unwrap().unwrap();

    // retrieve the address of a given symbol
    let addr = binary.addr_of_symbol("main").await.unwrap().unwrap();
}
```
"##
)]

/// Module handling the ELF format.
#[cfg(feature = "elf")]
pub mod elf;

mod error;

pub use self::error::{Error, Result};
