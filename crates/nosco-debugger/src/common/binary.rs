use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::Instrument;

use wholesym::{LookupAddress, SymbolManager, SymbolMap};

/// Loaded image.
pub struct MappedBinary {
    /// Base address of the loaded binary.
    addr: u64,

    /// File name of the loaded binary.
    file_name: String,

    /// Path from which the linker loaded the loaded binary.
    path: PathBuf,

    /// Binary symbol resolver.
    symbol_manager: Arc<SymbolManager>,
}

impl MappedBinary {
    /// Creates a new [MappedBinary].
    pub fn new(base_addr: u64, path: &Path, symbol_manager: Arc<SymbolManager>) -> Self {
        let path = match path.canonicalize() {
            Ok(p) => p,
            Err(_) => path.to_path_buf(),
        };

        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();

        Self {
            addr: base_addr,
            file_name,
            path,
            symbol_manager: symbol_manager.clone(),
        }
    }
}

impl nosco_tracer::debugger::BinaryInformation for MappedBinary {
    type View = MappedBinaryView;
    type Error = crate::Error;

    /// Returns the base address of the loaded binary.
    fn base_addr(&self) -> u64 {
        self.addr
    }

    /// Returns the file name of the loaded binary.
    fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Returns the path from which the linker loaded the loaded binary.
    fn path(&self) -> &Path {
        &self.path
    }

    /// Retrieves the in-memory view of the binary.
    async fn to_view(&self) -> crate::Result<MappedBinaryView> {
        let symbol_map = self
            .symbol_manager
            .load_symbol_map_for_binary_at_path(&self.path, None)
            .instrument(tracing::info_span!("LoadSymbols", binary = self.file_name))
            .await?;

        Ok(MappedBinaryView {
            addr: self.addr,
            symbol_map,
        })
    }
}

/// In-memory view of a loaded binary.
pub struct MappedBinaryView {
    /// Base address of the loaded binary.
    addr: u64,

    /// Symbols of the loaded binary.
    symbol_map: SymbolMap,
}

impl nosco_tracer::debugger::BinaryView for MappedBinaryView {
    type Error = crate::Error;

    /// Returns the address of the given symbol from the mapped binary.
    fn addr_of_symbol(&self, symbol: impl AsRef<str>) -> crate::Result<Option<u64>> {
        let offset = self
            .symbol_map
            .iter_symbols()
            .find_map(|(offset, name)| (name == symbol.as_ref()).then_some(offset));

        match offset {
            Some(offset) => Ok(Some(self.addr + offset as u64)),
            None => Ok(None),
        }
    }

    /// Returns the closest symbol to the given address.
    ///
    /// An offset from the start of the symbol is given as well.
    async fn symbol_of_addr(&self, addr: u64) -> crate::Result<Option<(String, u64)>> {
        let Some(rela_addr) = addr.checked_sub(self.addr) else {
            return Ok(None);
        };

        let Some(info) = self
            .symbol_map
            .lookup(LookupAddress::Relative(rela_addr as u32))
            .await
        else {
            return Ok(None);
        };

        let sym_addr = self.addr + info.symbol.address as u64;

        Ok(Some((info.symbol.name, addr - sym_addr)))
    }
}
