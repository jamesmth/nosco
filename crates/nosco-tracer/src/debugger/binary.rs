use std::future::Future;
use std::ops::Range;
use std::path::Path;

/// Trait providing functions for working with a mapped binary.
pub trait MappedBinary {
    /// Error returned by this trait.
    type Error;

    /// Address range of the mapped binary.
    fn addr_range(&self) -> &Range<u64>;

    /// File name of the binary.
    fn file_name(&self) -> &str;

    /// Path where the dynamic linker found the binary.
    fn path(&self) -> &Path;

    /// Returns the address of the given symbol from the mapped binary.
    fn addr_of_symbol(
        &mut self,
        symbol: impl AsRef<str>,
    ) -> impl Future<Output = Result<Option<u64>, Self::Error>>;

    /// Returns the closest symbol to the given address.
    ///
    /// An offset from the start of the symbol is given as well.
    fn symbol_of_addr(
        &mut self,
        addr: u64,
    ) -> impl Future<Output = Result<Option<(String, u64)>, Self::Error>>;
}
