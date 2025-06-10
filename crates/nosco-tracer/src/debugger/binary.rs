use std::future::Future;
use std::ops::Range;
use std::path::Path;

/// Trait providing functions for working with mapped binary information.
pub trait BinaryInformation {
    /// In-memory view of the binary.
    type View: BinaryView<Error: Into<Self::Error>>;

    /// Error returned by this trait.
    type Error;

    /// Address range of the mapped binary.
    fn addr_range(&self) -> &Range<u64>;

    /// File name of the binary.
    fn file_name(&self) -> &str;

    /// Path where the dynamic linker found the binary.
    fn path(&self) -> &Path;

    /// Retrieves the in-memory view of the binary.
    fn to_view(&self) -> impl Future<Output = Result<Self::View, Self::Error>>;
}

/// Trait providing functions for working with mapped binary views.
pub trait BinaryView {
    /// Error returned by this trait.
    type Error;

    /// Returns the address of the given symbol from the mapped binary.
    fn addr_of_symbol(&self, symbol: impl AsRef<str>) -> Result<Option<u64>, Self::Error>;

    /// Returns the closest symbol to the given address.
    ///
    /// An offset from the start of the symbol is given as well.
    fn symbol_of_addr(
        &self,
        addr: u64,
    ) -> impl Future<Output = Result<Option<(String, u64)>, Self::Error>>;
}
