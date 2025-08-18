use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use goblin::elf::header::ET_DYN;
use goblin::elf::program_header::PT_LOAD;
use goblin::elf::{Elf, ProgramHeader};
use tracing::Instrument;
use wholesym::{LookupAddress, SymbolManager, SymbolMap};

/// Loaded ELF image.
#[derive(Clone)]
pub struct MappedElf {
    /// Address range of the loaded binary.
    addr_range: Range<u64>,

    /// File name of the loaded binary.
    file_name: String,

    /// Path from which the linker loaded the loaded binary.
    path: PathBuf,

    /// Binary symbol resolver.
    symbol_manager: Arc<SymbolManager>,

    /// Symbols of the loaded binary.
    symbol_map: Option<Arc<SymbolMap>>,

    /// Current state of unwind information retrieval for the loaded binary.
    #[cfg(feature = "unwind")]
    unwind_info: Option<UnwindInfoState>,
}

impl MappedElf {
    /// Creates a new `MappedElf` for symbol resolution.
    pub fn new(addr_range: Range<u64>, path: PathBuf, symbol_manager: Arc<SymbolManager>) -> Self {
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();

        Self {
            addr_range,
            path,
            file_name,
            symbol_manager,
            symbol_map: None,
            #[cfg(feature = "unwind")]
            unwind_info: None,
        }
    }

    /// Creates a `MappedElf` from a [LinkMap] (see `link.h` from glibc).
    pub async fn from_link_map(
        lm: &LinkMap,
        symbol_manager: Arc<SymbolManager>,
    ) -> crate::Result<Self> {
        let path = Path::new(&lm.name);
        let path = match path.canonicalize() {
            Ok(p) => p,
            Err(_) => path.to_path_buf(),
        };

        if let Ok(elf) = tokio::fs::read(&path).await {
            let elf_header = Elf::parse_header(&elf)?;
            let elf_ctx =
                goblin::container::Ctx::new(elf_header.container()?, elf_header.endianness()?);

            let phdrs = ProgramHeader::parse(
                &elf,
                elf_header.e_phoff as usize,
                elf_header.e_phnum as usize,
                elf_ctx,
            )?;

            let end_addr = phdrs
                .iter()
                .rev()
                .find_map(|phdr| (phdr.p_type == PT_LOAD).then_some(phdr.p_vaddr + phdr.p_memsz))
                .map(|end_vaddr| {
                    if elf_header.e_type == ET_DYN {
                        lm.base_addr + end_vaddr
                    } else {
                        end_vaddr
                    }
                })
                .ok_or(crate::Error::MissingPtLoad)?;

            let binary = Self::new(lm.base_addr..end_addr, path, symbol_manager);

            #[cfg(feature = "unwind")]
            let binary = {
                let mut binary = binary;
                binary.unwind_info = Some(UnwindInfoState::NotRetrieved {
                    elf_header,
                    elf_ctx,
                });
                binary
            };

            Ok(binary)
        } else {
            // `vdso` cannot be read from disk
            Ok(Self::new(lm.base_addr..lm.base_addr, path, symbol_manager))
        }
    }
}

#[cfg(feature = "unwind")]
impl MappedElf {
    /// Returns a [Module](framehop::Module) associated with this `MappedElf`.
    #[tracing::instrument(name = "UnwindModule", skip_all, fields(path = %self.path.display()))]
    pub async fn to_unwind_module(&mut self) -> crate::Result<framehop::Module<Vec<u8>>> {
        let (elf, elf_header, elf_ctx) = match self.unwind_info {
            Some(UnwindInfoState::Retrieved(ref unwind_module)) => return Ok(unwind_module.clone()),
            Some(UnwindInfoState::NotRetrieved {
                elf_header,
                elf_ctx,
            }) => {
                let elf = tokio::fs::read(&self.path)
                    .await
                    .map_err(|e| crate::Error::File(self.path.to_path_buf(), e))?;

                (elf, elf_header, elf_ctx)
            }
            None => {
                let elf = tokio::fs::read(&self.path)
                    .await
                    .map_err(|e| crate::Error::File(self.path.to_path_buf(), e))?;

                let elf_header = Elf::parse_header(&elf)?;

                let elf_ctx =
                    goblin::container::Ctx::new(elf_header.container()?, elf_header.endianness()?);

                (elf, elf_header, elf_ctx)
            }
        };

        let base_svma = if elf_header.e_type == ET_DYN {
            0
        } else {
            self.addr_range.start
        };

        let mut sections_info = framehop::ExplicitModuleSectionInfo {
            base_svma,
            ..Default::default()
        };

        parse_sections_info(&elf, &elf_header, elf_ctx, &mut sections_info)?;

        let unwind_module = framehop::Module::new(
            self.file_name.clone(),
            self.addr_range.clone(),
            self.addr_range.start,
            sections_info,
        );

        self.unwind_info = Some(UnwindInfoState::Retrieved(unwind_module.clone()));

        Ok(unwind_module)
    }
}

impl nosco_tracer::debugger::MappedBinary for MappedElf {
    type Error = crate::Error;

    fn addr_range(&self) -> &Range<u64> {
        &self.addr_range
    }

    fn file_name(&self) -> &str {
        &self.file_name
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the address of the given symbol from the mapped binary.
    async fn addr_of_symbol(&mut self, symbol: impl AsRef<str>) -> crate::Result<Option<u64>> {
        let symbol_map = if let Some(ref symbol_map) = self.symbol_map {
            symbol_map
        } else {
            let symbol_map = self
                .symbol_manager
                .load_symbol_map_for_binary_at_path(&self.path, None)
                .instrument(tracing::info_span!("LoadSymbols", binary = self.file_name))
                .await?;
            self.symbol_map.get_or_insert(Arc::new(symbol_map))
        };

        let offset = symbol_map
            .iter_symbols()
            .find_map(|(offset, name)| (name == symbol.as_ref()).then_some(offset));

        match offset {
            Some(offset) => Ok(Some(self.addr_range.start + offset as u64)),
            None => Ok(None),
        }
    }

    /// Returns the closest symbol to the given address.
    ///
    /// An offset from the start of the symbol is given as well.
    async fn symbol_of_addr(&mut self, addr: u64) -> crate::Result<Option<(String, u64)>> {
        let Some(rela_addr) = addr.checked_sub(self.addr_range.start) else {
            return Ok(None);
        };

        let symbol_map = if let Some(ref symbol_map) = self.symbol_map {
            symbol_map
        } else {
            let symbol_map = self
                .symbol_manager
                .load_symbol_map_for_binary_at_path(&self.path, None)
                .instrument(tracing::info_span!("LoadSymbols", binary = self.file_name))
                .await?;
            self.symbol_map.get_or_insert(Arc::new(symbol_map))
        };

        let Some(info) = symbol_map
            .lookup(LookupAddress::Relative(rela_addr as u32))
            .await
        else {
            return Ok(None);
        };

        let sym_addr = self.addr_range.start + info.symbol.address as u64;

        Ok(Some((info.symbol.name, addr - sym_addr)))
    }
}

#[cfg(feature = "unwind")]
fn parse_sections_info(
    elf: &[u8],
    elf_header: &goblin::elf::Header,
    elf_ctx: goblin::container::Ctx,
    module_section_info: &mut framehop::ExplicitModuleSectionInfo<Vec<u8>>,
) -> crate::Result<()> {
    use goblin::elf::SectionHeader;
    use goblin::elf::section_header::{SHN_UNDEF, SHN_XINDEX};
    use goblin::strtab::Strtab;

    let shdrs = SectionHeader::parse(
        elf,
        elf_header.e_shoff as usize,
        elf_header.e_shnum as usize,
        elf_ctx,
    )?;

    let idx = match elf_header.e_shstrndx.into() {
        SHN_XINDEX => shdrs.first().map(|shdr| shdr.sh_link as usize),
        SHN_UNDEF => None,
        n => Some(n as usize),
    };

    let Some(snstrtab) = idx
        .and_then(|i| shdrs.get(i))
        .map(|shdr| Strtab::parse(elf, shdr.sh_offset as usize, shdr.sh_size as usize, 0x0))
        .transpose()?
    else {
        return Ok(());
    };

    for (name, shdr) in shdrs
        .iter()
        .filter_map(|shdr| snstrtab.get_at(shdr.sh_name).map(|name| (name, shdr)))
    {
        let Range { start, end } = shdr.vm_range();
        let vm_range = start as u64..end as u64;

        let section_data = shdr.file_range().and_then(|range| elf.get(range));

        match name {
            ".text" => {
                module_section_info.text_svma = Some(vm_range);
                module_section_info.text = section_data.map(|data| data.to_vec());
            }
            ".got" => {
                module_section_info.got_svma = Some(vm_range);
            }
            ".eh_frame" => {
                module_section_info.eh_frame_svma = Some(vm_range);
                module_section_info.eh_frame = section_data.map(|data| data.to_vec());
            }
            ".eh_frame_hdr" => {
                module_section_info.eh_frame_hdr_svma = Some(vm_range);
                module_section_info.eh_frame_hdr = section_data.map(|data| data.to_vec());
            }
            ".debug_frame" => {
                module_section_info.debug_frame = section_data.map(|data| data.to_vec());
            }
            _ => continue,
        }

        tracing::debug!(
            len = section_data.map(|data| data.len()).unwrap_or_default(),
            "found section {name}"
        );

        if module_section_info.text_svma.is_some()
            && module_section_info.got_svma.is_some()
            && module_section_info.eh_frame_svma.is_some()
            && module_section_info.eh_frame_hdr_svma.is_some()
            && module_section_info.debug_frame.is_some()
        {
            break;
        }
    }

    Ok(())
}

/// Loaded shared object.
///
/// This struct should be used in the same context as a `link_map` from `glibc/elf/link.h`.
#[derive(Hash, PartialEq, Eq)]
pub struct LinkMap {
    /// Base load address.
    pub base_addr: u64,

    /// Absolute file name of the loaded object.
    pub name: String,
}

#[cfg(feature = "unwind")]
#[derive(Clone)]
enum UnwindInfoState {
    Retrieved(framehop::Module<Vec<u8>>),
    NotRetrieved {
        elf_header: goblin::elf::Header,
        elf_ctx: goblin::container::Ctx,
    },
}
