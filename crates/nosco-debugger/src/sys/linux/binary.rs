use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use goblin::elf::header::ET_DYN;
use goblin::elf::program_header::PT_LOAD;
use goblin::elf::section_header::{SHN_UNDEF, SHN_XINDEX};
use goblin::elf::{Elf, ProgramHeader, SectionHeader};
use goblin::strtab::Strtab;

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

    pub async fn to_unwind_module(&self) -> crate::sys::Result<framehop::Module<Vec<u8>>> {
        let elf = tokio::fs::read(&self.path)
            .await
            .map_err(|e| crate::sys::Error::File(self.path.clone(), e))?;

        let elf_header = Elf::parse_header(&elf)?;
        let elf_ctx =
            goblin::container::Ctx::new(elf_header.container()?, elf_header.endianness()?);

        let phdrs = ProgramHeader::parse(
            &elf,
            elf_header.e_phoff as usize,
            elf_header.e_phnum as usize,
            elf_ctx,
        )?;

        let (last_load_vaddr, last_load_len) = phdrs
            .iter()
            .rev()
            .find_map(|phdr| (phdr.p_type == PT_LOAD).then_some((phdr.p_vaddr, phdr.p_memsz)))
            .ok_or(crate::sys::Error::MissingPtLoad)?;

        let (base_svma, end_addr) = if elf_header.e_type == ET_DYN {
            // PIE executable or dylib
            (0, self.addr + last_load_vaddr + last_load_len)
        } else {
            (self.addr, last_load_vaddr + last_load_len)
        };

        tracing::debug!(end_addr = format!("{end_addr:#x}"));

        let mut sections_info = framehop::ExplicitModuleSectionInfo {
            base_svma,
            ..Default::default()
        };

        parse_sections_info(&elf, &elf_header, elf_ctx, &mut sections_info)?;

        Ok(framehop::Module::new(
            self.file_name.clone(),
            self.addr..end_addr,
            self.addr,
            sections_info,
        ))
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

fn parse_sections_info(
    elf: &[u8],
    elf_header: &goblin::elf::Header,
    elf_ctx: goblin::container::Ctx,
    module_section_info: &mut framehop::ExplicitModuleSectionInfo<Vec<u8>>,
) -> crate::sys::Result<()> {
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
