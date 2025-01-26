use std::collections::HashSet;
use std::path::PathBuf;

use futures_util::TryStreamExt;

use goblin::elf::dynamic::{DT_DEBUG, DT_NULL};
use goblin::elf::header::{EM_386, EM_ARM, EM_X86_64, ET_DYN};
use goblin::elf::program_header::{PT_DYNAMIC, PT_INTERP, PT_LOAD};
use goblin::elf::section_header::SHT_SYMTAB;
use goblin::elf::{Dyn, Elf, ProgramHeader, ProgramHeaders, SectionHeader, Symtab};

use goblin::strtab::Strtab;
use nix::libc::{AT_BASE, AT_ENTRY, AT_PHDR, AT_PHNUM, AT_SYSINFO_EHDR};
use nix::unistd::Pid;

use scroll::Pread;

use super::auxv::auxv_entries;
use super::LinkMap;

pub struct ExecutableScan {
    pub exe_addr: u64,
    pub rdebug_addr_loc: u64,
    pub rdebug_addr: u64,
    pub elf_ctx: goblin::container::Ctx,
    pub lms: HashSet<LinkMap>,
}

/// Scan the debuggee's mapped executable.
pub async fn scan_debuggee_exe(debuggee_pid: Pid) -> crate::sys::Result<ExecutableScan> {
    //
    // Fetch ELF header.
    //

    let elf = read_elf(debuggee_pid).await?;
    let header = Elf::parse_header(&elf)?;

    if (cfg!(target_arch = "aarch64") && header.e_machine != EM_ARM)
        || (cfg!(target_arch = "x86_64")
            && header.e_machine != EM_X86_64
            && header.e_machine != EM_386)
    {
        return Err(crate::sys::Error::ElfPlatform(header.e_machine));
    }

    let elf_ctx = goblin::container::Ctx::new(header.container()?, header.endianness()?);

    tracing::debug!(endianness = ?elf_ctx.le, "fetched elf header");

    //
    // Traverse auxiliary vector.
    //

    let mut phdr = None;
    let mut phnum = None;
    let mut entry_addr = None;
    let mut vdso_addr = None;
    let mut ld_addr = None;

    let mut auxv = auxv_entries(debuggee_pid, elf_ctx).await?;

    while let Some((auxv_ty, auxv_val)) = auxv.try_next().await? {
        match auxv_ty {
            AT_PHDR => phdr = Some(auxv_val),
            AT_PHNUM => phnum = Some(auxv_val as usize),
            AT_ENTRY => entry_addr = Some(auxv_val),
            AT_BASE => ld_addr = Some(auxv_val),
            AT_SYSINFO_EHDR => vdso_addr = Some(auxv_val),
            _ => (),
        }

        if phdr.is_some()
            && phnum.is_some()
            && entry_addr.is_some()
            && ld_addr.is_some()
            && vdso_addr.is_some()
        {
            break;
        }
    }

    let phdr = phdr.ok_or(crate::sys::Error::MissingAuxv)?;
    let phnum = phnum.ok_or(crate::sys::Error::MissingAuxv)?;
    let entry_addr = entry_addr.ok_or(crate::sys::Error::MissingAuxv)?;

    tracing::debug!("scanned auxv");

    //
    // Fetch program headers.
    //

    let mut buf = vec![0u8; ProgramHeader::size(elf_ctx) * phnum];
    crate::sys::mem::read_process_memory(debuggee_pid.as_raw() as u64, phdr, &mut buf)?;

    let phdrs = ProgramHeader::parse(&buf, 0, phnum, elf_ctx)?;

    tracing::debug!(
        addr = format_args!("{phdr:#x}"),
        count = phnum,
        "fetched program headers"
    );

    //
    // Compute load address of executable.
    //

    let (is_pie, exe_addr) = if matches!(header.e_type, ET_DYN) {
        (true, entry_addr - header.e_entry)
    } else {
        let base_addr = phdrs
            .iter()
            .find_map(|phdr| (phdr.p_type == PT_LOAD).then_some(phdr.p_vaddr))
            .ok_or(crate::sys::Error::MissingPtLoad)?;

        (false, base_addr)
    };

    tracing::debug!(
        addr = format_args!("{exe_addr:#x}"),
        is_pie,
        "computed load address"
    );

    //
    // Fetch `r_debug` struct address.
    //

    let lms = init_link_map(debuggee_pid, exe_addr, is_pie, ld_addr, vdso_addr, &phdrs)?;

    let (rdebug_addr_loc, rdebug_addr) = if let Some((dyn_sect_addr, dyn_sect)) =
        fetch_dynamic_section(debuggee_pid, is_pie.then_some(exe_addr), &phdrs)?
    {
        fetch_rdebug_addr_from_dyn(dyn_sect_addr, &dyn_sect, elf_ctx)?
    } else {
        let rdebug_addr =
            fetch_rdebug_addr_from_symbols(&elf, header, elf_ctx, is_pie.then_some(exe_addr))?;
        (0 /* irrelevant */, rdebug_addr)
    };

    Ok(ExecutableScan {
        exe_addr,
        rdebug_addr_loc,
        rdebug_addr,
        elf_ctx,
        lms,
    })
}

/// Fetches the debuggee's ELF.
async fn read_elf(debuggee_pid: Pid) -> crate::sys::Result<Vec<u8>> {
    let path: PathBuf = format!("/proc/{debuggee_pid}/exe").into();

    tokio::fs::read(&path)
        .await
        .map_err(|e| crate::sys::Error::File(path, e))
}

/// Fetches the ELF section containing interpreter information.
///
/// # Warning
///
/// If the ELF is not a PIE, `base_addr` should be `None`.
fn fetch_interp_section(
    debuggee_pid: Pid,
    base_addr: Option<u64>,
    phdrs: &ProgramHeaders,
) -> crate::sys::Result<Vec<u8>> {
    let pt_interp = phdrs
        .iter()
        .find(|phdr| phdr.p_type == PT_INTERP)
        .ok_or(crate::sys::Error::MissingPtInterp)?;

    let addr = base_addr.map_or(pt_interp.p_vaddr, |addr| addr + pt_interp.p_vaddr);

    let mut buf = vec![0u8; pt_interp.p_memsz as usize];
    super::mem::read_process_memory(debuggee_pid.as_raw() as u64, addr, &mut buf)?;

    Ok(buf)
}

/// Fetches the ELF section containing dynamic linking information.
///
/// # Warning
///
/// If the ELF is not a PIE, `base_addr` must be `None`.
fn fetch_dynamic_section(
    debuggee_pid: Pid,
    base_addr: Option<u64>,
    phdrs: &ProgramHeaders,
) -> crate::sys::Result<Option<(u64, Vec<u8>)>> {
    let Some(pt_dyn) = phdrs.iter().find(|phdr| phdr.p_type == PT_DYNAMIC) else {
        return Ok(None);
    };

    let addr = base_addr.map_or(pt_dyn.p_vaddr, |addr| addr + pt_dyn.p_vaddr);

    let mut buf = vec![0u8; pt_dyn.p_memsz as usize];
    super::mem::read_process_memory(debuggee_pid.as_raw() as u64, addr, &mut buf)?;

    Ok(Some((addr, buf)))
}

fn init_link_map(
    debuggee_pid: Pid,
    exe_addr: u64,
    is_pie: bool,
    mut ld_addr: Option<u64>,
    mut vdso_addr: Option<u64>,
    phdrs: &ProgramHeaders,
) -> crate::sys::Result<HashSet<LinkMap>> {
    const VDSO_NAME: &str = "linux-vdso.so.1";

    let mut lms = HashSet::new();

    lms.insert(LinkMap {
        base_addr: exe_addr,
        name: format!("/proc/{debuggee_pid}/exe"),
    });

    if let Some(ld_addr) = ld_addr.take_if(|addr| *addr != 0) {
        let interp_sect = fetch_interp_section(debuggee_pid, is_pie.then_some(exe_addr), phdrs)?;

        lms.insert(LinkMap {
            base_addr: ld_addr,
            name: std::ffi::CStr::from_bytes_with_nul(&interp_sect)?
                .to_string_lossy()
                .into_owned(),
        });
    }

    if let Some(vdso_addr) = vdso_addr.take_if(|addr| *addr != 0) {
        lms.insert(LinkMap {
            base_addr: vdso_addr,
            name: VDSO_NAME.to_owned(),
        });
    }

    Ok(lms)
}

/// Fetches the debuggee's `r_debug` struct information from the `_r_debug`
/// symbol.
///
/// # Warning
///
/// If the ELF is not a PIE, `base_addr` should be `None`.
fn fetch_rdebug_addr_from_symbols(
    elf_bytes: &[u8],
    elf_header: goblin::elf::Header,
    elf_ctx: goblin::container::Ctx,
    base_addr: Option<u64>,
) -> crate::sys::Result<u64> {
    let shdrs = SectionHeader::parse(
        elf_bytes,
        elf_header.e_shoff as usize,
        elf_header.e_shnum as usize,
        elf_ctx,
    )?;

    let shdr = shdrs
        .iter()
        .rfind(|shdr| shdr.sh_type == SHT_SYMTAB)
        .ok_or(crate::sys::Error::MissingSymtab)?;

    let size = shdr.sh_entsize;
    let count = if size == 0 { 0 } else { shdr.sh_size / size };
    let syms = Symtab::parse(elf_bytes, shdr.sh_offset as usize, count as usize, elf_ctx)?;

    let index = shdr.sh_link as usize;
    let shdr = shdrs
        .get(index)
        .ok_or(crate::sys::Error::InvalidStrtabIndex(index))?;

    let strtab = Strtab::parse(
        elf_bytes,
        shdr.sh_offset as usize,
        shdr.sh_size as usize,
        0x0,
    )?;

    let rdebug_addr = syms
        .iter()
        .find_map(|sym| {
            let name = strtab.get_at(sym.st_name)?;
            let addr = base_addr.map_or(sym.st_value, |addr| addr + sym.st_value);
            (name == "_r_debug").then_some(addr)
        })
        .ok_or(crate::sys::Error::MissingRDebug)?;

    tracing::debug!(
        addr = format_args!("{rdebug_addr:#x}"),
        "fetched r_debug from _r_debug symbol"
    );

    Ok(rdebug_addr)
}

/// Fetches the debuggee's `r_debug` struct information.
fn fetch_rdebug_addr_from_dyn(
    dyn_sect_addr: u64,
    dyn_sect: &[u8],
    elf_ctx: goblin::container::Ctx,
) -> crate::sys::Result<(u64, u64)> {
    let dyn_len = dyn_sect.len() / Dyn::size(elf_ctx.container);

    let (rdebug_addr_loc, rdebug_addr) = (0..dyn_len)
        .scan(0, |offset, _| {
            let addr = dyn_sect_addr + *offset as u64;

            match dyn_sect.gread_with::<Dyn>(offset, elf_ctx) {
                Ok(dynamic) if dynamic.d_tag == DT_NULL => None,
                Ok(dynamic) => Some(Ok((addr, dynamic))),
                Err(e) => Some(Err(e)),
            }
        })
        .find_map(|res| match res {
            Ok((addr, d)) if d.d_tag == DT_DEBUG => {
                Some(Ok((addr + elf_ctx.size() as u64, d.d_val)))
            }
            Err(e) => Some(Err(e)),
            _ => None,
        })
        .ok_or(crate::sys::Error::MissingDtDebug)??;

    tracing::debug!(
        addr_of_addr = format_args!("{rdebug_addr_loc:#x}"),
        addr = format_args!("{rdebug_addr:#x}"),
        "fetched r_debug from PT_DYNAMIC"
    );

    Ok((rdebug_addr_loc, rdebug_addr))
}
