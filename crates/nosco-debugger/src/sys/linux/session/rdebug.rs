use indexmap::IndexSet;
use nix::sys::ptrace;
use nix::unistd::Pid;
use nosco_symbol::elf::LinkMap;
use scroll::Pread;

const RT_CONSISTENT: u64 = 0;
const RT_ADD: u64 = 1;
const RT_DELETE: u64 = 2;

/// Helper struct to manipulate a debuggee's `r_debug` data.
pub struct RDebug {
    /// Debuggee's process ID.
    pid: Pid,

    /// ELF context (e.g., endianness) in the debuggee.
    elf_ctx: goblin::container::Ctx,

    /// Executable address of the debuggee.
    exe_addr: u64,

    /// `r_debug` address in the debuggee.
    rdebug_addr: u64,

    /// Debuggee's address to the function internal to the run-time linker
    /// which is called whenever its state is changed (e.g., new library
    /// loaded).
    pub rbrk_addr: u64,

    /// Current loading state of shared object in the debuggee.
    rstate: u64,
}

impl RDebug {
    pub fn fetch(
        pid: Pid,
        elf_ctx: goblin::container::Ctx,
        exe_addr: u64,
        rdebug_addr: u64,
    ) -> crate::sys::Result<Self> {
        let rstate = fetch_rstate(pid, elf_ctx, rdebug_addr)?;
        let rbrk_addr = fetch_rbrk(pid, elf_ctx, rdebug_addr)?;

        Ok(Self {
            pid,
            elf_ctx,
            exe_addr,
            rdebug_addr,
            rbrk_addr,
            rstate,
        })
    }

    /// Refresh the debuggee's state from its `r_debug` struct.
    ///
    /// If an object was added/removed from the link map, the new link map is
    /// returned.
    pub fn refresh(&mut self) -> crate::sys::Result<Option<IndexSet<LinkMap>>> {
        let rstate = fetch_rstate(self.pid, self.elf_ctx, self.rdebug_addr)?;

        let lm = match (self.rstate, rstate) {
            (RT_CONSISTENT, RT_ADD | RT_DELETE) => None,
            (RT_ADD | RT_DELETE, RT_CONSISTENT) => self.fetch_link_maps().map(Some)?,
            _ => {
                return Err(crate::sys::Error::BadSoState(
                    self.rstate as u8,
                    rstate as u8,
                ));
            }
        };

        self.rstate = rstate;

        Ok(lm)
    }

    /// Reads the link map from the `r_debug` struct and update the input link
    /// map with it.
    pub fn fetch_link_maps(&self) -> crate::sys::Result<IndexSet<LinkMap>> {
        let lm_addr = self.rdebug_addr + self.elf_ctx.size() as u64;
        let mut addr = ptrace::read(self.pid, lm_addr as *mut _)? as u64;

        if !self.elf_ctx.is_big() {
            addr &= 0xffffffff;
        }

        LinkMapIter {
            pid: self.pid,
            addr,
            elf_ctx: self.elf_ctx,
            exe_addr: self.exe_addr,
        }
        .collect()
    }
}

fn fetch_rbrk(
    pid: Pid,
    elf_ctx: goblin::container::Ctx,
    rdebug_addr: u64,
) -> crate::sys::Result<u64> {
    let rbrk_addr = rdebug_addr + elf_ctx.size() as u64 * 2;
    let mut rbrk = ptrace::read(pid, rbrk_addr as *mut _)? as u64;

    if !elf_ctx.is_big() {
        rbrk &= 0xffffffff;
    }

    Ok(rbrk)
}

fn fetch_rstate(
    pid: Pid,
    elf_ctx: goblin::container::Ctx,
    rdebug_addr: u64,
) -> crate::sys::Result<u64> {
    let rstate_addr = rdebug_addr + elf_ctx.size() as u64 * 3;
    let mut rstate = ptrace::read(pid, rstate_addr as *mut _)? as u64; // FAIL HERE

    if !elf_ctx.is_big() {
        rstate &= 0xffffffff;
    }

    Ok(rstate)
}

struct LinkMapIter {
    pid: Pid,
    addr: u64,
    elf_ctx: goblin::container::Ctx,
    exe_addr: u64,
}

impl Iterator for LinkMapIter {
    type Item = crate::sys::Result<LinkMap>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.addr == 0 {
            return None;
        }

        let (link_map, next_addr) =
            match read_link_map(self.pid, self.addr, self.elf_ctx, self.exe_addr) {
                Ok(res) => res,
                Err(e) => return Some(Err(e)),
            };

        self.addr = next_addr;

        Some(Ok(link_map))
    }
}

fn read_link_map(
    pid: Pid,
    addr: u64,
    elf_ctx: goblin::container::Ctx,
    exe_addr: u64,
) -> crate::sys::Result<(LinkMap, u64)> {
    let mut buf = vec![0u8; elf_ctx.size() * 5];

    super::mem::read_process_memory(pid.as_raw() as u64, addr, &mut buf)?;

    let mut offset = 0;

    let (base_addr, name, next_addr) = if elf_ctx.is_big() {
        let base_addr = buf
            .gread_with(&mut offset, elf_ctx.le)
            .map_err(goblin::error::Error::from)?;

        let name_addr = buf
            .gread_with(&mut offset, elf_ctx.le)
            .map_err(goblin::error::Error::from)?;

        let name = super::mem::read_process_cstring(pid, name_addr)?;

        offset += elf_ctx.size();

        let next_addr = buf
            .gread_with(&mut offset, elf_ctx.le)
            .map_err(goblin::error::Error::from)?;

        (base_addr, name, next_addr)
    } else {
        let base_addr: u32 = buf
            .gread_with(&mut offset, elf_ctx.le)
            .map_err(goblin::error::Error::from)?;

        let name_addr: u32 = buf
            .gread_with(&mut offset, elf_ctx.le)
            .map_err(goblin::error::Error::from)?;

        let name = super::mem::read_process_cstring(pid, name_addr as u64)?;

        offset += elf_ctx.size();

        let next_addr: u32 = buf
            .gread_with(&mut offset, elf_ctx.le)
            .map_err(goblin::error::Error::from)?;

        (base_addr as u64, name, next_addr as u64)
    };

    let (base_addr, name) = if name.is_empty() {
        let base_addr = if base_addr == 0 { exe_addr } else { base_addr };
        (base_addr, format!("/proc/{pid}/exe"))
    } else {
        (base_addr, name.to_string_lossy().into_owned())
    };

    Ok((LinkMap { base_addr, name }, next_addr))
}
