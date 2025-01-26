use nix::sys::ptrace;
use nix::unistd::Pid;

// TODO: watchpoint on arm64

const DR0_OFFSET: usize = std::mem::offset_of!(nix::libc::user, u_debugreg);
const DR6_OFFSET: usize = DR0_OFFSET + 8 * 6;
const DR7_OFFSET: usize = DR6_OFFSET + 8;

/// Returns whether the given thread was stopped by a hardware watchpoint.
pub fn check_trap_is_watchpoint(thread_id: u64) -> crate::sys::Result<bool> {
    let pid = Pid::from_raw(thread_id as i32);

    let mut dr6 = ptrace::read_user(pid, DR6_OFFSET as *mut _)?;

    let is_hardware_watchpoint = dr6 & 0b1 != 0;

    if is_hardware_watchpoint {
        dr6 &= !0b1; // clear the bitflag
        ptrace::write_user(pid, DR6_OFFSET as *mut _, dr6)?;
    }

    Ok(is_hardware_watchpoint)
}

/// Adds a hardware watchpoint over the given address in a process.
///
/// # Warning
///
/// The process must be in a suspended state (e.g., SIGTRAP).
// TODO: handle DR0-3, instead of just DR0
pub fn add_hardware_watchpoint(
    pid: Pid,
    ctx: goblin::container::Ctx,
    addr: u64,
    write_only: bool,
) -> crate::sys::Result<()> {
    let mut dr7 = ptrace::read_user(pid, DR7_OFFSET as *mut _)?;

    let writeonly_mask = if write_only { 0b1 << 16 } else { 0b11 << 16 };
    let size_mask = if ctx.is_big() { 0b10 << 18 } else { 0b11 << 18 };

    dr7 |= writeonly_mask | size_mask | 0x401;

    ptrace::write_user(pid, DR0_OFFSET as *mut _, addr as i64)?;
    ptrace::write_user(pid, DR7_OFFSET as *mut _, dr7)?;

    Ok(())
}

/// Removes a hardware watchpoint from a process.
///
/// # Warning
///
/// The process must be in a suspended state (e.g., SIGTRAP).
// TODO: handle DR0-3, instead of just DR0
pub fn remove_hardware_watchpoint(pid: Pid) -> crate::sys::Result<()> {
    let mut dr7 = ptrace::read_user(pid, DR7_OFFSET as *mut _)?;

    let write_mask = 0b11 << 16;
    let size_mask = 0b11 << 18;

    dr7 &= !(write_mask | size_mask | 0x1);

    ptrace::write_user(pid, DR7_OFFSET as *mut _, dr7)?;

    Ok(())
}
