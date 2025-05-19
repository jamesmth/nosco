use std::ffi::CString;

use nix::errno::Errno;
use nix::libc::{iovec, process_vm_readv};
use nix::sys::ptrace;
use nix::unistd::Pid;

/// Reads a C-string from memory of the process with the given ID.
pub fn read_process_cstring(pid: Pid, mut addr: u64) -> crate::sys::Result<CString> {
    // FIXME optimize algo

    let mut s = Vec::new();
    loop {
        let data = ptrace::read(pid, addr as *mut _)?;

        for c in data.to_le_bytes() {
            s.push(c);

            if c == 0 {
                return Ok(unsafe { CString::from_vec_with_nul_unchecked(s) });
            }

            addr += 1;
        }
    }
}

/// Reads memory from the process with the given ID.
pub fn read_process_memory(process_id: u64, addr: u64, buf: &mut [u8]) -> crate::sys::Result<()> {
    let local_iov = iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };

    let remote_iov = iovec {
        iov_base: addr as *mut _,
        iov_len: buf.len(),
    };

    let len = unsafe {
        Errno::result(process_vm_readv(
            process_id as i32,
            &local_iov as *const _,
            1,
            &remote_iov as *const _,
            1,
            0,
        ))
        .inspect_err(
            |e| tracing::error!(error = %e, addr = format_args!("{addr:#x}"), "process_vm_readv"),
        )
        .map(|len| len as usize)?
    };

    if len != buf.len() {
        Err(crate::sys::Error::PartialMemOp(len, buf.len()))
    } else {
        Ok(())
    }
}

/// Writes memory into the process with the given ID.
pub fn write_process_memory(process_id: u64, addr: u64, buf: &[u8]) -> crate::sys::Result<()> {
    let pid = Pid::from_raw(process_id as i32);

    let mut data_to_write = buf.chunks_exact(std::mem::size_of::<u64>());

    let mut write_addr = addr;

    for chunk in &mut data_to_write {
        let Ok(data) = chunk.try_into().map(i64::from_le_bytes) else {
            unreachable!("chunk should be 64 bytes long");
        };

        ptrace::write(pid, write_addr as *mut _, data)
            .inspect_err(|e| tracing::error!(error = %e, addr = format_args!("{write_addr:#x}"), "ptrace(PTRACE_POKE_DATA)"))?;

        write_addr += chunk.len() as u64;
    }

    let remainder = data_to_write.remainder();

    if !remainder.is_empty() {
        let mut old_data = ptrace::read(pid, write_addr as *mut _)
            .inspect_err(|e| tracing::error!(error = %e, addr = format_args!("{write_addr:#x}"), "ptrace(PTRACE_PEEK_DATA)"))?
            .to_le_bytes();

        for (old, new) in old_data.iter_mut().zip(remainder) {
            *old = *new;
        }

        let new_data = i64::from_le_bytes(old_data);

        ptrace::write(pid, write_addr as *mut _, new_data)
            .inspect_err(|e| tracing::error!(error = %e, addr = format_args!("{write_addr:#x}"), "ptrace(PTRACE_POKE_DATA)"))?;
    }

    Ok(())
}
