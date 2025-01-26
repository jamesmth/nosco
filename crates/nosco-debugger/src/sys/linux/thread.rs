use nix::sys::ptrace;
use nix::unistd::Pid;

pub fn resume_thread(thread_id: u64, single_step: bool) -> crate::sys::Result<()> {
    if single_step {
        ptrace::step(Pid::from_raw(thread_id as i32), None)?;
    } else {
        ptrace::cont(Pid::from_raw(thread_id as i32), None)?;
    }

    Ok(())
}

pub fn get_thread_registers(thread_id: u64) -> crate::sys::Result<ThreadRegisters> {
    let regs = ptrace::getregs(Pid::from_raw(thread_id as i32))?;

    Ok(ThreadRegisters {
        inner: regs,
        #[cfg(target_arch = "x86_64")]
        ret_addr: 0,
    })
}

pub fn set_thread_registers(thread_id: u64, regs: ThreadRegisters) -> crate::sys::Result<()> {
    ptrace::setregs(Pid::from_raw(thread_id as i32), regs.inner)?;
    Ok(())
}

pub struct ThreadRegisters {
    inner: nix::libc::user_regs_struct,

    #[cfg(target_arch = "x86_64")]
    ret_addr: u64,
}

impl ThreadRegisters {
    pub fn frame_ptr_mut(&mut self) -> &mut u64 {
        #[cfg(target_arch = "x86_64")]
        {
            &mut self.inner.rbp
        }

        #[cfg(target_arch = "aarch64")]
        {
            &mut self.inner.regs[29]
        }
    }

    pub fn stack_ptr_mut(&mut self) -> &mut u64 {
        #[cfg(target_arch = "x86_64")]
        {
            &mut self.inner.rsp
        }

        #[cfg(target_arch = "aarch64")]
        {
            &mut self.inner.sp
        }
    }
}

impl nosco_tracer::debugger::Registers for ThreadRegisters {
    fn instr_addr_mut(&mut self) -> &mut u64 {
        #[cfg(target_arch = "x86_64")]
        {
            &mut self.inner.rip
        }

        #[cfg(target_arch = "aarch64")]
        {
            &mut self.inner.pc
        }
    }

    fn ret_addr_mut(&mut self) -> &mut u64 {
        #[cfg(target_arch = "x86_64")]
        {
            &mut self.ret_addr
        }

        #[cfg(target_arch = "aarch64")]
        {
            &mut self.inner.regs[30]
        }
    }
}
