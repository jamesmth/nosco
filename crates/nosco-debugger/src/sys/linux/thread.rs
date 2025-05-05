use std::ffi::c_void;
use std::mem;

use nix::errno::Errno;
use nix::libc;
use nix::sys::ptrace::regset::NT_PRSTATUS;
use nix::sys::ptrace::{self, RegisterSet};
use nix::unistd::Pid;

use nosco_tracer::debugger::{DebugSession, Thread};
use nosco_tracer::debugger::{RegistersAarch64, RegistersArm, RegistersX86, RegistersX86_64};

use crate::Session;

#[cfg(target_arch = "x86_64")]
type StackUnwinderRegisters = framehop::x86_64::UnwindRegsX86_64;
#[cfg(target_arch = "aarch64")]
type StackUnwinderRegisters = framehop::aarch64::UnwindRegsAarch64;

pub fn resume_thread(thread_id: u64, single_step: bool) -> crate::sys::Result<()> {
    if single_step {
        ptrace::step(Pid::from_raw(thread_id as i32), None)?;
    } else {
        ptrace::cont(Pid::from_raw(thread_id as i32), None)?;
    }

    Ok(())
}

pub fn get_thread_registers(thread_id: u64) -> crate::sys::Result<Registers> {
    let mut data = mem::MaybeUninit::<libc::user_regs_struct>::uninit();

    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: mem::size_of::<libc::user_regs_struct>(),
    };

    unsafe {
        Errno::result(libc::ptrace(
            ptrace::Request::PTRACE_GETREGSET as u32,
            thread_id as i32,
            NT_PRSTATUS::VALUE as i32,
            &mut iov as *mut libc::iovec,
        ))
        .map(|_| 0)?
    };

    let regs = if iov.iov_len == mem::size_of::<user_regs_64>() {
        let data = unsafe { data.assume_init() };
        Registers::B64(Registers64(data))
    } else {
        let data = unsafe { *data.as_ptr().cast::<user_regs_32>() };
        Registers::B32(Registers32(data))
    };

    Ok(regs)
}

fn set_thread_registers<T>(thread_id: u64, regs: &T) -> crate::sys::Result<()> {
    let mut iov = libc::iovec {
        iov_base: regs as *const T as *mut c_void,
        iov_len: mem::size_of::<T>(),
    };

    unsafe {
        Errno::result(libc::ptrace(
            ptrace::Request::PTRACE_SETREGSET as u32,
            thread_id as i32,
            NT_PRSTATUS::VALUE as i32,
            &mut iov as *mut libc::iovec,
        ))
        .map(|_| 0)?
    };

    Ok(())
}

pub enum Registers {
    B32(Registers32),
    B64(Registers64),
}

impl Registers {
    pub fn instr_addr(&self) -> u64 {
        match self {
            Self::B32(regs) => {
                #[cfg(target_arch = "x86_64")]
                {
                    regs.0.eip as u64
                }
                #[cfg(target_arch = "aarch64")]
                {
                    regs.0.arm_pc as u64
                }
            }
            Self::B64(regs) => {
                #[cfg(target_arch = "x86_64")]
                {
                    regs.0.rip
                }
                #[cfg(target_arch = "aarch64")]
                {
                    regs.0.pc
                }
            }
        }
    }

    pub fn set_instr_addr(&mut self, addr: u64) {
        match self {
            Self::B32(regs) => {
                #[cfg(target_arch = "x86_64")]
                {
                    regs.0.eip = addr as u32;
                }
                #[cfg(target_arch = "aarch64")]
                {
                    regs.0.arm_pc = addr as u32;
                }
            }
            Self::B64(regs) => {
                #[cfg(target_arch = "x86_64")]
                {
                    regs.0.rip = addr;
                }
                #[cfg(target_arch = "aarch64")]
                {
                    regs.0.pc = addr;
                }
            }
        }
    }

    pub fn assign_to_thread(
        &self,
        session: &Session,
        thread: &<Session as DebugSession>::StoppedThread,
    ) -> Result<(), <Session as DebugSession>::Error> {
        match self {
            Self::B32(regs) => {
                if cfg!(target_arch = "x86_64") {
                    <Registers32 as RegistersX86<Session>>::assign_to_thread(regs, session, thread)
                } else {
                    <Registers32 as RegistersArm<Session>>::assign_to_thread(regs, session, thread)
                }
            }
            Self::B64(regs) => {
                if cfg!(target_arch = "x86_64") {
                    <Registers64 as RegistersX86_64<Session>>::assign_to_thread(
                        regs, session, thread,
                    )
                } else {
                    <Registers64 as RegistersAarch64<Session>>::assign_to_thread(
                        regs, session, thread,
                    )
                }
            }
        }
    }

    pub fn to_unwind(&self) -> Option<StackUnwinderRegisters> {
        match self {
            Self::B32(_) => None, // `framehop` doesn't support 32-bit architectures yet
            Self::B64(regs) => {
                #[cfg(target_arch = "x86_64")]
                {
                    Some(StackUnwinderRegisters::new(
                        regs.rip(),
                        regs.rsp(),
                        regs.rbp(),
                    ))
                }
                #[cfg(target_arch = "aarch64")]
                {
                    Some(StackUnwinderRegisters::new(self.lr(), self.sp(), self.fp()))
                }
            }
        }
    }
}

pub struct Registers32(user_regs_32);

impl RegistersX86<Session> for Registers32 {
    fn assign_to_thread(
        &self,
        _session: &Session,
        thread: &<Session as DebugSession>::StoppedThread,
    ) -> Result<(), <Session as DebugSession>::Error> {
        set_thread_registers(thread.id(), &self.0).map_err(Into::into)
    }

    fn eax(&self) -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.eax
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn ebx(&self) -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.ebx
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn ecx(&self) -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.ecx
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn edx(&self) -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.edx
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn cs(&self) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.cs as u16
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn ds(&self) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.ds as u16
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn es(&self) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.es as u16
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn ss(&self) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.ss as u16
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn gs(&self) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.gs as u16
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn fs(&self) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.fs as u16
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn ebp(&self) -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.ebp
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn esp(&self) -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.esp
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn edi(&self) -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.edi
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn esi(&self) -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.esi
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn eip(&self) -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.eip
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn eflags(&self) -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.eflags
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }
}

impl RegistersArm<Session> for Registers32 {
    fn assign_to_thread(
        &self,
        _session: &Session,
        thread: &<Session as DebugSession>::StoppedThread,
    ) -> Result<(), <Session as DebugSession>::Error> {
        set_thread_registers(thread.id(), &self.0).map_err(Into::into)
    }

    fn r0(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_r0
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r1(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_r1
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r2(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_r2
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r3(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_r3
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r4(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_r4
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r5(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_r5
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r6(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_r6
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r7(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_r7
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r8(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_r8
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r9(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_r9
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r10(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_r10
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn fp(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_fp
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn ip(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_ip
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn sp(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_sp
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn lr(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_lr
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn pc(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_pc
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn cpsr(&self) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.arm_cpsr
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }
}

pub struct Registers64(nix::libc::user_regs_struct);

impl RegistersX86_64<Session> for Registers64 {
    fn assign_to_thread(
        &self,
        _session: &Session,
        thread: &<Session as DebugSession>::StoppedThread,
    ) -> Result<(), <Session as DebugSession>::Error> {
        set_thread_registers(thread.id(), &self.0).map_err(Into::into)
    }

    fn rax(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.rax
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn rbx(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.rbx
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn rcx(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.rcx
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn rdx(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.rdx
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn r8(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.r8
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn r9(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.r9
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn r10(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.r10
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn r11(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.r11
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn r12(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.r12
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn r13(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.r13
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn r14(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.r14
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn r15(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.r15
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn cs(&self) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.cs as u16
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn ds(&self) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.ds as u16
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn es(&self) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.es as u16
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn ss(&self) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.ss as u16
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn gs(&self) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.gs as u16
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn fs(&self) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.fs as u16
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn rdi(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.rdi
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn rsi(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.rsi
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn rbp(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.rbp
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn rsp(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.rsp
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn rip(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.rip
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }

    fn rflags(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.0.eflags
        }
        #[cfg(target_arch = "aarch64")]
        {
            unreachable!()
        }
    }
}

impl RegistersAarch64<Session> for Registers64 {
    fn assign_to_thread(
        &self,
        _session: &Session,
        thread: &<Session as DebugSession>::StoppedThread,
    ) -> Result<(), <Session as DebugSession>::Error> {
        set_thread_registers(thread.id(), &self.0).map_err(Into::into)
    }

    fn r0(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[0]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r1(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[1]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r2(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[2]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r3(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[3]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r4(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[4]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r5(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[5]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r6(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[6]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r7(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[7]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r8(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[8]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r9(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[9]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r10(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[10]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r11(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[11]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r12(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[12]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r13(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[13]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r14(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[14]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r15(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[15]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r16(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[16]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r17(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[17]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r18(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[18]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r19(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[19]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r20(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[20]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r21(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[21]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r22(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[22]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r23(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[23]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r24(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[24]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r25(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[25]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r26(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[26]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r27(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[27]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn r28(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[28]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn fp(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[29]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn lr(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.regs[30]
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn sp(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.sp
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn pc(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.pc
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }

    fn pstate(&self) -> u64 {
        #[cfg(target_arch = "aarch64")]
        {
            self.0.pstate
        }
        #[cfg(target_arch = "x86_64")]
        {
            unreachable!()
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
struct user_regs_32 {
    ebx: u32,
    ecx: u32,
    edx: u32,
    esi: u32,
    edi: u32,
    ebp: u32,
    eax: u32,
    ds: u32,
    es: u32,
    fs: u32,
    gs: u32,
    orig_eax: u32,
    eip: u32,
    cs: u32,
    eflags: u32,
    esp: u32,
    ss: u32,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
struct user_regs_32 {
    arm_r0: u32,
    arm_r1: u32,
    arm_r2: u32,
    arm_r3: u32,
    arm_r4: u32,
    arm_r5: u32,
    arm_r6: u32,
    arm_r7: u32,
    arm_r8: u32,
    arm_r9: u32,
    arm_r10: u32,
    arm_fp: u32,
    arm_ip: u32,
    arm_sp: u32,
    arm_lr: u32,
    arm_pc: u32,
    arm_cpsr: u32,
    arm_orig_r0: u32,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
struct user_regs_64 {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
    fs_base: u64,
    gs_base: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
struct user_regs_64 {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}
