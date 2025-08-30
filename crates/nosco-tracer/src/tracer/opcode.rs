use crate::debugger::DebugSession;

#[cfg(target_arch = "x86_64")]
const MAX_OPCODES_LEN: usize = 15;
#[cfg(target_arch = "aarch64")]
const MAX_OPCODES_LEN: usize = 4;

pub enum OpcodesType {
    Call,
    Ret,
}

pub struct Opcodes {
    pub bytes: [u8; MAX_OPCODES_LEN],
    pub ty: Option<OpcodesType>,
}

impl Opcodes {
    /// Reads opcodes of a single instruction at the given address.
    pub fn read_once<S: DebugSession>(
        session: &S,
        thread: &S::StoppedThread,
        addr: u64,
    ) -> Result<Opcodes, S::Error> {
        let mut opcodes = [0u8; MAX_OPCODES_LEN];
        session.read_memory(thread, addr, &mut opcodes)?;

        let ty = if session.binary_ctx().is_big_container {
            if is_call_64(opcodes) {
                Some(OpcodesType::Call)
            } else if is_ret_64(opcodes) {
                Some(OpcodesType::Ret)
            } else {
                None
            }
        } else if is_call_32(opcodes) {
            Some(OpcodesType::Call)
        } else if is_ret_32(opcodes) {
            Some(OpcodesType::Ret)
        } else {
            None
        };

        Ok(Opcodes { bytes: opcodes, ty })
    }
}

#[cfg(target_arch = "x86_64")]
fn is_call_32(opcodes: [u8; MAX_OPCODES_LEN]) -> bool {
    // whether the byte is a segment override prefix
    let is_seg = |b: u8| b == 0x2e || b == 0x36 || b == 0x3e || b == 0x26 || b == 0x64 || b == 0x65;

    // whether the byte is an address-size override prefix
    let is_adr = |b: u8| b == 0x67;

    // whether the byte is an operand-size override prefix
    let is_ope = |b: u8| b == 0x66;

    // whether the ModR/M byte has the opcode extension of a call
    let is_cal_ext = |b: u8| ((b >> 3) & 7) == 2 || ((b >> 3) & 7) == 3;

    // whether the byte is a 'call' mnemonic
    let is_cal = |b1: u8, b2: u8| (b1 == 0xff && is_cal_ext(b2)) || b1 == 0xe8 || b1 == 0x9a;

    let o = opcodes;

    if is_cal(o[0], o[1]) {
        return true;
    }

    if is_cal(o[1], o[2]) && (is_ope(o[0]) || is_adr(o[0]) || is_seg(o[0])) {
        return true;
    }

    if is_cal(o[2], o[3])
        && ((is_ope(o[1]) && (is_adr(o[0]) || is_seg(o[0]))) || (is_adr(o[1]) && is_seg(o[0])))
    {
        return true;
    }

    is_cal(o[3], o[4]) && is_ope(o[2]) && is_adr(o[1]) && is_seg(o[0])
}

#[cfg(target_arch = "aarch64")]
fn is_call_32(opcodes: [u8; MAX_OPCODES_LEN]) -> bool {
    let opcodes = u32::from_le_bytes(opcodes);

    // TODO: add thumb-mode encoding check

    let is_bl = |o: u32| (o & 0x0b000000) == 0x0b000000;
    let is_blx = |o: u32| (o & 0xfa000000) == 0xfa000000;
    let is_blx_reg = |o: u32| (o & 0x012fff30) == 0x012fff30;

    is_bl(opcodes) || is_blx(opcodes) || is_blx_reg(opcodes)
}

#[cfg(target_arch = "x86_64")]
fn is_call_64(opcodes: [u8; MAX_OPCODES_LEN]) -> bool {
    // whether the byte is a segment override prefix
    let is_seg = |b: u8| b == 0x2e || b == 0x36 || b == 0x3e || b == 0x26 || b == 0x64 || b == 0x65;

    // whether the byte is an address-size override prefix
    let is_adr = |b: u8| b == 0x67;

    // whether the byte is an operand-size override prefix
    let is_ope = |b: u8| b == 0x66;

    // whether the byte is a REX prefix
    let is_rex = |b: u8| (b & 0xf0) == 0x40;

    // whether the ModR/M byte has the opcode extension of a call
    let is_cal_ext = |b: u8| ((b >> 3) & 7) == 2 || ((b >> 3) & 7) == 3;

    // whether the byte is a 'call' mnemonic
    let is_cal = |b1: u8, b2: u8| (b1 == 0xff && is_cal_ext(b2)) || b1 == 0xe8;

    let o = opcodes;

    if is_cal(o[0], o[1]) {
        return true;
    }

    if is_cal(o[1], o[2]) && (is_rex(o[0]) || is_ope(o[0]) || is_adr(o[0]) || is_seg(o[0])) {
        return true;
    }

    if is_cal(o[2], o[3])
        && ((is_rex(o[1]) && (is_ope(o[0]) || is_adr(o[0]) || is_seg(o[0])))
            || (is_ope(o[1]) && (is_adr(o[0]) || is_seg(o[0])))
            || (is_adr(o[1]) && is_seg(o[0])))
    {
        return true;
    }

    if is_cal(o[3], o[4])
        && ((is_rex(o[2]) && is_ope(o[1]) && (is_adr(o[0]) || is_seg(o[0])))
            || (is_rex(o[2]) && is_adr(o[1]) && is_seg(o[0]))
            || (is_ope(o[2]) && is_adr(o[1]) && is_seg(o[0])))
    {
        return true;
    }

    is_cal(o[4], o[5]) && is_rex(o[3]) && is_ope(o[2]) && is_adr(o[1]) && is_seg(o[0])
}

#[cfg(target_arch = "aarch64")]
fn is_call_64(opcodes: [u8; MAX_OPCODES_LEN]) -> bool {
    let opcodes = u32::from_le_bytes(opcodes);

    let is_bl = |o: u32| (o & 0x94000000) == 0x94000000;
    let is_blr = |o: u32| (o & 0xd63f0000) == 0xd63f0000;

    is_bl(opcodes) || is_blr(opcodes)
}

#[cfg(target_arch = "x86_64")]
fn is_ret_32(opcodes: [u8; MAX_OPCODES_LEN]) -> bool {
    // whether the byte is an operand-size override prefix
    let is_ope = |b: u8| b == 0x66;

    // whether the byte is a 'ret' mnemonic
    let is_ret = |b: u8| b == 0xc3 || b == 0xc2 || b == 0xcb || b == 0xca;

    let o = opcodes;

    is_ret(o[0]) || (is_ret(o[1]) && is_ope(o[0]))
}

#[cfg(target_arch = "aarch64")]
fn is_ret_32(opcodes: [u8; MAX_OPCODES_LEN]) -> bool {
    let opcodes = u32::from_le_bytes(opcodes);

    // TODO: add thumb-mode encoding check

    let is_bx_lr = |o: u32| (o & 0x12fff1e) == 0x12fff1e;

    is_bx_lr(opcodes)
}

#[cfg(target_arch = "x86_64")]
fn is_ret_64(opcodes: [u8; MAX_OPCODES_LEN]) -> bool {
    // whether the byte is an operand-size override prefix
    let is_ope = |b: u8| b == 0x66;

    // whether the byte is a REX prefix
    let is_rex = |b: u8| (b & 0xf0) == 0x40;

    // whether the byte is a 'ret' mnemonic
    let is_ret = |b: u8| b == 0xc3 || b == 0xc2 || b == 0xcb || b == 0xca;

    let o = opcodes;

    if is_ret(o[0]) {
        return true;
    }

    is_ret(o[1]) && (is_rex(o[0]) || is_ope(o[0]))
}

#[cfg(target_arch = "aarch64")]
fn is_ret_64(opcodes: [u8; MAX_OPCODES_LEN]) -> bool {
    let opcodes = u32::from_le_bytes(opcodes);

    let is_ret = |o: u32| o & 0xd65f0000 == 0xd65f0000;
    let is_reta = |o: u32| o & 0xd65f0bff == 0xd65f0bff;
    let is_retasppc = |o: u32| o & 0x5500001f == 0x5500001f;
    let is_retasppcr = |o: u32| o & 0xd65f0be0 == 0xd65f0be0;

    is_ret(opcodes) || is_reta(opcodes) || is_retasppc(opcodes) || is_retasppcr(opcodes)
}
