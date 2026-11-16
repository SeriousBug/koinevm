//! AArch64 (A64) decoder. Produces a small IR; the emitter is the only consumer.
//!
//! Structure follows the ARM ARM top-level encoding tree rather than ad-hoc bit tests: `op0` is
//! bits[28:25] and splits the space into data-processing-immediate, branch/system,
//! data-processing-register and load/store. Testing groups out of order produces real collisions
//! (`cmp x10, x11` is 0xEB0B015F, which matches the load/store-pair pattern if you check bits
//! [29:27] before bits [28:24]).
//!
//! Everything not decoded is `Insn::Undefined`, which the emitter refuses at the address where it
//! is reached, rather than guessing.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shift {
    Lsl,
    Lsr,
    Asr,
    Ror,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extend {
    Uxtb,
    Uxth,
    Uxtw,
    Uxtx,
    Sxtb,
    Sxth,
    Sxtw,
    Sxtx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsMode {
    Unsigned,
    Unscaled,
    PostIndex,
    PreIndex,
    Register,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairMode {
    Offset,
    PostIndex,
    PreIndex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insn {
    Adr { rd: u32, imm: i64 },
    Adrp { rd: u32, imm: i64 },
    /// `rn`/`rd` are SP-encoded when 31 (add/sub immediate is the form where 31 means SP).
    AddSubImm { sf: bool, sub: bool, setflags: bool, shift: u32, imm: u64, rn: u32, rd: u32 },
    LogicalImm { sf: bool, opc: u32, imm: u64, rn: u32, rd: u32 },
    MoveWide { sf: bool, opc: u32, hw: u32, imm16: u64, rd: u32 },
    Bitfield { sf: bool, opc: u32, n: u32, immr: u32, imms: u32, rn: u32, rd: u32 },
    Extract { sf: bool, rm: u32, lsb: u32, rn: u32, rd: u32 },
    /// op: 0 rbit, 1 rev16, 2 rev32, 3 rev, 4 clz, 5 cls
    OneSource { sf: bool, op: u32, rn: u32, rd: u32 },
    Div { sf: bool, signed: bool, rn: u32, rm: u32, rd: u32 },
    /// op: 8 lsl, 9 lsr, 10 asr, 11 ror
    ShiftReg { sf: bool, op: u32, rn: u32, rm: u32, rd: u32 },
    MaddMsub { sf: bool, sub: bool, rm: u32, ra: u32, rn: u32, rd: u32 },
    MulHigh { sf: bool, signed: bool, rn: u32, rm: u32, rd: u32 },
    AddSubReg { sf: bool, sub: bool, setflags: bool, shift: Shift, amount: u32, rm: u32, rn: u32, rd: u32 },
    AddSubExt { sf: bool, sub: bool, setflags: bool, extend: Extend, amount: u32, rm: u32, rn: u32, rd: u32 },
    AddSubCarry { sf: bool, sub: bool, setflags: bool, rm: u32, rn: u32, rd: u32 },
    LogicalReg { sf: bool, opc: u32, invert: bool, shift: Shift, amount: u32, rm: u32, rn: u32, rd: u32 },
    CondSelect { sf: bool, op2: u32, rm: u32, cond: u32, rn: u32, rd: u32 },
    CondCompare { sf: bool, sub: bool, reg: bool, rm_or_imm: u32, nzcv: u32, cond: u32, rn: u32 },
    LoadStore { size: u32, is_load: bool, opc: u32, mode: LsMode, offset: i64, rn: u32, rt: u32, rm: u32, option: u32, scaled: bool },
    LoadStorePair { is_load: bool, mode: PairMode, offset: i64, rn: u32, rt: u32, rt2: u32, width: u32, signed_word: bool },
    Literal { sf: bool, offset: i64, rt: u32 },
    B { offset: i64 },
    Bl { offset: i64 },
    BCond { cond: u32, offset: i64 },
    Cbz { sf: bool, nonzero: bool, rt: u32, offset: i64 },
    Tbz { nonzero: bool, bit: u32, rt: u32, offset: i64 },
    Br { rn: u32 },
    Blr { rn: u32 },
    Ret { rn: u32 },
    Svc,
    MrsTpidr { rd: u32 },
    MsrTpidr { rn: u32 },
    Hint,
    Undefined,
}

fn sx(v: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    (((v << shift) as i32) >> shift) as i64
}

/// ARM ARM DecodeBitMasks, for logical immediates.
pub fn decode_bitmask(n: u32, imms: u32, immr: u32, sf: bool) -> Option<u64> {
    let combined: u32 = (n << 6) | (!imms & 0x3f);
    if combined == 0 {
        return None;
    }
    let len = 31 - combined.leading_zeros();
    if len < 1 {
        return None;
    }
    let levels = (1u32 << len) - 1;
    if (imms & levels) == levels {
        return None;
    }
    let s = imms & levels;
    let r = (immr & levels) % (1 << len);
    let esize = 1u32 << len;
    let m = if esize >= 64 { u64::MAX } else { (1u64 << esize) - 1 };
    let welem = if s + 1 >= 64 { u64::MAX } else { (1u64 << (s + 1)) - 1 };
    let masked = welem & m;
    let rotated = if esize >= 64 {
        masked.rotate_right(r)
    } else {
        ((masked >> r) | (masked << (esize - r))) & m
    };
    let mut out = 0u64;
    let mut shift = 0u32;
    while shift < 64 {
        out |= rotated << shift;
        shift += esize;
    }
    if sf {
        Some(out)
    } else {
        Some(out & 0xffff_ffff)
    }
}

pub fn decode(w: u32) -> Insn {
    let sf = w >> 31 != 0;
    let rd = w & 31;
    let rn = (w >> 5) & 31;
    let rm = (w >> 16) & 31;
    let op0 = (w >> 25) & 0xf;

    match op0 {
        0b1000 | 0b1001 => decode_dp_imm(w, sf, rd, rn),
        0b1010 | 0b1011 => decode_branch_system(w, sf, rd, rn),
        0b0101 | 0b1101 => decode_dp_reg(w, sf, rd, rn, rm),
        0b0100 | 0b0110 | 0b1100 | 0b1110 => decode_loadstore(w, sf, rd, rn),
        // 001x is SVE, x111 is scalar FP/SIMD: deliberately not decoded yet.
        _ => Insn::Undefined,
    }
}

fn decode_dp_imm(w: u32, sf: bool, rd: u32, rn: u32) -> Insn {
    match (w >> 23) & 7 {
        0 => {
            let immlo = (w >> 29) & 3;
            let immhi = (w >> 5) & 0x7ffff;
            let imm = sx((immhi << 2) | immlo, 21);
            if sf {
                Insn::Adrp { rd, imm }
            } else {
                Insn::Adr { rd, imm }
            }
        }
        1 | 2 => Insn::AddSubImm {
            sf,
            sub: (w >> 30) & 1 != 0,
            setflags: (w >> 29) & 1 != 0,
            shift: (w >> 22) & 1,
            imm: ((w >> 10) & 0xfff) as u64,
            rn,
            rd,
        },
        4 => {
            let n = (w >> 22) & 1;
            let immr = (w >> 16) & 0x3f;
            let imms = (w >> 10) & 0x3f;
            match decode_bitmask(n, imms, immr, sf) {
                Some(imm) => Insn::LogicalImm { sf, opc: (w >> 29) & 3, imm, rn, rd },
                None => Insn::Undefined,
            }
        }
        5 => Insn::MoveWide {
            sf,
            opc: (w >> 29) & 3,
            hw: (w >> 21) & 3,
            imm16: ((w >> 5) & 0xffff) as u64,
            rd,
        },
        6 => Insn::Bitfield {
            sf,
            opc: (w >> 29) & 3,
            n: (w >> 22) & 1,
            immr: (w >> 16) & 0x3f,
            imms: (w >> 10) & 0x3f,
            rn,
            rd,
        },
        7 => Insn::Extract { sf, rm: (w >> 16) & 31, lsb: (w >> 10) & 0x3f, rn, rd },
        _ => Insn::Undefined,
    }
}

fn decode_branch_system(w: u32, sf: bool, rd: u32, _rn: u32) -> Insn {
    if w >> 24 == 0xD4 {
        return if w == 0xD400_0001 { Insn::Svc } else { Insn::Undefined };
    }
    if w >> 24 == 0xD5 {
        if w & 0xFFFF_F01F == 0xD503_201F || w & 0xFFFF_F0DF == 0xD503_30DF {
            return Insn::Hint; // hint #n, dsb/dmb/isb
        }
        if w & 0xFFFF_FFE0 == 0xD53B_D040 {
            return Insn::MrsTpidr { rd };
        }
        if w & 0xFFFF_FFE0 == 0xD51B_D040 {
            return Insn::MsrTpidr { rn: rd };
        }
        return Insn::Undefined;
    }
    if w >> 24 == 0x54 {
        let imm19 = (w >> 5) & 0x7ffff;
        return Insn::BCond { cond: w & 0xf, offset: sx(imm19, 19) << 2 };
    }
    if (w >> 26) & 0x1f == 0b00101 {
        let off = sx(w & 0x3ffffff, 26) << 2;
        return if sf { Insn::Bl { offset: off } } else { Insn::B { offset: off } };
    }
    if w >> 25 == 0b1101_011 {
        return match (w >> 21) & 0xf {
            0 => Insn::Br { rn: (w >> 5) & 31 },
            1 => Insn::Blr { rn: (w >> 5) & 31 },
            2 => Insn::Ret { rn: (w >> 5) & 31 },
            _ => Insn::Undefined,
        };
    }
    if (w >> 25) & 0x3f == 0b011_010 {
        let imm19 = (w >> 5) & 0x7ffff;
        return Insn::Cbz { sf, nonzero: (w >> 24) & 1 != 0, rt: rd, offset: sx(imm19, 19) << 2 };
    }
    if (w >> 25) & 0x3f == 0b011_011 {
        let bit = ((w >> 26) & 0x20) | ((w >> 19) & 0x1f);
        let imm14 = (w >> 5) & 0x3fff;
        return Insn::Tbz { nonzero: (w >> 24) & 1 != 0, bit, rt: rd, offset: sx(imm14, 14) << 2 };
    }
    Insn::Undefined
}

fn decode_dp_reg(w: u32, sf: bool, rd: u32, rn: u32, rm: u32) -> Insn {
    let shift = match (w >> 22) & 3 {
        0 => Shift::Lsl,
        1 => Shift::Lsr,
        2 => Shift::Asr,
        _ => Shift::Ror,
    };
    match (w >> 24) & 0x1f {
        0b01010 => Insn::LogicalReg {
            sf,
            opc: (w >> 29) & 3,
            invert: (w >> 21) & 1 != 0,
            shift,
            amount: (w >> 10) & 0x3f,
            rm,
            rn,
            rd,
        },
        0b01011 => {
            if (w >> 21) & 1 == 0 {
                Insn::AddSubReg {
                    sf,
                    sub: (w >> 30) & 1 != 0,
                    setflags: (w >> 29) & 1 != 0,
                    shift,
                    amount: (w >> 10) & 0x3f,
                    rm,
                    rn,
                    rd,
                }
            } else {
                Insn::AddSubExt {
                    sf,
                    sub: (w >> 30) & 1 != 0,
                    setflags: (w >> 29) & 1 != 0,
                    extend: match (w >> 13) & 7 {
                        0 => Extend::Uxtb,
                        1 => Extend::Uxth,
                        2 => Extend::Uxtw,
                        3 => Extend::Uxtx,
                        4 => Extend::Sxtb,
                        5 => Extend::Sxth,
                        6 => Extend::Sxtw,
                        _ => Extend::Sxtx,
                    },
                    amount: (w >> 10) & 7,
                    rm,
                    rn,
                    rd,
                }
            }
        }
        0b11011 => {
            let op31 = (w >> 21) & 7;
            let o0 = (w >> 15) & 1;
            match (op31, o0) {
                (0, 0) => Insn::MaddMsub { sf, sub: false, rm, ra: (w >> 10) & 31, rn, rd },
                (0, 1) => Insn::MaddMsub { sf, sub: true, rm, ra: (w >> 10) & 31, rn, rd },
                (2, 0) if sf => Insn::MulHigh { sf, signed: true, rn, rm, rd },
                (6, 0) if sf => Insn::MulHigh { sf, signed: false, rn, rm, rd },
                _ => Insn::Undefined,
            }
        }
        0b11010 => match (w >> 21) & 0xf {
            0b0000 => Insn::AddSubCarry {
                sf,
                sub: (w >> 30) & 1 != 0,
                setflags: (w >> 29) & 1 != 0,
                rm,
                rn,
                rd,
            },
            0b0010 => {
                let reg = (w >> 10) & 1 == 0;
                Insn::CondCompare {
                    sf,
                    sub: (w >> 30) & 1 != 0,
                    reg,
                    rm_or_imm: if reg { rm } else { (w >> 16) & 31 },
                    nzcv: w & 0xf,
                    cond: (w >> 12) & 0xf,
                    rn,
                }
            }
            0b0100 => Insn::CondSelect { sf, op2: (w >> 10) & 3, rm, cond: (w >> 12) & 0xf, rn, rd },
            0b0110 => {
                let opcode = (w >> 10) & 0x3f;
                if (w >> 29) & 3 == 0b10 {
                    // data processing (1 source)
                    if opcode > 5 {
                        return Insn::Undefined;
                    }
                    Insn::OneSource { sf, op: opcode, rn, rd }
                } else {
                    match opcode {
                        0b000010 => Insn::Div { sf, signed: false, rn, rm, rd },
                        0b000011 => Insn::Div { sf, signed: true, rn, rm, rd },
                        0b001000..=0b001011 => {
                            Insn::ShiftReg { sf, op: 8 + (opcode - 0b001000), rn, rm, rd }
                        }
                        _ => Insn::Undefined,
                    }
                }
            }
            _ => Insn::Undefined,
        },
        _ => Insn::Undefined,
    }
}

fn decode_loadstore(w: u32, sf: bool, rd: u32, rn: u32) -> Insn {
    match (w >> 27) & 7 {
        0b111 => {
            let size = (w >> 30) & 3;
            let v = (w >> 26) & 1;
            if v != 0 {
                return Insn::Undefined;
            }
            let opc = (w >> 22) & 3;
            if !sf && size == 3 {
                return Insn::Undefined;
            }
            let is_load = opc != 0;
            let mode_bits = (w >> 24) & 3;
            let (mode, offset, rmx, option, scaled) = if mode_bits == 0b01 {
                (LsMode::Unsigned, (((w >> 10) & 0xfff) as i64) << size, 0, 0, false)
            } else if mode_bits == 0b00 {
                let imm9 = sx((w >> 12) & 0x1ff, 9);
                match (w >> 10) & 3 {
                    0b00 => (LsMode::Unscaled, imm9, 0, 0, false),
                    0b01 => (LsMode::PostIndex, imm9, 0, 0, false),
                    0b11 => (LsMode::PreIndex, imm9, 0, 0, false),
                    0b10 => (LsMode::Register, 0, (w >> 16) & 31, (w >> 13) & 7, (w >> 12) & 1 != 0),
                    _ => return Insn::Undefined,
                }
            } else {
                return Insn::Undefined;
            };
            // opc/size combinations that are prefetch or unallocated
            if (size == 3 && opc != 0 && opc != 1) || (size == 2 && opc == 3) || (size == 0 && opc == 3 && false) {
                return Insn::Undefined;
            }
            Insn::LoadStore { size, is_load, opc, mode, offset, rn, rt: rd, rm: rmx, option, scaled }
        }
        0b101 => {
            let opc = (w >> 30) & 3;
            let v = (w >> 26) & 1;
            if v != 0 {
                return Insn::Undefined;
            }
            let mode = match (w >> 23) & 3 {
                1 => PairMode::PostIndex,
                2 => PairMode::Offset,
                3 => PairMode::PreIndex,
                _ => return Insn::Undefined,
            };
            let width = if opc == 2 { 64 } else { 32 };
            let scale = if opc == 2 { 3 } else { 2 };
            let imm7 = sx((w >> 15) & 0x7f, 7);
            Insn::LoadStorePair {
                is_load: (w >> 22) & 1 != 0,
                mode,
                offset: imm7 << scale,
                rn,
                rt: rd,
                rt2: (w >> 10) & 31,
                width,
                signed_word: opc == 1,
            }
        }
        0b011 => {
            let v = (w >> 26) & 1;
            let opc = (w >> 30) & 3;
            if v != 0 || opc > 1 {
                return Insn::Undefined;
            }
            let imm19 = (w >> 5) & 0x7ffff;
            Insn::Literal { sf: opc == 1, offset: sx(imm19, 19) << 2, rt: rd }
        }
        _ => Insn::Undefined,
    }
}
