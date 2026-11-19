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

/// How a multi-register load or store updates its base register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostIndex {
    Imm(i64),
    Reg(u32),
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
    /// SMADDL/SMSUBL/UMADDL/UMSUBL: 32-bit operands widened into a 64-bit product and accumulator.
    MulLong { signed: bool, sub: bool, rm: u32, ra: u32, rn: u32, rd: u32 },
    /// `mrs Xt, <system register>`, for the registers a guest can legitimately read.
    MrsSys { reg: SysReg, rd: u32 },
    /// `msr <system register>, Xt`, for the ones whose writes mean something here.
    MsrSys { reg: SysReg, rn: u32 },
    /// `dc cvau`/`ic ivau`/`at`/`tlbi`: cache maintenance, which this machine does not have. The
    /// instruction cache one is where translation invalidation will hang once code can change.
    CacheOp,
    /// `brk #imm`: a deliberate trap.
    Brk,

    // ---- Advanced SIMD and scalar floating point
    /// Single-register vector load/store, B/H/S/D/Q wide.
    VecLoadStore {
        width: u32,
        is_load: bool,
        mode: LsMode,
        offset: i64,
        rn: u32,
        rt: u32,
        rm: u32,
        option: u32,
        scaled: bool,
    },
    VecLoadStorePair { width: u32, is_load: bool, mode: PairMode, offset: i64, rn: u32, rt: u32, rt2: u32 },
    /// `ld1`/`st1` of one to four whole registers, contiguous, with an optional post-index.
    VecLd1 { is_load: bool, count: u32, q: bool, post: Option<PostIndex>, rn: u32, rt: u32 },
    /// `ld2`/`st2`, `ld3`/`st3`, `ld4`/`st4`: the registers interleaved in memory one element at a
    /// time. `e` is an element in bytes, `lanes` the elements each register holds.
    VecStruct { is_load: bool, count: u32, e: u32, lanes: u32, q: bool, post: Option<PostIndex>, rn: u32, rt: u32 },
    /// `ld1r`: load one element and replicate it across the register.
    VecLd1r { q: bool, size: u32, post: Option<PostIndex>, rn: u32, rt: u32 },
    /// One lane of one to four registers: `ld1 {v0.b}[3], [x1]` and the stores and multi-structure
    /// forms of the same shape. `size` is the element width in bytes as a shift.
    VecLane { is_load: bool, nregs: u32, size: u32, index: u32, post: Option<PostIndex>, rn: u32, rt: u32 },
    /// Three-register, same-width integer or FP operation: `add v.4s`, `cmeq`, `umaxp`, ...
    VecThreeSame { q: bool, u: bool, size: u32, op: u32, rn: u32, rm: u32, rd: u32 },
    /// Two-register, same-width operation: `not`, `abs`, `cmeq ... #0`, `rev64`, `cnt`, ...
    VecTwoMisc { q: bool, u: bool, size: u32, op: u32, rn: u32, rd: u32 },
    /// One result across the lanes: `addv`, `smaxv`, `uminv`, `addp` to a scalar.
    VecAcross { q: bool, u: bool, size: u32, op: u32, rn: u32, rd: u32 },
    /// Narrowing and widening between element widths: `xtn`, `addhn`, `saddl`, ...
    VecThreeDiff { q: bool, u: bool, size: u32, op: u32, rn: u32, rm: u32, rd: u32 },
    /// Shift by immediate: `ushr`, `sshr`, `shl`, `sli`, `sri`, `shrn`, `sshll`, ...
    VecShiftImm { q: bool, u: bool, immh: u32, immb: u32, op: u32, rn: u32, rd: u32 },
    /// `dup`, `ins`, `umov`, `smov`: moves between the vector file and the general registers.
    VecCopy { q: bool, op: bool, imm5: u32, imm4: u32, rn: u32, rd: u32 },
    /// The scalar `dup Sd, Vn.T[index]`, which `mov d1, v0.d[1]` is: one lane of the source, and
    /// the rest of the register zero.
    FpDupElement { size: u32, index: u32, rn: u32, rd: u32 },
    /// A shift of the single 64-bit lane: `ushr d1, d0, #8` and the forms that accumulate or
    /// insert into the destination. `imm` is the encoded 64-based count.
    ScalarShift { u: bool, op: u32, imm: u32, rn: u32, rd: u32 },
    /// `movi` and `mvni`, whose result is a constant the translator can build.
    VecModImm { q: bool, op: bool, cmode: u32, imm8: u32, rd: u32 },
    /// `zip1/2`, `uzp1/2`, `trn1/2`.
    VecPermute { q: bool, size: u32, op: u32, rn: u32, rm: u32, rd: u32 },
    /// `ext`: concatenate two registers and take 16 bytes from a byte offset.
    VecExt { q: bool, imm4: u32, rn: u32, rm: u32, rd: u32 },
    /// `tbl`/`tbx`: byte permutation through a table of one to four registers.
    VecTbl { q: bool, tbx: bool, len: u32, rn: u32, rm: u32, rd: u32 },
    /// Scalar FP between the vector file and the general registers: `fmov`, `fcvtzs`, ...
    FpToGpr { sf: bool, signed: bool, size: u32, round: u32, fmov: bool, rn: u32, rd: u32 },
    GprToFp { sf: bool, signed: bool, size: u32, rmode: u32, opcode: u32, rn: u32, rd: u32 },
    /// `fcvtzs`/`fcvtzu` with a fraction-bit count: the fixed-point conversion a scaled cast uses.
    FpToGprFixed { sf: bool, unsigned: bool, size: u32, fbits: u32, rn: u32, rd: u32 },
    /// `scvtf`/`ucvtf` with a fraction-bit count, the other direction of the same conversion.
    FpFromIntFixed { sf: bool, unsigned: bool, size: u32, fbits: u32, rn: u32, rd: u32 },
    /// Scalar FP arithmetic on one register: `fmov`, `fabs`, `fneg`, `fsqrt`, `fcvt`, ...
    FpOneSource { size: u32, opcode: u32, rn: u32, rd: u32 },
    /// Scalar FP arithmetic on two registers: `fadd`, `fdiv`, `fmax`, ...
    FpTwoSource { size: u32, opcode: u32, rn: u32, rm: u32, rd: u32 },
    /// The two scalar FP forms that live in the three-same space: `fabd`, and `fmulx`.
    FpScalarSame { double: bool, multiply: bool, rn: u32, rm: u32, rd: u32 },
    /// `fcmp`/`fcmpe`: a comparison that writes NZCV instead of a register. `zero` compares the
    /// register against `+0.0` in the form that names no second register.
    FpCompare { size: u32, signaling: bool, zero: bool, rn: u32, rm: u32 },
    /// The fused multiply-add group: `fmadd`, `fmsub`, `fnmadd`, `fnmsub`.
    FpFused { size: u32, negate_product: bool, subtract: bool, rn: u32, rm: u32, ra: u32, rd: u32 },
    /// A scalar `fcmge`/`fcmgt`/`fcmle`/`fcmlt`/`fcmeq` against `#0.0`, which writes a mask into the
    /// destination lane rather than the condition flags. `op` is 0 eq, 1 ge, 2 gt, 3 le, 4 lt.
    FpCompareZero { double: bool, op: u32, integer: bool, rn: u32, rd: u32 },
    /// `fcsel`: a conditional select between two FP registers.
    FpCondSelect { size: u32, cond: u32, rn: u32, rm: u32, rd: u32 },
    /// Scalar FP with an immediate: `fmov s0, #1.0`.
    FpImm { size: u32, imm8: u32, rd: u32 },
    /// The scalar three-same group: a vector operation on the one 64-bit lane a `d` register names.
    ScalarThree { u: bool, size: u32, op: u32, rn: u32, rm: u32, rd: u32 },
    /// The scalar forms of the two-register group: `abs` and `neg` of the integer in one lane.
    ScalarTwoMisc { size: u32, negate: bool, rn: u32, rd: u32 },
    /// `fmov x0, v0.d[1]`: the high half of a vector register into a general one.
    VecHighToGpr { rn: u32, rd: u32 },
    /// `fmov v0.d[1], x0`: a general register into the high half of a vector one.
    GprToVecHigh { rn: u32, rd: u32 },
    /// `fccmp`: a comparison that defers to a condition, taking its flags from `nzcv` when the
    /// condition does not hold.
    FpCondCompare { size: u32, cond: u32, nzcv: u32, rn: u32, rm: u32 },
    /// `scvtf d0, d0`: the integer in a scalar FP register, converted to a floating point value of
    /// the same width.
    FpFromInt { double: bool, unsigned: bool, rn: u32, rd: u32 },
    /// `fcvtzu d0, d0`: the scalar in an FP register converted to an integer of its own width, left
    /// in the same register, which is the form a cast that stays in the vector file takes. `rmode`
    /// is how the value is rounded on the way, which is the only thing the family's members differ
    /// in: truncate, floor, ceiling, nearest or away.
    FpToInt { double: bool, unsigned: bool, rmode: u32, rn: u32, rd: u32 },
    /// Ordered and exclusive loads and stores. One thread, so an exclusive always succeeds.
    Atomic { is_load: bool, exclusive: bool, size: u32, rn: u32, rt: u32, rs: u32 },
    /// Compare and swap (`cas`/`casa`/`casl`): the loaded value goes back into Rs either way.
    AtomicCas { size: u32, rn: u32, rt: u32, rs: u32 },
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

/// The system registers the guest is allowed to read or write, resolved at decode time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysReg {
    Nzcv,
    Fpcr,
    Fpsr,
    CtrEl0,
    DczidEl0,
    MidrEl1,
    MpidrEl1,
    CntvctEl0,
    TpidrEl0,
    TpidrroEl0,
    /// Cache and feature identification: answered as the baseline AArch64 model.
    IdAa64Pfr0,
    IdAa64Isar0,
    Unknown,
}

fn sys_reg(o0: u32, op1: u32, crn: u32, crm: u32, op2: u32) -> SysReg {
    match (o0, op1, crn, crm, op2) {
        (3, 3, 4, 2, 0) => SysReg::Nzcv,
        (3, 3, 4, 4, 0) => SysReg::Fpcr,
        (3, 3, 4, 4, 1) => SysReg::Fpsr,
        (3, 3, 0, 0, 1) => SysReg::CtrEl0,
        (3, 3, 0, 0, 7) => SysReg::DczidEl0,
        (3, 0, 0, 0, 0) => SysReg::MidrEl1,
        (3, 0, 0, 0, 5) => SysReg::MpidrEl1,
        (3, 3, 14, 0, 2) => SysReg::CntvctEl0,
        (3, 3, 13, 0, 2) => SysReg::TpidrEl0,
        (3, 3, 13, 0, 3) => SysReg::TpidrroEl0,
        (3, 0, 0, 4, 0) => SysReg::IdAa64Pfr0,
        (3, 0, 0, 6, 0) => SysReg::IdAa64Isar0,
        _ => SysReg::Unknown,
    }
}

pub fn decode(w: u32) -> Insn {
    let sf = w >> 31 != 0;
    let rd = w & 31;
    let rn = (w >> 5) & 31;
    let rm = (w >> 16) & 31;
    let op0 = (w >> 25) & 0xf;

    // SIMD&FP loads and stores share their encoding space with the integer ones and are told apart
    // by bit 26; the multi-structure forms (ld1 and friends) sit in a corner of their own.
    match (w >> 24) & 0x3f {
        0b001100 | 0b001101 => return decode_simd_multi(w),
        _ => {}
    }
    let top3 = (w >> 27) & 7;
    // A vector load/store has bit 26 set and bit 25 clear; the vector data-processing encodings that
    // also have bit 26 set use bit 25 to say so.
    if (w >> 26) & 1 == 1 && (w >> 25) & 1 == 0 && (top3 == 0b111 || top3 == 0b101) {
        return decode_simd_loadstore(w);
    }

    match op0 {
        0b1000 | 0b1001 => decode_dp_imm(w, sf, rd, rn),
        0b1010 | 0b1011 => decode_branch_system(w, sf, rd, rn),
        0b0101 | 0b1101 => decode_dp_reg(w, sf, rd, rn, rm),
        0b0100 | 0b0110 | 0b1100 | 0b1110 => decode_loadstore(w, sf, rd, rn),
        // 0b0111 is vector data processing, 0b1111 is scalar floating point.
        0b0111 | 0b1111 => decode_simd_dp(w),
        _ => Insn::Undefined,
    }
}

fn decode_dp_imm(w: u32, sf: bool, rd: u32, rn: u32) -> Insn {
    // Bit 23 belongs to the class for add/subtract immediate (0), logical immediate and move wide,
    // but for ADR/ADRP it is the top bit of immhi, so a negative offset also lands on key 1.
    match (w >> 23) & 7 {
        0 | 1 => {
            let immlo = (w >> 29) & 3;
            let immhi = (w >> 5) & 0x7ffff;
            let imm = sx((immhi << 2) | immlo, 21);
            if sf {
                Insn::Adrp { rd, imm }
            } else {
                Insn::Adr { rd, imm }
            }
        }
        2 => Insn::AddSubImm {
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
        if w == 0xD400_0001 {
            return Insn::Svc;
        }
        if w & 0xFFE0_001F == 0xD420_0000 {
            return Insn::Brk; // brk #imm16
        }
        return Insn::Undefined;
    }
    if w >> 24 == 0xD5 {
        // HINT #imm and the DSB/DMB/ISB group: nothing to do in a single-threaded translated guest
        // that has no caches of its own.
        if w & 0xFFFF_F01F == 0xD503_201F || w & 0xFFFF_F09F == 0xD503_309F {
            return Insn::Hint;
        }
        if w & 0xFFC0_0000 == 0xD500_0000 {
            // Bits 21:20 pick the form: 11 reads a system register, 01 writes one, 00/10 are the
            // cache and TLB maintenance instructions, which have nothing to act on here.
            let o0 = 2 + ((w >> 19) & 1);
            let op1 = (w >> 16) & 7;
            let crn = (w >> 12) & 0xf;
            let crm = (w >> 8) & 0xf;
            let op2 = (w >> 5) & 7;
            let rt = w & 31;
            let reg = sys_reg(o0, op1, crn, crm, op2);
            return match (w >> 20) & 3 {
                3 => Insn::MrsSys { reg, rd: rt },
                1 => Insn::MsrSys { reg, rn: rt },
                _ => Insn::CacheOp,
            };
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
                (1, _) if sf => {
                    Insn::MulLong { signed: true, sub: o0 == 1, rm, ra: (w >> 10) & 31, rn, rd }
                }
                (5, _) if sf => {
                    Insn::MulLong { signed: false, sub: o0 == 1, rm, ra: (w >> 10) & 31, rn, rd }
                }
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
                // Bit 11 picks the form: set means an immediate in bits 20:16, clear means Rm there.
                let reg = (w >> 11) & 1 == 0;
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
            // op2 is two bits in two places: bit 30 says invert instead of select, bit 10 says
            // increment or negate the else operand.
            0b0100 => Insn::CondSelect {
                sf,
                op2: (((w >> 30) & 1) << 1) | ((w >> 10) & 1),
                rm,
                cond: (w >> 12) & 0xf,
                rn,
                rd,
            },
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
    // Load/store exclusive and ordered. Bit 23 clear means the exclusive pair form, bit 22 is the
    // direction, and bit 15 selects acquire/release over the plain exclusive.
    if (w >> 24) & 0x3f == 0b001000 && (w >> 21) & 7 == 0b111 {
        // Compare and swap, from the atomic memory operations group.
        let size = (w >> 30) & 3;
        if (w >> 12) & 7 != 0b111 {
            return Insn::Undefined;
        }
        return Insn::AtomicCas { size, rn: (w >> 5) & 31, rt: w & 31, rs: (w >> 16) & 31 };
    }
    if (w >> 24) & 0x3f == 0b001000 {
        let size = (w >> 30) & 3;
        let is_load = (w >> 22) & 1 != 0;
        // Bit 23 picks between the exclusive pair (LDXR/STXR and their acquire/release forms, which
        // differ only by bit 15) and LDAR/STLR, which is one ordered access with no monitor. Bit 21
        // is the o1 group, whose forms are not translated.
        if (w >> 21) & 1 == 1 {
            return Insn::Undefined;
        }
        let exclusive = (w >> 23) & 1 == 0;
        // A store's status register is Rs; a load leaves that field unused.
        return Insn::Atomic { is_load, exclusive, size, rn, rt: rd, rs: (w >> 16) & 31 };
    }
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
            // A prefetch is a hint: it has no architectural effect, and there is nothing for the
            // translation to do with it. Compilers emit it in front of the copy loops a hash
            // library walks, so leaving it undecoded stops real code.
            if size == 3 && opc == 2 {
                return Insn::Hint;
            }
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
            // opc 2 is `prfm` of a literal address, the hint form again.
            if v != 0 || opc > 2 {
                return Insn::Undefined;
            }
            if opc == 2 {
                return Insn::Hint;
            }
            let imm19 = (w >> 5) & 0x7ffff;
            Insn::Literal { sf: opc == 1, offset: sx(imm19, 19) << 2, rt: rd }
        }
        _ => Insn::Undefined,
    }
}

// ---------------------------------------------------------------- SIMD and floating point

/// `ldr`/`str`/`ldur`/`stur`/`ldp`/`stp` for the vector and FP registers.
fn decode_simd_loadstore(w: u32) -> Insn {
    let q = (w >> 30) & 1 != 0;
    let rn = (w >> 5) & 31;
    let rt = w & 31;
    let rm = (w >> 16) & 31;

    if (w >> 27) & 7 == 0b101 {
        // Pair: `opc 101 V 01 L imm7 Rt2 Rn Rt`, with bits 24:23 picking the addressing form.
        let opc = (w >> 30) & 3;
        let width = match opc {
            0 => 4,
            1 => 8,
            2 => 16,
            _ => return Insn::Undefined,
        };
        let is_load = (w >> 22) & 1 != 0;
        let mode = match (w >> 23) & 3 {
            0b01 => PairMode::PostIndex,
            0b10 => PairMode::Offset,
            0b11 => PairMode::PreIndex,
            _ => return Insn::Undefined,
        };
        let offset = sx(((w >> 15) & 0x7f) as u32, 7) * width as i64;
        return Insn::VecLoadStorePair { width, is_load, mode, offset, rn, rt, rt2: (w >> 10) & 31 };
    }

    // Single register. `size` is the access width; `opc` picks load or store, and its high bit
    // means "Q register", which is only valid with size 00.
    let size = (w >> 30) & 3;
    let opc = (w >> 22) & 3;
    let width = match opc {
        0b00 | 0b01 => 1 << size,
        0b10 | 0b11 if size == 0 => 16,
        _ => return Insn::Undefined,
    };
    let is_load = opc & 1 != 0;
    let _ = q;
    let imm12 = ((w >> 10) & 0xfff) as i64;
    match (w >> 24) & 3 {
        0b01 => Insn::VecLoadStore {
            width,
            is_load,
            mode: LsMode::Unsigned,
            offset: imm12 * width as i64,
            rn,
            rt,
            rm: 0,
            option: 0,
            scaled: false,
        },
        0b00 if (w >> 21) & 1 == 0 => {
            let offset = sx(((w >> 12) & 0x1ff) as u32, 9);
            let mode = match (w >> 10) & 3 {
                0b00 => LsMode::Unscaled,
                0b01 => LsMode::PostIndex,
                0b11 => LsMode::PreIndex,
                _ => return Insn::Undefined,
            };
            Insn::VecLoadStore { width, is_load, mode, offset, rn, rt, rm: 0, option: 0, scaled: false }
        }
        0b00 => Insn::VecLoadStore {
            width,
            is_load,
            mode: LsMode::Register,
            offset: 0,
            rn,
            rt,
            rm: (w >> 16) & 31,
            option: (w >> 13) & 7,
            scaled: (w >> 12) & 1 != 0,
        },
        _ => Insn::Undefined,
    }
}

/// The multi-structure loads and stores: `ld1`/`st1` and the replicating `ld1r`.
fn decode_simd_multi(w: u32) -> Insn {
    let q = (w >> 30) & 1 != 0;
    let rn = (w >> 5) & 31;
    let rt = w & 31;
    let rm = (w >> 16) & 31;
    let opcode = (w >> 12) & 0xf;
    let size = (w >> 10) & 3;
    let is_load = (w >> 22) & 1 != 0;
    let post_index = (w >> 23) & 1 != 0;

    if (w >> 24) & 0x3f == 0b001101 {
        // One lane of one to four registers, or the same element replicated into every lane. 001101
        // in bits 29:24 is what separates this group from the whole-register one at 001100. The
        // opcode's top two bits are 11 for the replicating forms, so they are the ones at 1100.
        let opcode = (w >> 12) & 0xf;
        if opcode >> 2 == 3 {
            let count = 1 + (opcode & 3);
            let size = (w >> 10) & 3;
            if count != 1 {
                return Insn::Undefined;
            }
            return Insn::VecLd1r {
                q,
                size,
                post: if post_index {
                    Some(if rm == 31 {
                        PostIndex::Imm(1 << size)
                    } else {
                        PostIndex::Reg(rm)
                    })
                } else {
                    None
                },
                rn,
                rt,
            };
        }
        if opcode >> 2 > 2 {
            return Insn::Undefined;
        }
        let nregs = 1 + 2 * ((opcode >> 1) & 1) + ((w >> 21) & 1);
        let size = match (opcode >> 2, (w >> 10) & 3) {
            (0, _) => 0,
            (1, _) => 1,
            (2, 0) => 2,
            (2, 1) => 3,
            _ => return Insn::Undefined,
        };
        let index = (((q as u32) << 3) | (((w >> 12) & 1) << 2) | ((w >> 10) & 3)) >> size;
        let rm_imm = (w >> 16) & 0x1f;
        return Insn::VecLane {
            is_load,
            nregs,
            size,
            index,
            post: if rm_imm == 0 {
                None
            } else if rm_imm == 0x1f {
                Some(PostIndex::Imm((1 << size) * nregs as i64))
            } else {
                Some(PostIndex::Reg(rm))
            },
            rn,
            rt,
        };
    }

    // `ld1`/`st1` of whole registers: opcode 0111 is one register, 1010 two, 0110 three, 0010 four.
    // `ld2`/`st2`, `ld3`/`st3` and `ld4`/`st4` are the same shape with their own opcodes, and they
    // interleave the registers in memory one element at a time.
    let bytes = if q { 16 } else { 8 };
    let count = match opcode {
        0b0111 => 1,
        0b1010 => 2,
        0b0110 => 3,
        0b0010 => 4,
        0b1000 => 2,
        0b0100 => 3,
        0b0000 => 4,
        _ => return Insn::Undefined, // the single-lane and replicating forms are a group of their own
    };
    let post = if post_index {
        Some(if rm == 31 {
            PostIndex::Imm(count as i64 * bytes as i64)
        } else {
            PostIndex::Reg(rm)
        })
    } else {
        None
    };
    if matches!(opcode, 0b1000 | 0b0100 | 0b0000) {
        let e = 1u32 << size;
        if e > bytes {
            return Insn::Undefined;
        }
        return Insn::VecStruct { is_load, count, e, lanes: bytes / e, q, post, rn, rt };
    }
    Insn::VecLd1 { is_load, count, q, post, rn, rt }
}

/// How a conversion to an integer rounds, which the two-bit field of the instruction names, except
/// for the two that ask for ties away from zero.
pub mod round {
    pub const ZERO: u32 = 0;
    pub const NEAREST: u32 = 1;
    pub const UP: u32 = 2;
    pub const DOWN: u32 = 3;
    pub const AWAY: u32 = 4;
}

/// Vector data processing (bit 28 clear) and scalar FP (bit 28 set).
fn decode_simd_dp(w: u32) -> Insn {
    if (w >> 28) & 1 == 1 {
        return decode_scalar_fp(w);
    }
    let q = (w >> 30) & 1 != 0;
    let u = (w >> 29) & 1 != 0;
    let rn = (w >> 5) & 31;
    let rd = w & 31;
    let rm = (w >> 16) & 31;
    let size = (w >> 22) & 3;
    let op = (w >> 11) & 0x1f;
    let bit10 = (w >> 10) & 1;
    let bit21 = (w >> 21) & 1;

    // `movi`/`mvni` and the shift-by-immediate group share bits 28:24, told apart by whether an
    // element width is present.
    if (w >> 24) & 0x1f == 0b01111 {
        if (w >> 19) & 0xf != 0 {
            return Insn::VecShiftImm {
                q,
                u,
                immh: (w >> 19) & 0xf,
                immb: (w >> 16) & 7,
                op,
                rn,
                rd,
            };
        }
        let imm8 = (((w >> 16) & 7) << 5 | ((w >> 5) & 0x1f)) as u32;
        return Insn::VecModImm { q, op: u, cmode: (w >> 12) & 0xf, imm8, rd };
    }

    if bit21 == 1 {
        if bit10 == 1 {
            return Insn::VecThreeSame { q, u, size, op, rn, rm, rd };
        }
        // The two-register and across-the-lanes forms set bit 11, where the opcode of a
        // three-different form never does, and put a marker in bits 21:17 where those put Rm.
        if (w >> 11) & 1 == 1 {
            return match (w >> 17) & 0x1f {
                0b11000 => Insn::VecAcross { q, u, size, op: (w >> 12) & 0x1f, rn, rd },
                _ => Insn::VecTwoMisc { q, u, size, op: (w >> 12) & 0x1f, rn, rd },
            };
        }
        return Insn::VecThreeDiff { q, u, size, op, rn, rm, rd };
    }
    if bit10 == 1 {
        return Insn::VecCopy { q, op: u, imm5: (w >> 16) & 0x1f, imm4: (w >> 11) & 0xf, rn, rd };
    }
    // `ext` shares this space with the permutes and with the table forms: it is the only instruction
    // here with bit 15 clear and U set, and its imm4 occupies bits 14:11.
    if u && (w >> 15) & 1 == 0 {
        return Insn::VecExt { q, imm4: (w >> 11) & 0xf, rn, rm, rd };
    }
    if (w >> 11) & 1 == 1 {
        return Insn::VecPermute { q, size, op, rn, rm, rd };
    }
    Insn::VecTbl { q, tbx: (w >> 12) & 1 != 0, len: (w >> 13) & 3, rn, rm, rd }
}

/// Scalar floating point: the one- and two-source arithmetic, comparisons, selects, conversions and
/// the immediate form.
fn decode_scalar_fp(w: u32) -> Insn {
    // The scalar shift by immediate, which shares the vector shifts' encoding with bit 28 set. The
    // opcode is bits 15:10 and the count is seven bits at 22:16, counted from twice the lane width
    // for a right shift and from the width itself for a left one. `sha512` writes a length into a
    // register one byte at a time with these.
    if (w & 0xff800000) == 0x5f000000 || (w & 0xff800000) == 0x7f000000 {
        let immh = (w >> 19) & 0xf;
        if immh < 0b1000 {
            return Insn::Undefined; // the narrow scalar forms travel with the vector ones
        }
        return Insn::ScalarShift {
            u: (w >> 29) & 1 != 0,
            op: (w >> 10) & 0x3f,
            imm: (immh << 3) | ((w >> 16) & 7),
            rn: (w >> 5) & 31,
            rd: w & 31,
        };
    }

    // The scalar copy: one element of a register duplicated into the lowest lane, with the rest of
    // the register zero. `mov d1, v0.d[1]` is how a compiler moves a 128-bit register's high half.
    if (w & 0xffe0fc00) == 0x5e000400 {
        let imm5 = (w >> 16) & 0x1f;
        let size = imm5.trailing_zeros();
        return Insn::FpDupElement { size, index: imm5 >> (size + 1), rn: (w >> 5) & 31, rd: w & 31 };
    }

    let sf = (w >> 31) & 1 != 0;
    let size = (w >> 22) & 3;
    let rn = (w >> 5) & 31;
    let rd = w & 31;
    let rm = (w >> 16) & 31;
    let rmode = (w >> 19) & 3;
    let opcode = (w >> 12) & 0x3f;

    // Between FP and the general registers. Bit 21 is set, bits 15:10 are zero, and bits 20:16 name
    // the operation: 6 and 24..31 take their result from an FP register, 7 and 2..3 from a general
    // one. The direction is a property of those codes, not of a direction bit.
    if (w >> 21) & 1 == 1 && (w >> 10) & 0x3f == 0 {
        let code = (w >> 16) & 0x1f;
        let opcode = code & 7;
        // The top two bits of the field are the rounding mode: nearest, towards +inf, towards
        // -inf, towards zero. Opcode 100 and 101 name ties away from zero, which no mode does.
        let round = match opcode {
            0b100 | 0b101 => round::AWAY,
            _ => match code >> 3 {
                0 => round::NEAREST,
                1 => round::UP,
                2 => round::DOWN,
                _ => round::ZERO,
            },
        };
        // The two that move the high half of a `d` register, which only the 64-bit forms have.
        if sf {
            match code {
                14 => return Insn::VecHighToGpr { rn, rd },
                15 => return Insn::GprToVecHigh { rn, rd },
                _ => {}
            }
        }
        return match code {
            6 => Insn::FpToGpr { sf, signed: false, size, round: round::ZERO, fmov: true, rn, rd },
            7 | 2..=3 => Insn::GprToFp { sf, signed: code != 7 && code == 2, size, rmode, opcode: code, rn, rd },
            _ => match opcode {
                0b000 | 0b001 | 0b100 | 0b101 => Insn::FpToGpr {
                    sf,
                    signed: opcode & 1 == 0,
                    size,
                    round,
                    fmov: false,
                    rn,
                    rd,
                },
                _ => Insn::Undefined,
            },
        };
    }

    // Scalar FP compare against zero. Bit 23 is set where the other scalar forms of this shape leave
    // it clear, so the type is bit 22, and the four bits at 15:12 pick which comparison it is: the
    // two that are not `gt` differ in the U bit as well. Bits 11:10 are the marker `10`, which is
    // what tells these from the register forms of the same comparisons and from `cmtst`.
    if (w >> 23) & 1 == 1 && (w >> 16) & 0x1f == 0 && (w >> 10) & 3 == 0b10 {
        // Comparisons against zero come in the same shape twice: bit 14 set is the floating point
        // family, clear is the integer one on the 64-bit lane.
        let u = (w >> 29) & 1 == 1;
        let integer = (w >> 14) & 1 == 0;
        let base = if integer { 0b1000 } else { 0b1100 };
        let op = match ((w >> 12) & 0xf, u) {
            (b, true) if b == base => Some(1),
            (b, false) if b == base => Some(2),
            (b, true) if b == base + 1 => Some(3),
            (b, false) if b == base + 1 => Some(0),
            (b, false) if b == base + 2 => Some(4),
            _ => None,
        };
        if let Some(op) = op {
            return Insn::FpCompareZero {
                double: (w >> 22) & 1 == 1,
                op,
                integer,
                rn,
                rd,
            };
        }
    }

    // The same group the other way round: an FP scalar converted to an integer of its own width, in
    // the register it came from. Bits 21:16 are the marker and bits 15:10 pick the rounding, in
    // pairs that bit 23 splits: `n`/`p`, `m`/`z` and `a` alone. The marker is not enough on its own,
    // because `fsqrt` and `fabs` carry it with an opcode of 110000.
    if (w >> 16) & 0x3f == 0b100001 {
        let second = (w >> 23) & 1 == 1;
        let rmode = match ((w >> 10) & 0x3f, second) {
            (0b101010, false) => Some(round::NEAREST),
            (0b101010, true) => Some(round::UP),
            (0b101110, false) => Some(round::DOWN),
            (0b101110, true) => Some(round::ZERO),
            (0b110010, false) => Some(round::AWAY),
            _ => None,
        };
        if let Some(rmode) = rmode {
            return Insn::FpToInt {
                double: (w >> 22) & 1 == 1,
                unsigned: (w >> 29) & 1 == 1,
                rmode,
                rn,
                rd,
            };
        }
    }

    // An integer in a scalar FP register converted to floating point. Bits 15:10 are 110110, where
    // `fcsel` puts a condition in 15:12 and 11 in 11:10, so the whole field is what tells them
    // apart - and the class bits have to be part of the pattern too, because the pairwise pair at
    // 7e70d820 shares the field without being one.
    if w & 0xdf3ffc00 == 0x5e21d800 {
        return Insn::FpFromInt {
            double: (w >> 22) & 1 == 1,
            unsigned: (w >> 29) & 1 == 1,
            rn,
            rd,
        };
    }

    // The fused multiply-add group: bits 28:24 are 11111 and the rounding-mode field holds the two
    // negate bits. Bit 21 is the first and bit 15 the second.
    if (w >> 24) & 0x1f == 0b11111 {
        if size > 1 {
            return Insn::Undefined;
        }
        return Insn::FpFused {
            size,
            negate_product: (w >> 21) & 1 != 0,
            subtract: (w >> 15) & 1 != 0,
            rn,
            rm,
            ra: (w >> 10) & 31,
            rd,
        };
    }

    // The same conversion the other way: an integer scaled by a power of two becomes a float. Bit 16
    // is the sign, bit 31 the width of the integer, and the count is 64 minus the fraction bits.
    if w & 0x7f3f0000 == 0x1e020000 || w & 0x7f3f0000 == 0x1e030000 {
        return Insn::FpFromIntFixed {
            sf,
            unsigned: (w >> 16) & 1 == 1,
            size: (w >> 22) & 3,
            fbits: 64 - ((w >> 10) & 0x3f),
            rn,
            rd,
        };
    }

    // The two scalar FP forms of the three-same group, `fabd` and `fmulx`: bit 23 is which of them
    // it is, and bit 22 is the type, as in the vector forms they mirror.
    if w & 0xffa0fc00 == 0x7ea0d400 || w & 0xffa0fc00 == 0x5e20dc00 {
        return Insn::FpScalarSame {
            double: (w >> 22) & 1 == 1,
            multiply: (w >> 23) & 1 == 0,
            rn,
            rm,
            rd,
        };
    }

    // The conversions with a fraction-bit count: bit 21 is clear, the rounding mode bits say
    // truncate, and the count is stored as 64 minus the fraction bits.
    if (w >> 21) & 1 == 0 && (w >> 19) & 3 == 3 && (w >> 16) & 7 <= 1 {
        return Insn::FpToGprFixed {
            sf,
            unsigned: (w >> 16) & 1 == 1,
            size,
            fbits: 64 - ((w >> 10) & 0x3f),
            rn,
            rd,
        };
    }

    // FP immediate: `fmov s0, #const`. The immediate is bits 20:13 and bits 12:10 are the marker.
    if (w >> 21) & 1 == 1 && (w >> 10) & 7 == 0b100 && (w >> 5) & 0x1f == 0 {
        return Insn::FpImm { size, imm8: (w >> 13) & 0xff, rd };
    }

    // Everything else in the FP data-processing space, whose marker is 0011110 in bits 30:24 (bit
    // 30 is what separates it from the scalar pairwise group at 1011110), told apart by bits 11:10.
    if (w >> 24) & 0x7f == 0b0011110 && (w >> 21) & 1 == 1 {
        return match (w >> 10) & 3 {
            // fcmp/fcmpe write NZCV: bits 15:10 are 001000, bit 4 signals and bit 3 asks for the
            // form that compares against zero, whose second register is the marker 01000.
            0b00 if (w >> 10) & 0x1f == 0b01000 => {
                let zero = (w >> 3) & 1 != 0;
                if zero && (w >> 16) & 0x1f != 0 {
                    return Insn::Undefined;
                }
                Insn::FpCompare { size, signaling: (w >> 4) & 1 != 0, zero, rn, rm }
            }
            // One source shares bits 11:10 with the comparisons; its marker is 10000 at 14:10,
            // because bit 15 is the low bit of the opcode.
            0b00 if (w >> 10) & 0x1f == 0b10000 => {
                Insn::FpOneSource { size, opcode: (w >> 15) & 0x3f, rn, rd }
            }
            // fccmp: the comparison the condition defers to, with bits 15:12 the condition and
            // bits 3:0 the flags to take instead. Bit 4 is the signaling form, which differs only
            // in what it does about a quiet NaN and which this kernel does not raise.
            0b01 => Insn::FpCondCompare {
                size,
                cond: (w >> 12) & 0xf,
                nzcv: w & 0xf,
                rn,
                rm,
            },
            // fcsel: `cond` sits where the two-source opcode would be.
            0b11 => {
                Insn::FpCondSelect { size, cond: (w >> 12) & 0xf, rn, rm, rd }
            }
            0b10 => Insn::FpTwoSource { size, opcode: (w >> 12) & 0xf, rn, rm, rd },
            _ => Insn::Undefined,
        };
    }

    // Scalar `abs` and `neg` of the integer in one lane: the two-register group with bit 28 set,
    // where bit 23 stays clear and the U bit names the sign operation.
    if w & 0xff3ffc00 == 0x5e20b800 || w & 0xff3ffc00 == 0x7e20b800 {
        return Insn::ScalarTwoMisc { size: (w >> 22) & 3, negate: (w >> 29) & 1 == 1, rn, rd };
    }

    // The scalar three-same group shares this space with the scalar two-register one, and its
    // integer forms are the vector operations on the single 64-bit lane a `d` register names: `add
    // d0, d1, d2` is the 64-bit add that perl's own number code reaches for.
    if w & 0xffe0fc00 == 0x5ee08400 || w & 0xffe0fc00 == 0x7ee08400 {
        return Insn::ScalarThree {
            u: (w >> 29) & 1 != 0,
            size: 3,
            op: 0b10000,
            rn,
            rm,
            rd,
        };
    }

    // The scalar forms of the across-lane reductions live in this space: `addp d2, v0.2d` and
    // friends carry the same 11000 marker as the vector form and reduce the whole register.
    if (w >> 17) & 0x1f == 0b11000 {
        return Insn::VecAcross { q: true, u: (w >> 29) & 1 != 0, size, op: (w >> 12) & 0x1f, rn, rd };
    }

    // One source: bits 20:15 name the operation and bits 15:10 are the marker `10000`.
    Insn::FpOneSource { size, opcode: (w >> 15) & 0x3f, rn, rd }
}
