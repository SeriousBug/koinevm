//! Minimal WebAssembly binary encoder. Only the subset the translator needs.

pub const I32: u8 = 0x7f;
pub const I64: u8 = 0x7e;
pub const F32: u8 = 0x7d;
pub const F64: u8 = 0x7c;
pub const V128: u8 = 0x7b;

pub fn uleb(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

pub fn sleb(out: &mut Vec<u8>, mut v: i64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        let sign = b & 0x40 != 0;
        if (v == 0 && !sign) || (v == -1 && sign) {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

pub mod op {
    pub const UNREACHABLE: u8 = 0x00;
    pub const BLOCK: u8 = 0x02;
    pub const LOOP: u8 = 0x03;
    pub const IF: u8 = 0x04;
    pub const ELSE: u8 = 0x05;
    pub const END: u8 = 0x0b;
    pub const BR: u8 = 0x0c;
    pub const BR_IF: u8 = 0x0d;
    pub const BR_TABLE: u8 = 0x0e;
    pub const RETURN: u8 = 0x0f;
    pub const CALL: u8 = 0x10;
    pub const CALL_INDIRECT: u8 = 0x11;
    pub const DROP: u8 = 0x1a;
    pub const SELECT: u8 = 0x1b;
    pub const LOCAL_GET: u8 = 0x20;
    pub const LOCAL_SET: u8 = 0x21;
    pub const LOCAL_TEE: u8 = 0x22;
    pub const I32_LOAD: u8 = 0x28;
    pub const I64_LOAD: u8 = 0x29;
    pub const I32_LOAD8_S: u8 = 0x2c;
    pub const I32_LOAD8_U: u8 = 0x2d;
    pub const I32_LOAD16_S: u8 = 0x2e;
    pub const I32_LOAD16_U: u8 = 0x2f;
    pub const I64_LOAD8_S: u8 = 0x30;
    pub const I64_LOAD8_U: u8 = 0x31;
    pub const I64_LOAD16_S: u8 = 0x32;
    pub const I64_LOAD16_U: u8 = 0x33;
    pub const I64_LOAD32_S: u8 = 0x34;
    pub const I64_LOAD32_U: u8 = 0x35;
    pub const I32_STORE: u8 = 0x36;
    pub const I64_STORE: u8 = 0x37;
    pub const I32_STORE8: u8 = 0x3a;
    pub const I32_STORE16: u8 = 0x3b;
    pub const I64_STORE8: u8 = 0x3c;
    pub const I64_STORE16: u8 = 0x3d;
    pub const I64_STORE32: u8 = 0x3e;
    pub const I32_CONST: u8 = 0x41;
    pub const I64_CONST: u8 = 0x42;
    pub const F32_CONST: u8 = 0x43;
    pub const F64_CONST: u8 = 0x44;

    pub const I32_EQZ: u8 = 0x45;
    pub const I32_EQ: u8 = 0x46;
    pub const I32_NE: u8 = 0x47;
    pub const I32_LT_S: u8 = 0x48;
    pub const I32_LT_U: u8 = 0x49;
    pub const I32_GT_S: u8 = 0x4a;
    pub const I32_GT_U: u8 = 0x4b;
    pub const I32_LE_S: u8 = 0x4c;
    pub const I32_LE_U: u8 = 0x4d;
    pub const I32_GE_S: u8 = 0x4e;
    pub const I32_GE_U: u8 = 0x4f;

    pub const I64_EQZ: u8 = 0x50;
    pub const I64_EQ: u8 = 0x51;
    pub const I64_NE: u8 = 0x52;
    pub const I64_LT_S: u8 = 0x53;
    pub const I64_LT_U: u8 = 0x54;
    pub const I64_GT_S: u8 = 0x55;
    pub const I64_GT_U: u8 = 0x56;
    pub const I64_LE_S: u8 = 0x57;
    pub const I64_LE_U: u8 = 0x58;
    pub const I64_GE_S: u8 = 0x59;
    pub const I64_GE_U: u8 = 0x5a;

    pub const F32_EQ: u8 = 0x5b;
    pub const F32_NE: u8 = 0x5c;
    pub const F32_LT: u8 = 0x5d;
    pub const F32_GT: u8 = 0x5e;
    pub const F32_LE: u8 = 0x5f;
    pub const F32_GE: u8 = 0x60;
    pub const F64_EQ: u8 = 0x61;
    pub const F64_NE: u8 = 0x62;
    pub const F64_LT: u8 = 0x63;
    pub const F64_GT: u8 = 0x64;
    pub const F64_LE: u8 = 0x65;
    pub const F64_GE: u8 = 0x66;

    pub const F32_ABS: u8 = 0x8b;
    pub const F32_NEG: u8 = 0x8c;
    pub const F32_CEIL: u8 = 0x8d;
    pub const F32_FLOOR: u8 = 0x8e;
    pub const F32_TRUNC: u8 = 0x8f;
    pub const F32_NEAREST: u8 = 0x90;
    pub const F32_SQRT: u8 = 0x91;
    pub const F32_ADD: u8 = 0x92;
    pub const F32_SUB: u8 = 0x93;
    pub const F32_MUL: u8 = 0x94;
    pub const F32_DIV: u8 = 0x95;
    pub const F32_MIN: u8 = 0x96;
    pub const F32_MAX: u8 = 0x97;
    pub const F32_COPYSIGN: u8 = 0x98;
    pub const F64_ABS: u8 = 0x99;
    pub const F64_NEG: u8 = 0x9a;
    pub const F64_CEIL: u8 = 0x9b;
    pub const F64_FLOOR: u8 = 0x9c;
    pub const F64_TRUNC: u8 = 0x9d;
    pub const F64_NEAREST: u8 = 0x9e;
    pub const F64_SQRT: u8 = 0x9f;
    pub const F64_ADD: u8 = 0xa0;
    pub const F64_SUB: u8 = 0xa1;
    pub const F64_MUL: u8 = 0xa2;
    pub const F64_DIV: u8 = 0xa3;
    pub const F64_MIN: u8 = 0xa4;
    pub const F64_MAX: u8 = 0xa5;
    pub const F64_COPYSIGN: u8 = 0xa6;

    pub const I32_CLZ: u8 = 0x67;
    pub const I32_CTZ: u8 = 0x68;
    pub const I32_POPCNT: u8 = 0x69;
    pub const I32_EXTEND8_S: u8 = 0xc0;
    pub const I32_EXTEND16_S: u8 = 0xc1;
    pub const I32_ADD: u8 = 0x6a;
    pub const I32_SUB: u8 = 0x6b;
    pub const I32_MUL: u8 = 0x6c;
    pub const I32_DIV_S: u8 = 0x6d;
    pub const I32_DIV_U: u8 = 0x6e;
    pub const I32_AND: u8 = 0x71;
    pub const I32_OR: u8 = 0x72;
    pub const I32_XOR: u8 = 0x73;
    pub const I32_SHL: u8 = 0x74;
    pub const I32_SHR_S: u8 = 0x75;
    pub const I32_SHR_U: u8 = 0x76;
    pub const I32_ROTL: u8 = 0x77;
    pub const I32_ROTR: u8 = 0x78;

    pub const I64_CLZ: u8 = 0x79;
    pub const I64_CTZ: u8 = 0x7a;
    pub const I64_POPCNT: u8 = 0x7b;
    pub const I64_ADD: u8 = 0x7c;
    pub const I64_SUB: u8 = 0x7d;
    pub const I64_MUL: u8 = 0x7e;
    pub const I64_DIV_S: u8 = 0x7f;
    pub const I64_DIV_U: u8 = 0x80;
    pub const I64_AND: u8 = 0x83;
    pub const I64_OR: u8 = 0x84;
    pub const I64_XOR: u8 = 0x85;
    pub const I64_SHL: u8 = 0x86;
    pub const I64_SHR_S: u8 = 0x87;
    pub const I64_SHR_U: u8 = 0x88;
    pub const I64_ROTL: u8 = 0x89;
    pub const I64_ROTR: u8 = 0x8a;

    pub const I32_WRAP_I64: u8 = 0xa7;
    pub const F32_CONVERT_I32_S: u8 = 0xb2;
    pub const F32_CONVERT_I32_U: u8 = 0xb3;
    pub const F32_CONVERT_I64_S: u8 = 0xb4;
    pub const F32_CONVERT_I64_U: u8 = 0xb5;
    pub const F32_DEMOTE_F64: u8 = 0xb6;
    pub const F64_CONVERT_I32_S: u8 = 0xb7;
    pub const F64_CONVERT_I32_U: u8 = 0xb8;
    pub const F64_CONVERT_I64_S: u8 = 0xb9;
    pub const F64_CONVERT_I64_U: u8 = 0xba;
    pub const F64_PROMOTE_F32: u8 = 0xbb;
    pub const I32_REINTERPRET_F32: u8 = 0xbc;
    pub const I64_REINTERPRET_F64: u8 = 0xbd;
    pub const F32_REINTERPRET_I32: u8 = 0xbe;
    pub const F64_REINTERPRET_I64: u8 = 0xbf;
    pub const I64_EXTEND_I32_S: u8 = 0xac;
    pub const I64_EXTEND_I32_U: u8 = 0xad;
    pub const I64_EXTEND8_S: u8 = 0xc2;
    pub const I64_EXTEND16_S: u8 = 0xc3;
    pub const I64_EXTEND32_S: u8 = 0xc4;
}

/// Nontrapping float-to-integer conversions and other `0xfc`-prefixed opcodes.
pub mod sat {
    pub const I32_TRUNC_SAT_F32_S: u32 = 0x00;
    pub const I32_TRUNC_SAT_F32_U: u32 = 0x01;
    pub const I32_TRUNC_SAT_F64_S: u32 = 0x02;
    pub const I32_TRUNC_SAT_F64_U: u32 = 0x03;
    pub const I64_TRUNC_SAT_F32_S: u32 = 0x04;
    pub const I64_TRUNC_SAT_F32_U: u32 = 0x05;
    pub const I64_TRUNC_SAT_F64_S: u32 = 0x06;
    pub const I64_TRUNC_SAT_F64_U: u32 = 0x07;
}

/// WebAssembly SIMD opcodes (`0xfd` prefix), as numbered by the SIMD proposal's binary format.
pub mod simd {
    pub const V128_LOAD: u32 = 0x00;
    pub const V128_LOAD8X8_S: u32 = 0x01;
    pub const V128_LOAD8X8_U: u32 = 0x02;
    pub const V128_LOAD16X4_S: u32 = 0x03;
    pub const V128_LOAD16X4_U: u32 = 0x04;
    pub const V128_LOAD32X2_S: u32 = 0x05;
    pub const V128_LOAD32X2_U: u32 = 0x06;
    pub const V128_LOAD8_SPLAT: u32 = 0x07;
    pub const V128_LOAD16_SPLAT: u32 = 0x08;
    pub const V128_LOAD32_SPLAT: u32 = 0x09;
    pub const V128_LOAD64_SPLAT: u32 = 0x0a;
    pub const V128_STORE: u32 = 0x0b;
    pub const V128_CONST: u32 = 0x0c;
    pub const I8X16_SHUFFLE: u32 = 0x0d;
    pub const I8X16_SWIZZLE: u32 = 0x0e;
    pub const I8X16_SPLAT: u32 = 0x0f;
    pub const I16X8_SPLAT: u32 = 0x10;
    pub const I32X4_SPLAT: u32 = 0x11;
    pub const I64X2_SPLAT: u32 = 0x12;
    pub const F32X4_SPLAT: u32 = 0x13;
    pub const F64X2_SPLAT: u32 = 0x14;
    pub const I8X16_EXTRACT_LANE_S: u32 = 0x15;
    pub const I8X16_EXTRACT_LANE_U: u32 = 0x16;
    pub const I8X16_REPLACE_LANE: u32 = 0x17;
    pub const I16X8_EXTRACT_LANE_S: u32 = 0x18;
    pub const I16X8_EXTRACT_LANE_U: u32 = 0x19;
    pub const I16X8_REPLACE_LANE: u32 = 0x1a;
    pub const I32X4_EXTRACT_LANE: u32 = 0x1b;
    pub const I32X4_REPLACE_LANE: u32 = 0x1c;
    pub const I64X2_EXTRACT_LANE: u32 = 0x1d;
    pub const I64X2_REPLACE_LANE: u32 = 0x1e;
    pub const F32X4_EXTRACT_LANE: u32 = 0x1f;
    pub const F32X4_REPLACE_LANE: u32 = 0x20;
    pub const F64X2_EXTRACT_LANE: u32 = 0x21;
    pub const F64X2_REPLACE_LANE: u32 = 0x22;
    pub const I8X16_EQ: u32 = 0x23;
    pub const I8X16_NE: u32 = 0x24;
    pub const I8X16_LT_S: u32 = 0x25;
    pub const I8X16_LT_U: u32 = 0x26;
    pub const I8X16_GT_S: u32 = 0x27;
    pub const I8X16_GT_U: u32 = 0x28;
    pub const I8X16_LE_S: u32 = 0x29;
    pub const I8X16_GE_S: u32 = 0x2b;
    pub const I8X16_GE_U: u32 = 0x2c;
    pub const I16X8_EQ: u32 = 0x2d;
    pub const I16X8_NE: u32 = 0x2e;
    pub const I16X8_LT_S: u32 = 0x2f;
    pub const I16X8_GT_S: u32 = 0x31;
    pub const I16X8_GT_U: u32 = 0x32;
    pub const I16X8_LE_S: u32 = 0x33;
    pub const I16X8_GE_S: u32 = 0x35;
    pub const I16X8_GE_U: u32 = 0x36;
    pub const I32X4_EQ: u32 = 0x37;
    pub const I32X4_NE: u32 = 0x38;
    pub const I32X4_LT_S: u32 = 0x39;
    pub const I32X4_GT_S: u32 = 0x3b;
    pub const I32X4_GT_U: u32 = 0x3c;
    pub const I32X4_LE_S: u32 = 0x3d;
    pub const I32X4_GE_S: u32 = 0x3f;
    pub const I32X4_GE_U: u32 = 0x40;
    pub const F32X4_EQ: u32 = 0x41;
    pub const F32X4_NE: u32 = 0x42;
    pub const F32X4_LT: u32 = 0x43;
    pub const F32X4_GT: u32 = 0x44;
    pub const F32X4_LE: u32 = 0x45;
    pub const F32X4_GE: u32 = 0x46;
    pub const F64X2_EQ: u32 = 0x47;
    pub const F64X2_NE: u32 = 0x48;
    pub const F64X2_LT: u32 = 0x49;
    pub const F64X2_GT: u32 = 0x4a;
    pub const F64X2_LE: u32 = 0x4b;
    pub const F64X2_GE: u32 = 0x4c;
    pub const V128_NOT: u32 = 0x4d;
    pub const V128_AND: u32 = 0x4e;
    pub const V128_ANDNOT: u32 = 0x4f;
    pub const V128_OR: u32 = 0x50;
    pub const V128_XOR: u32 = 0x51;
    pub const V128_BITSELECT: u32 = 0x52;
    pub const V128_ANY_TRUE: u32 = 0x53;
    pub const V128_LOAD8_LANE: u32 = 0x54;
    pub const V128_LOAD16_LANE: u32 = 0x55;
    pub const V128_LOAD32_LANE: u32 = 0x56;
    pub const V128_LOAD64_LANE: u32 = 0x57;
    pub const V128_STORE8_LANE: u32 = 0x58;
    pub const V128_STORE16_LANE: u32 = 0x59;
    pub const V128_STORE32_LANE: u32 = 0x5a;
    pub const V128_STORE64_LANE: u32 = 0x5b;
    pub const V128_LOAD32_ZERO: u32 = 0x5c;
    pub const V128_LOAD64_ZERO: u32 = 0x5d;
    pub const F32X4_DEMOTE_F64X2_ZERO: u32 = 0x5e;
    pub const F64X2_PROMOTE_LOW_F32X4: u32 = 0x5f;
    pub const I8X16_ABS: u32 = 0x60;
    pub const I8X16_NEG: u32 = 0x61;
    pub const I8X16_POPCNT: u32 = 0x62;
    pub const I8X16_ALL_TRUE: u32 = 0x63;
    pub const I8X16_BITMASK: u32 = 0x64;
    pub const I8X16_NARROW_I16X8_S: u32 = 0x65;
    pub const I8X16_NARROW_I16X8_U: u32 = 0x66;
    pub const F32X4_CEIL: u32 = 0x67;
    pub const F32X4_FLOOR: u32 = 0x68;
    pub const F32X4_TRUNC: u32 = 0x69;
    pub const F32X4_NEAREST: u32 = 0x6a;
    pub const F64X2_CEIL: u32 = 0x74;
    pub const F64X2_FLOOR: u32 = 0x75;
    pub const F64X2_TRUNC: u32 = 0x7a;
    pub const F64X2_NEAREST: u32 = 0x94;
    pub const I8X16_SHL: u32 = 0x6b;
    pub const I8X16_SHR_S: u32 = 0x6c;
    pub const I8X16_SHR_U: u32 = 0x6d;
    pub const I8X16_ADD: u32 = 0x6e;
    pub const I8X16_SUB: u32 = 0x71;
    pub const I8X16_MIN_S: u32 = 0x76;
    pub const I8X16_MIN_U: u32 = 0x77;
    pub const I8X16_MAX_S: u32 = 0x78;
    pub const I8X16_MAX_U: u32 = 0x79;
    pub const I16X8_EXTADD_PAIRWISE_I8X16_S: u32 = 0x7c;
    pub const I16X8_EXTADD_PAIRWISE_I8X16_U: u32 = 0x7d;
    pub const I32X4_EXTADD_PAIRWISE_I16X8_S: u32 = 0x7e;
    pub const I32X4_EXTADD_PAIRWISE_I16X8_U: u32 = 0x7f;
    pub const I16X8_ABS: u32 = 0x80;
    pub const I16X8_NEG: u32 = 0x81;
    pub const I16X8_ALL_TRUE: u32 = 0x83;
    pub const I16X8_BITMASK: u32 = 0x84;
    pub const I16X8_NARROW_I32X4_S: u32 = 0x85;
    pub const I16X8_NARROW_I32X4_U: u32 = 0x86;
    pub const I16X8_EXTEND_LOW_I8X16_S: u32 = 0x87;
    pub const I16X8_EXTEND_HIGH_I8X16_S: u32 = 0x88;
    pub const I16X8_EXTEND_LOW_I8X16_U: u32 = 0x89;
    pub const I16X8_EXTEND_HIGH_I8X16_U: u32 = 0x8a;
    pub const I16X8_SHL: u32 = 0x8b;
    pub const I16X8_SHR_S: u32 = 0x8c;
    pub const I16X8_SHR_U: u32 = 0x8d;
    pub const I16X8_ADD: u32 = 0x8e;
    pub const I16X8_SUB: u32 = 0x91;
    pub const I16X8_MUL: u32 = 0x95;
    pub const I16X8_MIN_S: u32 = 0x96;
    pub const I16X8_MIN_U: u32 = 0x97;
    pub const I16X8_MAX_S: u32 = 0x98;
    pub const I16X8_MAX_U: u32 = 0x99;
    pub const I32X4_ABS: u32 = 0xa0;
    pub const I32X4_NEG: u32 = 0xa1;
    pub const I32X4_ALL_TRUE: u32 = 0xa3;
    pub const I32X4_BITMASK: u32 = 0xa4;
    pub const I32X4_EXTEND_LOW_I16X8_S: u32 = 0xa7;
    pub const I32X4_EXTEND_HIGH_I16X8_S: u32 = 0xa8;
    pub const I32X4_EXTEND_LOW_I16X8_U: u32 = 0xa9;
    pub const I32X4_EXTEND_HIGH_I16X8_U: u32 = 0xaa;
    pub const I32X4_SHL: u32 = 0xab;
    pub const I32X4_SHR_S: u32 = 0xac;
    pub const I32X4_SHR_U: u32 = 0xad;
    pub const I32X4_ADD: u32 = 0xae;
    pub const I32X4_SUB: u32 = 0xb1;
    pub const I32X4_MUL: u32 = 0xb5;
    pub const I32X4_MIN_S: u32 = 0xb6;
    pub const I32X4_MIN_U: u32 = 0xb7;
    pub const I32X4_MAX_S: u32 = 0xb8;
    pub const I32X4_MAX_U: u32 = 0xb9;
    pub const I32X4_EXTMUL_LOW_I16X8_S: u32 = 0xbc;
    pub const I32X4_EXTMUL_HIGH_I16X8_S: u32 = 0xbd;
    pub const I32X4_EXTMUL_LOW_I16X8_U: u32 = 0xbe;
    pub const I32X4_EXTMUL_HIGH_I16X8_U: u32 = 0xbf;
    pub const I64X2_ABS: u32 = 0xc0;
    pub const I64X2_NEG: u32 = 0xc1;
    pub const I64X2_ALL_TRUE: u32 = 0xc3;
    pub const I64X2_BITMASK: u32 = 0xc4;
    pub const I64X2_EXTEND_LOW_I32X4_S: u32 = 0xc7;
    pub const I64X2_EXTEND_HIGH_I32X4_S: u32 = 0xc8;
    pub const I64X2_EXTEND_LOW_I32X4_U: u32 = 0xc9;
    pub const I64X2_EXTEND_HIGH_I32X4_U: u32 = 0xca;
    pub const I64X2_SHL: u32 = 0xcb;
    pub const I64X2_SHR_S: u32 = 0xcc;
    pub const I64X2_SHR_U: u32 = 0xcd;
    pub const I64X2_ADD: u32 = 0xce;
    pub const I64X2_SUB: u32 = 0xd1;
    pub const I64X2_MUL: u32 = 0xd5;
    pub const I64X2_EQ: u32 = 0xd6;
    pub const I64X2_NE: u32 = 0xd7;
    pub const I64X2_LT_S: u32 = 0xd8;
    pub const I64X2_GT_S: u32 = 0xd9;
    pub const I64X2_LE_S: u32 = 0xda;
    pub const I64X2_GE_S: u32 = 0xdb;
    pub const I64X2_EXTMUL_LOW_I32X4_S: u32 = 0xdc;
    pub const I64X2_EXTMUL_HIGH_I32X4_S: u32 = 0xdd;
    pub const I64X2_EXTMUL_LOW_I32X4_U: u32 = 0xde;
    pub const I64X2_EXTMUL_HIGH_I32X4_U: u32 = 0xdf;
    pub const F32X4_ABS: u32 = 0xe0;
    pub const F32X4_NEG: u32 = 0xe1;
    pub const F32X4_SQRT: u32 = 0xe3;
    pub const F32X4_ADD: u32 = 0xe4;
    pub const F32X4_SUB: u32 = 0xe5;
    pub const F32X4_MUL: u32 = 0xe6;
    pub const F32X4_DIV: u32 = 0xe7;
    pub const F32X4_MIN: u32 = 0xe8;
    pub const F32X4_MAX: u32 = 0xe9;
    pub const F32X4_PMIN: u32 = 0xea;
    pub const F32X4_PMAX: u32 = 0xeb;
    pub const F64X2_ABS: u32 = 0xec;
    pub const F64X2_NEG: u32 = 0xed;
    pub const F64X2_SQRT: u32 = 0xef;
    pub const F64X2_ADD: u32 = 0xf0;
    pub const F64X2_SUB: u32 = 0xf1;
    pub const F64X2_MUL: u32 = 0xf2;
    pub const F64X2_DIV: u32 = 0xf3;
    pub const F64X2_MIN: u32 = 0xf4;
    pub const F64X2_MAX: u32 = 0xf5;
    pub const I32X4_TRUNC_SAT_F32X4_S: u32 = 0xf8;
    pub const I32X4_TRUNC_SAT_F32X4_U: u32 = 0xf9;
    pub const F32X4_CONVERT_I32X4_S: u32 = 0xfa;
    pub const F32X4_CONVERT_I32X4_U: u32 = 0xfb;
    pub const I32X4_TRUNC_SAT_F64X2_S_ZERO: u32 = 0xfc;
    pub const I32X4_TRUNC_SAT_F64X2_U_ZERO: u32 = 0xfd;
    pub const F64X2_CONVERT_LOW_I32X4_S: u32 = 0xfe;
    pub const F64X2_CONVERT_LOW_I32X4_U: u32 = 0xff;
}

#[derive(Default)]
pub struct Func {
    pub ty: u32,
    pub locals: Vec<u8>,
    pub body: Vec<u8>,
}

impl Func {
    pub fn new(ty: u32) -> Self {
        Func { ty, locals: Vec::new(), body: Vec::new() }
    }
    pub fn op(&mut self, o: u8) -> &mut Self {
        self.body.push(o);
        self
    }
    pub fn idx(&mut self, o: u8, i: u32) -> &mut Self {
        self.body.push(o);
        uleb(&mut self.body, i as u64);
        self
    }
    pub fn i32c(&mut self, v: i32) -> &mut Self {
        self.body.push(op::I32_CONST);
        sleb(&mut self.body, v as i64);
        self
    }
    pub fn i64c(&mut self, v: i64) -> &mut Self {
        self.body.push(op::I64_CONST);
        sleb(&mut self.body, v);
        self
    }
    /// The bit pattern of the float. Unlike an integer, a float immediate travels as its IEEE bytes
    /// in little-endian order at a fixed width, not as a variable-length integer.
    pub fn f32c(&mut self, bits: u32) -> &mut Self {
        self.body.push(op::F32_CONST);
        self.body.extend_from_slice(&bits.to_le_bytes());
        self
    }

    pub fn f64c(&mut self, bits: u64) -> &mut Self {
        self.body.push(op::F64_CONST);
        self.body.extend_from_slice(&bits.to_le_bytes());
        self
    }

    pub fn lg(&mut self, i: u32) -> &mut Self {
        self.idx(op::LOCAL_GET, i)
    }
    pub fn ls(&mut self, i: u32) -> &mut Self {
        self.idx(op::LOCAL_SET, i)
    }
    pub fn lt(&mut self, i: u32) -> &mut Self {
        self.idx(op::LOCAL_TEE, i)
    }
    pub fn call(&mut self, f: u32) -> &mut Self {
        self.idx(op::CALL, f)
    }
    pub fn block(&mut self) -> &mut Self {
        self.body.push(op::BLOCK);
        self.body.push(0x40);
        self
    }
    pub fn loop_(&mut self) -> &mut Self {
        self.body.push(op::LOOP);
        self.body.push(0x40);
        self
    }
    pub fn if_(&mut self) -> &mut Self {
        self.body.push(op::IF);
        self.body.push(0x40);
        self
    }
    pub fn else_(&mut self) -> &mut Self {
        self.body.push(op::ELSE);
        self
    }
    pub fn end(&mut self) -> &mut Self {
        self.body.push(op::END);
        self
    }
    pub fn br(&mut self, l: u32) -> &mut Self {
        self.idx(op::BR, l)
    }
    pub fn br_table(&mut self, labels: &[u32], default: u32) -> &mut Self {
        self.body.push(op::BR_TABLE);
        uleb(&mut self.body, labels.len() as u64);
        for &l in labels {
            uleb(&mut self.body, l as u64);
        }
        uleb(&mut self.body, default as u64);
        self
    }
    pub fn ret(&mut self) -> &mut Self {
        self.body.push(op::RETURN);
        self
    }
    pub fn mem(&mut self, o: u8, align_log2: u32, offset: u64) -> &mut Self {
        self.body.push(o);
        uleb(&mut self.body, align_log2 as u64);
        uleb(&mut self.body, offset);
        self
    }
    /// A `0xfd`-prefixed SIMD instruction.
    pub fn simd(&mut self, op: u32) -> &mut Self {
        self.body.push(0xfd);
        uleb(&mut self.body, op as u64);
        self
    }
    pub fn simd_mem(&mut self, op: u32, align_log2: u32, offset: u64) -> &mut Self {
        self.simd(op);
        uleb(&mut self.body, align_log2 as u64);
        uleb(&mut self.body, offset);
        self
    }
    pub fn simd_mem_lane(&mut self, op: u32, align_log2: u32, offset: u64, lane: u8) -> &mut Self {
        self.simd(op);
        uleb(&mut self.body, align_log2 as u64);
        uleb(&mut self.body, offset);
        self.body.push(lane);
        self
    }
    pub fn simd_lane(&mut self, op: u32, lane: u8) -> &mut Self {
        self.simd(op);
        self.body.push(lane);
        self
    }
    pub fn sat(&mut self, op: u32) -> &mut Self {
        self.body.push(0xfc);
        uleb(&mut self.body, op as u64);
        self
    }
    pub fn v128c(&mut self, bytes: [u8; 16]) -> &mut Self {
        self.simd(simd::V128_CONST);
        self.body.extend_from_slice(&bytes);
        self
    }
    pub fn wrap_i64(&mut self) -> &mut Self {
        self.op(op::I32_WRAP_I64)
    }
    pub fn extend_i32_u(&mut self) -> &mut Self {
        self.op(op::I64_EXTEND_I32_U)
    }
}

pub struct Import {
    pub module: String,
    pub name: String,
    pub ty: u32,
}

pub struct Module {
    pub types: Vec<(Vec<u8>, Vec<u8>)>,
    pub imports: Vec<Import>,
    pub funcs: Vec<Func>,
    pub table_min: u32,
    /// Present when the host grows the table at run time to add translated code.
    pub table_max: Option<u32>,
    pub elems: Vec<(u32, Vec<u32>)>,
    /// (name, kind, index): kind 0 = func, 1 = table, 2 = memory
    pub exports: Vec<(String, u8, u32)>,
    pub mem_pages: u32,
    /// A module that translates more code for an existing run takes the host's memory instead of
    /// defining one, so both see the same bytes.
    pub mem_import: Option<(String, String)>,
    pub data: Vec<(u64, Vec<u8>)>,
}

impl Module {
    pub fn new() -> Self {
        Module {
            types: Vec::new(),
            imports: Vec::new(),
            funcs: Vec::new(),
            table_min: 0,
            table_max: None,
            elems: Vec::new(),
            exports: Vec::new(),
            mem_pages: 0,
            mem_import: None,
            data: Vec::new(),
        }
    }
    pub fn ty(&mut self, params: Vec<u8>, results: Vec<u8>) -> u32 {
        if let Some(i) = self.types.iter().position(|t| t.0 == params && t.1 == results) {
            return i as u32;
        }
        self.types.push((params, results));
        (self.types.len() - 1) as u32
    }
    pub fn n_imports(&self) -> u32 {
        self.imports.len() as u32
    }
    /// Declares a function and returns its index (imports counted first).
    pub fn add_func(&mut self, ty: u32) -> u32 {
        self.funcs.push(Func::new(ty));
        self.n_imports() + (self.funcs.len() - 1) as u32
    }
    pub fn func_mut(&mut self, index: u32) -> &mut Func {
        let i = (index - self.n_imports()) as usize;
        &mut self.funcs[i]
    }

    fn section(out: &mut Vec<u8>, id: u8, body: &[u8]) {
        if body.is_empty() {
            return;
        }
        out.push(id);
        uleb(out, body.len() as u64);
        out.extend_from_slice(body);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

        let mut s = Vec::new();
        uleb(&mut s, self.types.len() as u64);
        for (p, r) in &self.types {
            s.push(0x60);
            uleb(&mut s, p.len() as u64);
            s.extend_from_slice(p);
            uleb(&mut s, r.len() as u64);
            s.extend_from_slice(r);
        }
        Self::section(&mut out, 1, &s);

        let n_imports = self.imports.len() + self.mem_import.iter().count();
        if n_imports > 0 {
            let mut s = Vec::new();
            uleb(&mut s, n_imports as u64);
            for im in &self.imports {
                uleb(&mut s, im.module.len() as u64);
                s.extend_from_slice(im.module.as_bytes());
                uleb(&mut s, im.name.len() as u64);
                s.extend_from_slice(im.name.as_bytes());
                s.push(0x00);
                uleb(&mut s, im.ty as u64);
            }
            if let Some((module, name)) = &self.mem_import {
                uleb(&mut s, module.len() as u64);
                s.extend_from_slice(module.as_bytes());
                uleb(&mut s, name.len() as u64);
                s.extend_from_slice(name.as_bytes());
                s.push(0x02);
                s.push(0x00);
                uleb(&mut s, 1);
            }
            Self::section(&mut out, 2, &s);
        }

        let mut s = Vec::new();
        uleb(&mut s, self.funcs.len() as u64);
        for f in &self.funcs {
            uleb(&mut s, f.ty as u64);
        }
        Self::section(&mut out, 3, &s);

        if self.table_min > 0 {
            let mut s = Vec::new();
            uleb(&mut s, 1);
            s.push(0x70);
            match self.table_max {
                None => {
                    s.push(0x00);
                    uleb(&mut s, self.table_min as u64);
                }
                Some(max) => {
                    s.push(0x01);
                    uleb(&mut s, self.table_min as u64);
                    uleb(&mut s, max as u64);
                }
            }
            Self::section(&mut out, 4, &s);
        }

        if self.mem_pages > 0 {
            let mut s = Vec::new();
            uleb(&mut s, 1);
            s.push(0x00);
            uleb(&mut s, self.mem_pages as u64);
            Self::section(&mut out, 5, &s);
        }

        if !self.exports.is_empty() {
            let mut s = Vec::new();
            uleb(&mut s, self.exports.len() as u64);
            for (name, kind, idx) in &self.exports {
                uleb(&mut s, name.len() as u64);
                s.extend_from_slice(name.as_bytes());
                s.push(*kind);
                uleb(&mut s, *idx as u64);
            }
            Self::section(&mut out, 7, &s);
        }

        if !self.elems.is_empty() {
            let mut s = Vec::new();
            uleb(&mut s, self.elems.len() as u64);
            for (offset, funcs) in &self.elems {
                uleb(&mut s, 0);
                s.push(op::I32_CONST);
                sleb(&mut s, *offset as i64);
                s.push(op::END);
                uleb(&mut s, funcs.len() as u64);
                for &f in funcs {
                    uleb(&mut s, f as u64);
                }
            }
            Self::section(&mut out, 9, &s);
        }

        let mut s = Vec::new();
        uleb(&mut s, self.funcs.len() as u64);
        for f in &self.funcs {
            let mut fb = Vec::new();
            let mut groups: Vec<(u32, u8)> = Vec::new();
            for &t in &f.locals {
                match groups.last_mut() {
                    Some((n, ty)) if *ty == t => *n += 1,
                    _ => groups.push((1, t)),
                }
            }
            uleb(&mut fb, groups.len() as u64);
            for (n, t) in groups {
                uleb(&mut fb, n as u64);
                fb.push(t);
            }
            fb.extend_from_slice(&f.body);
            fb.push(op::END);
            uleb(&mut s, fb.len() as u64);
            s.extend_from_slice(&fb);
        }
        Self::section(&mut out, 10, &s);

        if !self.data.is_empty() {
            let mut s = Vec::new();
            uleb(&mut s, self.data.len() as u64);
            for (off, bytes) in &self.data {
                uleb(&mut s, 0);
                s.push(op::I32_CONST);
                // i32.const is a signed LEB: an offset above 2^31 must be sign-extended, not
                // encoded as a positive 5-byte varint
                sleb(&mut s, *off as u32 as i32 as i64);
                s.push(op::END);
                uleb(&mut s, bytes.len() as u64);
                s.extend_from_slice(bytes);
            }
            Self::section(&mut out, 11, &s);
        }

        out
    }
}
