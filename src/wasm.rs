//! Minimal WebAssembly binary encoder. Only the subset the translator needs.

pub const I32: u8 = 0x7f;
pub const I64: u8 = 0x7e;
pub const F32: u8 = 0x7d;
pub const F64: u8 = 0x7c;

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

// opcodes
pub mod op {
    pub const UNREACHABLE: u8 = 0x00;
    pub const NOP: u8 = 0x01;
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
    pub const GLOBAL_GET: u8 = 0x23;
    pub const GLOBAL_SET: u8 = 0x24;
    pub const I32_LOAD: u8 = 0x28;
    pub const I64_LOAD: u8 = 0x29;
    pub const F32_LOAD: u8 = 0x2a;
    pub const F64_LOAD: u8 = 0x2b;
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
    pub const F32_STORE: u8 = 0x38;
    pub const F64_STORE: u8 = 0x39;
    pub const I32_STORE8: u8 = 0x3a;
    pub const I32_STORE16: u8 = 0x3b;
    pub const I64_STORE8: u8 = 0x3c;
    pub const I64_STORE16: u8 = 0x3d;
    pub const I64_STORE32: u8 = 0x3e;
    pub const I32_CONST: u8 = 0x41;
    pub const I64_CONST: u8 = 0x42;
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

    pub const F64_EQ: u8 = 0x61;
    pub const F64_NE: u8 = 0x62;
    pub const F64_LT: u8 = 0x63;
    pub const F64_GT: u8 = 0x64;
    pub const F64_LE: u8 = 0x65;
    pub const F64_GE: u8 = 0x66;

    pub const I32_CLZ: u8 = 0x67;
    pub const I32_CTZ: u8 = 0x68;
    pub const I32_POPCNT: u8 = 0x69;
    pub const I32_ADD: u8 = 0x6a;
    pub const I32_SUB: u8 = 0x6b;
    pub const I32_MUL: u8 = 0x6c;
    pub const I32_DIV_S: u8 = 0x6d;
    pub const I32_DIV_U: u8 = 0x6e;
    pub const I32_REM_S: u8 = 0x6f;
    pub const I32_REM_U: u8 = 0x70;
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
    pub const I64_REM_S: u8 = 0x81;
    pub const I64_REM_U: u8 = 0x82;
    pub const I64_AND: u8 = 0x83;
    pub const I64_OR: u8 = 0x84;
    pub const I64_XOR: u8 = 0x85;
    pub const I64_SHL: u8 = 0x86;
    pub const I64_SHR_S: u8 = 0x87;
    pub const I64_SHR_U: u8 = 0x88;
    pub const I64_ROTL: u8 = 0x89;
    pub const I64_ROTR: u8 = 0x8a;

    pub const F64_ABS: u8 = 0x99;
    pub const F64_NEG: u8 = 0x9a;
    pub const F64_SQRT: u8 = 0x9f;
    pub const F64_ADD: u8 = 0xa0;
    pub const F64_SUB: u8 = 0xa1;
    pub const F64_MUL: u8 = 0xa2;
    pub const F64_DIV: u8 = 0xa3;

    pub const I32_WRAP_I64: u8 = 0xa7;
    pub const I64_EXTEND_I32_S: u8 = 0xac;
    pub const I64_EXTEND_I32_U: u8 = 0xad;
    pub const F64_CONVERT_I64_S: u8 = 0xb9;
    pub const F64_CONVERT_I64_U: u8 = 0xba;
    pub const I64_REINTERPRET_F64: u8 = 0xbd;
    pub const F64_REINTERPRET_I64: u8 = 0xbf;
    pub const I64_EXTEND8_S: u8 = 0xc2;
    pub const I64_EXTEND16_S: u8 = 0xc3;
    pub const I64_EXTEND32_S: u8 = 0xc4;
}

#[derive(Default)]
pub struct Func {
    pub ty: u32,
    /// value type of each declared local (excluding params)
    pub locals: Vec<u8>,
    pub body: Vec<u8>,
}

impl Func {
    pub fn new(ty: u32) -> Self {
        Func { ty, locals: Vec::new(), body: Vec::new() }
    }
    pub fn local(&mut self, t: u8) -> u32 {
        self.locals.push(t);
        // index 0..nparams unknown here; the caller patches by absolute index
        self.locals.len() as u32
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
    pub fn block(&mut self, bt: u8) -> &mut Self {
        self.body.push(op::BLOCK);
        self.body.push(bt);
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
    pub fn br_if(&mut self, l: u32) -> &mut Self {
        self.idx(op::BR_IF, l)
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
    pub fn mem(&mut self, o: u8, align_log2: u32, offset: u32) -> &mut Self {
        self.body.push(o);
        uleb(&mut self.body, align_log2 as u64);
        uleb(&mut self.body, offset as u64);
        self
    }
    /// i64 local -> i32 local, truncating (for guest W-register ops)
    pub fn wrap_i64(&mut self) -> &mut Self {
        self.op(op::I32_WRAP_I64)
    }
    pub fn extend_i32_u(&mut self) -> &mut Self {
        self.op(op::I64_EXTEND_I32_U)
    }
    pub fn extend_i32_s(&mut self) -> &mut Self {
        self.op(op::I64_EXTEND_I32_S)
    }
}

pub struct Module {
    pub types: Vec<(Vec<u8>, Vec<u8>)>,
    pub funcs: Vec<Func>,
    pub exports: Vec<(String, u32)>,
    pub mem_pages: u32,
    pub data: Vec<(u32, Vec<u8>)>,
}

impl Module {
    pub fn new() -> Self {
        Module { types: Vec::new(), funcs: Vec::new(), exports: Vec::new(), mem_pages: 0, data: Vec::new() }
    }
    pub fn ty(&mut self, params: Vec<u8>, results: Vec<u8>) -> u32 {
        if let Some(i) = self.types.iter().position(|t| t.0 == params && t.1 == results) {
            return i as u32;
        }
        self.types.push((params, results));
        (self.types.len() - 1) as u32
    }

    fn section(out: &mut Vec<u8>, id: u8, body: &[u8]) {
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

        let mut s = Vec::new();
        uleb(&mut s, self.funcs.len() as u64);
        for f in &self.funcs {
            uleb(&mut s, f.ty as u64);
        }
        Self::section(&mut out, 3, &s);

        if self.mem_pages > 0 {
            let mut s = Vec::new();
            uleb(&mut s, 1);
            s.push(0x00); // no max
            uleb(&mut s, self.mem_pages as u64);
            Self::section(&mut out, 5, &s);
        }

        let mut s = Vec::new();
        uleb(&mut s, self.exports.len() as u64);
        for (name, idx) in &self.exports {
            uleb(&mut s, name.len() as u64);
            s.extend_from_slice(name.as_bytes());
            s.push(0x00);
            uleb(&mut s, *idx as u64);
        }
        if self.mem_pages > 0 {
            let name = b"mem";
            uleb(&mut s, name.len() as u64);
            s.extend_from_slice(name);
            s.push(0x02);
            uleb(&mut s, 0);
        }
        let exported = self.exports.len() + if self.mem_pages > 0 { 1 } else { 0 };
        let mut s2 = Vec::new();
        uleb(&mut s2, exported as u64);
        s2.drain(0..0);
        // rebuild: count first (patched), then entries
        let mut body = Vec::new();
        uleb(&mut body, exported as u64);
        for (name, idx) in &self.exports {
            uleb(&mut body, name.len() as u64);
            body.extend_from_slice(name.as_bytes());
            body.push(0x00);
            uleb(&mut body, *idx as u64);
        }
        if self.mem_pages > 0 {
            let name = b"mem";
            uleb(&mut body, name.len() as u64);
            body.extend_from_slice(name);
            body.push(0x02);
            uleb(&mut body, 0);
        }
        Self::section(&mut out, 7, &body);

        let mut s = Vec::new();
        uleb(&mut s, self.funcs.len() as u64);
        for f in &self.funcs {
            let mut fb = Vec::new();
            // group consecutive identical local types
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
                uleb(&mut s, 0); // active, memory 0
                s.push(op::I32_CONST);
                sleb(&mut s, *off as i64);
                s.push(op::END);
                uleb(&mut s, bytes.len() as u64);
                s.extend_from_slice(bytes);
            }
            Self::section(&mut out, 11, &s);
        }

        out
    }
}
