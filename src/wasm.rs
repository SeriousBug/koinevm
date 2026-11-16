//! Minimal WebAssembly binary encoder. Only the subset the translator needs.

pub const I32: u8 = 0x7f;
pub const I64: u8 = 0x7e;

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

    pub const I32_CLZ: u8 = 0x67;
    pub const I32_CTZ: u8 = 0x68;
    pub const I32_POPCNT: u8 = 0x69;
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
    pub const I64_EXTEND_I32_S: u8 = 0xac;
    pub const I64_EXTEND_I32_U: u8 = 0xad;
    pub const I64_EXTEND8_S: u8 = 0xc2;
    pub const I64_EXTEND16_S: u8 = 0xc3;
    pub const I64_EXTEND32_S: u8 = 0xc4;
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
    pub elems: Vec<(u32, Vec<u32>)>,
    /// (name, kind, index): kind 0 = func, 2 = memory
    pub exports: Vec<(String, u8, u32)>,
    pub mem_pages: u32,
    pub data: Vec<(u64, Vec<u8>)>,
}

impl Module {
    pub fn new() -> Self {
        Module {
            types: Vec::new(),
            imports: Vec::new(),
            funcs: Vec::new(),
            table_min: 0,
            elems: Vec::new(),
            exports: Vec::new(),
            mem_pages: 0,
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

        if !self.imports.is_empty() {
            let mut s = Vec::new();
            uleb(&mut s, self.imports.len() as u64);
            for im in &self.imports {
                uleb(&mut s, im.module.len() as u64);
                s.extend_from_slice(im.module.as_bytes());
                uleb(&mut s, im.name.len() as u64);
                s.extend_from_slice(im.name.as_bytes());
                s.push(0x00);
                uleb(&mut s, im.ty as u64);
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
            s.push(0x00);
            uleb(&mut s, self.table_min as u64);
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
