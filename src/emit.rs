//! Turns a decoded guest image into a wasm module.
//!
//! Decisions the rest of the system depends on:
//!
//! * Guest AArch64 state lives in wasm locals: x0-x30, sp and the packed NZCV word are parameters
//!   and results of every translated region. The host engine is the register allocator.
//! * A region is the set of blocks reachable from one entry point through non-call edges. One wasm
//!   function per region, one nested `block` per guest block, a `br_table` on a local pc. Direct
//!   branches inside a region are plain `br`s; everything else returns the next pc to the
//!   dispatcher, which indexes a guest-PC-keyed table of region functions.
//! * Calls, returns and computed jumps all go through the dispatcher, so wasm stack depth is
//!   constant: guest recursion is bounded by the guest stack in linear memory, as a kernel bounds
//!   it, and computed jumps and tail calls need no special case.
//! * Guest addresses are linear-memory offsets. With `bounds_check` on, every access compares the
//!   full 64-bit address against the memory size, so an address above 4 GiB traps instead of
//!   silently aliasing low memory.

use crate::decode::*;
use crate::elf::Elf;
use crate::wasm::op::*;
use crate::wasm::*;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

pub const NR: u32 = 33; // x0..x30 (0..30), sp (31), nzcv (32)
/// Parameter 33 of a region is the block index to start at, so a guest return can resume at any
/// block rather than only at the region entry.
pub const P_ENTRY: u32 = 33;
pub const L_PC: u32 = 34;
pub const L_T0: u32 = 35;
pub const L_T1: u32 = 36;
pub const L_T2: u32 = 37;
pub const L_T3: u32 = 38;
pub const L_T4: u32 = 39;
pub const L_TI: u32 = 40;

pub const SHADOW: u64 = 0x0;
pub const SHADOW_SP: u64 = SHADOW + 31 * 8;
pub const SHADOW_NZCV: u64 = SHADOW_SP + 8;
pub const SHADOW_PC: u64 = SHADOW_NZCV + 8;
pub const SHADOW_TP: u64 = SHADOW_PC + 8;
/// Trace mode ring buffer of dispatched guest pcs: a count at RING_IDX and 256 slots at RING.
pub const RING_IDX: u64 = 0x1fc;
pub const RING: u64 = 0x200;
pub const ENGINE_HI: u64 = 0x1000;

/// 4 GiB less a page: every guest address is then checked by the engine itself, and an address in
/// the last page traps rather than aliasing.
pub const DEFAULT_MEM_PAGES: u32 = 65535;
pub const STACK_RESERVE: u64 = 8 * 1024 * 1024;

pub struct Config {
    pub bounds_check: bool,
    pub mem_pages: u32,
    /// Write the register shadow on every dispatch, so a trap can report guest state.
    pub trace: bool,
}

struct Block {
    addr: u64,
    insns: Vec<(u64, Insn)>,
}

struct Region {
    blocks: Vec<Block>,
    index_of: HashMap<u64, usize>,
}

pub struct Stats {
    pub instructions: usize,
    pub regions: usize,
    pub wasm_bytes: usize,
}

pub struct Output {
    pub wasm: Vec<u8>,
    pub entry: u64,
    pub sp: u64,
    pub mem_pages: u32,
    pub stats: Stats,
    pub code_lo: u64,
    pub code_hi: u64,
    pub unsupported: Vec<(u64, String)>,
}

fn is_terminator(i: &Insn) -> bool {
    matches!(
        i,
        Insn::B { .. }
            | Insn::Bl { .. }
            | Insn::BCond { .. }
            | Insn::Cbz { .. }
            | Insn::Tbz { .. }
            | Insn::Br { .. }
            | Insn::Blr { .. }
            | Insn::Ret { .. }
    )
}

fn page_align(x: u64) -> u64 {
    (x + 0xfff) & !0xfff
}

pub fn translate(elf: &Elf, cfg: &Config, argv: &[String], envp: &[String]) -> Result<Output, String> {
    let (code_lo, code_hi) = elf.code_range().ok_or("no executable segment")?;
    let mem_size = cfg.mem_pages as u64 * 65536;

    // Decode the executable range once. Literal pools and padding decode to Undefined, which is
    // only an error if a translated block actually reaches it.
    let mut insns: BTreeMap<u64, Insn> = BTreeMap::new();
    let mut a = code_lo;
    while a + 4 <= code_hi {
        let Some(w) = elf.vaddr_bytes(a, 4) else { break };
        insns.insert(a, decode(u32::from_le_bytes(w.try_into().unwrap())));
        a += 4;
    }

    // Entry points: the ELF entry, every function symbol in executable code, every direct call
    // target. A branch to an entry starts a new region instead of being folded into this one.
    let mut entries: BTreeSet<u64> = BTreeSet::new();
    entries.insert(elf.entry);
    for s in &elf.symbols {
        if s.is_func && s.value >= code_lo && s.value < code_hi {
            entries.insert(s.value);
        }
    }
    for (&addr, i) in &insns {
        if let Insn::Bl { offset } = i {
            let t = (addr as i64 + *offset) as u64;
            if t >= code_lo && t <= code_hi {
                entries.insert(t);
            }
        }
    }

    let mut regions: Vec<Region> = Vec::new();
    let mut region_index: HashMap<u64, usize> = HashMap::new();
    let mut queue: VecDeque<u64> = VecDeque::new();
    for &e in &entries {
        queue.push_back(e);
    }
    while let Some(entry) = queue.pop_front() {
        if region_index.contains_key(&entry) {
            continue;
        }
        let region = discover_region(entry, &insns, &entries, code_hi);
        if region.blocks.is_empty() {
            continue;
        }
        region_index.insert(entry, regions.len());
        regions.push(region);
    }
    if !region_index.contains_key(&elf.entry) {
        return Err(format!("entry point 0x{:x} did not decode", elf.entry));
    }

    let data_limit = elf.data_limit().max(elf.image_end());
    let table_size = ((code_hi - code_lo) / 4) * 4;
    let callmap = page_align(data_limit.max(ENGINE_HI));
    let brk_base = page_align(callmap + table_size);
    let stack_top = (mem_size - 0x1000) & !0xf;
    let stack_floor = stack_top - STACK_RESERVE;
    if brk_base >= stack_floor {
        return Err("image too large for the fixed layout".into());
    }
    for s in &elf.segments {
        let overlaps_callmap = s.vaddr < callmap + table_size && s.end() > callmap;
        if s.vaddr < ENGINE_HI || overlaps_callmap || s.end() > stack_floor {
            return Err(format!(
                "segment 0x{:x}..0x{:x} collides with the engine area, the call table or the stack",
                s.vaddr,
                s.end()
            ));
        }
    }
    let _ = brk_base;

    let (stack_bytes, stack_used) = build_initial_stack(elf, argv, envp, stack_top);
    let sp = stack_top - stack_used;

    let mut m = Module::new();
    m.mem_pages = cfg.mem_pages;

    let mut region_params = vec![I64; NR as usize];
    region_params.push(I32); // entry block
    let mut region_results = vec![I64; NR as usize];
    region_results.push(I32);
    let ty_region = m.ty(region_params, region_results);
    let ty_syscall = m.ty(vec![I64; 7], vec![I64, I32]);
    let ty_trap = m.ty(vec![I32, I64, I32], vec![]);
    let ty_ii_i64 = m.ty(vec![I64, I64], vec![I64]);
    let ty_run = m.ty(vec![I32, I64], vec![I32]);

    m.imports.push(Import { module: "env".into(), name: "syscall".into(), ty: ty_syscall });
    m.imports.push(Import { module: "env".into(), name: "trap".into(), ty: ty_trap });
    let trace_idx = if cfg.trace {
        let ty = m.ty(vec![I32, I64], vec![]);
        m.imports.push(Import { module: "env".into(), name: "trace2".into(), ty });
        Some(m.n_imports() - 1)
    } else {
        None
    };

    let umulh_id = emit_umulh(&mut m, ty_ii_i64);
    let smulh_id = emit_smulh(&mut m, ty_ii_i64, umulh_id);
    let ids = Ids {
        syscall: 0,
        trap: 1,
        trace: trace_idx,
        umulh: umulh_id,
        smulh: smulh_id,
        udiv: emit_udiv(&mut m, ty_ii_i64),
        sdiv: emit_sdiv(&mut m, ty_ii_i64),
        bswap64: emit_bswap(&mut m, ty_ii_i64, 64),
        bswap32: emit_bswap(&mut m, ty_ii_i64, 32),
        rbit64: emit_rbit(&mut m, ty_ii_i64),
        ty_region,
    };

    let mut region_func_ids = Vec::new();
    for _ in &regions {
        region_func_ids.push(m.add_func(ty_region));
    }
    let run_id = m.add_func(ty_run);
    m.table_min = regions.len() as u32;
    m.elems.push((0, region_func_ids.clone()));

    let layout =
        Layout { callmap, stack_floor, bounds_check: cfg.bounds_check, trace: cfg.trace, mem_size };

    if std::env::var("ARMJIT_DUMP_REGIONS").is_ok() {
        for (i, r) in regions.iter().enumerate() {
            eprintln!("region {i} entry 0x{:x}", r.blocks[0].addr);
            for (bi, b) in r.blocks.iter().enumerate() {
                let end = b.insns.last().map(|x| x.0).unwrap_or(b.addr);
                eprintln!("  block {bi}: 0x{:x}..0x{:x} ({} insns)", b.addr, end, b.insns.len());
            }
        }
    }
    let mut instructions = 0usize;
    let mut unsupported = Vec::new();
    for (i, region) in regions.iter().enumerate() {
        let body = RegionEmitter::new(region, &layout, &ids).emit()?;
        instructions += region.blocks.iter().map(|b| b.insns.len()).sum::<usize>();
        *m.func_mut(region_func_ids[i]) = body;
    }
    *m.func_mut(run_id) = emit_run(&ids, &layout, code_lo, code_hi, ty_run);

    for s in &elf.segments {
        let bytes = elf.image[s.file_offset as usize..(s.file_offset + s.filesz) as usize].to_vec();
        m.data.push((s.vaddr, bytes));
    }
    // One word per 4 bytes of code: low half the region index + 1, high half the block index.
    let mut callmap_bytes = vec![0u8; table_size as usize];
    for (entry, idx) in &region_index {
        let region = &regions[*idx];
        for (block_idx, block) in region.blocks.iter().enumerate() {
            let off = ((block.addr - code_lo) / 4) as usize * 4;
            if off + 4 <= callmap_bytes.len() {
                let word = ((*idx as u32) + 1) | ((block_idx as u32) << 16);
                callmap_bytes[off..off + 4].copy_from_slice(&word.to_le_bytes());
            }
        }
        let _ = entry;
    }
    m.data.push((callmap, callmap_bytes));
    if !stack_bytes.is_empty() {
        m.data.push((sp, stack_bytes));
    }

    m.exports.push(("run".into(), 0, run_id));
    m.exports.push(("mem".into(), 2, 0));

    let wasm = m.encode();
    unsupported.sort();
    Ok(Output {
        entry: elf.entry,
        sp,
        mem_pages: cfg.mem_pages,
        stats: Stats { instructions, regions: regions.len(), wasm_bytes: wasm.len() },
        code_lo,
        code_hi,
        unsupported,
        wasm,
    })
}

struct Layout {
    callmap: u64,
    stack_floor: u64,
    bounds_check: bool,
    trace: bool,
    mem_size: u64,
}

struct Ids {
    syscall: u32,
    trap: u32,
    /// Present only with --trace; called before every guest instruction.
    trace: Option<u32>,
    umulh: u32,
    smulh: u32,
    udiv: u32,
    sdiv: u32,
    bswap64: u32,
    bswap32: u32,
    rbit64: u32,
    ty_region: u32,
}

fn discover_region(
    entry: u64,
    insns: &BTreeMap<u64, Insn>,
    entries: &BTreeSet<u64>,
    code_hi: u64,
) -> Region {
    // Pass 1: find every block start. A block runs from its start to the first terminator, which
    // may pass over a later block's start; that is fine here because only terminators and their
    // targets matter. Pass 2 slices the blocks so that they are disjoint.
    let mut starts: BTreeSet<u64> = BTreeSet::new();
    let mut worklist = vec![entry];
    while let Some(start) = worklist.pop() {
        if !starts.insert(start) {
            continue;
        }
        if start >= code_hi || start % 4 != 0 {
            starts.remove(&start);
            continue;
        }
        let mut a = start;
        loop {
            let Some(&ins) = insns.get(&a) else { break };
            let here = a;
            a += 4;
            if !is_terminator(&ins) {
                continue;
            }
            let mut succ = Vec::new();
            match ins {
                Insn::B { offset } => succ.push((here as i64 + offset) as u64),
                Insn::BCond { offset, .. } | Insn::Cbz { offset, .. } | Insn::Tbz { offset, .. } => {
                    succ.push((here as i64 + offset) as u64);
                    if a < code_hi {
                        succ.push(a);
                    }
                }
                // blr is a call: its return address is the fallthrough, exactly like bl.
                Insn::Br { .. } | Insn::Ret { .. } => {}
                _ => {
                    if a < code_hi {
                        succ.push(a);
                    }
                }
            }
            for s in succ {
                if (!entries.contains(&s) || s == entry) && !starts.contains(&s) {
                    worklist.push(s);
                }
            }
            break;
        }
    }

    // Pass 2: slice, stopping at any other block start or region entry, so no instruction is
    // emitted twice and every fallthrough lands on a real block boundary.
    let mut blocks: Vec<Block> = Vec::new();
    for &start in &starts {
        let mut list = Vec::new();
        let mut a = start;
        loop {
            if a != start && (starts.contains(&a) || entries.contains(&a)) {
                break;
            }
            let Some(&ins) = insns.get(&a) else { break };
            list.push((a, ins));
            a += 4;
            if is_terminator(&ins) {
                break;
            }
        }
        if !list.is_empty() {
            blocks.push(Block { addr: start, insns: list });
        }
    }
    blocks.sort_by_key(|b| b.addr);
    if let Some(pos) = blocks.iter().position(|b| b.addr == entry) {
        let b = blocks.remove(pos);
        blocks.insert(0, b);
    }
    let index_of = blocks.iter().enumerate().map(|(i, b)| (b.addr, i)).collect();
    Region { blocks, index_of }
}

// ---------------------------------------------------------------- initial stack

struct StackBuilder {
    cur: u64,
    chunks: Vec<(u64, Vec<u8>)>,
}

impl StackBuilder {
    fn bytes(&mut self, b: &[u8]) -> u64 {
        self.cur -= b.len() as u64;
        self.chunks.push((self.cur, b.to_vec()));
        self.cur
    }
    fn u64(&mut self, v: u64) -> u64 {
        self.bytes(&v.to_le_bytes())
    }
    fn align16(&mut self) {
        self.cur &= !0xf;
    }
}

pub fn build_initial_stack(
    elf: &Elf,
    argv: &[String],
    envp: &[String],
    stack_top: u64,
) -> (Vec<u8>, u64) {
    let mut sb = StackBuilder { cur: stack_top, chunks: Vec::new() };

    let argv: Vec<String> =
        if argv.is_empty() { vec!["guest".to_string()] } else { argv.to_vec() };

    let execfn_addr = sb.bytes(format!("{}\0", argv[0]).as_bytes());
    let mut env_addrs = Vec::new();
    for e in envp {
        env_addrs.push(sb.bytes(format!("{e}\0").as_bytes()));
    }
    let mut argv_addrs = Vec::new();
    for a in &argv {
        argv_addrs.push(sb.bytes(format!("{a}\0").as_bytes()));
    }
    sb.bytes(b"aarch64\0");
    // Fixed AT_RANDOM: runs reproduce, at the cost of every run being identical.
    let random_addr = sb.bytes(&[
        0x4a, 0x9f, 0x11, 0x2c, 0x77, 0x03, 0xd5, 0x6e, 0x21, 0xb8, 0x64, 0x9a, 0x0f, 0x33, 0xc7, 0x58,
    ]);

    let phdr = elf
        .segments
        .iter()
        .filter(|s| elf.phoff >= s.file_offset && elf.phoff < s.file_offset + s.filesz)
        .map(|s| s.vaddr + (elf.phoff - s.file_offset))
        .next();

    let mut auxv: Vec<(u64, u64)> = Vec::new();
    if let Some(p) = phdr {
        auxv.push((3, p));
    }
    auxv.push((4, elf.phentsize as u64));
    auxv.push((5, elf.phnum as u64));
    auxv.push((6, 4096));
    auxv.push((7, 0));
    auxv.push((8, 0));
    auxv.push((9, elf.entry));
    auxv.push((11, 0));
    auxv.push((12, 0));
    auxv.push((13, 0));
    auxv.push((14, 0));
    // AT_HWCAP stays 0. FP and ASIMD are not translated yet; claiming them turns into a trap on
    // the first vector instruction instead of an honest refusal.
    auxv.push((16, 0));
    auxv.push((17, 100));
    auxv.push((23, 0));
    auxv.push((25, random_addr));
    auxv.push((26, 0));
    auxv.push((31, execfn_addr));

    let slots = 1 + (argv_addrs.len() + 1) + (env_addrs.len() + 1) + (auxv.len() * 2 + 2);
    sb.align16();
    if slots % 2 == 1 {
        sb.cur -= 8;
    }

    sb.u64(0);
    for (t, v) in auxv.iter().rev() {
        sb.u64(*v);
        sb.u64(*t);
    }
    sb.u64(0);
    for a in env_addrs.iter().rev() {
        sb.u64(*a);
    }
    sb.u64(0);
    for a in argv_addrs.iter().rev() {
        sb.u64(*a);
    }
    let sp = sb.u64(argv_addrs.len() as u64);

    let mut blob = vec![0u8; (stack_top - sp) as usize];
    for (addr, bytes) in &sb.chunks {
        let off = (addr - sp) as usize;
        blob[off..off + bytes.len()].copy_from_slice(bytes);
    }
    (blob, stack_top - sp)
}

// ---------------------------------------------------------------- numeric helpers

fn emit_umulh(m: &mut Module, ty: u32) -> u32 {
    let id = m.add_func(ty);
    let f = m.func_mut(id);
    f.locals = vec![I64; 9]; // 2..10
    let (alo, ahi, blo, bhi, p0, p1, p2, p3, mid) = (2u32, 3u32, 4u32, 5u32, 6u32, 7u32, 8u32, 9u32, 10u32);
    f.lg(0);
    f.i64c(0xffff_ffff);
    f.op(I64_AND);
    f.ls(alo);
    f.lg(0);
    f.i64c(32);
    f.op(I64_SHR_U);
    f.ls(ahi);
    f.lg(1);
    f.i64c(0xffff_ffff);
    f.op(I64_AND);
    f.ls(blo);
    f.lg(1);
    f.i64c(32);
    f.op(I64_SHR_U);
    f.ls(bhi);
    f.lg(alo);
    f.lg(blo);
    f.op(I64_MUL);
    f.ls(p0);
    f.lg(alo);
    f.lg(bhi);
    f.op(I64_MUL);
    f.ls(p1);
    f.lg(ahi);
    f.lg(blo);
    f.op(I64_MUL);
    f.ls(p2);
    f.lg(ahi);
    f.lg(bhi);
    f.op(I64_MUL);
    f.ls(p3);
    f.lg(p0);
    f.i64c(32);
    f.op(I64_SHR_U);
    f.lg(p1);
    f.i64c(0xffff_ffff);
    f.op(I64_AND);
    f.op(I64_ADD);
    f.lg(p2);
    f.i64c(0xffff_ffff);
    f.op(I64_AND);
    f.op(I64_ADD);
    f.ls(mid);
    f.lg(p3);
    f.lg(p1);
    f.i64c(32);
    f.op(I64_SHR_U);
    f.op(I64_ADD);
    f.lg(p2);
    f.i64c(32);
    f.op(I64_SHR_U);
    f.op(I64_ADD);
    f.lg(mid);
    f.i64c(32);
    f.op(I64_SHR_U);
    f.op(I64_ADD);
    id
}

fn emit_smulh(m: &mut Module, ty: u32, umulh_id: u32) -> u32 {
    let id = m.add_func(ty);
    let f = m.func_mut(id);
    f.locals = vec![I64; 2]; // 2 = a, 3 = b
    f.lg(0);
    f.ls(2);
    f.lg(1);
    f.ls(3);
    f.lg(2);
    f.lg(3);
    f.call(umulh_id);
    // high(a*b signed) = umulh(a,b) - (a >>s 63 & b) - (b >>s 63 & a)
    f.lg(2);
    f.i64c(63);
    f.op(I64_SHR_S);
    f.lg(3);
    f.op(I64_AND);
    f.op(I64_SUB);
    f.lg(3);
    f.i64c(63);
    f.op(I64_SHR_S);
    f.lg(2);
    f.op(I64_AND);
    f.op(I64_SUB);
    id
}

fn emit_udiv(m: &mut Module, ty: u32) -> u32 {
    let id = m.add_func(ty);
    let f = m.func_mut(id);
    f.lg(1);
    f.op(I64_EQZ);
    f.op(IF);
    f.body.push(I64);
    f.i64c(0);
    f.op(ELSE);
    f.lg(0);
    f.lg(1);
    f.op(I64_DIV_U);
    f.end();
    id
}

fn emit_sdiv(m: &mut Module, ty: u32) -> u32 {
    let id = m.add_func(ty);
    let f = m.func_mut(id);
    f.lg(1);
    f.op(I64_EQZ);
    f.op(IF);
    f.body.push(I64);
    f.i64c(0);
    f.op(ELSE);
    f.lg(0);
    f.i64c(i64::MIN);
    f.op(I64_EQ);
    f.lg(1);
    f.i64c(-1);
    f.op(I64_EQ);
    f.op(I32_AND);
    f.op(IF);
    f.body.push(I64);
    f.lg(0);
    f.op(ELSE);
    f.lg(0);
    f.lg(1);
    f.op(I64_DIV_S);
    f.end();
    f.end();
    id
}

fn emit_bswap(m: &mut Module, ty: u32, bits: u32) -> u32 {
    let id = m.add_func(ty);
    let f = m.func_mut(id);
    f.locals = vec![I64; 1]; // 2 = accumulator
    let bytes = bits / 8;
    f.i64c(0);
    f.ls(2);
    for i in 0..bytes {
        let mask_shift = i * 8;
        let out_shift = (bytes - 1 - i) * 8;
        f.lg(2);
        f.lg(0);
        f.i64c(mask_shift as i64);
        f.op(I64_SHR_U);
        f.i64c(0xff);
        f.op(I64_AND);
        if out_shift != 0 {
            f.i64c(out_shift as i64);
            f.op(I64_SHL);
        }
        f.op(I64_OR);
        f.ls(2);
    }
    f.lg(2);
    if bits == 32 {
        f.i64c(0xffff_ffff);
        f.op(I64_AND);
    }
    id
}

/// Full 64-bit bit reversal; the 32-bit form is `rbit64(x) >> 32` at the call site.
fn emit_rbit(m: &mut Module, ty: u32) -> u32 {
    let id = m.add_func(ty);
    let f = m.func_mut(id);
    f.locals = vec![I64; 2]; // 2 = x, 3 = reversed bytes
    f.lg(0);
    f.ls(2);
    for (shift, mask) in [(1i64, 0x5555_5555_5555_5555u64), (2, 0x3333_3333_3333_3333), (4, 0x0f0f_0f0f_0f0f_0f0f)] {
        f.lg(2);
        f.i64c(shift);
        f.op(I64_SHR_U);
        f.i64c(mask as i64);
        f.op(I64_AND);
        f.lg(2);
        f.i64c(mask as i64);
        f.op(I64_AND);
        f.i64c(shift);
        f.op(I64_SHL);
        f.op(I64_OR);
        f.ls(2);
    }
    // reverse the byte order of the swapped value
    f.i64c(0);
    f.ls(3);
    for i in 0..8 {
        let mask_shift = i * 8;
        let out_shift = (7 - i) * 8;
        f.lg(3);
        f.lg(2);
        f.i64c(mask_shift as i64);
        f.op(I64_SHR_U);
        f.i64c(0xff);
        f.op(I64_AND);
        if out_shift != 0 {
            f.i64c(out_shift as i64);
            f.op(I64_SHL);
        }
        f.op(I64_OR);
        f.ls(3);
    }
    f.lg(3);
    id
}

// ---------------------------------------------------------------- dispatcher

fn emit_run(ids: &Ids, layout: &Layout, code_lo: u64, code_hi: u64, ty: u32) -> Func {
    let mut f = Func::new(ty);
    f.locals = vec![I64; 31]; // x0..x30 -> 2..32
    f.locals.push(I64); // nzcv -> 33
    f.locals.push(I32); // idx -> 34
    f.locals.push(I32); // next -> 35
    f.locals.push(I32); // status -> 36
    f.locals.push(I32); // entry block -> 37

    for i in 0..31u32 {
        f.i64c(0);
        f.ls(2 + i);
    }
    f.i64c(0);
    f.ls(33);

    f.block(); // $exit, depth from inside the loop's ifs = 2
    f.loop_();
    if layout.trace {
        for i in 0..31u32 {
            f.i32c(SHADOW as i32 + (i as i32) * 8);
            f.lg(2 + i);
            f.mem(I64_STORE, 3, 0);
        }
        f.i32c(SHADOW_SP as i32);
        f.lg(1);
        f.mem(I64_STORE, 3, 0);
        f.i32c(SHADOW_PC as i32);
        f.lg(0);
        f.mem(I32_STORE, 2, 0);
        // ring[idx & 255] = pc; idx++
        f.i32c(RING as i32);
        f.i32c(RING_IDX as i32);
        f.mem(I32_LOAD, 2, 0);
        f.i32c(255);
        f.op(I32_AND);
        f.i32c(4);
        f.op(I32_MUL);
        f.op(I32_ADD);
        f.lg(0);
        f.mem(I32_STORE, 2, 0);
        f.i32c(RING_IDX as i32);
        f.i32c(RING_IDX as i32);
        f.mem(I32_LOAD, 2, 0);
        f.i32c(1);
        f.op(I32_ADD);
        f.mem(I32_STORE, 2, 0);
    }
    // pc outside the translated code range: report an untranslated jump.
    f.lg(0);
    f.i32c(code_lo as i32);
    f.op(I32_LT_U);
    f.op(IF);
    f.body.push(0x40);
    f.i32c(2);
    f.ls(36);
    f.br(2);
    f.end();

    f.lg(0);
    f.i32c(code_hi as i32);
    f.op(I32_GE_U);
    f.op(IF);
    f.body.push(0x40);
    f.i32c(2);
    f.ls(36);
    f.br(2);
    f.end();

    f.lg(0);
    f.i32c(code_lo as i32);
    f.op(I32_SUB);
    f.mem(I32_LOAD, 2, layout.callmap);
    f.ls(34);
    f.lg(34);
    f.op(I32_EQZ);
    f.op(IF);
    f.body.push(0x40);
    f.i32c(2);
    f.ls(36);
    f.br(2);
    f.end();

    // block index = word >> 16, region slot = (word & 0xffff) - 1
    f.lg(34);
    f.i32c(16);
    f.op(I32_SHR_U);
    f.ls(37); // entry block
    f.lg(34);
    f.i32c(0xffff);
    f.op(I32_AND);
    f.i32c(1);
    f.op(I32_SUB);
    f.ls(34); // table slot

    for i in 0..31u32 {
        f.lg(2 + i);
    }
    f.lg(1); // sp
    f.lg(33); // nzcv
    f.lg(37); // entry block
    f.lg(34); // table slot, popped by call_indirect last
    f.op(CALL_INDIRECT);
    uleb(&mut f.body, ids.ty_region as u64);
    uleb(&mut f.body, 0);

    f.ls(35); // next
    f.ls(33); // nzcv
    f.ls(1); // sp
    for i in (0..31u32).rev() {
        f.ls(2 + i);
    }

    f.lg(35);
    f.op(I32_EQZ);
    f.op(IF);
    f.body.push(0x40);
    f.i32c(0);
    f.ls(36);
    f.br(2);
    f.end();

    f.lg(35);
    f.ls(0);
    f.br(0);
    f.end(); // loop
    f.end(); // exit block

    for i in 0..31u32 {
        f.i32c(SHADOW as i32 + (i as i32) * 8);
        f.lg(2 + i);
        f.mem(I64_STORE, 3, 0);
    }
    f.i32c(SHADOW_SP as i32);
    f.lg(1);
    f.mem(I64_STORE, 3, 0);
    f.i32c(SHADOW_NZCV as i32);
    f.lg(33);
    f.mem(I64_STORE, 3, 0);
    f.i32c(SHADOW_PC as i32);
    f.lg(0);
    f.mem(I32_STORE, 2, 0);
    f.lg(36);
    f
}

// ---------------------------------------------------------------- region bodies
//
// Invariant: a register local always holds the architecturally correct 64-bit value, so the top 32
// bits of a register are zero after any W-register write. An operation knows its own width, and a
// 32-bit operation masks its result before storing.

struct RegionEmitter<'a> {
    f: Func,
    region: &'a Region,
    layout: &'a Layout,
    ids: &'a Ids,
    open: u32,
    cur_pc: u64,
}

impl<'a> RegionEmitter<'a> {
    fn new(region: &'a Region, layout: &'a Layout, ids: &'a Ids) -> Self {
        let mut f = Func::new(ids.ty_region);
        f.locals = vec![I32, I64, I64, I64, I64, I64, I32];
        RegionEmitter { f, region, layout, ids, open: 0, cur_pc: 0 }
    }

    fn emit(mut self) -> Result<Func, String> {
        let n = self.region.blocks.len();
        self.f.lg(P_ENTRY);
        self.f.ls(L_PC);
        // Stack overflow is caught at region entry, which every guest call and return passes.
        self.f.lg(31);
        self.f.i64c(self.layout.stack_floor as i64);
        self.f.op(I64_LT_U);
        self.f.op(IF);
        self.f.body.push(0x40);
        self.f.i32c(2);
        self.f.lg(31);
        self.f.i32c(self.region.blocks[0].addr as i32);
        self.f.call(self.ids.trap);
        self.f.op(UNREACHABLE);
        self.f.end();

        self.f.loop_();
        self.open = 1;
        for _ in 0..n {
            self.f.block();
            self.open += 1;
        }
        self.f.lg(L_PC);
        let labels: Vec<u32> = (0..n as u32).collect();
        self.f.br_table(&labels, 0);
        for i in 0..n {
            self.f.end();
            self.open -= 1;
            self.emit_block(i)?;
        }
        self.f.end();
        self.f.op(UNREACHABLE);
        Ok(self.f)
    }

    fn emit_block(&mut self, i: usize) -> Result<(), String> {
        let insns = self.region.blocks[i].insns.clone();
        let mut next = self.region.blocks[i].addr;
        let mut ended = false;
        for (addr, insn) in insns {
            next = addr + 4;
            if is_terminator(&insn) {
                self.emit_term(addr, insn)?;
                ended = true;
                break;
            }
            self.emit_insn(addr, insn)?;
        }
        if !ended {
            let n = self.region.blocks.len();
            let falls = i + 1 < n && self.region.blocks[i + 1].addr == next;
            if !falls {
                self.emit_jump(next);
            }
        }
        Ok(())
    }

    // ---- value plumbing

    fn get(&mut self, r: u32, sf: bool) {
        if r == 31 {
            if sf {
                self.f.i64c(0);
            } else {
                self.f.i32c(0);
            }
            return;
        }
        self.f.lg(r);
        if !sf {
            self.f.wrap_i64();
        }
    }

    fn set(&mut self, r: u32, sf: bool) {
        if r == 31 {
            self.f.op(DROP);
            return;
        }
        if !sf {
            self.f.extend_i32_u();
        }
        self.f.ls(r);
    }

    /// 31 means SP in the addressing and add/sub-immediate forms.
    fn get_sp(&mut self, r: u32, sf: bool) {
        if r == 31 {
            self.f.lg(31);
        } else {
            self.f.lg(r);
        }
        if !sf {
            self.f.wrap_i64();
        }
    }

    fn set_sp(&mut self, r: u32, sf: bool) {
        if !sf {
            self.f.extend_i32_u();
        }
        if r == 31 {
            self.f.ls(31);
        } else {
            self.f.ls(r);
        }
    }

    /// Stack top is 32-bit; widen to a zero-extended 64-bit value.
    fn to_i64(&mut self, sf: bool) {
        if !sf {
            self.f.extend_i32_u();
        }
    }

    /// Stack top is 64-bit; truncate to the operation width.
    fn mask_w(&mut self, sf: bool) {
        if !sf {
            self.f.i64c(0xffff_ffff);
            self.f.op(I64_AND);
        }
    }

    fn width_mask(&self, sf: bool) -> i64 {
        if sf {
            -1
        } else {
            0xffff_ffff
        }
    }

    fn store_t0(&mut self, rd: u32, sf: bool, is_sp: bool) {
        self.f.lg(L_T0);
        self.mask_w(sf);
        if rd == 31 {
            if is_sp {
                self.f.ls(31);
            } else {
                self.f.op(DROP);
            }
        } else {
            self.f.ls(rd);
        }
    }

    /// Results are (33 x i64, i32 next pc), so the register file goes first and the next pc last.
    fn begin_return(&mut self) {
        for r in 0..NR {
            self.f.lg(r);
        }
    }

    fn end_return(&mut self) {
        self.f.op(RETURN);
    }

    fn emit_return_const(&mut self, target: u64) {
        self.begin_return();
        self.f.i64c(target as i64);
        self.f.wrap_i64();
        self.end_return();
    }

    fn emit_return_reg(&mut self, r: u32) {
        self.begin_return();
        if r == 31 {
            self.f.i64c(0);
        } else {
            self.f.lg(r);
        }
        self.f.wrap_i64();
        self.end_return();
    }

    fn emit_jump(&mut self, target: u64) {
        if let Some(&idx) = self.region.index_of.get(&target) {
            self.f.i32c(idx as i32);
            self.f.ls(L_PC);
            let depth = self.open - 1;
            self.f.br(depth);
        } else {
            self.emit_return_const(target);
        }
    }

    fn open_if(&mut self) {
        self.f.op(IF);
        self.f.body.push(0x40);
        self.open += 1;
    }

    fn close_if(&mut self) {
        self.f.end();
        self.open -= 1;
    }

    fn emit_term(&mut self, addr: u64, insn: Insn) -> Result<(), String> {
        match insn {
            Insn::B { offset } => self.emit_jump((addr as i64 + offset) as u64),
            Insn::Bl { offset } => {
                let t = (addr as i64 + offset) as u64;
                self.f.i64c((addr + 4) as i64);
                self.f.ls(30);
                self.emit_return_const(t);
            }
            Insn::BCond { cond, offset } => {
                let t = (addr as i64 + offset) as u64;
                self.push_cond(cond);
                self.open_if();
                self.emit_jump(t);
                self.close_if();
            }
            Insn::Cbz { sf, nonzero, rt, offset } => {
                let t = (addr as i64 + offset) as u64;
                self.get(rt, sf);
                self.f.op(if sf { I64_EQZ } else { I32_EQZ });
                if nonzero {
                    self.f.op(I32_EQZ);
                }
                self.open_if();
                self.emit_jump(t);
                self.close_if();
            }
            Insn::Tbz { nonzero, bit, rt, offset } => {
                let t = (addr as i64 + offset) as u64;
                self.f.lg(rt);
                self.f.i64c(bit as i64);
                self.f.op(I64_SHR_U);
                self.f.i64c(1);
                self.f.op(I64_AND);
                self.f.i64c(0);
                self.f.op(I64_NE);
                if !nonzero {
                    self.f.op(I32_EQZ);
                }
                self.open_if();
                self.emit_jump(t);
                self.close_if();
            }
            Insn::Br { rn } | Insn::Ret { rn } => self.emit_return_reg(rn),
            Insn::Blr { rn } => {
                self.f.i64c((addr + 4) as i64);
                self.f.ls(30);
                self.emit_return_reg(rn);
            }
            _ => return Err(format!("not a terminator at 0x{addr:x}")),
        }
        Ok(())
    }

    // ---- condition codes

    fn cond_bit(&mut self, mask: i64) {
        self.f.lg(32);
        self.f.i64c(mask);
        self.f.op(I64_AND);
        self.f.i64c(0);
        self.f.op(I64_NE);
    }

    fn push_cond(&mut self, cond: u32) {
        match cond {
            0 => self.cond_bit(4),
            1 => {
                self.cond_bit(4);
                self.f.op(I32_EQZ);
            }
            2 => self.cond_bit(2),
            3 => {
                self.cond_bit(2);
                self.f.op(I32_EQZ);
            }
            4 => self.cond_bit(8),
            5 => {
                self.cond_bit(8);
                self.f.op(I32_EQZ);
            }
            6 => self.cond_bit(1),
            7 => {
                self.cond_bit(1);
                self.f.op(I32_EQZ);
            }
            8 => {
                self.cond_bit(2);
                self.cond_bit(4);
                self.f.op(I32_EQZ);
                self.f.op(I32_AND);
            }
            9 => {
                self.cond_bit(2);
                self.f.op(I32_EQZ);
                self.cond_bit(4);
                self.f.op(I32_OR);
            }
            10 => {
                self.cond_bit(8);
                self.cond_bit(1);
                self.f.op(I32_EQ);
            }
            11 => {
                self.cond_bit(8);
                self.cond_bit(1);
                self.f.op(I32_EQ);
                self.f.op(I32_EQZ);
            }
            12 => {
                self.cond_bit(8);
                self.cond_bit(1);
                self.f.op(I32_EQ);
                self.cond_bit(4);
                self.f.op(I32_EQZ);
                self.f.op(I32_AND);
            }
            13 => {
                self.cond_bit(8);
                self.cond_bit(1);
                self.f.op(I32_EQ);
                self.f.op(I32_EQZ);
                self.cond_bit(4);
                self.f.op(I32_OR);
            }
            _ => {
                self.f.i32c(1);
            }
        }
    }

    // ---- flags: packed as N<<3 | Z<<2 | C<<1 | V
    //
    // T0 holds the result masked to the operation width, T1 the first operand, T2 the second, both
    // zero-extended. Unsigned comparisons on zero-extended values are the width's comparisons.

    fn flags_zd(&mut self, sf: bool) {
        let shift = if sf { 63 } else { 31 };
        // N
        self.f.lg(L_T0);
        self.f.i64c(shift);
        self.f.op(I64_SHR_U);
        self.f.i64c(1);
        self.f.op(I64_AND);
        self.f.i64c(3);
        self.f.op(I64_SHL);
        // Z
        self.f.lg(L_T0);
        self.f.op(I64_EQZ);
        self.f.op(I64_EXTEND_I32_U);
        self.f.i64c(2);
        self.f.op(I64_SHL);
        self.f.op(I64_OR);
    }

    fn flags_addsub(&mut self, sf: bool, sub: bool) {
        let shift = if sf { 63 } else { 31 };
        self.flags_zd(sf);
        // C
        if sub {
            self.f.lg(L_T1);
            self.f.lg(L_T2);
            self.f.op(I64_GE_U);
        } else {
            self.f.lg(L_T0);
            self.f.lg(L_T1);
            self.f.op(I64_LT_U);
        }
        self.f.op(I64_EXTEND_I32_U);
        self.f.i64c(1);
        self.f.op(I64_SHL);
        self.f.op(I64_OR);
        // V
        if sub {
            self.f.lg(L_T1);
            self.f.lg(L_T2);
            self.f.op(I64_XOR);
            self.f.lg(L_T1);
            self.f.lg(L_T0);
            self.f.op(I64_XOR);
            self.f.op(I64_AND);
        } else {
            self.f.lg(L_T1);
            self.f.lg(L_T0);
            self.f.op(I64_XOR);
            self.f.lg(L_T2);
            self.f.lg(L_T0);
            self.f.op(I64_XOR);
            self.f.op(I64_AND);
        }
        self.f.i64c(shift);
        self.f.op(I64_SHR_U);
        self.f.i64c(1);
        self.f.op(I64_AND);
        self.f.op(I64_OR);
        self.f.ls(32);
    }

    fn flags_logic(&mut self, sf: bool) {
        self.flags_zd(sf);
        self.f.ls(32);
    }

    /// a and b into T1/T2 as zero-extended i64, result into T0 masked to width.
    fn addsub_into_t0(&mut self, sf: bool, sub: bool) {
        self.f.lg(L_T1);
        self.f.lg(L_T2);
        self.f.op(if sub { I64_SUB } else { I64_ADD });
        self.mask_w(sf);
        self.f.ls(L_T0);
    }

    // ---- shifts and extensions

    fn push_shifted(&mut self, r: u32, shift: Shift, amount: u32, sf: bool) {
        self.get(r, sf);
        if amount % if sf { 64 } else { 32 } == 0 {
            return;
        }
        self.push_imm(amount as u64, sf);
        self.f.op(match (shift, sf) {
            (Shift::Lsl, true) => I64_SHL,
            (Shift::Lsr, true) => I64_SHR_U,
            (Shift::Asr, true) => I64_SHR_S,
            (Shift::Ror, true) => I64_ROTR,
            (Shift::Lsl, false) => I32_SHL,
            (Shift::Lsr, false) => I32_SHR_U,
            (Shift::Asr, false) => I32_SHR_S,
            (Shift::Ror, false) => I32_ROTR,
        });
    }

    /// Extended register operand, always as a 64-bit value.
    fn push_extended(&mut self, r: u32, ext: Extend) {
        match ext {
            Extend::Uxtb | Extend::Uxth => {
                self.get(r, false);
                self.f.i32c(if ext == Extend::Uxtb { 0xff } else { 0xffff });
                self.f.op(I32_AND);
                self.f.op(I64_EXTEND_I32_U);
            }
            Extend::Uxtw => {
                self.get(r, false);
                self.f.op(I64_EXTEND_I32_U);
            }
            Extend::Uxtx | Extend::Sxtx => {
                if r == 31 {
                    self.f.i64c(0);
                } else {
                    self.f.lg(r);
                }
            }
            Extend::Sxtb | Extend::Sxth => {
                self.get(r, false);
                let sh = if ext == Extend::Sxtb { 24 } else { 16 };
                self.f.i32c(sh);
                self.f.op(I32_SHL);
                self.f.i32c(sh);
                self.f.op(I32_SHR_S);
                self.f.op(I64_EXTEND_I32_S);
            }
            Extend::Sxtw => {
                self.get(r, false);
                self.f.op(I64_EXTEND_I32_S);
            }
        }
    }

    // ---- memory

    fn addr_base_off(&mut self, base: u32, offset: i64) {
        if base == 31 {
            self.f.lg(31);
        } else {
            self.f.lg(base);
        }
        if offset != 0 {
            self.f.i64c(offset);
            self.f.op(I64_ADD);
        }
        self.f.ls(L_T1);
    }

    fn addr_base_reg(&mut self, base: u32, rm: u32, option: u32, scaled: bool, size: u32) {
        if base == 31 {
            self.f.lg(31);
        } else {
            self.f.lg(base);
        }
        let ext = match option & 7 {
            0 => Extend::Uxtb,
            1 => Extend::Uxth,
            2 => Extend::Uxtw,
            3 => Extend::Uxtx,
            4 => Extend::Sxtb,
            5 => Extend::Sxth,
            6 => Extend::Sxtw,
            _ => Extend::Sxtx,
        };
        self.push_extended(rm, ext);
        if scaled && size > 0 {
            self.f.i64c(size as i64);
            self.f.op(I64_SHL);
        }
        self.f.op(I64_ADD);
        self.f.ls(L_T1);
    }

    fn check_byte(&mut self, addr: u32, size: u64) {
        if !self.layout.bounds_check {
            return;
        }
        self.f.lg(addr);
        self.f.i64c((self.layout.mem_size - size) as i64);
        self.f.op(I64_GT_U);
        self.open_if();
        self.f.i32c(1);
        self.f.lg(addr);
        self.f.i32c(self.cur_pc as i32);
        self.f.call(self.ids.trap);
        self.f.op(UNREACHABLE);
        self.close_if();
    }

    fn emit_load(&mut self, addr: u32, size: u32, opc: u32, rt: u32) {
        self.check_byte(addr, 1u64 << size);
        self.f.lg(addr);
        self.f.wrap_i64();
        match (size, opc) {
            (0, 1) => {
                self.f.mem(I32_LOAD8_U, 0, 0);
                self.set(rt, false);
            }
            (1, 1) => {
                self.f.mem(I32_LOAD16_U, 1, 0);
                self.set(rt, false);
            }
            (2, 1) => {
                self.f.mem(I32_LOAD, 2, 0);
                self.set(rt, false);
            }
            (3, 1) => {
                self.f.mem(I64_LOAD, 3, 0);
                self.set(rt, true);
            }
            (0, 2) => {
                self.f.mem(I32_LOAD8_S, 0, 0);
                self.set(rt, false);
            }
            (1, 2) => {
                self.f.mem(I32_LOAD16_S, 1, 0);
                self.set(rt, false);
            }
            (2, 2) => {
                self.f.mem(I64_LOAD32_S, 2, 0);
                self.set(rt, true);
            }
            (0, 3) => {
                self.f.mem(I64_LOAD8_S, 0, 0);
                self.set(rt, true);
            }
            (1, 3) => {
                self.f.mem(I64_LOAD16_S, 1, 0);
                self.set(rt, true);
            }
            _ => unreachable!("load size/opc {size}/{opc}"),
        }
    }

    fn emit_store(&mut self, addr: u32, size: u32, rt: u32) {
        self.check_byte(addr, 1u64 << size);
        self.f.lg(addr);
        self.f.wrap_i64();
        match size {
            0 => {
                self.get(rt, false);
                self.f.mem(I32_STORE8, 0, 0);
            }
            1 => {
                self.get(rt, false);
                self.f.mem(I32_STORE16, 1, 0);
            }
            2 => {
                self.get(rt, false);
                self.f.mem(I32_STORE, 2, 0);
            }
            _ => {
                self.get(rt, true);
                self.f.mem(I64_STORE, 3, 0);
            }
        }
    }

    // ---- instructions

    fn emit_insn(&mut self, addr: u64, insn: Insn) -> Result<(), String> {
        self.cur_pc = addr;
        if let Some(t) = self.ids.trace {
            for r in 0..NR {
                self.f.i32c(SHADOW as i32 + (r as i32) * 8);
                self.f.lg(r);
                self.f.mem(I64_STORE, 3, 0);
            }
            self.f.i32c(SHADOW_PC as i32);
            self.f.i32c(addr as i32);
            self.f.mem(I32_STORE, 2, 0);
            self.f.i32c(addr as i32);
            self.f.lg(31);
            self.f.call(t);
        }
        match insn {
            Insn::Hint => {}
            Insn::Undefined => {
                let raw = u32::from_le_bytes([0, 0, 0, 0]);
                let _ = raw;
                return Err(format!("unsupported instruction at 0x{addr:x}"));
            }
            Insn::Adr { rd, imm } => {
                if rd != 31 {
                    self.f.i64c((addr as i64).wrapping_add(imm));
                    self.f.ls(rd);
                }
            }
            Insn::Adrp { rd, imm } => {
                if rd != 31 {
                    self.f.i64c(((addr & !0xfff) as i64).wrapping_add(imm << 12));
                    self.f.ls(rd);
                }
            }
            Insn::AddSubImm { sf, sub, setflags, shift, imm, rn, rd } => {
                let imm = if shift == 1 { imm << 12 } else { imm };
                let imm = imm & if sf { u64::MAX } else { 0xffff_ffff };
                if setflags {
                    self.get_sp(rn, sf);
                    self.to_i64(sf);
                    self.f.ls(L_T1);
                    self.f.i64c(imm as i64);
                    self.f.ls(L_T2);
                    self.addsub_into_t0(sf, sub);
                    self.flags_addsub(sf, sub);
                    // with S=1 a destination of 31 is XZR, not SP
                    self.store_t0(rd, sf, false);
                } else {
                    self.get_sp(rn, sf);
                    self.push_imm(imm, sf);
                    self.f.op(match (sub, sf) {
                        (true, true) => I64_SUB,
                        (true, false) => I32_SUB,
                        (false, true) => I64_ADD,
                        (false, false) => I32_ADD,
                    });
                    self.set_sp(rd, sf);
                }
            }
            Insn::LogicalImm { sf, opc, imm, rn, rd } => {
                self.get(rn, sf);
                self.push_imm(imm, sf);
                self.f.op(match (opc, sf) {
                    (0 | 3, true) => I64_AND,
                    (0 | 3, false) => I32_AND,
                    (1, true) => I64_OR,
                    (1, false) => I32_OR,
                    (_, true) => I64_XOR,
                    (_, false) => I32_XOR,
                });
                if opc == 3 {
                    self.to_i64(sf);
                    self.f.ls(L_T0);
                    self.flags_logic(sf);
                    self.store_t0(rd, sf, false);
                } else {
                    self.set(rd, sf);
                }
            }
            Insn::MoveWide { sf, opc, hw, imm16, rd } => {
                let mask = if sf { u64::MAX } else { 0xffff_ffff };
                let value = (imm16 << (hw * 16)) & mask;
                match opc {
                    0 => {
                        if rd != 31 {
                            self.f.i64c((!value & mask) as i64);
                            self.f.ls(rd);
                        }
                    }
                    2 => {
                        if rd != 31 {
                            self.f.i64c(value as i64);
                            self.f.ls(rd);
                        }
                    }
                    3 => {
                        if rd != 31 {
                            self.f.lg(rd);
                            self.f.i64c((!(0xffffu64 << (hw * 16)) & mask) as i64);
                            self.f.op(I64_AND);
                            self.f.i64c(value as i64);
                            self.f.op(I64_OR);
                            self.f.ls(rd);
                        }
                    }
                    _ => return Err(format!("unallocated move-wide at 0x{addr:x}")),
                }
            }
            Insn::Bitfield { sf, opc, n, immr, imms, rn, rd } => {
                let w: u32 = if sf { 64 } else { 32 };
                if n != sf as u32 || immr >= w || imms >= w {
                    return Err(format!("invalid bitfield at 0x{addr:x}"));
                }
                let (len, middle) = if imms >= immr {
                    (imms - immr + 1, false)
                } else {
                    (imms + 1 + w - immr, true)
                };
                let mask: u64 = if len >= 64 { u64::MAX } else { (1u64 << len) - 1 };
                // field into T0
                if rn == 31 {
                    self.f.i64c(0);
                } else {
                    self.f.lg(rn);
                }
                self.mask_w(sf);
                if immr != 0 {
                    self.f.i64c(immr as i64);
                    self.f.op(I64_SHR_U);
                }
                if middle {
                    if rn == 31 {
                        self.f.i64c(0);
                    } else {
                        self.f.lg(rn);
                    }
                    self.mask_w(sf);
                    self.f.i64c((w - immr) as i64);
                    self.f.op(I64_SHL);
                    self.mask_w(sf);
                    self.f.op(I64_OR);
                }
                self.f.i64c(mask as i64);
                self.f.op(I64_AND);
                self.f.ls(L_T0);
                match opc {
                    0 => {
                        if len < w {
                            let sh = w - len;
                            self.f.lg(L_T0);
                            self.f.i64c(sh as i64);
                            self.f.op(I64_SHL);
                            self.f.i64c(sh as i64);
                            self.f.op(I64_SHR_S);
                            self.f.ls(L_T0);
                        }
                        if rd != 31 {
                            self.f.lg(L_T0);
                            self.mask_w(sf);
                            self.f.ls(rd);
                        }
                    }
                    2 => {
                        if rd != 31 {
                            self.f.lg(L_T0);
                            self.f.ls(rd);
                        }
                    }
                    1 => {
                        if rd != 31 {
                            self.f.lg(rd);
                            self.f.i64c(!mask as i64);
                            self.f.op(I64_AND);
                            self.f.lg(L_T0);
                            self.f.op(I64_OR);
                            self.mask_w(sf);
                            self.f.ls(rd);
                        }
                    }
                    _ => return Err(format!("unallocated bitfield at 0x{addr:x}")),
                }
            }
            Insn::Extract { sf, rm, lsb, rn, rd } => {
                let w: u32 = if sf { 64 } else { 32 };
                if lsb >= w {
                    return Err(format!("invalid extr at 0x{addr:x}"));
                }
                if rn == rm {
                    self.f.lg(rn);
                    if !sf {
                        self.f.i64c(0xffff_ffff);
                        self.f.op(I64_AND);
                    }
                    if lsb != 0 {
                        self.f.i64c(lsb as i64);
                        self.f.op(I64_ROTR);
                    }
                } else if lsb == 0 {
                    self.f.lg(rn);
                } else {
                    self.f.lg(rn);
                    self.f.i64c(lsb as i64);
                    self.f.op(I64_SHR_U);
                    self.f.lg(rm);
                    self.f.i64c((w - lsb) as i64);
                    self.f.op(I64_SHL);
                    self.f.op(I64_OR);
                }
                if rd != 31 {
                    self.mask_w(sf);
                    self.f.ls(rd);
                } else {
                    self.f.op(DROP);
                }
            }
            Insn::OneSource { sf, op, rn, rd } => {
                if rd == 31 {
                    return Ok(());
                }
                match op {
                    4 => {
                        self.get(rn, sf);
                        self.f.op(if sf { I64_CLZ } else { I32_CLZ });
                        self.set(rd, sf);
                    }
                    0 => {
                        self.f.lg(rn);
                        self.f.call(self.ids.rbit64);
                        if !sf {
                            self.f.i64c(32);
                            self.f.op(I64_SHR_U);
                            self.mask_w(false);
                        }
                        self.f.ls(rd);
                    }
                    1 => {
                        let (m1, m2) = if sf {
                            (0x00ff_00ff_00ff_00ffu64, 0xff00_ff00_ff00_ff00u64)
                        } else {
                            (0x00ff_00ffu64, 0xff00_ff00u64)
                        };
                        self.f.lg(rn);
                        self.f.i64c(m1 as i64);
                        self.f.op(I64_AND);
                        self.f.i64c(8);
                        self.f.op(I64_SHL);
                        self.f.lg(rn);
                        self.f.i64c(m2 as i64);
                        self.f.op(I64_AND);
                        self.f.i64c(8);
                        self.f.op(I64_SHR_U);
                        self.f.op(I64_OR);
                        self.mask_w(sf);
                        self.f.ls(rd);
                    }
                    2 => {
                        self.f.lg(rn);
                        if sf {
                            self.f.call(self.ids.bswap64);
                            self.f.i64c(32);
                            self.f.op(I64_ROTL);
                        } else {
                            self.f.call(self.ids.bswap32);
                        }
                        self.f.ls(rd);
                    }
                    _ => {
                        self.f.lg(rn);
                        self.f.call(if sf { self.ids.bswap64 } else { self.ids.bswap32 });
                        self.f.ls(rd);
                    }
                }
            }
            Insn::Div { sf, signed, rn, rm, rd } => {
                if rf(rd) {
                    if signed {
                        self.get(rn, sf);
                        if !sf {
                            self.f.op(I64_EXTEND_I32_S);
                        }
                        self.get(rm, sf);
                        if !sf {
                            self.f.op(I64_EXTEND_I32_S);
                        }
                        self.f.call(self.ids.sdiv);
                    } else {
                        self.get(rn, sf);
                        self.to_i64(sf);
                        self.get(rm, sf);
                        self.to_i64(sf);
                        self.f.call(self.ids.udiv);
                    }
                    self.mask_w(sf);
                    self.f.ls(rd);
                }
            }
            Insn::ShiftReg { sf, op, rn, rm, rd } => {
                self.get(rn, sf);
                self.get(rm, sf);
                self.f.op(match (op, sf) {
                    (8, true) => I64_SHL,
                    (9, true) => I64_SHR_U,
                    (10, true) => I64_SHR_S,
                    (_, true) => I64_ROTL,
                    (8, false) => I32_SHL,
                    (9, false) => I32_SHR_U,
                    (10, false) => I32_SHR_S,
                    (_, false) => I32_ROTL,
                });
                self.set(rd, sf);
            }
            Insn::MaddMsub { sf, sub, rm, ra, rn, rd } => {
                if sub {
                    self.get(ra, sf);
                    self.get(rn, sf);
                    self.get(rm, sf);
                    self.f.op(if sf { I64_MUL } else { I32_MUL });
                    self.f.op(if sf { I64_SUB } else { I32_SUB });
                } else {
                    self.get(rn, sf);
                    self.get(rm, sf);
                    self.f.op(if sf { I64_MUL } else { I32_MUL });
                    self.get(ra, sf);
                    self.f.op(if sf { I64_ADD } else { I32_ADD });
                }
                self.set(rd, sf);
            }
            Insn::MulHigh { sf, signed, rn, rm, rd } => {
                if !sf {
                    return Err(format!("smulh/umulh only exist in 64-bit form at 0x{addr:x}"));
                }
                if rd != 31 {
                    self.f.lg(rn);
                    self.f.lg(rm);
                    self.f.call(if signed { self.ids.smulh } else { self.ids.umulh });
                    self.f.ls(rd);
                }
            }
            Insn::AddSubReg { sf, sub, setflags, shift, amount, rm, rn, rd } => {
                if setflags {
                    self.get(rn, sf);
                    self.to_i64(sf);
                    self.f.ls(L_T1);
                    self.push_shifted(rm, shift, amount, sf);
                    self.to_i64(sf);
                    self.f.ls(L_T2);
                    self.addsub_into_t0(sf, sub);
                    self.flags_addsub(sf, sub);
                    self.store_t0(rd, sf, false);
                } else {
                    self.get(rn, sf);
                    self.push_shifted(rm, shift, amount, sf);
                    self.f.op(if sub { if sf { I64_SUB } else { I32_SUB } } else if sf { I64_ADD } else { I32_ADD });
                    self.set(rd, sf);
                }
            }
            Insn::AddSubExt { sf, sub, setflags, extend, amount, rm, rn, rd } => {
                if setflags {
                    self.get(rn, sf);
                    self.to_i64(sf);
                    self.f.ls(L_T1);
                    self.push_extended(rm, extend);
                    if amount != 0 {
                        self.f.i64c(amount as i64);
                        self.f.op(I64_SHL);
                    }
                    self.f.ls(L_T2);
                    self.addsub_into_t0(sf, sub);
                    self.flags_addsub(sf, sub);
                    self.store_t0(rd, sf, false);
                } else {
                    self.get(rn, sf);
                    self.to_i64(sf);
                    self.push_extended(rm, extend);
                    if amount != 0 {
                        self.f.i64c(amount as i64);
                        self.f.op(I64_SHL);
                    }
                    self.f.op(if sub { I64_SUB } else { I64_ADD });
                    self.mask_w(sf);
                    if rd == 31 {
                        self.f.op(DROP);
                    } else {
                        self.f.ls(rd);
                    }
                }
            }
            Insn::AddSubCarry { sf, sub, setflags, rm, rn, rd } => {
                if rd == 31 && !setflags {
                    return Ok(());
                }
                let wmask = self.width_mask(sf);
                // T1 = a, T4 = b original, T2 = operand (inverted for sbc), T3 = carry in
                self.get(rn, sf);
                self.to_i64(sf);
                self.f.ls(L_T1);
                self.get(rm, sf);
                self.to_i64(sf);
                self.f.ls(L_T4);
                self.f.lg(L_T4);
                if sub {
                    self.f.i64c(wmask);
                    self.f.op(I64_XOR);
                }
                self.f.ls(L_T2);
                self.f.lg(32);
                self.f.i64c(1);
                self.f.op(I64_SHR_U);
                self.f.i64c(1);
                self.f.op(I64_AND);
                self.f.ls(L_T3);
                // T0 = partial = a + b
                self.addsub_into_t0(sf, false);
                // carry out = (partial < a) | (res < partial), res = (partial + carry) & mask
                self.f.lg(L_T0);
                self.f.lg(L_T1);
                self.f.op(I64_LT_U);
                self.f.lg(L_T0);
                self.f.lg(L_T3);
                self.f.op(I64_ADD);
                self.mask_w(sf);
                self.f.ls(L_T2); // res temporarily in T2
                self.f.lg(L_T2);
                self.f.lg(L_T0);
                self.f.op(I64_LT_U);
                self.f.op(I32_OR);
                self.f.op(I64_EXTEND_I32_U);
                self.f.ls(L_T3); // carry out
                if setflags {
                    // T0 = res, T1 = a, T2 = b for the flag formulas
                    self.f.lg(L_T2);
                    self.f.ls(L_T0);
                    self.f.lg(L_T4);
                    self.f.ls(L_T2);
                    self.flags_addsub(sf, sub);
                    // overwrite C with the two-step carry
                    self.f.lg(32);
                    self.f.i64c(!2);
                    self.f.op(I64_AND);
                    self.f.lg(L_T3);
                    self.f.i64c(1);
                    self.f.op(I64_SHL);
                    self.f.op(I64_OR);
                    self.f.ls(32);
                }
                if rd != 31 {
                    self.f.lg(L_T2);
                    self.mask_w(sf);
                    self.f.ls(rd);
                }
            }
            Insn::LogicalReg { sf, opc, invert, shift, amount, rm, rn, rd } => {
                self.get(rn, sf);
                self.push_shifted(rm, shift, amount, sf);
                if invert {
                    self.push_imm(self.width_mask(sf) as u64, sf);
                    self.f.op(if sf { I64_XOR } else { I32_XOR });
                }
                self.f.op(match (opc, sf) {
                    (0 | 3, true) => I64_AND,
                    (0 | 3, false) => I32_AND,
                    (1, true) => I64_OR,
                    (1, false) => I32_OR,
                    (_, true) => I64_XOR,
                    (_, false) => I32_XOR,
                });
                if opc == 3 {
                    self.to_i64(sf);
                    self.f.ls(L_T0);
                    self.flags_logic(sf);
                    self.store_t0(rd, sf, false);
                } else {
                    self.set(rd, sf);
                }
            }
            Insn::CondSelect { sf, op2, rm, cond, rn, rd } => {
                if rd == 31 {
                    return Ok(());
                }
                self.push_cond(cond);
                self.f.op(IF);
                self.f.body.push(if sf { I64 } else { I32 });
                self.get(rn, sf);
                self.f.op(ELSE);
                self.get(rm, sf);
                match op2 {
                    1 => {
                        self.push_imm(1, sf);
                        self.f.op(if sf { I64_OR } else { I32_OR });
                    }
                    2 => {
                        self.push_imm(self.width_mask(sf) as u64, sf);
                        self.f.op(if sf { I64_XOR } else { I32_XOR });
                    }
                    3 => {
                        self.push_imm(0, sf);
                        self.f.op(if sf { I64_SUB } else { I32_SUB });
                    }
                    _ => {}
                }
                self.f.end();
                self.set(rd, sf);
            }
            Insn::CondCompare { sf, sub, reg, rm_or_imm, nzcv, cond, rn } => {
                self.push_cond(cond);
                self.open_if();
                self.get(rn, sf);
                self.to_i64(sf);
                self.f.ls(L_T1);
                if reg {
                    self.get(rm_or_imm, sf);
                    self.to_i64(sf);
                    self.f.ls(L_T2);
                } else {
                    self.f.i64c(rm_or_imm as i64);
                    self.f.ls(L_T2);
                }
                self.addsub_into_t0(sf, sub);
                self.flags_addsub(sf, sub);
                self.f.op(ELSE);
                self.f.i64c(nzcv as i64);
                self.f.ls(32);
                self.f.end();
                self.open -= 1;
            }
            Insn::LoadStore { size, is_load, opc, mode, offset, rn, rt, rm, option, scaled } => {
                let mut writeback = None;
                match mode {
                    LsMode::Unsigned | LsMode::Unscaled => self.addr_base_off(rn, offset),
                    LsMode::PreIndex => {
                        self.addr_base_off(rn, offset);
                        writeback = Some(0i64);
                    }
                    LsMode::PostIndex => {
                        self.addr_base_off(rn, 0);
                        writeback = Some(offset);
                    }
                    LsMode::Register => self.addr_base_reg(rn, rm, option, scaled, size),
                }
                if is_load {
                    self.emit_load(L_T1, size, opc, rt);
                } else {
                    self.emit_store(L_T1, size, rt);
                }
                if let Some(extra) = writeback {
                    self.f.lg(L_T1);
                    if extra != 0 {
                        self.f.i64c(extra);
                        self.f.op(I64_ADD);
                    }
                    if rn == 31 {
                        self.f.ls(31);
                    } else {
                        self.f.ls(rn);
                    }
                }
            }
            Insn::LoadStorePair { is_load, mode, offset, rn, rt, rt2, width, signed_word } => {
                let base_off = if mode == PairMode::PostIndex { 0 } else { offset };
                self.addr_base_off(rn, base_off);
                let elem = (width / 8) as i64;
                self.emit_load_or_store_pair(is_load, width, signed_word, L_T1, rt);
                self.f.lg(L_T1);
                self.f.i64c(elem);
                self.f.op(I64_ADD);
                self.f.ls(L_T2);
                self.emit_load_or_store_pair(is_load, width, signed_word, L_T2, rt2);
                match mode {
                    PairMode::Offset => {}
                    PairMode::PreIndex => {
                        self.f.lg(L_T1);
                        if rn == 31 {
                            self.f.ls(31);
                        } else {
                            self.f.ls(rn);
                        }
                    }
                    PairMode::PostIndex => {
                        self.f.lg(L_T1);
                        self.f.i64c(offset);
                        self.f.op(I64_ADD);
                        if rn == 31 {
                            self.f.ls(31);
                        } else {
                            self.f.ls(rn);
                        }
                    }
                }
            }
            Insn::Literal { sf, offset, rt } => {
                let target = (addr as i64 + offset) as u64;
                self.f.i64c(target as i64);
                self.f.ls(L_T1);
                self.emit_load(L_T1, if sf { 3 } else { 2 }, 1, rt);
            }
            Insn::Svc => {
                self.f.lg(8);
                for i in 0..6u32 {
                    self.f.lg(i);
                }
                self.f.call(self.ids.syscall);
                self.f.ls(L_TI);
                self.f.ls(L_T0);
                self.f.lg(L_TI);
                self.open_if();
                self.begin_return();
                self.f.i32c(0);
                self.end_return();
                self.close_if();
                if self.f.body.last() == Some(&UNREACHABLE) {}
                self.f.lg(L_T0);
                self.f.ls(0);
            }
            Insn::MrsTpidr { rd } => {
                if rd != 31 {
                    self.f.i32c(SHADOW_TP as i32);
                    self.f.mem(I64_LOAD, 3, 0);
                    self.f.ls(rd);
                }
            }
            Insn::MsrTpidr { rn } => {
                self.f.i32c(SHADOW_TP as i32);
                if rn == 31 {
                    self.f.i64c(0);
                } else {
                    self.f.lg(rn);
                }
                self.f.mem(I64_STORE, 3, 0);
            }
            Insn::B { .. }
            | Insn::Bl { .. }
            | Insn::BCond { .. }
            | Insn::Cbz { .. }
            | Insn::Tbz { .. }
            | Insn::Br { .. }
            | Insn::Blr { .. }
            | Insn::Ret { .. } => unreachable!("terminator reached emit_insn"),
        }
        Ok(())
    }

    fn emit_load_or_store_pair(&mut self, is_load: bool, width: u32, signed_word: bool, addr: u32, r: u32) {
        if is_load {
            if signed_word {
                self.check_byte(addr, 4);
                self.f.lg(addr);
                self.f.wrap_i64();
                self.f.mem(I64_LOAD32_S, 2, 0);
                self.set(r, true);
            } else if width == 64 {
                self.emit_load(addr, 3, 1, r);
            } else {
                self.emit_load(addr, 2, 1, r);
            }
        } else if width == 64 {
            self.emit_store(addr, 3, r);
        } else {
            self.emit_store(addr, 2, r);
        }
    }

    fn push_imm(&mut self, imm: u64, sf: bool) {
        if sf {
            self.f.i64c(imm as i64);
        } else {
            self.f.i32c(imm as u32 as i32);
        }
    }
}

fn rf(r: u32) -> bool {
    r != 31
}
