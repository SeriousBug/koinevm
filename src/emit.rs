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
use crate::elf::{Elf, PF_W, PF_X};
use crate::wasm::op::*;
use crate::wasm::*;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

pub const NR: u32 = 33; // x0..x30 (0..30), sp (31), nzcv (32)
/// v0..v31, the SIMD/FP register file: 128-bit values, first vector parameter at NVEC0.
pub const NVEC: u32 = 32;
pub const NVEC0: u32 = NR; // 33
/// The last parameter of a region is the block index to start at, so a guest return can resume at
/// any block rather than only at the region entry.
pub const P_ENTRY: u32 = NR + NVEC; // 65
pub const L_PC: u32 = P_ENTRY + 1; // 66
pub const L_T0: u32 = L_PC + 1;
pub const L_T1: u32 = L_T0 + 1;
pub const L_T2: u32 = L_T1 + 1;
pub const L_T3: u32 = L_T2 + 1;
pub const L_T4: u32 = L_T3 + 1;
pub const L_TI: u32 = L_T4 + 1;
/// The scratch 128-bit values for the sequences that need more than one vector live at a time.
pub const L_V0: u32 = L_TI + 1;
pub const L_V1: u32 = L_V0 + 1;
pub const L_V2: u32 = L_V1 + 1;
pub const L_V3: u32 = L_V2 + 1;
pub const L_V4: u32 = L_V3 + 1;
/// Two scalars wide enough that an f32 can go through them exactly, for the sequences that need a
/// temporary in the middle of a floating point operation.
pub const L_F0: u32 = L_V4 + 1;
pub const L_F1: u32 = L_F0 + 1;
/// Where the trace writes the vector file, one 16-byte value per register.
pub const SHADOW_V0: u64 = 0x600;

pub const SHADOW: u64 = 0x0;
pub const SHADOW_SP: u64 = SHADOW + 31 * 8;
pub const SHADOW_NZCV: u64 = SHADOW_SP + 8;
pub const SHADOW_PC: u64 = SHADOW_NZCV + 8;
pub const SHADOW_TP: u64 = SHADOW_PC + 8;
/// Where the guest continues after a syscall the host had to answer: the instruction after the
/// `svc`, which the run's own exit path cannot report because it names the block it was in.
pub const SHADOW_RESUME: u64 = 0x118;
/// Trace mode ring buffer of dispatched guest pcs: a count at RING_IDX and 256 slots at RING.
pub const RING_IDX: u64 = 0x1fc;
pub const RING: u64 = 0x200;
/// FPCR and FPSR live where a guest read returns what a guest write put there.
pub const SHADOW_FPCR: u64 = 0x120;
pub const SHADOW_FPSR: u64 = 0x128;
/// What the guest is told about the machine. DCZID_EL0 has DZP set, so no `dc zva` in `memset`.
/// The cache line is 64 bytes. ID registers describe plain AArch64 with FP and ASIMD, and no LSE,
/// no crypto, no SVE.
pub const CTR_EL0_VALUE: u64 = 0x8444_c004;
pub const DCZID_EL0_VALUE: u64 = 0x10;
pub const MIDR_EL1_VALUE: u64 = 0x410f_d034;
pub const ID_AA64PFR0_VALUE: u64 = 0x0000_0000_00ff_0011;
pub const ID_AA64ISAR0_VALUE: u64 = 0;
/// End of the control block. Everything below IMAGE_BASE is engine memory the guest never sees.
pub const ENGINE_HI: u64 = 0x1000;

// Address space plan. The guest's whole map is the linear memory, so the layout is fixed and the
// same for every process: control block, soft page table, dispatch table, images, heap, stack.
//
//   0x00000000  control block: register shadow, trace ring
//   0x00001000  soft page table, one byte per 4 KiB page (1 MiB, covers 4 GiB)
//   0x00400000  images: non-PIE ET_EXEC link here, PIE and shared objects are placed here
//   0x20000000  dispatch table arena (16 MiB: two slots for every block an image may hold)
//   ...         heap grows up from the end of the images, mmap areas grow down from the stack
//   mem_size - stack reserve - 4 KiB   stack, growing down
/// One PTE byte per 4 KiB page.
pub const PTE_BASE: u64 = ENGINE_HI;
pub const PTE_PAGES: u64 = 1 << 20;
/// Halfway up the address space, in the gap between the loader and the arena `mmap` fills: the
/// table is twice the size of the largest image, and where the images go is the toolchain's to
/// choose, so the two cannot share a corner of the map.
pub const TABLE_BASE: u64 = 0x2000_0000;
/// A dispatch slot is `[u32 payload][u32 tag]`: payload 0 is empty, else `block << 16 | region + 1`,
/// tag is `pc >> 2` plus one so it is never zero.
pub const TABLE_SLOT: u64 = 8;
/// The smallest arena any image is given. The table is open-addressed, so it is two slots for every
/// block the image holds and a power of two for the mask, and the host adds blocks later when it
/// translates a page of a library the guest jumps into: the floor is what leaves room for those.
pub const TABLE_MIN_SLOTS: u64 = 1 << 21;
/// The most the arena may grow to. `cc1` is 1373914 blocks, which is more than the floor holds; at
/// four slots a block a gigabyte of code would still fit, and no image this machine runs is that.
pub const TABLE_MAX_SLOTS: u64 = 1 << 23;
/// Region slots in the wasm table: a dispatch word holds `slot + 1` in 16 bits.
pub const TABLE_SLOTS_MAX: u32 = 0xffff;
/// PoC simplification against a real kernel's randomized layout: images start at fixed addresses.
/// The program at 4 MiB, its dynamic loader well above the heap, `mmap` in between.
pub const IMAGE_BASE: u64 = 0x400000;
pub const INTERP_BASE: u64 = 0x1000_0000;
pub const MMAP_BASE: u64 = 0x4000_0000;

pub mod pte {
    pub const MAPPED: u8 = 1;
    pub const WRITABLE: u8 = 2;
    pub const EXECUTABLE: u8 = 4;
    /// The page holds at least one translated block, so `mprotect` or a write has something to drop.
    pub const TRANSLATED: u8 = 8;
}

/// 4 GiB less a page: every guest address is then checked by the engine itself, and an address in
/// the last page traps rather than aliasing.
pub const DEFAULT_MEM_PAGES: u32 = 65535;
pub const STACK_RESERVE: u64 = 8 * 1024 * 1024;

pub struct Config {
    pub bounds_check: bool,
    pub mem_pages: u32,
    /// Write the register shadow on every dispatch, so a trap can report guest state.
    pub trace: bool,
    /// Report every branch and return the guest takes, which is enough to find a loop that never
    /// ends without the cost of tracing every instruction. A loop needs a transfer backwards, and
    /// a transfer is a branch or a return, however the guest reached it.
    pub trace_loops: bool,
    /// Translate what decodes and trap at what does not, instead of refusing the whole image. This
    /// is how `scan` measures the gap, and how a run gets far enough to say what it is missing.
    pub allow_undefined: bool,
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
    pub guest_bytes: usize,
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
    /// Where the dynamic loader was placed, or zero when the program has none.
    pub interp_base: u64,
    /// The map the host has to maintain: where the page table is, where the heap and `mmap` areas
    /// start, and where the stack ends. The host reports these rather than assuming them.
    pub map: MapInfo,
}

pub struct MapInfo {
    pub pte_base: u64,
    /// The dispatch table, which the host patches when it translates a page at run time.
    pub table_base: u64,
    pub table_mask: u32,
    pub heap_base: u64,
    /// Where the heap has to stop: the loader, if there is one, sits above it.
    pub heap_limit: u64,
    pub mmap_base: u64,
    pub stack_floor: u64,
}

fn is_terminator(i: &Insn) -> bool {
    matches!(
        i,
        // A syscall ends the block so that the instruction after it is a block start, which is what
        // makes the address a run resumes at dispatchable.
        Insn::Svc
            | Insn::B { .. }
            | Insn::Bl { .. }
            | Insn::BCond { .. }
            | Insn::Cbz { .. }
            | Insn::Tbz { .. }
            | Insn::Br { .. }
            | Insn::Blr { .. }
            | Insn::Ret { .. }
    )
}

/// Whether an instruction's destination is a 64-bit form, which writes the low half and leaves the
/// upper half zero. Lane inserts are not in this list: they leave the rest of the register alone.
fn narrows_to_low_half(i: &Insn) -> bool {
    match *i {
        Insn::VecLd1 { q, .. }
        | Insn::VecStruct { q, .. }
        | Insn::VecLd1r { q, .. }
        | Insn::VecThreeSame { q, .. }
        | Insn::VecAcross { q, .. }
        | Insn::VecModImm { q, .. }
        | Insn::VecPermute { q, .. }
        | Insn::VecExt { q, .. }
        | Insn::VecTbl { q, .. } => !q,
        // `shll` widens into the whole register, so the q bit picks which half of the source it
        // reads rather than how much it writes, and the narrowing and widening float conversions
        // write all of the destination whichever half they take.
        Insn::VecTwoMisc { q, op, .. } => !q && !matches!(op, 0b10011 | 0b10110 | 0b10111),
        // The long multiplies write the whole destination even with the q bit clear, and so do
        // sshll and ushll: q picks which half of the sources widen, not how much is written.
        Insn::VecThreeDiff { q, op, .. } => {
            !q && !matches!(op, 0b00010 | 0b00110) && op & 0b10011 != 0b10000
        }
        Insn::VecShiftImm { q, op, .. } => !q && op != 0b10100,
        Insn::FpDupElement { .. } | Insn::ScalarShift { .. } => true,
        _ => false,
    }
}

/// Whether control can continue at the next instruction after this one. The branch emitters end a
/// block with the taken path, so the fallthrough has to be emitted as a jump of its own when the
/// next instruction is not the region's next block: a page region reaches its blocks in the order
/// the control flow graph finds them, which is not the order the code runs in.
fn falls_through(i: &Insn) -> bool {
    matches!(i, Insn::BCond { .. } | Insn::Cbz { .. } | Insn::Tbz { .. } | Insn::Svc)
}

/// The eight-bit floating point immediate, expanded to the width of the register it lands in:
/// one sign bit, the exponent that says how large, and the four-bit fraction that says how much.
fn vfp_expand_imm(imm8: u32, n: u32) -> u64 {
    let bit = |i: u32| ((imm8 >> i) & 1) as u64;
    let (exp_bits, frac_bits) = if n == 64 { (11, 52) } else { (8, 23) };
    let repeat = exp_bits - 3;
    let exp = ((1 - bit(6)) << (exp_bits - 1)) | (bit(6) * ((1 << repeat) - 1) << 2) | (bit(5) << 1) | bit(4);
    let frac = (bit(3) << 3 | bit(2) << 2 | bit(1) << 1 | bit(0)) << (frac_bits - 4);
    (bit(7) << (n - 1)) | (exp << frac_bits) | frac
}

fn page_align(x: u64) -> u64 {
    (x + 0xfff) & !0xfff
}

/// Kick off at one block start, or any pc inside a block that the dispatcher can resume at.
/// Open addressing with linear probing; a block start is unique in `pc >> 2`, so no key repeats and
/// a probe only has to skip slots taken by other blocks that hashed to the same index.
fn build_dispatch_table(regions: &[Region], failed: &[bool]) -> Result<(Vec<u8>, u32), String> {
    let blocks: usize = regions
        .iter()
        .zip(failed)
        .map(|(r, &bad)| if bad { 1 } else { r.blocks.len() })
        .sum();
    // How many slots a run needs is not known when the program is translated: the host translates a
    // page of a library the first time the guest jumps into it, and every block of it takes a slot.
    // A table sized to the initial image fills up part way through a package manager and the insert
    // that cannot find an empty slot has nowhere to go, so the arena is always the whole of it.
    // Two slots per block keeps the probes short, and the count is rounded up to a power of two so
    // that the mask that names a slot is one.
    let slots = (blocks as u64 * 2).next_power_of_two().max(TABLE_MIN_SLOTS);
    if slots > TABLE_MAX_SLOTS {
        return Err(format!(
            "{blocks} blocks needs more than the {TABLE_MAX_SLOTS} dispatch slots the arena holds"
        ));
    }
    let mask = (slots - 1) as u32;
    let mut table = vec![0u8; (slots * TABLE_SLOT) as usize];
    for (region_idx, region) in regions.iter().enumerate() {
        let keep = if failed[region_idx] { 1 } else { region.blocks.len() };
        for (block_idx, block) in region.blocks.iter().enumerate().take(keep) {
            let key = (block.addr >> 2) as u32;
            let mut slot = (key & mask) as usize;
            loop {
                let at = slot * TABLE_SLOT as usize;
                if table[at] == 0 && table[at + 1] == 0 && table[at + 2] == 0 && table[at + 3] == 0 {
                    let payload = ((region_idx as u32) + 1) | ((block_idx as u32) << 16);
                    table[at..at + 4].copy_from_slice(&payload.to_le_bytes());
                    table[at + 4..at + 8].copy_from_slice(&(key + 1).to_le_bytes());
                    break;
                }
                slot = (slot + 1) & mask as usize;
            }
        }
    }
    Ok((table, mask))
}

/// One byte per 4 KiB page for the ranges this translator maps: engine memory, the images and the
/// stack. `mmap` and `mprotect` maintain the rest of it at run time.
fn page_table(images: &[&Elf], stack_floor: u64, stack_top: u64) -> Vec<u8> {
    let mut ptes = vec![0u8; PTE_PAGES as usize];
    let mut set = |lo: u64, hi: u64, bits: u8| {
        let lo_page = (lo >> 12) as usize;
        let hi_page = (((hi + 0xfff) >> 12) as usize).min(ptes.len());
        for p in lo_page..hi_page {
            ptes[p] |= bits;
        }
    };
    set(0, IMAGE_BASE, pte::MAPPED | pte::WRITABLE);
    set(stack_floor, stack_top, pte::MAPPED | pte::WRITABLE);
    for image in images {
        for s in &image.segments {
            let mut bits = pte::MAPPED;
            if s.flags & crate::elf::PF_W != 0 {
                bits |= pte::WRITABLE;
            }
            if s.flags & crate::elf::PF_X != 0 {
                bits |= pte::EXECUTABLE | pte::TRANSLATED;
            }
            set(s.vaddr, s.end(), bits);
        }
    }
    ptes
}

/// Data segments for the nonzero runs of `bytes`, so a mostly-empty page table costs its entries
/// rather than its size: linear memory starts zeroed.
fn push_sparse(m: &mut Module, base: u64, bytes: &[u8]) {
    // A run reaches across a gap of zeros up to a page, so a segment is a page of an image rather
    // than a run of instructions: an engine holds a hundred thousand data segments and a program of
    // any size has more runs than that.
    const GAP: usize = 4096;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0 {
            i += 1;
            continue;
        }
        let start = i;
        let mut last = i;
        while i < bytes.len() {
            if bytes[i] != 0 {
                last = i;
            } else if i - last > GAP {
                break;
            }
            i += 1;
        }
        m.data.push((base + start as u64, bytes[start..=last].to_vec()));
    }
}

/// The images one process starts with: the program itself and, when it is dynamically linked, the
/// loader the kernel would have started instead. Both are translated into one module, because the
/// loader hands control to the program by jumping, not by `exec`.
pub struct Images<'a> {
    pub main: &'a Elf,
    pub interp: Option<&'a Elf>,
}

impl Images<'_> {
    fn all(&self) -> impl Iterator<Item = &Elf> {
        std::iter::once(self.main).chain(self.interp)
    }
}

/// Instruction words, and the addresses a region may start at, for a set of images.
///
/// The whole-image translator and the page translator that runs later both call this, so a page
/// translated on demand cannot disagree with what a single pass would have produced.
pub struct Site {
    pub insns: BTreeMap<u64, Insn>,
    pub entries: BTreeSet<u64>,
    pub pointer_entries: BTreeSet<u64>,
}

pub fn sites<'a>(images: &[&'a Elf]) -> Site {
    // Decode every image's instructions once, section by section: an executable segment also holds
    // read-only data, and a word of that is not an instruction. Literal pools and padding inside a
    // code section decode to Undefined, which is only an error if a translated block reaches it.
    let mut insns: BTreeMap<u64, Insn> = BTreeMap::new();
    for image in images {
        for (lo, hi) in image.instruction_ranges() {
            let mut a = lo;
            while a + 4 <= hi {
                let Some(w) = image.vaddr_bytes(a, 4) else { break };
                insns.insert(a, decode(u32::from_le_bytes(w.try_into().unwrap())));
                a += 4;
            }
        }
    }

    // Entry points: the ELF entries, every function symbol in executable code, every direct call
    // target. A branch to an entry starts a new region instead of being folded into this one.
    let mut entries: BTreeSet<u64> = BTreeSet::new();
    for image in images {
        entries.insert(image.entry);
        for s in &image.symbols {
            if s.is_func && insns.contains_key(&s.value) {
                entries.insert(s.value);
            }
        }
    }
    for (&addr, i) in &insns {
        if let Insn::Bl { offset } = i {
            let t = (addr as i64 + *offset) as u64;
            if insns.contains_key(&t) {
                entries.insert(t);
            }
        }
    }
    // Every function the unwind tables describe, which is the only complete list of entry points a
    // stripped image has.
    for image in images {
        for at in image.function_entries() {
            if insns.contains_key(&at) {
                entries.insert(at);
            }
        }
    }

    // Addresses that only a value reaches: built by `adrp` + `add`, or stored in the image's data.
    // Either can land on a number that is not code, so a region that fails to translate there
    // becomes a trap rather than failing the image.
    let mut pointer_entries: BTreeSet<u64> = BTreeSet::new();
    for (&addr, insn) in &insns {
        let Insn::AddSubImm { sf: _, sub: false, setflags: false, shift, imm: add, rn, rd } = *insn
        else {
            continue;
        };
        if rn != rd {
            continue;
        }
        // The `adrp` that a following `add` completes need not be its immediate predecessor: the
        // compiler interleaves several pairs.
        let page = (1..=8u64).find_map(|k| match insns.get(&addr.checked_sub(4 * k)?) {
            Some(Insn::Adrp { rd: base, imm }) if *base == rn => Some((addr - 4 * k, *imm)),
            _ => None,
        });
        let Some((page_addr, page_imm)) = page else { continue };
        let target = ((page_addr & !0xfff) as i64
            + (page_imm << 12)
            + ((add as i64) << (12 * shift))) as u64;
        if insns.contains_key(&target) {
            pointer_entries.insert(target);
        }
    }

    // A function reached only through a pointer has no branch to discover it: the pointer is what
    // makes it an entry, so every code address an image stores in its writable data becomes one.
    // Read-only data is left out: an ELF header holds addresses by construction.
    for image in images {
        // The headers are mapped inside the first loadable segment, so their words are not pointers.
        let headers_end = image.phoff + image.phnum as u64 * image.phentsize as u64;
        for s in &image.segments {
            if s.flags & PF_X != 0 || s.filesz < 8 {
                continue;
            }
            let start = s.file_offset.max(headers_end) as usize;
            let end = (s.file_offset + s.filesz) as usize;
            let Some(bytes) = image.image.get(start..end) else { continue };
            for w in bytes.chunks_exact(8) {
                let word = u64::from_le_bytes(w.try_into().unwrap());
                // A null pointer is not a code address, and with a relocatable image it would
                // otherwise land on the image base, which is the ELF header.
                if word == 0 {
                    continue;
                }
                let v = word.wrapping_add(image.bias);
                if insns.contains_key(&v) {
                    pointer_entries.insert(v);
                }
            }
        }
    }
    Site { insns, entries, pointer_entries }
}

/// Everything a module needs before its region bodies: the types, the two host imports and the
/// helpers the bodies call. A page translated later repeats this exactly, so a function emitted in
/// one module and a function emitted in the other see the same signatures and helper ids.
struct Prelude {
    ids: Ids,
    ty_region: u32,
}

fn prelude(m: &mut Module, cfg: &Config) -> Prelude {
    let mut region_params = vec![I64; NR as usize];
    region_params.extend(vec![V128; NVEC as usize]);
    region_params.push(I32); // entry block
    let mut region_results = vec![I64; NR as usize];
    region_results.extend(vec![V128; NVEC as usize]);
    region_results.push(I32);
    let ty_region = m.ty(region_params, region_results);
    let ty_syscall = m.ty(vec![I64; 7], vec![I64, I32]);
    let ty_trap = m.ty(vec![I32, I64, I32], vec![]);
    let ty_ii_i64 = m.ty(vec![I64, I64], vec![I64]);
    let ty_i_i64 = m.ty(vec![I64], vec![I64]);

    m.imports.push(Import { module: "env".into(), name: "syscall".into(), ty: ty_syscall });
    m.imports.push(Import { module: "env".into(), name: "trap".into(), ty: ty_trap });
    let trace_idx = if cfg.trace || cfg.trace_loops {
        let ty = m.ty(vec![I32, I64], vec![]);
        m.imports.push(Import { module: "env".into(), name: "trace2".into(), ty });
        Some(m.n_imports() - 1)
    } else {
        None
    };

    let umulh_id = emit_umulh(m, ty_ii_i64);
    let smulh_id = emit_smulh(m, ty_ii_i64, umulh_id);
    let ids = Ids {
        syscall: 0,
        trap: 1,
        trace: trace_idx,
        umulh: umulh_id,
        smulh: smulh_id,
        udiv: emit_udiv(m, ty_ii_i64),
        sdiv: emit_sdiv(m, ty_ii_i64),
        bswap64: emit_bswap(m, ty_i_i64, 64),
        bswap32: emit_bswap(m, ty_i_i64, 32),
        rbit64: emit_rbit(m, ty_i_i64),
        ty_region,
    };
    Prelude { ids, ty_region }
}

pub fn translate(
    images: Images,
    cfg: &Config,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
) -> Result<Output, String> {
    let elf = images.main;
    let ranges = elf.instruction_ranges();
    if ranges.is_empty() {
        return Err("no executable segment".into());
    }
    let code_lo = ranges.iter().map(|r| r.0).min().unwrap();
    let code_hi = ranges.iter().map(|r| r.1).max().unwrap();
    let mem_size = cfg.mem_pages as u64 * 65536;
    let entry = images.interp.map(|i| i.entry).unwrap_or(elf.entry);

    let loaded: Vec<&Elf> = images.all().collect();
    let Site { insns, entries, pointer_entries } = sites(&loaded);

    let mut regions: Vec<Region> = Vec::new();
    let mut region_index: HashMap<u64, usize> = HashMap::new();
    let mut queue: VecDeque<u64> = VecDeque::new();
    for &e in entries.iter().chain(pointer_entries.iter()) {
        queue.push_back(e);
    }
    while let Some(start) = queue.pop_front() {
        if region_index.contains_key(&start) {
            continue;
        }
        let region = discover_region(start, &insns, &entries);
        if region.blocks.is_empty() {
            continue;
        }
        for chunk in split_region(region) {
            region_index.insert(chunk.blocks[0].addr, regions.len());
            regions.push(chunk);
        }
    }
    if !region_index.contains_key(&entry) {
        return Err(format!("entry point 0x{entry:x} did not decode"));
    }

    if regions.len() > 0xfffe {
        return Err(format!("{} regions exceeds the dispatch table encoding", regions.len()));
    }

    let stack_top = (mem_size - 0x1000) & !0xf;
    let stack_floor = stack_top - STACK_RESERVE;
    let heap_base = page_align(elf.image_end().max(IMAGE_BASE));
    if heap_base >= stack_floor {
        return Err("image too large for the fixed layout".into());
    }
    for (image, arena) in images.all().zip([IMAGE_BASE, INTERP_BASE]) {
        for s in &image.segments {
            if s.vaddr < arena || s.end() > stack_floor {
                return Err(format!(
                    "segment 0x{:x}..0x{:x} collides with engine memory, another image or the stack",
                    s.vaddr,
                    s.end()
                ));
            }
        }
    }
    if let Some(interp) = images.interp {
        let span = |e: &Elf| {
            (e.segments.iter().map(|s| s.vaddr).min().unwrap_or(0), e.image_end())
        };
        let (main_lo, main_hi) = span(elf);
        let (interp_lo, interp_hi) = span(interp);
        if main_lo < interp_hi && interp_lo < main_hi {
            return Err("the program and its loader overlap".into());
        }
    }

    let ptes = page_table(&loaded, stack_floor, stack_top);

    // AT_BASE is the loader's load address, which after relocation is its own base.
    let interp_base = images.interp.map(|i| i.load_offset()).unwrap_or(0);
    let (stack_bytes, stack_used) =
        build_initial_stack(elf, interp_base, argv, envp, stack_top);
    let sp = stack_top - stack_used;

    let mut m = Module::new();
    m.mem_pages = cfg.mem_pages;

    let Prelude { ids, ty_region } = prelude(&mut m, cfg);
    let ty_run = m.ty(vec![I32, I64, I32], vec![I32]);

    // The dispatch table is built once the regions are emitted, and only the run loop reads its
    // mask, so the region bodies are emitted with a placeholder.
    let layout = Layout {
        table_mask: 0,
        stack_floor,
        bounds_check: cfg.bounds_check,
        trace: cfg.trace,
        trace_loops: cfg.trace_loops,
        allow_undefined: cfg.allow_undefined,
        mem_size,
    };

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
    let mut unsupported: Vec<(u64, String)> = Vec::new();
    let (bodies, failed) = emit_regions(&regions, &layout, &ids, ty_region, &mut unsupported);
    let mut region_func_ids = Vec::new();
    for (region, body) in regions.iter().zip(bodies) {
        instructions += region.blocks.iter().map(|b| b.insns.len()).sum::<usize>();
        let id = m.add_func(ty_region);
        *m.func_mut(id) = body;
        region_func_ids.push(id);
    }
    let run_id = m.add_func(ty_run);
    m.table_min = region_func_ids.len() as u32;
    m.table_max = Some(TABLE_SLOTS_MAX);
    m.elems.push((0, region_func_ids.clone()));
    let (table_bytes, table_mask) = build_dispatch_table(&regions, &failed)?;
    *m.func_mut(run_id) = emit_run(&ids, &Layout { table_mask, ..layout }, ty_run);

    for image in images.all() {
        for s in &image.segments {
            let bytes =
                image.image[s.file_offset as usize..(s.file_offset + s.filesz) as usize].to_vec();
            m.data.push((s.vaddr, bytes));
        }
    }
    push_sparse(&mut m, TABLE_BASE, &table_bytes);
    push_sparse(&mut m, PTE_BASE, &ptes);
    if !stack_bytes.is_empty() {
        m.data.push((sp, stack_bytes));
    }

    m.exports.push(("run".into(), 0, run_id));
    m.exports.push(("mem".into(), 2, 0));
    m.exports.push(("tbl".into(), 1, 0));

    let wasm = m.encode();
    unsupported.sort();
    Ok(Output {
        entry,
        sp,
        mem_pages: cfg.mem_pages,
        stats: Stats {
            instructions,
            regions: regions.len(),
            wasm_bytes: wasm.len(),
            guest_bytes: elf.image.len() + images.interp.map(|i| i.image.len()).unwrap_or(0),
        },
        interp_base,
        code_lo,
        code_hi,
        unsupported,
        wasm,
        map: MapInfo {
            pte_base: PTE_BASE,
            table_base: TABLE_BASE,
            table_mask,
            heap_base,
            // The heap grows up from the images and stops at whichever fixed thing is above it:
            // the loader when there is one, and never the dispatch arena.
            heap_limit: if images.interp.is_some() { INTERP_BASE } else { MMAP_BASE.min(TABLE_BASE) },
            mmap_base: MMAP_BASE,
            stack_floor,
        },
    })
}

#[derive(Clone, Copy)]
struct Layout {
    /// Slot count minus one for the open-addressed dispatch table: `slot = (pc >> 2) & table_mask`.
    table_mask: u32,
    stack_floor: u64,
    bounds_check: bool,
    trace: bool,
    trace_loops: bool,
    allow_undefined: bool,
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

/// How many guest blocks one emitted function may hold. The body of a region nests one wasm block
/// per guest block for its jump table, and the engine's bookkeeping for a function grows with the
/// square of that: `cc1` has a region of 48 thousand blocks whose wasm function V8 refuses to
/// compile at all. A chunk of a few hundred blocks is emitted as a region of its own, and the
/// dispatcher hands over at the boundary like it does at any other.
const REGION_BLOCKS_MAX: usize = 512;

/// One discovered region, as the pieces it is emitted from: a piece that begins at a block start is
/// a region, because that is what the dispatcher can be given.
fn split_region(region: Region) -> Vec<Region> {
    if region.blocks.len() <= REGION_BLOCKS_MAX {
        return vec![region];
    }
    let mut chunks = Vec::new();
    let mut blocks = region.blocks;
    while !blocks.is_empty() {
        let take = REGION_BLOCKS_MAX.min(blocks.len());
        let rest = blocks.split_off(take);
        let index_of = blocks.iter().enumerate().map(|(i, b)| (b.addr, i)).collect();
        chunks.push(Region { blocks, index_of });
        blocks = rest;
    }
    chunks
}

fn discover_region(entry: u64, insns: &BTreeMap<u64, Insn>, entries: &BTreeSet<u64>) -> Region {
    // Pass 1: find every block start. A block runs from its start to the first terminator, which
    // may pass over a later block's start; that is fine here because only terminators and their
    // targets matter. Pass 2 slices the blocks so that they are disjoint.
    let mut starts: BTreeSet<u64> = BTreeSet::new();
    let mut worklist = vec![entry];
    while let Some(start) = worklist.pop() {
        if !starts.insert(start) {
            continue;
        }
        if start % 4 != 0 || !insns.contains_key(&start) {
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
                    if insns.contains_key(&a) {
                        succ.push(a);
                    }
                }
                // blr is a call: its return address is the fallthrough, exactly like bl.
                Insn::Br { .. } | Insn::Ret { .. } => {}
                _ => {
                    if insns.contains_key(&a) {
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

/// A NUL-terminated copy of a string argument, which is what the stack holds.
fn cstr(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.extend_from_slice(bytes);
    out.push(0);
    out
}

pub fn build_initial_stack(
    elf: &Elf,
    interp_base: u64,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
    stack_top: u64,
) -> (Vec<u8>, u64) {
    let mut sb = StackBuilder { cur: stack_top, chunks: Vec::new() };

    // The strings are bytes, not text: `execve` passes whatever the program gave it.
    let default: Vec<Vec<u8>> = vec![b"guest".to_vec()];
    let argv = if argv.is_empty() { &default } else { argv };

    let execfn_addr = sb.bytes(&cstr(&argv[0]));
    let mut env_addrs = Vec::new();
    for e in envp {
        env_addrs.push(sb.bytes(&cstr(e)));
    }
    let mut argv_addrs = Vec::new();
    for a in argv {
        argv_addrs.push(sb.bytes(&cstr(a)));
    }
    let platform_addr = sb.bytes(b"aarch64\0");
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
    // AT_BASE is the loader's load address, and the only auxv entry about the loader: AT_ENTRY and
    // AT_PHDR describe the program itself, which is how the loader finds what it was started for.
    if interp_base != 0 {
        auxv.push((7, interp_base));
    }
    auxv.push((8, 0));
    auxv.push((9, elf.entry));
    auxv.push((11, 0));
    auxv.push((12, 0));
    auxv.push((13, 0));
    auxv.push((14, 0));
    auxv.push((15, platform_addr));
    // AT_HWCAP stays 0, which puts glibc on its baseline routines. The ones it would pick for a CPU
    // with FP and ASIMD are hand-written assembly - the string, memory and crypto paths - and that is
    // the instruction coverage that has been checked least; a refusal there kills the run.
    auxv.push((16, 0));
    auxv.push((17, 100));
    auxv.push((23, 0));
    auxv.push((25, random_addr));
    auxv.push((26, 0));
    auxv.push((31, execfn_addr));

    let slots = 1 + (argv_addrs.len() + 1) + (env_addrs.len() + 1) + (auxv.len() * 2 + 2);
    sb.align16();
    // `argc` is the lowest word, so the entry point sees a 16-byte aligned stack only if the
    // words below it come to an even count, which is what the ABI expects at a function entry.
    if slots % 2 == 1 {
        sb.cur -= 8;
    }

    // AT_NULL is a pair like every other entry.
    sb.u64(0);
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
    f.locals = vec![I64; 1]; // 1 = accumulator, since the only parameter is 0
    let bytes = bits / 8;
    f.i64c(0);
    f.ls(1);
    for i in 0..bytes {
        let mask_shift = i * 8;
        let out_shift = (bytes - 1 - i) * 8;
        f.lg(1);
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
        f.ls(1);
    }
    f.lg(1);
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
    f.locals = vec![I64; 2]; // 1 = x, 2 = reversed bytes (the only parameter is 0)
    f.lg(0);
    f.ls(1);
    for (shift, mask) in [(1i64, 0x5555_5555_5555_5555u64), (2, 0x3333_3333_3333_3333), (4, 0x0f0f_0f0f_0f0f_0f0f)] {
        f.lg(1);
        f.i64c(shift);
        f.op(I64_SHR_U);
        f.i64c(mask as i64);
        f.op(I64_AND);
        f.lg(1);
        f.i64c(mask as i64);
        f.op(I64_AND);
        f.i64c(shift);
        f.op(I64_SHL);
        f.op(I64_OR);
        f.ls(1);
    }
    // Reverse the byte order of the swapped value, which has to stay put while the result is
    // assembled in the other local.
    f.lg(1);
    f.ls(2);
    f.i64c(0);
    f.ls(1);
    for i in 0..8 {
        let mask_shift = i * 8;
        let out_shift = (7 - i) * 8;
        f.lg(1);
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
        f.ls(1);
    }
    f.lg(1);
    id
}

// ---------------------------------------------------------------- dispatcher

fn emit_run(ids: &Ids, layout: &Layout, ty: u32) -> Func {
    // Parameters: 0 = pc, 1 = sp, 2 = resume. Locals hold the rest of the guest state.
    let mut f = Func::new(ty);
    const PC: u32 = 0;
    const SP: u32 = 1;
    const X0: u32 = 3;
    f.locals = vec![I64; 31]; // x0..x30 -> 3..33
    f.locals.push(I64); // nzcv -> 34
    f.locals.push(I32); // idx -> 35
    f.locals.push(I32); // next -> 36
    f.locals.push(I32); // status -> 37
    f.locals.push(I32); // entry block -> 38
    f.locals.push(I32); // key: pc >> 2 -> 39
    f.locals.push(I32); // want tag: key + 1 -> 40
    f.locals.push(I64); // dispatch slot -> 41
    f.locals.push(I32); // slot address -> 42
    f.locals.extend(vec![V128; NVEC as usize]); // v0..v31 -> 43..74
    const NZCV: u32 = X0 + 31;
    const IDX: u32 = NZCV + 1;
    const NEXT: u32 = IDX + 1;
    const STATUS: u32 = NEXT + 1;
    const ENTRY: u32 = STATUS + 1;
    const KEY: u32 = ENTRY + 1;
    const WANT: u32 = KEY + 1;
    const SLOTV: u32 = WANT + 1;
    const SLOTA: u32 = SLOTV + 1;
    const V0: u32 = SLOTA + 1;

    // A resumed run takes the guest state the previous run left in the shadow, which is how the
    // host hands control back after it has translated the page the guest jumped into.
    f.lg(2);
    f.op(IF);
    f.body.push(0x40);
    for r in 0..31u32 {
        f.i32c(SHADOW as i32 + (r as i32) * 8);
        f.mem(I64_LOAD, 3, 0);
        f.ls(X0 + r);
    }
    f.i32c(SHADOW_SP as i32);
    f.mem(I64_LOAD, 3, 0);
    f.ls(SP);
    f.i32c(SHADOW_NZCV as i32);
    f.mem(I64_LOAD, 3, 0);
    f.ls(NZCV);
    f.i32c(SHADOW_PC as i32);
    f.mem(I32_LOAD, 2, 0);
    f.ls(PC);
    for r in 0..NVEC {
        f.i32c((SHADOW_V0 + r as u64 * 16) as i32);
        f.simd_mem(simd::V128_LOAD, 4, 0);
        f.ls(V0 + r);
    }
    f.op(ELSE);
    for i in 0..31u32 {
        f.i64c(0);
        f.ls(X0 + i);
    }
    f.i64c(0);
    f.ls(NZCV);
    for i in 0..NVEC {
        f.v128c([0; 16]);
        f.ls(V0 + i);
    }
    f.end();

    f.block(); // $exit, depth from inside the loop's ifs = 2
    f.loop_();
    if layout.trace {
        for i in 0..31u32 {
            f.i32c(SHADOW as i32 + (i as i32) * 8);
            f.lg(X0 + i);
            f.mem(I64_STORE, 3, 0);
        }
        f.i32c(SHADOW_SP as i32);
        f.lg(SP);
        f.mem(I64_STORE, 3, 0);
        for i in 0..NVEC {
            f.i32c((SHADOW_V0 + i as u64 * 16) as i32);
            f.lg(V0 + i);
            f.simd_mem(simd::V128_STORE, 4, 0);
        }
        f.i32c(SHADOW_PC as i32);
        f.lg(PC);
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
        f.lg(PC);
        f.mem(I32_STORE, 2, 0);
        f.i32c(RING_IDX as i32);
        f.i32c(RING_IDX as i32);
        f.mem(I32_LOAD, 2, 0);
        f.i32c(1);
        f.op(I32_ADD);
        f.mem(I32_STORE, 2, 0);
    }
    // Dispatch: open addressing on `(pc >> 2) & mask`. A slot holds `[payload][tag]`, the payload
    // being region + 1 in the low half and block index in the high half, and an empty slot reads
    // zero. A pc that no block starts at leaves the slot zero, which reports an untranslated jump.
    f.lg(PC);
    f.i32c(2);
    f.op(I32_SHR_U);
    f.lt(KEY); // key
    f.lg(KEY);
    f.i32c(1);
    f.op(I32_ADD);
    f.ls(WANT); // want
    f.lg(KEY);
    f.i32c(layout.table_mask as i32);
    f.op(I32_AND);
    f.ls(IDX); // slot

    f.block(); // $found
    f.loop_();
    f.i32c(TABLE_BASE as i32);
    f.lg(IDX);
    f.i32c(3);
    f.op(I32_SHL);
    f.op(I32_ADD);
    f.lt(SLOTA);
    f.lg(SLOTA);
    f.mem(I64_LOAD, 3, 0);
    f.lt(SLOTV);

    // tag match: the slot is this block
    f.lg(SLOTV);
    f.i64c(32);
    f.op(I64_SHR_U);
    f.wrap_i64();
    f.lt(KEY);
    f.lg(KEY);
    f.lg(WANT);
    f.op(I32_EQ);
    f.op(IF);
    f.body.push(0x40);
    f.lg(SLOTV);
    f.wrap_i64();
    f.ls(IDX);
    f.br(2); // $found
    f.end();

    // empty slot: nothing translated at this pc
    f.lg(KEY);
    f.op(I32_EQZ);
    f.op(IF);
    f.body.push(0x40);
    f.i32c(0);
    f.ls(IDX);
    f.br(2); // $found
    f.end();

    f.lg(IDX);
    f.i32c(1);
    f.op(I32_ADD);
    f.i32c(layout.table_mask as i32);
    f.op(I32_AND);
    f.ls(IDX);
    f.br(0); // keep probing
    f.end(); // loop
    f.end(); // $found

    f.lg(IDX);
    f.op(I32_EQZ);
    f.op(IF);
    f.body.push(0x40);
    f.i32c(2);
    f.ls(STATUS);
    f.br(2);
    f.end();

    // block index = word >> 16, region slot = (word & 0xffff) - 1
    f.lg(IDX);
    f.i32c(16);
    f.op(I32_SHR_U);
    f.ls(ENTRY); // entry block
    f.lg(IDX);
    f.i32c(0xffff);
    f.op(I32_AND);
    f.i32c(1);
    f.op(I32_SUB);
    f.ls(IDX); // table slot

    f.i32c(SHADOW_PC as i32);
    f.lg(PC);
    f.mem(I32_STORE, 2, 0);
    for i in 0..31u32 {
        f.lg(X0 + i);
    }
    f.lg(SP); // sp
    f.lg(NZCV); // nzcv
    for i in 0..NVEC {
        f.lg(V0 + i);
    }
    f.lg(ENTRY); // entry block
    f.lg(IDX); // table slot, popped by call_indirect last
    f.op(CALL_INDIRECT);
    uleb(&mut f.body, ids.ty_region as u64);
    uleb(&mut f.body, 0);

    f.ls(NEXT); // next
    for i in (0..NVEC).rev() {
        f.ls(V0 + i);
    }
    f.ls(NZCV); // nzcv
    f.ls(SP); // sp
    for i in (0..31u32).rev() {
        f.ls(X0 + i);
    }

    // A region handed back a next pc of zero: the guest stopped, either because a syscall wants the
    // host or because it jumped to an address no block starts at. Status 1 says so; 2 is a pc that
    // needs translating.
    f.lg(NEXT);
    f.op(I32_EQZ);
    f.op(IF);
    f.body.push(0x40);
    f.i32c(1);
    f.ls(STATUS);
    f.br(2);
    f.end();

    f.lg(NEXT);
    f.ls(PC);
    f.br(0);
    f.end(); // loop
    f.end(); // exit block

    for i in 0..31u32 {
        f.i32c(SHADOW as i32 + (i as i32) * 8);
        f.lg(X0 + i);
        f.mem(I64_STORE, 3, 0);
    }
    f.i32c(SHADOW_SP as i32);
    f.lg(SP);
    f.mem(I64_STORE, 3, 0);
    for i in 0..NVEC {
        f.i32c((SHADOW_V0 + i as u64 * 16) as i32);
        f.lg(V0 + i);
        f.simd_mem(simd::V128_STORE, 4, 0);
    }
    f.i32c(SHADOW_NZCV as i32);
    f.lg(NZCV);
    f.mem(I64_STORE, 3, 0);
    f.i32c(SHADOW_PC as i32);
    f.lg(PC);
    f.mem(I32_STORE, 2, 0);
    f.lg(STATUS);
    f
}



/// All ones in the low 64 bits and zeros above: what a D-register operation writes.
/// The sign bit of every lane: what `fneg` flips and `fabs` clears.
fn sign_mask(double: bool) -> [u8; 16] {
    let width = if double { 8 } else { 4 };
    let mut m = [0u8; 16];
    for lane in 0..16 / width {
        m[lane * width + width - 1] = 0x80;
    }
    m
}

/// One float spread across every lane of a register, which is how a constant meets a vector op.
fn lane_repeat(double: bool, wide: u64, narrow: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    if double {
        for half in 0..2 {
            out[half * 8..half * 8 + 8].copy_from_slice(&wide.to_le_bytes());
        }
    } else {
        for lane in 0..4 {
            out[lane * 4..lane * 4 + 4].copy_from_slice(&narrow.to_le_bytes());
        }
    }
    out
}

fn low_half_mask() -> [u8; 16] {
    let mut out = [0xffu8; 16];
    for b in 8..16 {
        out[b] = 0;
    }
    out
}

/// A per-lane mask of the low `bits` bits, for the insert-style shifts.
fn low_bits_mask(esize: u32, bits: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    let lane_bytes = (esize / 8) as usize;
    let masked = if bits >= esize { u64::MAX } else { (1u64 << bits) - 1 };
    for lane in 0..(16 / lane_bytes) {
        for b in 0..lane_bytes {
            out[lane * lane_bytes + b] = ((masked >> (8 * b)) & 0xff) as u8;
        }
    }
    out
}

/// All ones in the first lane and zeros above: the shape of a result reduced across the lanes.
fn lane_zero_mask(size: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    for b in 0..(1usize << size) {
        out[b] = 0xff;
    }
    out
}

/// A per-lane mask of everything above the low `bits` bits.
fn high_bits_mask(esize: u32, bits: u32) -> [u8; 16] {
    low_bits_mask(esize, bits).map(|b| !b)
}

/// A per-lane constant, used for the rounding bias of a rounding narrowing shift.
fn round_mask(esize: u32, value: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    let lane_bytes = (esize / 8) as usize;
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = ((value >> (8 * (i % lane_bytes))) & 0xff) as u8;
    }
    out
}

/// The byte shuffle for zip1/zip2/uzp1/uzp2/trn1/trn2 at one element width.
fn permute_mask(size: u32, op: u32) -> Option<[u8; 16]> {
    let lane = 1u32 << size;
    let lanes = 16 / lane;
    let half = lanes / 2;
    let mut m = [0u8; 16];
    let mut put = |dst_lane: u32, src_lane: u32, from_b: bool| {
        for b in 0..lane {
            m[(dst_lane * lane + b) as usize] =
                (src_lane * lane + b) as u8 + if from_b { 16 } else { 0 };
        }
    };
    match op {
        0b00111 => {
            // zip1: interleave the low halves
            for i in 0..half {
                put(i * 2, i, false);
                put(i * 2 + 1, i, true);
            }
        }
        0b01111 => {
            // zip2: interleave the high halves
            for i in 0..half {
                put(i * 2, half + i, false);
                put(i * 2 + 1, half + i, true);
            }
        }
        0b00011 => {
            // uzp1: the even lanes of both
            for i in 0..half {
                put(i, i * 2, false);
                put(half + i, i * 2, true);
            }
        }
        0b01011 => {
            // uzp2: the odd lanes of both
            for i in 0..half {
                put(i, i * 2 + 1, false);
                put(half + i, i * 2 + 1, true);
            }
        }
        0b00101 => {
            // trn1: even lanes interleaved
            for i in 0..half {
                put(i * 2, i * 2, false);
                put(i * 2 + 1, i * 2, true);
            }
        }
        0b01101 => {
            // trn2: odd lanes interleaved
            for i in 0..half {
                put(i * 2, i * 2 + 1, false);
                put(i * 2 + 1, i * 2 + 1, true);
            }
        }
        _ => return None,
    }
    Some(m)
}


/// Reverse the element order within each 64-bit half, for the element width `size` codes.
fn rev64_mask(size: u32) -> [u8; 16] {
    let lane = 1u32 << size;
    let per_half = 8 / lane;
    let mut m = [0u8; 16];
    for half in 0..2 {
        for i in 0..per_half {
            for b in 0..lane {
                m[(half * 8 + i * lane + b) as usize] = (half * 8 + (per_half - 1 - i) * lane + b) as u8;
            }
        }
    }
    m
}

/// Reverse the bytes of every group of `group` bytes.
/// Swap the two halfwords of every 4-byte group: `rev32` on 16-bit elements.
fn swap_halfword_mask() -> [u8; 16] {
    let mut m = [0u8; 16];
    for g in 0..4u32 {
        for b in 0..4u32 {
            m[(g * 4 + b) as usize] = (g * 4 + (b ^ 2)) as u8;
        }
    }
    m
}

fn rev_group_mask(group: u32) -> [u8; 16] {
    let mut m = [0u8; 16];
    let groups = 16 / group;
    for g in 0..groups {
        for b in 0..group {
            m[(g * group + b) as usize] = (g * group + (group - 1 - b)) as u8;
        }
    }
    m
}

// ---------------------------------------------------------------- SIMD shuffle masks
//
// The wasm shuffle takes a byte index per result byte: 0..15 selects from the first operand, 16..31
// from the second. These build the index patterns a NEON operation needs, at translate time.

/// Even lanes of both operands, then odd lanes of both: the layout of a pairwise operation.
fn pair_masks(size: u32) -> ([u8; 16], [u8; 16]) {
    let lane = 1u32 << size;
    let half = (16 / lane) / 2;
    let mut even = [0u8; 16];
    let mut odd = [0u8; 16];
    for i in 0..half {
        for b in 0..lane {
            even[((i * lane) + b) as usize] = ((i * 2 * lane) + b) as u8;
            even[(((half + i) * lane) + b) as usize] = (16 + (i * 2 * lane) + b) as u8;
            odd[((i * lane) + b) as usize] = (((i * 2 + 1) * lane) + b) as u8;
            odd[(((half + i) * lane) + b) as usize] = (16 + ((i * 2 + 1) * lane) + b) as u8;
        }
    }
    (even, odd)
}

/// Where the bytes of one register of an interleaved access come from: register `i` of `count` holds
/// the elements at `j*count + i`, so its bytes are spread over every register of the structure. The
/// mask takes the ones that live in the pair `pair`, and `keep` is the byte mask that zeroes the
/// lanes the pair does not fill: every byte of a shuffle index has to name a lane.
fn struct_load_mask(count: u32, lanes: u32, e: u32, i: u32, pair: u32, bytes: u32) -> ([u8; 16], [u8; 16]) {
    let mut mask = [0u8; 16];
    let mut keep = [0u8; 16];
    for k in 0..bytes {
        let m = (k / e) * count + i;
        let (s, l) = (m / lanes, m % lanes);
        if s == pair * 2 {
            mask[k as usize] = (l * e + k % e) as u8;
            keep[k as usize] = 0xff;
        } else if s == pair * 2 + 1 {
            mask[k as usize] = (16 + l * e + k % e) as u8;
            keep[k as usize] = 0xff;
        }
    }
    (mask, keep)
}

/// The other direction: the bytes of word `p` of the interleaved stream, which the store writes out,
/// taken from the registers of the structure.
fn struct_store_mask(count: u32, e: u32, p: u32, pair: u32, bytes: u32) -> ([u8; 16], [u8; 16]) {
    let mut mask = [0u8; 16];
    let mut keep = [0u8; 16];
    for k in 0..bytes {
        let at = p * bytes + k;
        let m = at / e;
        let (s, l) = (m % count, m / count);
        if s == pair * 2 {
            mask[k as usize] = (l * e + at % e) as u8;
            keep[k as usize] = 0xff;
        } else if s == pair * 2 + 1 {
            mask[k as usize] = (16 + l * e + at % e) as u8;
            keep[k as usize] = 0xff;
        }
    }
    (mask, keep)
}

/// Move lanes `width..2*width` down onto `0..width`, for one step of a reduction.
/// Where the even and odd lanes of a pairwise FP operation come from, by lane width in bytes and how
/// many lanes of each source it covers.
fn fp_pair_masks(lane: u32, lanes: u32) -> ([u8; 16], [u8; 16]) {
    let (lane, lanes) = (lane as usize, lanes as usize);
    let mut even = [0u8; 16];
    let mut odd = [0u8; 16];
    for i in 0..lanes / 2 {
        for b in 0..lane {
            even[i * lane + b] = (2 * i * lane + b) as u8;
            odd[i * lane + b] = ((2 * i + 1) * lane + b) as u8;
            even[(lanes / 2 + i) * lane + b] = (16 + 2 * i * lane + b) as u8;
            odd[(lanes / 2 + i) * lane + b] = (16 + (2 * i + 1) * lane + b) as u8;
        }
    }
    (even, odd)
}

/// The two halves of a register swapped, which folds the lanes of a `d` register together.
fn swap_halves_mask() -> [u8; 16] {
    let mut m = [0u8; 16];
    for i in 0..8 {
        m[i] = (i + 8) as u8;
        m[i + 8] = i as u8;
    }
    m
}

/// The 32-bit words of each half swapped, the second fold of a four-lane reduction.
fn swap_words_mask() -> [u8; 16] {
    let mut m = [0u8; 16];
    for half in 0..2 {
        for w in 0..2 {
            for b in 0..4 {
                m[half * 8 + w * 4 + b] = (half * 8 + (1 - w) * 4 + b) as u8;
            }
        }
    }
    m
}

fn halve_mask(size: u32, width: u32) -> [u8; 16] {
    let lane = 1u32 << size;
    let mut m = [0u8; 16];
    for j in 0..width {
        for b in 0..lane {
            m[((j * lane) + b) as usize] = (((j + width) * lane) + b) as u8;
        }
    }
    m
}

/// The low half of every source lane, packed into one half of the result and taken from the second
/// shuffle operand. The other half comes from the first operand: zeros for `xtn`, the destination
/// for `xtn2`.
fn narrow_mask(size: u32, into_high: bool) -> [u8; 16] {
    let dlane = 1u32 << size;
    let mut m = [0u8; 16];
    for b in 0..8 {
        m[b as usize] = b as u8;
    }
    let base = if into_high { 8 } else { 0 };
    for j in 0..(8 / dlane) {
        for b in 0..dlane {
            m[(base + j * dlane + b) as usize] = (16 + j * 2 * dlane + b) as u8;
        }
    }
    m
}

/// The high byte of every lane: what a narrowing add takes from a wider sum.
fn high_half_mask(size: u32) -> [u8; 16] {
    let slane = 1u32 << size;
    let mut m = [0u8; 16];
    for j in 0..(16 / slane) {
        for b in 0..(slane / 2) {
            m[(j * (slane / 2) + b) as usize] = (16 + j * slane + slane / 2 + b) as u8;
        }
    }
    m
}

/// The 128-bit value of a `movi`/`mvni`, built at translate time from the modified immediate fields.
fn modified_immediate(q: bool, op: bool, cmode: u32, imm8: u32) -> [u8; 16] {
    let bytes = if q { 16 } else { 8 }; // a Q register or a D one
    let mut out = [0u8; 16];
    let (lane, shift, low_ones) = match cmode {
        0b0000 => (4, 0, false),
        0b0010 => (4, 8, false),
        0b0100 => (4, 16, false),
        0b0110 => (4, 24, false),
        0b1000 => (2, 0, false),
        0b1010 => (2, 8, false),
        0b1100 => (4, 8, true),  // the masked forms fill the bits under the immediate
        0b1101 => (4, 16, true),
        0b1110 => (1, 0, false), // 8-bit lanes, either 8 or 16 of them
        _ => (1, 0, false),
    };
    // The bitmask form, which the assembler writes as `movi <Vd>.2d, #<imm64>`: each bit of imm8
    // becomes one whole byte of the 64-bit pattern, which both halves repeat when Q is set.
    if cmode == 0b1110 && op || cmode == 0b1111 && !op {
        for i in 0..bytes {
            out[i] = if (imm8 >> (i % 8)) & 1 == 1 { 0xff } else { 0x00 };
        }
        return out;
    }
    let width = lane as usize;
    let mut pattern = (imm8 as u64) << shift;
    if low_ones {
        pattern |= (1u64 << shift) - 1;
    }
    for i in 0..bytes {
        let byte = ((pattern >> (8 * (i % width))) & 0xff) as u8;
        out[i] = if op { !byte } else { byte };
    }
    out
}
// ---------------------------------------------------------------- region bodies
//
// Invariant: a register local always holds the architecturally correct 64-bit value, so the top 32
// bits of a register are zero after any W-register write. An operation knows its own width, and a
// 32-bit operation masks its result before storing.

/// Emit one region, and when that fails, emit it again with refusals turned into traps.
///
/// A stored address that leads to code with one instruction this machine does not translate must
/// cost that instruction, not the function around it: the first attempt refuses the whole region,
/// the second traps at the words it cannot translate and leaves the rest working.
fn region_body(
    region: &Region,
    layout: &Layout,
    ids: &Ids,
    unsupported: &mut Vec<(u64, String)>,
) -> Result<Func, String> {
    let mut first = Vec::new();
    match RegionEmitter::new(region, layout, ids, &mut first).emit() {
        Ok(body) => {
            unsupported.extend(first);
            Ok(body)
        }
        Err(e) if !layout.allow_undefined => {
            let lenient = Layout { allow_undefined: true, ..*layout };
            let mut second = Vec::new();
            match RegionEmitter::new(region, &lenient, ids, &mut second).emit() {
                Ok(body) => {
                    unsupported.extend(second);
                    Ok(body)
                }
                Err(e) => {
                    unsupported.extend(second);
                    Err(e)
                }
            }
        }
        Err(e) => {
            unsupported.extend(first);
            Err(e)
        }
    }
}

/// A region that no amount of retrying can emit becomes a trap that names where it started.
fn trap_body(ty_region: u32, entry: u64, ids: &Ids) -> Func {
    let mut f = Func::new(ty_region);
    f.i32c(3);
    f.i64c(entry as i64);
    f.i32c(entry as i32);
    f.call(ids.trap);
    f.op(UNREACHABLE);
    f
}

/// Emit one region per entry, and remember the ones that could not be emitted.
///
/// A region is discovered from one entry and runs on until the next, so an entry that is not code
/// at all (a stored value, or a word of data that decodes as a call) can swallow real functions
/// that nothing else marked. Such a region keeps only its first block as a trap: the rest of its
/// block starts are left out of the dispatch table, so reaching one of them stops the run and the
/// host translates that address as a page of its own, from the code it really is.
fn emit_regions(
    regions: &[Region],
    layout: &Layout,
    ids: &Ids,
    ty_region: u32,
    unsupported: &mut Vec<(u64, String)>,
) -> (Vec<Func>, Vec<bool>) {
    let mut bodies = Vec::with_capacity(regions.len());
    let mut failed = Vec::with_capacity(regions.len());
    for region in regions {
        let entry = region.blocks[0].addr;
        match region_body(region, layout, ids, unsupported) {
            Ok(body) => {
                bodies.push(body);
                failed.push(false);
            }
            Err(e) => {
                unsupported.push((entry, e));
                bodies.push(trap_body(ty_region, entry, ids));
                failed.push(true);
            }
        }
    }
    (bodies, failed)
}

struct RegionEmitter<'a> {
    f: Func,
    region: &'a Region,
    layout: &'a Layout,
    ids: &'a Ids,
    unsupported: &'a mut Vec<(u64, String)>,
    open: u32,
    cur_pc: u64,
    /// Whether the instruction being emitted is a 64-bit vector form, whose destination keeps the
    /// upper half clear.
    narrow: bool,
}

impl<'a> RegionEmitter<'a> {
    fn new(
        region: &'a Region,
        layout: &'a Layout,
        ids: &'a Ids,
        unsupported: &'a mut Vec<(u64, String)>,
    ) -> Self {
        let mut f = Func::new(ids.ty_region);
        f.locals = vec![I32, I64, I64, I64, I64, I64, I32, V128, V128, V128, V128, V128, F64, F64];
        RegionEmitter { f, region, layout, ids, unsupported, open: 0, cur_pc: 0, narrow: false }
    }

    fn emit(mut self) -> Result<Func, String> {
        let n = self.region.blocks.len();
        self.f.lg(P_ENTRY);
        self.f.ls(L_PC);
        // The stack pointer has to name a page the guest mapped writable, which is what a kernel's
        // guard page answers and what holds for a thread's own stack as much as for the process's.
        // A stack that ran off the end of its mapping traps here, at region entry, which every
        // guest call and return passes.
        self.f.i32c(PTE_BASE as i32);
        self.f.lg(31);
        self.f.i64c(12);
        self.f.op(I64_SHR_U);
        self.f.wrap_i64();
        self.f.op(I32_ADD);
        self.f.mem(I32_LOAD8_U, 0, 0);
        self.f.i32c((pte::MAPPED | pte::WRITABLE) as i32);
        self.f.op(I32_AND);
        self.f.op(I32_EQZ);
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
        for (addr, insn) in insns {
            next = addr + 4;
            if is_terminator(&insn) {
                self.emit_trace(addr, self.layout.trace);
                self.emit_term(addr, insn)?;
                if !falls_through(&insn) {
                    return Ok(());
                }
                break;
            }
            self.emit_insn(addr, insn)?;
        }
        let n = self.region.blocks.len();
        let falls = i + 1 < n && self.region.blocks[i + 1].addr == next;
        if !falls {
            self.emit_jump(next);
        }
        Ok(())
    }

    // ---- value plumbing

    /// One operand of `extr`, as a 64-bit value of the instruction's width: register 31 is the
    /// zero register, not the stack pointer that a bare local read would give.
    fn extr_operand(&mut self, r: u32, sf: bool) {
        if r == 31 {
            self.f.i64c(0);
            return;
        }
        self.f.lg(r);
        if !sf {
            self.f.i64c(0xffff_ffff);
            self.f.op(I64_AND);
        }
    }

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
        for r in 0..NVEC {
            self.f.lg(NVEC0 + r);
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
            Insn::B { offset } => {
                self.emit_jump((addr as i64 + offset) as u64)
            }
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
            Insn::Svc => {
                // The host side reports which instruction called it, which is how a failing
                // syscall is traced back to the guest code that asked for it.
                self.f.i32c(SHADOW_PC as i32);
                self.f.i32c(addr as i32);
                self.f.mem(I32_STORE, 2, 0);
                self.f.i32c(SHADOW_RESUME as i32);
                self.f.i32c((addr + 4) as i32);
                self.f.mem(I32_STORE, 2, 0);
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
                // A region that returns a zero next pc is what stops the run loop, and the host
                // resumes this process with x0 holding the syscall's answer.
                self.f.i32c(0);
                self.end_return();
                self.close_if();
                if self.f.body.last() == Some(&UNREACHABLE) {}
                self.f.lg(L_T0);
                self.f.ls(0);
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


    // ---- SIMD and floating point

    fn getv(&mut self, r: u32) {
        self.f.lg(NVEC0 + r);
    }

    fn setv(&mut self, r: u32) {
        if self.narrow {
            // The 64-bit forms write the low half only. Guest code reads the register whole, so the
            // upper half has to be zero rather than whatever the operation left there.
            self.f.ls(L_V3);
            self.f.lg(L_V3);
            self.f.v128c([
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
            ]);
            self.f.simd(simd::V128_AND);
        }
        self.f.ls(NVEC0 + r);
    }

    /// The scalar in lane 0 of an FP register, as the wasm value of its own width.
    /// What a comparison of two FP scalars leaves in the flags: unordered is C and V set, greater
    /// is C, and equal is Z and C, packed the way the integer flags are.
    fn fp_compare_flags(&mut self, rn: u32, rm: u32, zero: bool, double: bool) {
        // An unordered comparison is the one outcome no ordinary comparison reports, and it has its
        // own NZCV: C and V set, which is what everything downstream tests.
        self.fp_is_nan(rn, double);
        if zero {
            self.f.i32c(0);
        } else {
            self.fp_is_nan(rm, double);
        }
        self.f.op(I32_OR);
        self.f.op(IF);
        self.f.body.push(I32);
        self.f.i32c(3);
        self.f.op(ELSE);
        self.fp_get(rn, double);
        self.fp_other(rm, zero, double);
        self.f.op(if double { F64_GT } else { F32_GT });
        self.f.op(IF);
        self.f.body.push(I32);
        self.f.i32c(2);
        self.f.op(ELSE);
        self.fp_get(rn, double);
        self.fp_other(rm, zero, double);
        self.f.op(if double { F64_EQ } else { F32_EQ });
        self.f.op(IF);
        self.f.body.push(I32);
        self.f.i32c(6);
        self.f.op(ELSE);
        self.f.i32c(8);
        self.f.end();
        self.f.end();
        self.f.end();
        self.f.op(I64_EXTEND_I32_U);
        self.f.ls(32);
    }

    fn fp_get(&mut self, r: u32, double: bool) {
        self.getv(r);
        self.f.simd_lane(if double { simd::F64X2_EXTRACT_LANE } else { simd::F32X4_EXTRACT_LANE }, 0);
    }

    /// A cleared register for a scalar result to land in lane 0 of: a scalar write zeroes the rest
    /// of the register, so the whole 128 bits are built rather than patched into what was there.
    fn fp_base(&mut self) {
        self.f.v128c([0; 16]);
    }

    /// Store the scalar on the stack into lane 0 of `r`, leaving the rest zero.
    fn fp_put(&mut self, r: u32, double: bool) {
        self.f.simd_lane(if double { simd::F64X2_REPLACE_LANE } else { simd::F32X4_REPLACE_LANE }, 0);
        self.setv(r);
    }

    fn fp_const(&mut self, bits: u64, double: bool) {
        if double {
            self.f.f64c(bits);
        } else {
            self.f.f32c(bits as u32);
        }
    }

    /// The second operand of a comparison, which is `+0.0` in the form that names no register.
    fn fp_other(&mut self, r: u32, zero: bool, double: bool) {
        if zero {
            self.fp_const(0, double);
        } else {
            self.fp_get(r, double);
        }
    }

    /// Push whether the scalar in `r` is a NaN, which is the only thing that tells wasm's min and
    /// max apart from AArch64's.
    fn fp_is_nan(&mut self, r: u32, double: bool) {
        self.fp_get(r, double);
        self.fp_get(r, double);
        self.f.op(if double { F64_NE } else { F32_NE });
    }

    /// The bit pattern of a scalar, for the NaN questions that only bits can answer.
    fn fp_bits(&mut self, r: u32, double: bool) {
        self.fp_get(r, double);
        self.f.op(if double { I64_REINTERPRET_F64 } else { I32_REINTERPRET_F32 });
    }

    /// The quiet form of a NaN: the bit that says it will not signal again.
    fn fp_quiet(&mut self, r: u32, double: bool) {
        let quiet = if double { 0x0008_0000_0000_0000u64 } else { 0x0040_0000 };
        self.fp_bits(r, double);
        if double {
            self.f.i64c(quiet as i64);
            self.f.op(I64_OR);
            self.f.op(F64_REINTERPRET_I64);
        } else {
            self.f.i32c(quiet as i32);
            self.f.op(I32_OR);
            self.f.op(F32_REINTERPRET_I32);
        }
    }

    /// Whether the scalar in `r` is a NaN that would signal.
    fn fp_is_snan(&mut self, r: u32, double: bool) {
        let quiet = if double { 0x0008_0000_0000_0000u64 } else { 0x0040_0000 };
        self.fp_is_nan(r, double);
        self.fp_bits(r, double);
        if double {
            self.f.i64c(quiet as i64);
            self.f.op(I64_AND);
            self.f.op(I64_EQZ);
        } else {
            self.f.i32c(quiet as i32);
            self.f.op(I32_AND);
            self.f.op(I32_EQZ);
        }
        self.f.op(I32_AND);
    }

    /// The NaN a binary operation hands back when it has one: the first signalling operand, made
    /// quiet, else the first quiet one. Both widths, so both tests, and the order matters.
    fn fp_process_nans(&mut self, rn: u32, rm: u32, double: bool) {
        let scalar = if double { F64 } else { F32 };
        self.fp_is_snan(rn, double);
        self.f.op(IF);
        self.f.body.push(scalar);
        self.fp_quiet(rn, double);
        self.f.op(ELSE);
        self.fp_is_snan(rm, double);
        self.f.op(IF);
        self.f.body.push(scalar);
        self.fp_quiet(rm, double);
        self.f.op(ELSE);
        self.fp_is_nan(rn, double);
        self.f.op(IF);
        self.f.body.push(scalar);
        self.fp_get(rn, double);
        self.f.op(ELSE);
        self.fp_get(rm, double);
        self.f.end();
        self.f.end();
        self.f.end();
    }

    /// `fmax`/`fmin` and their number forms. A signalling NaN wins over everything, quieted; a
    /// quiet one wins over the number in the ordinary form and loses to it in the number form.
    /// wasm's min and max do neither, and their NaN is whatever the engine picks.
    fn fp_minmax(&mut self, rn: u32, rm: u32, double: bool, max: bool, number: bool) {
        let scalar = if double { F64 } else { F32 };
        let op = match (max, double) {
            (true, true) => F64_MAX,
            (true, false) => F32_MAX,
            (false, true) => F64_MIN,
            (false, false) => F32_MIN,
        };
        self.fp_is_nan(rn, double);
        self.fp_is_nan(rm, double);
        self.f.op(I32_OR);
        self.f.op(I32_EQZ);
        self.f.op(IF);
        self.f.body.push(scalar);
        self.fp_get(rn, double);
        self.fp_get(rm, double);
        self.f.op(op);
        self.f.op(ELSE);
        self.fp_is_snan(rn, double);
        self.f.op(IF);
        self.f.body.push(scalar);
        self.fp_quiet(rn, double);
        self.f.op(ELSE);
        self.fp_is_snan(rm, double);
        self.f.op(IF);
        self.f.body.push(scalar);
        self.fp_quiet(rm, double);
        self.f.op(ELSE);
        self.fp_is_nan(rn, double);
        self.f.op(IF);
        self.f.body.push(scalar);
        self.fp_get(if number { rm } else { rn }, double);
        self.f.op(ELSE);
        self.fp_get(if number { rn } else { rm }, double);
        self.f.end();
        self.f.end();
        self.f.end();
        self.f.end();
    }

    /// `frinta`: round to nearest with ties away from zero, which wasm does not have. Rounding
    /// through a double is exact for a single, and the result of rounding is always representable.
    fn fp_round_away(&mut self, r: u32, double: bool) {
        self.fp_get(r, double);
        if !double {
            self.f.op(F64_PROMOTE_F32);
        }
        self.f.ls(L_F0);
        self.f.lg(L_F0);
        self.f.op(F64_TRUNC);
        self.f.ls(L_F1);
        self.f.lg(L_F0);
        self.f.lg(L_F1);
        self.f.op(F64_SUB);
        self.f.op(F64_ABS);
        self.f.f64c(0.5f64.to_bits());
        self.f.op(F64_GE);
        self.f.op(IF);
        self.f.body.push(F64);
        self.f.lg(L_F1);
        // copysign takes its magnitude first and its sign second, so the one goes on first.
        self.f.f64c(1.0f64.to_bits());
        self.f.lg(L_F0);
        self.f.op(F64_COPYSIGN);
        self.f.op(F64_ADD);
        self.f.op(ELSE);
        self.f.lg(L_F1);
        self.f.end();
        if !double {
            self.f.op(F32_DEMOTE_F64);
        }
    }

    /// A vector register read into a scratch local, so a second read can follow.
    fn savev(&mut self, r: u32, tmp: u32) {
        self.getv(r);
        self.f.ls(tmp);
    }

    fn vload(&mut self, width: u32, addr: u32, rt: u32) {
        self.vload_local(width, addr, NVEC0 + rt);
    }

    /// The same load into a scratch local, for a form whose destination registers are still the
    /// source of the next step.
    fn vload_local(&mut self, width: u32, addr: u32, local: u32) {
        self.check_byte(addr, width as u64);
        match width {
            16 | 8 | 4 => {
                self.f.lg(addr);
                self.f.wrap_i64();
                let op = match width {
                    16 => simd::V128_LOAD,
                    8 => simd::V128_LOAD64_ZERO,
                    _ => simd::V128_LOAD32_ZERO,
                };
                self.f.simd_mem(op, width.trailing_zeros(), 0);
            }
            _ => {
                self.f.v128c([0; 16]);
                self.f.lg(addr);
                self.f.wrap_i64();
                if width == 2 {
                    self.f.mem(I32_LOAD16_U, 1, 0);
                } else {
                    self.f.mem(I32_LOAD8_U, 0, 0);
                }
                self.f.simd_lane(simd::I32X4_REPLACE_LANE, 0);
            }
        }
        self.f.ls(local);
    }

    fn vstore(&mut self, width: u32, addr: u32, rt: u32) {
        self.vstore_local(width, addr, NVEC0 + rt);
    }

    fn vstore_local(&mut self, width: u32, addr: u32, local: u32) {
        self.check_byte(addr, width as u64);
        self.f.lg(addr);
        self.f.wrap_i64();
        match width {
            16 => {
                self.f.lg(local);
                self.f.simd_mem(simd::V128_STORE, 4, 0);
            }
            8 => {
                self.f.lg(local);
                self.f.simd_mem_lane(simd::V128_STORE64_LANE, 3, 0, 0);
            }
            4 => {
                self.f.lg(local);
                self.f.simd_mem_lane(simd::V128_STORE32_LANE, 2, 0, 0);
            }
            2 => {
                self.f.lg(local);
                self.f.simd_lane(simd::I16X8_EXTRACT_LANE_U, 0);
                self.f.mem(I32_STORE16, 1, 0);
            }
            _ => {
                self.f.lg(local);
                self.f.simd_lane(simd::I8X16_EXTRACT_LANE_U, 0);
                self.f.mem(I32_STORE8, 0, 0);
            }
        }
    }

    /// Writeback of the addressing-mode increment for the paired and multi-register forms.
    fn writeback(&mut self, rn: u32, base: u32, add: i64) {
        self.f.lg(base);
        if add != 0 {
            self.f.i64c(add);
            self.f.op(I64_ADD);
        }
        self.f.ls(rn);
    }

    /// Store a value already in a scratch local into a guest register, honouring the zero register.
    fn set_loaded(&mut self, r: u32, tmp: u32) {
        if r == 31 {
            return;
        }
        self.f.lg(tmp);
        self.f.ls(r);
    }

    /// A single `v128` op with two vector sources and a vector destination.
    fn vec3(&mut self, rn: u32, rm: u32, rd: u32, op: u32) {
        self.getv(rn);
        self.getv(rm);
        self.f.simd(op);
        self.setv(rd);
    }

    fn vec2(&mut self, rn: u32, rd: u32, op: u32) {
        self.getv(rn);
        self.f.simd(op);
        self.setv(rd);
    }

    /// `fmax`/`fmin` and their `nm` pair, lane by lane. A lane with a NaN on both sides keeps the
    /// first of them in the order the architecture passes NaN operands on, quieted - a signalling
    /// one before a quiet one, and the first operand before the second - and the two forms part
    /// only where one side is a number: the plain form passes the NaN on, `nm` answers the number.
    /// wasm's own max decides a NaN lane for itself, so every such lane is put right afterwards.
    fn vec_minmax(&mut self, rn: u32, rm: u32, rd: u32, double: bool, max: bool, number: bool) {
        self.getv(rn);
        self.f.ls(L_V0);
        self.getv(rm);
        self.f.ls(L_V1);
        self.minmax_into(double, max, number);
        self.f.lg(L_V2);
        self.setv(rd);
    }

    /// The same, on the two operands the caller left in the first two scratch values, with the
    /// answer in the third: a reduction has to fold a vector against a copy of itself.
    fn minmax_into(&mut self, double: bool, max: bool, number: bool) {
        let (op, ne, eq) = if double {
            (
                if max { simd::F64X2_MAX } else { simd::F64X2_MIN },
                simd::F64X2_NE,
                simd::I64X2_EQ,
            )
        } else {
            (
                if max { simd::F32X4_MAX } else { simd::F32X4_MIN },
                simd::F32X4_NE,
                simd::I32X4_EQ,
            )
        };
        let quiet = lane_repeat(double, 0x0008_0000_0000_0000, 0x0040_0000);
        self.f.lg(L_V0);
        self.f.lg(L_V1);
        self.f.simd(op);
        self.f.ls(L_V2);
        // `bitselect` takes its first operand where the mask is set, so each step names what the
        // lanes it covers should hold, and the one that is not a NaN comes next.
        self.nan_lanes_quiet(L_V1, L_V2, ne, quiet);
        self.nan_lanes_quiet(L_V0, L_V2, ne, quiet);
        // The second operand signalling where the first is only quiet is the one passed on.
        self.f.lg(L_V1);
        self.f.v128c(quiet);
        self.f.simd(simd::V128_OR);
        self.f.lg(L_V2);
        self.f.lg(L_V1);
        self.f.lg(L_V1);
        self.f.simd(ne);
        self.f.lg(L_V1);
        self.f.v128c(quiet);
        self.f.simd(simd::V128_AND);
        self.f.v128c([0; 16]);
        self.f.simd(eq);
        self.f.simd(simd::V128_AND);
        self.f.lg(L_V0);
        self.f.v128c(quiet);
        self.f.simd(simd::V128_AND);
        self.f.v128c([0; 16]);
        self.f.simd(eq);
        self.f.simd(simd::V128_ANDNOT);
        self.f.simd(simd::V128_BITSELECT);
        self.f.ls(L_V2);
        if number {
            // One NaN and one number: the number is the answer.
            self.nan_lanes_take_number(L_V1, L_V0, L_V2, ne, eq, quiet);
            self.nan_lanes_take_number(L_V0, L_V1, L_V2, ne, eq, quiet);
        }
    }

    /// The lanes of `scratch` where `other` is a NaN, taken as its quiet form.
    fn nan_lanes_quiet(&mut self, other: u32, scratch: u32, ne: u32, quiet: [u8; 16]) {
        self.f.lg(other);
        self.f.v128c(quiet);
        self.f.simd(simd::V128_OR);
        self.f.lg(scratch);
        self.f.lg(other);
        self.f.lg(other);
        self.f.simd(ne);
        self.f.simd(simd::V128_BITSELECT);
        self.f.ls(scratch);
    }

    /// The lanes of `scratch` where `nan` is a quiet NaN and `number` is not a NaN: those take the
    /// number, which is the whole difference `nm` has from the plain max and min. A signalling NaN
    /// is not one of them: it is passed on, quieted, by both forms.
    fn nan_lanes_take_number(
        &mut self,
        nan: u32,
        number: u32,
        scratch: u32,
        ne: u32,
        eq: u32,
        quiet: [u8; 16],
    ) {
        self.f.lg(number);
        self.f.lg(scratch);
        self.f.lg(nan);
        self.f.lg(nan);
        self.f.simd(ne);
        self.f.lg(number);
        self.f.lg(number);
        self.f.simd(ne);
        self.f.simd(simd::V128_NOT);
        self.f.simd(simd::V128_AND);
        self.f.lg(nan);
        self.f.v128c(quiet);
        self.f.simd(simd::V128_AND);
        self.f.v128c([0; 16]);
        self.f.simd(eq);
        self.f.simd(simd::V128_ANDNOT);
        self.f.simd(simd::V128_BITSELECT);
        self.f.ls(scratch);
    }

    /// Round to integral with ties away from zero, lane by lane: the truncation plus one in the
    /// direction of the sign where half a lane or more was left over. A value that is already an
    /// integer, and an infinity or a NaN, come back as they are, because their leftover is either
    /// zero or not a number.
    fn vec_round_away(&mut self, rn: u32, rd: u32, double: bool) {
        let (trunc, sub, abs, ge, add) = if double {
            (
                simd::F64X2_TRUNC,
                simd::F64X2_SUB,
                simd::F64X2_ABS,
                simd::F64X2_GE,
                simd::F64X2_ADD,
            )
        } else {
            (
                simd::F32X4_TRUNC,
                simd::F32X4_SUB,
                simd::F32X4_ABS,
                simd::F32X4_GE,
                simd::F32X4_ADD,
            )
        };
        self.getv(rn);
        self.f.simd(trunc);
        self.f.ls(L_V0);
        self.getv(rn);
        self.f.ls(L_V1);
        // The leftover, as a magnitude: what is left after the truncation, one way or the other.
        self.f.lg(L_V1);
        self.f.lg(L_V0);
        self.f.simd(sub);
        self.f.simd(abs);
        self.f.v128c(lane_repeat(double, 0x3fe0_0000_0000_0000, 0x3f00_0000));
        self.f.simd(ge);
        self.f.ls(L_V2);
        // One with the sign of the value, masked out where the leftover was less than a half.
        self.f.lg(L_V1);
        self.f.v128c(sign_mask(double));
        self.f.simd(simd::V128_AND);
        self.f.v128c(lane_repeat(double, 0x3ff0_0000_0000_0000, 0x3f80_0000));
        self.f.simd(simd::V128_OR);
        self.f.lg(L_V2);
        self.f.simd(simd::V128_AND);
        self.f.lg(L_V0);
        self.f.simd(add);
        self.setv(rd);
    }

    /// Element width code (0..3) to the matching wasm lane opcode, so one table can serve all sizes.
    fn lanes_op(&self, size: u32, ops: [u32; 4]) -> Option<u32> {
        if size > 3 {
            None
        } else {
            Some(ops[size as usize])
        }
    }

    /// Byte shuffle of two operands: `mask` holds 16 lane indices, 0..15 from `a`, 16..31 from `b`.
    fn shuffle(&mut self, a: u32, b: u32, mask: [u8; 16]) {
        self.f.lg(a);
        self.f.lg(b);
        self.f.simd(simd::I8X16_SHUFFLE);
        self.f.body.extend_from_slice(&mask);
    }


    /// A pairwise operation across adjacent lanes: `pairs(a)` in the low half, `pairs(b)` in the high.
    fn vec_pairwise(&mut self, size: u32, op: u32, rn: u32, rm: u32, rd: u32) {
        let (even, odd) = pair_masks(size);
        self.shuffle(NVEC0 + rn, NVEC0 + rm, even);
        self.f.ls(L_V0);
        self.shuffle(NVEC0 + rn, NVEC0 + rm, odd);
        self.f.ls(L_V1);
        self.f.lg(L_V0);
        self.f.lg(L_V1);
        self.f.simd(op);
        self.setv(rd);
    }

    /// The byte product of two vectors, which wasm has no lane opcode for: widen each half to 16
    /// bits, multiply, then take the low byte of every product.
    fn byte_mul(&mut self, rn: u32, rm: u32, out: u32) {
        self.getv(rn);
        self.f.simd(simd::I16X8_EXTEND_LOW_I8X16_U);
        self.f.ls(L_V2);
        self.getv(rm);
        self.f.simd(simd::I16X8_EXTEND_LOW_I8X16_U);
        self.f.lg(L_V2);
        self.f.simd(simd::I16X8_MUL);
        self.f.ls(L_V2);
        self.getv(rn);
        self.f.simd(simd::I16X8_EXTEND_HIGH_I8X16_U);
        self.f.ls(L_V3);
        self.getv(rm);
        self.f.simd(simd::I16X8_EXTEND_HIGH_I8X16_U);
        self.f.lg(L_V3);
        self.f.simd(simd::I16X8_MUL);
        self.f.ls(L_V3);
        self.shuffle(L_V2, L_V3, [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30]);
        self.f.ls(out);
    }

    /// `cmhi`/`cmhs` on 64-bit lanes: wasm has only the signed comparison, so flipping the sign bit
    /// of both operands turns it into the unsigned one.
    fn vec_cmp_64_unsigned(&mut self, rn: u32, rm: u32, rd: u32, strict: bool) {
        let mut sign = [0u8; 16];
        sign[7] = 0x80;
        sign[15] = 0x80;
        self.getv(rn);
        self.f.v128c(sign);
        self.f.simd(simd::V128_XOR);
        self.f.ls(L_V0);
        self.getv(rm);
        self.f.v128c(sign);
        self.f.simd(simd::V128_XOR);
        self.f.ls(L_V1);
        if strict {
            self.f.lg(L_V1);
            self.f.lg(L_V0);
            self.f.simd(simd::I64X2_LT_S);
        } else {
            self.f.lg(L_V0);
            self.f.lg(L_V1);
            self.f.simd(simd::I64X2_LT_S);
            self.f.simd(simd::V128_NOT);
        }
        self.setv(rd);
    }

    /// A vector with the same constant in every lane.
    fn splat_const(&mut self, size: u32, value: i64) {
        if size == 3 {
            self.f.i64c(value);
            self.f.simd(simd::I64X2_SPLAT);
        } else {
            self.f.i32c(value as i32);
            self.f.simd([simd::I8X16_SPLAT, simd::I16X8_SPLAT, simd::I32X4_SPLAT][size as usize]);
        }
    }

    /// `acc op= 2^k` for the lanes whose `count` has bit `k` set, for every bit of a lane's count.
    fn doubling_shift(&mut self, acc: u32, count: u32, op: u32, ne: u32, size: u32, steps: u32) {
        for k in 0..steps {
            self.f.lg(acc);
            self.f.i32c(1 << k);
            self.f.simd(op);
            self.f.lg(acc);
            self.f.lg(count);
            self.splat_const(size, 1 << k);
            self.f.simd(simd::V128_AND);
            self.f.v128c([0; 16]);
            self.f.simd(ne);
            self.f.simd(simd::V128_BITSELECT);
            self.f.ls(acc);
        }
    }

    /// `sshl`/`ushl`: a positive count in the second operand shifts left, a negative one shifts
    /// right, and a count that reaches the lane width leaves zero or, for the arithmetic form, the
    /// sign. Wasm shifts take one count for the whole vector and mask it, so each lane's count is
    /// applied as `log2(esize)` conditional doublings of the shift amount.
    fn vec_shift_by_lane(&mut self, addr: u64, size: u32, u: bool, rn: u32, rm: u32, rd: u32) -> Result<(), String> {
        let esize = 8i64 << size;
        let shl = self.lanes_op(size, [simd::I8X16_SHL, simd::I16X8_SHL, simd::I32X4_SHL, simd::I64X2_SHL]);
        let shr_s = self.lanes_op(size, [simd::I8X16_SHR_S, simd::I16X8_SHR_S, simd::I32X4_SHR_S, simd::I64X2_SHR_S]);
        let shr_u = self.lanes_op(size, [simd::I8X16_SHR_U, simd::I16X8_SHR_U, simd::I32X4_SHR_U, simd::I64X2_SHR_U]);
        let ge = self.lanes_op(size, [simd::I8X16_GE_S, simd::I16X8_GE_S, simd::I32X4_GE_S, simd::I64X2_GE_S]);
        let lt = self.lanes_op(size, [simd::I8X16_LT_S, simd::I16X8_LT_S, simd::I32X4_LT_S, simd::I64X2_LT_S]);
        let le = self.lanes_op(size, [simd::I8X16_LE_S, simd::I16X8_LE_S, simd::I32X4_LE_S, simd::I64X2_LE_S]);
        let ne = self.lanes_op(size, [simd::I8X16_NE, simd::I16X8_NE, simd::I32X4_NE, simd::I64X2_NE]);
        let sub = self.lanes_op(size, [simd::I8X16_SUB, simd::I16X8_SUB, simd::I32X4_SUB, simd::I64X2_SUB]);
        let (Some(shl), Some(shr_s), Some(shr_u), Some(ge), Some(lt), Some(le), Some(ne), Some(sub)) =
            (shl, shr_s, shr_u, ge, lt, le, ne, sub)
        else {
            return self.refuse(format!("unsupported lane shift at 0x{addr:x}"));
        };
        let steps = (esize as u32).trailing_zeros();

        // The shift amount of a lane is the low byte of that lane, as a signed 8-bit value.
        if size == 0 {
            self.getv(rm);
            self.f.ls(L_V1);
        } else {
            self.getv(rm);
            self.splat_const(size, 0xff);
            self.f.simd(simd::V128_AND);
            self.f.ls(L_V2);
            self.f.lg(L_V2);
            self.splat_const(size, 0x80);
            self.f.simd(ge);
            self.splat_const(size, 0x100);
            self.f.simd(simd::V128_AND);
            self.f.ls(L_V3);
            self.f.lg(L_V2);
            self.f.lg(L_V3);
            self.f.simd(sub);
            self.f.ls(L_V1);
        }
        self.f.v128c([0; 16]);
        self.f.lg(L_V1);
        self.f.simd(sub);
        self.f.ls(L_V2); // its negation, the right-shift amount

        self.getv(rn);
        self.f.ls(L_V0);
        self.doubling_shift(L_V0, L_V1, shl, ne, size, steps);
        self.f.lg(L_V0);
        self.f.lg(L_V1);
        self.f.v128c([0; 16]);
        self.f.simd(ge);
        self.f.lg(L_V1);
        self.splat_const(size, esize);
        self.f.simd(lt);
        self.f.simd(simd::V128_AND);
        self.f.simd(simd::V128_AND);
        self.f.ls(L_V3);

        self.getv(rn);
        self.f.ls(L_V0);
        self.doubling_shift(L_V0, L_V2, if u { shr_u } else { shr_s }, ne, size, steps);
        // The saturation term comes first: bitselect keeps its first operand where the mask is set.
        if u {
            self.f.v128c([0; 16]);
        } else {
            self.getv(rn);
            self.f.i32c((esize - 1) as i32);
            self.f.simd(shr_s);
            self.f.i32c((esize - 1) as i32);
            self.f.simd(shr_s);
        }
        self.f.lg(L_V0);
        self.f.lg(L_V1);
        self.splat_const(size, -esize);
        self.f.simd(le);
        self.f.simd(simd::V128_BITSELECT);
        self.f.lg(L_V1);
        self.f.v128c([0; 16]);
        self.f.simd(lt);
        self.f.simd(simd::V128_AND);
        self.f.lg(L_V3);
        self.f.simd(simd::V128_OR);
        self.setv(rd);
        Ok(())
    }

    /// A reduction across all lanes, confined to the element width and left in lane 0.
    fn vec_across(&mut self, size: u32, op: u32, rn: u32, rd: u32) {
        self.getv(rn);
        self.f.ls(L_V0);
        let lanes = 16u32 >> size;
        let mut width = lanes;
        while width > 1 {
            width /= 2;
            let mask = halve_mask(size, width);
            self.f.lg(L_V0);
            self.f.lg(L_V0);
            self.f.simd(simd::I8X16_SHUFFLE);
            self.f.body.extend_from_slice(&mask);
            self.f.ls(L_V1);
            self.f.lg(L_V0);
            self.f.lg(L_V1);
            self.f.simd(op);
            self.f.ls(L_V0);
        }
        // The partial sums past the first lane are dead: the reduction is a scalar result.
        self.f.lg(L_V0);
        self.f.v128c(lane_zero_mask(size));
        self.f.simd(simd::V128_AND);
        self.setv(rd);
    }

    /// The FP forms of the across group: a scalar out of the two lanes of a `d` register or the four
    /// of a `q` one, by folding the halves of the register together.
    fn vec_across_fp(&mut self, rn: u32, rd: u32, double: bool, max: bool) {
        self.getv(rn);
        self.f.ls(L_V0);
        self.f.lg(L_V0);
        self.f.lg(L_V0);
        self.f.simd(simd::I8X16_SHUFFLE);
        self.f.body.extend_from_slice(&swap_halves_mask());
        self.f.ls(L_V1);
        self.minmax_into(double, max, false);
        if !double {
            self.f.lg(L_V2);
            self.f.ls(L_V0);
            self.f.lg(L_V0);
            self.f.lg(L_V0);
            self.f.simd(simd::I8X16_SHUFFLE);
            self.f.body.extend_from_slice(&swap_words_mask());
            self.f.ls(L_V1);
            self.minmax_into(double, max, false);
        }
        // The lanes past the first are dead: a scalar result, with the rest of the register clear.
        self.f.lg(L_V2);
        self.f.v128c(lane_zero_mask(if double { 3 } else { 2 }));
        self.f.simd(simd::V128_AND);
        self.setv(rd);
    }

    /// `faddp` in its scalar form: the two lanes of a `d` register added.
    fn vec_across_fp_add(&mut self, rn: u32, rd: u32, double: bool) {
        let add = if double { simd::F64X2_ADD } else { simd::F32X4_ADD };
        self.getv(rn);
        self.f.ls(L_V0);
        self.f.lg(L_V0);
        self.f.lg(L_V0);
        self.f.simd(simd::I8X16_SHUFFLE);
        self.f.body.extend_from_slice(&swap_halves_mask());
        self.f.ls(L_V1);
        self.f.lg(L_V0);
        self.f.lg(L_V1);
        self.f.simd(add);
        self.f.v128c(lane_zero_mask(if double { 3 } else { 2 }));
        self.f.simd(simd::V128_AND);
        self.setv(rd);
    }

    /// Narrow a vector to half-width lanes, packed into the low 8 bytes and zeroing (XTN) or keeping
    /// (XTN2) the upper half.
    fn vec_narrow(&mut self, size: u32, src: u32, dst: u32, into_high: bool) {
        let mask = narrow_mask(size, into_high);
        if into_high {
            // The source arrives in L_V0, so the preserved destination goes to another local.
            self.getv(dst);
            self.f.ls(L_V1);
            self.f.lg(L_V1);
            self.f.lg(src);
        } else {
            self.f.v128c([0; 16]);
            self.f.lg(src);
        }
        self.f.simd(simd::I8X16_SHUFFLE);
        self.f.body.extend_from_slice(&mask);
        self.setv(dst);
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
            // opc 2 sign-extends to the full register and opc 3 to 32 bits, which zeroes the top
            // half: an `ldrsb x` whose sign stops at bit 31 puts 0x00000000ffffffff in a register
            // where the guest expects 0xffffffffffffffff, and every index built from it is wrong.
            (0, 2) => {
                self.f.mem(I64_LOAD8_S, 0, 0);
                self.set(rt, true);
            }
            (1, 2) => {
                self.f.mem(I64_LOAD16_S, 1, 0);
                self.set(rt, true);
            }
            (2, 2) => {
                self.f.mem(I64_LOAD32_S, 2, 0);
                self.set(rt, true);
            }
            (0, 3) => {
                self.f.mem(I32_LOAD8_S, 0, 0);
                self.set(rt, false);
            }
            (1, 3) => {
                self.f.mem(I32_LOAD16_S, 1, 0);
                self.set(rt, false);
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

    /// An instruction the translator cannot emit. With `allow_undefined` it becomes a trap at the
    /// instruction instead of a refusal, so one run reports every gap rather than the first.
    fn refuse(&mut self, why: String) -> Result<(), String> {
        self.unsupported.push((self.cur_pc, why.clone()));
        if !self.layout.allow_undefined {
            return Err(why);
        }
        self.f.i32c(3);
        self.f.i64c(self.cur_pc as i64);
        self.f.i32c(self.cur_pc as i32);
        self.f.call(self.ids.trap);
        self.f.op(UNREACHABLE);
        Ok(())
    }

    // ---- instructions

    /// The register shadow and the call into the host, before the instruction at `addr` runs.
    /// `state` says whether the register file goes with it: finding a loop that never ends needs
    /// the address alone, and writing all 63 registers at every branch would make the module ten
    /// times the size of the image for it.
    fn emit_trace(&mut self, addr: u64, state: bool) {
        let Some(t) = self.ids.trace else { return };
        if state {
            for r in 0..NR {
                self.f.i32c(SHADOW as i32 + (r as i32) * 8);
                self.f.lg(r);
                self.f.mem(I64_STORE, 3, 0);
            }
            for r in 0..NVEC {
                self.f.i32c((SHADOW_V0 + r as u64 * 16) as i32);
                self.f.lg(NVEC0 + r);
                self.f.simd_mem(simd::V128_STORE, 4, 0);
            }
            self.f.i32c(SHADOW_PC as i32);
            self.f.i32c(addr as i32);
            self.f.mem(I32_STORE, 2, 0);
        }
        self.f.i32c(addr as i32);
        self.f.lg(31);
        self.f.call(t);
    }

    fn emit_insn(&mut self, addr: u64, insn: Insn) -> Result<(), String> {
        self.cur_pc = addr;
        self.narrow = narrows_to_low_half(&insn);
        if self.layout.trace {
            self.emit_trace(addr, true);
        }
        match insn {
            Insn::Hint => {}
            // The terminator table handles a syscall: it ends the block it is in.
            Insn::Svc => return Err(format!("syscall at 0x{addr:x} is not a block end")),
            Insn::Undefined => return self.refuse(format!("undecoded instruction at 0x{addr:x}")),
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
                    self.set_sp(rd, sf);
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
                // A bitfield move names a field of the source and where it lands. The plain form
                // extracts it from `immr` down to the bottom; the wrapping form, which is what a
                // compiler emits for a shifted field (ubfiz/sbfiz/bfi), takes the low `imms + 1`
                // bits and puts them at the top of the register.
                let (len, pos) = if imms >= immr { (imms - immr + 1, 0) } else { (imms + 1, w - immr) };
                let mask: u64 = if len >= 64 { u64::MAX } else { (1u64 << len) - 1 };
                if rn == 31 {
                    self.f.i64c(0);
                } else {
                    self.f.lg(rn);
                }
                self.mask_w(sf);
                if pos == 0 && immr != 0 {
                    self.f.i64c(immr as i64);
                    self.f.op(I64_SHR_U);
                }
                self.f.i64c(mask as i64);
                self.f.op(I64_AND);
                self.f.ls(L_T0);
                if opc == 0 && len < w {
                    // The extension fills the whole register, so the shift is the register's width:
                    // a 32-bit `sxtb w` still has to reach bit 63 for its result to be negative.
                    let sh = 64 - len;
                    self.f.lg(L_T0);
                    self.f.i64c(sh as i64);
                    self.f.op(I64_SHL);
                    self.f.i64c(sh as i64);
                    self.f.op(I64_SHR_S);
                    self.f.ls(L_T0);
                }
                match opc {
                    0 | 2 => {
                        if rd == 31 {
                            return Ok(());
                        }
                        self.f.lg(L_T0);
                        if pos != 0 {
                            self.f.i64c(pos as i64);
                            self.f.op(I64_SHL);
                        }
                        self.mask_w(sf);
                        self.f.ls(rd);
                    }
                    1 => {
                        if rd == 31 {
                            return Ok(());
                        }
                        // bfi/bfxil: the field replaces the same bits of the destination.
                        let at = if len >= 64 { u64::MAX } else { mask << pos };
                        self.f.lg(rd);
                        self.f.i64c(!at as i64);
                        self.f.op(I64_AND);
                        self.f.lg(L_T0);
                        if pos != 0 {
                            self.f.i64c(pos as i64);
                            self.f.op(I64_SHL);
                        }
                        self.f.op(I64_OR);
                        self.mask_w(sf);
                        self.f.ls(rd);
                    }
                    _ => return Err(format!("unallocated bitfield at 0x{addr:x}")),
                }
            }
            Insn::Extract { sf, rm, lsb, rn, rd } => {
                let w: u32 = if sf { 64 } else { 32 };
                if lsb >= w {
                    return Err(format!("invalid extr at 0x{addr:x}"));
                }
                // The low half of `rn:rm` shifted right: the bits that leave `rm` come back at the
                // top of `rn`, which is why the same register twice is a rotate by immediate. Both
                // operands are narrowed to the instruction's width first, because a 32-bit value
                // shifted up into the high half of the register would lose exactly the bits the
                // rotate is supposed to bring back. Register 31 is the zero register here, so it
                // reads as zero: `extr x, xzr, x, #63` is how OpenSSL's montgomery square brings a
                // carry bit in.
                self.extr_operand(rm, sf);
                if lsb != 0 {
                    self.f.i64c(lsb as i64);
                    self.f.op(I64_SHR_U);
                    self.extr_operand(rn, sf);
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
                    3 => {
                        // `rev`: reverse the byte order of the whole register.
                        self.f.lg(rn);
                        self.f.call(if sf { self.ids.bswap64 } else { self.ids.bswap32 });
                        self.f.ls(rd);
                    }
                    5 => {
                        // `cls` counts the leading bits that repeat the sign, so it is `clz` of the
                        // value xor its own sign bit, one less.
                        self.get(rn, sf);
                        self.f.ls(L_T0);
                        self.f.lg(L_T0);
                        self.f.i64c(if sf { 63 } else { 31 });
                        self.f.op(I64_SHR_U);
                        self.f.i64c(1);
                        self.f.op(I64_AND);
                        self.f.ls(L_T1);
                        self.f.i64c(0);
                        self.f.lg(L_T1);
                        self.f.op(I64_SUB);
                        if !sf {
                            self.f.i64c(0xffff_ffff);
                            self.f.op(I64_AND);
                        }
                        self.f.lg(L_T0);
                        self.f.op(I64_XOR);
                        if !sf {
                            self.f.wrap_i64();
                        }
                        self.f.op(if sf { I64_CLZ } else { I32_CLZ });
                        self.to_i64(sf);
                        self.f.i64c(1);
                        self.f.op(I64_SUB);
                        self.set(rd, sf);
                    }
                    _ => return self.refuse(format!("unsupported one-source op {op} at 0x{addr:x}")),
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
            Insn::MulLong { signed, sub, rm, ra, rn, rd } => {
                // Widen the 32-bit operands to 64: a mask for unsigned, a shift pair for signed,
                // because the sign-extending wasm opcodes are one instruction each but the shift
                // pair works for both widths without another table.
                let widen = |e: &mut Self| {
                    if signed {
                        e.f.i64c(32);
                        e.f.op(I64_SHL);
                        e.f.i64c(32);
                        e.f.op(I64_SHR_S);
                    } else {
                        e.f.i64c(0xffff_ffff);
                        e.f.op(I64_AND);
                    }
                };
                self.get(rn, true);
                widen(self);
                self.f.ls(L_T1);
                self.get(rm, true);
                widen(self);
                self.f.ls(L_T2);
                self.f.lg(L_T1);
                self.f.lg(L_T2);
                self.f.op(I64_MUL);
                self.f.ls(L_T0);
                self.get(ra, true);
                self.f.lg(L_T0);
                self.f.op(if sub { I64_SUB } else { I64_ADD });
                self.set(rd, true);
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
                    self.get_sp(rn, sf);
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
                    self.get_sp(rn, sf);
                    self.to_i64(sf);
                    self.push_extended(rm, extend);
                    if amount != 0 {
                        self.f.i64c(amount as i64);
                        self.f.op(I64_SHL);
                    }
                    self.f.op(if sub { I64_SUB } else { I64_ADD });
                    self.mask_w(sf);
                    // The result is already a zero-extended 64-bit value, so storing it needs no
                    // widening: set_sp would ask for an i32 that the mask has already cleared.
                    self.f.ls(if rd == 31 { 31 } else { rd });
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
                // The result moves to T0, where the store reads it whatever the flags wanted: the
                // formulas take T1 and T2 for the two operands, and T2 is where the result was.
                self.f.lg(L_T2);
                self.f.ls(L_T0);
                if setflags {
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
                    self.f.lg(L_T0);
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
                match op2 {
                    1 => {
                        // csinc adds one, which only looks like an or for an even operand.
                        self.get(rm, sf);
                        self.push_imm(1, sf);
                        self.f.op(if sf { I64_ADD } else { I32_ADD });
                    }
                    2 => {
                        self.get(rm, sf);
                        self.push_imm(self.width_mask(sf) as u64, sf);
                        self.f.op(if sf { I64_XOR } else { I32_XOR });
                    }
                    3 => {
                        // csneg is zero minus the operand, so the zero goes on the stack first.
                        self.push_imm(0, sf);
                        self.get(rm, sf);
                        self.f.op(if sf { I64_SUB } else { I32_SUB });
                    }
                    _ => self.get(rm, sf),
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
            Insn::CacheOp => {}
            Insn::MsrSys { reg, rn } => match reg {
                SysReg::Nzcv => {
                    // The architectural register holds N,Z,C,V in bits 31:28; the emitter packs the
                    // same four flags into bits 3:0, so the two differ by a shift and nothing else.
                    if rn == 31 {
                        self.f.i64c(0);
                    } else {
                        self.f.lg(rn);
                        self.f.i64c(28);
                        self.f.op(I64_SHR_U);
                    }
                    self.f.ls(32);
                }
                SysReg::TpidrEl0 | SysReg::TpidrroEl0 => {
                    self.f.i32c(SHADOW_TP as i32);
                    if rn == 31 {
                        self.f.i64c(0);
                    } else {
                        self.f.lg(rn);
                    }
                    self.f.mem(I64_STORE, 3, 0);
                }
                // FPCR and FPSR are stored so a read returns what was written; nothing acts on
                // them yet, which means FP rounding stays at the default.
                SysReg::Fpcr | SysReg::Fpsr => {
                    let at = if reg == SysReg::Fpcr { SHADOW_FPCR } else { SHADOW_FPSR };
                    self.f.i32c(at as i32);
                    if rn == 31 {
                        self.f.i64c(0);
                    } else {
                        self.f.lg(rn);
                    }
                    self.f.mem(I64_STORE, 3, 0);
                }
                _ => {}
            },
            Insn::MrsSys { reg, rd } => {
                match reg {
                    SysReg::Nzcv => {
                        self.f.lg(32);
                        self.f.i64c(28);
                        self.f.op(I64_SHL);
                    }
                    SysReg::Fpcr | SysReg::Fpsr => {
                        let at = if reg == SysReg::Fpcr { SHADOW_FPCR } else { SHADOW_FPSR };
                        self.f.i32c(at as i32);
                        self.f.mem(I64_LOAD, 3, 0);
                    }
                    SysReg::CtrEl0 => {
                        self.f.i64c(CTR_EL0_VALUE as i64);
                    }
                    SysReg::DczidEl0 => {
                        self.f.i64c(DCZID_EL0_VALUE as i64);
                    }
                    SysReg::MidrEl1 => {
                        self.f.i64c(MIDR_EL1_VALUE as i64);
                    }
                    SysReg::MpidrEl1 => {
                        self.f.i64c(0x8000_0000);
                    }
                    SysReg::CntvctEl0 => {
                        self.f.i64c(0);
                    }
                    SysReg::TpidrEl0 | SysReg::TpidrroEl0 => {
                        self.f.i32c(SHADOW_TP as i32);
                        self.f.mem(I64_LOAD, 3, 0);
                    }
                    SysReg::IdAa64Pfr0 => {
                        self.f.i64c(ID_AA64PFR0_VALUE as i64);
                    }
                    SysReg::IdAa64Isar0 => {
                        self.f.i64c(ID_AA64ISAR0_VALUE as i64);
                    }
                    SysReg::Unknown => {
                        let why = format!("mrs of an unknown system register at 0x{addr:x}");
                        self.unsupported.push((addr, why.clone()));
                        if !self.layout.allow_undefined {
                            return Err(why);
                        }
                        self.f.i64c(0);
                    }
                }
                if rd != 31 {
                    self.f.ls(rd);
                } else {
                    self.f.op(DROP);
                }
            }
            Insn::Brk => {
                self.f.i32c(3);
                self.f.i64c(addr as i64);
                self.f.i32c(addr as i32);
                self.f.call(self.ids.trap);
                self.f.op(UNREACHABLE);
            }

            Insn::VecLoadStore { width, is_load, mode, offset, rn, rt, rm, option, scaled } => {
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
                    LsMode::Register => {
                        self.addr_base_reg(rn, rm, option, scaled, width.trailing_zeros())
                    }
                }
                if is_load {
                    self.vload(width, L_T1, rt);
                } else {
                    self.vstore(width, L_T1, rt);
                }
                if let Some(extra) = writeback {
                    self.writeback(rn, L_T1, extra);
                }
            }
            Insn::VecLoadStorePair { width, is_load, mode, offset, rn, rt, rt2 } => {
                let base_off = if mode == PairMode::PostIndex { 0 } else { offset };
                self.addr_base_off(rn, base_off);
                self.f.lg(L_T1);
                self.f.ls(L_T2);
                let step = width as i64;
                if is_load {
                    self.vload(width, L_T1, rt);
                    self.f.lg(L_T2);
                    self.f.i64c(step);
                    self.f.op(I64_ADD);
                    self.f.ls(L_T1);
                    self.vload(width, L_T1, rt2);
                } else {
                    self.vstore(width, L_T1, rt);
                    self.f.lg(L_T2);
                    self.f.i64c(step);
                    self.f.op(I64_ADD);
                    self.f.ls(L_T1);
                    self.vstore(width, L_T1, rt2);
                }
                match mode {
                    // L_T2 holds the address the pair was accessed at, so a pre-indexed writeback
                    // is that address and a post-indexed one is the address plus the offset.
                    PairMode::PostIndex => self.writeback(rn, L_T2, offset),
                    PairMode::PreIndex => {
                        self.f.lg(L_T2);
                        self.f.ls(rn);
                    }
                    PairMode::Offset => {}
                }
            }
            Insn::VecLd1 { is_load, count, q, post, rn, rt } => {
                let step: u32 = if q { 16 } else { 8 };
                self.addr_base_off(rn, 0);
                self.f.lg(L_T1);
                self.f.ls(L_T2);
                for i in 0..count {
                    if i > 0 {
                        self.f.lg(L_T1);
                        self.f.i64c(step as i64);
                        self.f.op(I64_ADD);
                        self.f.ls(L_T1);
                    }
                    let r = (rt + i) % 32;
                    if is_load {
                        self.vload(step, L_T1, r);
                    } else {
                        self.vstore(step, L_T1, r);
                    }
                }
                if let Some(index) = post {
                    match index {
                        PostIndex::Imm(imm) => self.writeback(rn, L_T2, imm),
                        PostIndex::Reg(r) => {
                            self.f.lg(L_T2);
                            self.get(r, true);
                            self.f.op(I64_ADD);
                            self.f.ls(rn);
                        }
                    }
                }
            }
            Insn::VecStruct { is_load, count, e, lanes, q, post, rn, rt } => {
                let bytes = if q { 16 } else { 8 };
                self.addr_base_off(rn, 0);
                self.f.lg(L_T1);
                self.f.ls(L_T2);
                if is_load {
                    // The host's bytes are interleaved, so each register is gathered out of every
                    // one of them. They are read into the scratch locals first: the registers they
                    // belong to are the destination of the gather.
                    for s in 0..count {
                        if s > 0 {
                            self.f.lg(L_T1);
                            self.f.i64c(bytes as i64);
                            self.f.op(I64_ADD);
                            self.f.ls(L_T1);
                        }
                        self.vload_local(bytes, L_T1, L_V0 + s);
                    }
                    for i in 0..count {
                        for pair in 0..count.div_ceil(2) {
                            let (mask, keep) = struct_load_mask(count, lanes, e, i, pair, bytes);
                            let a = L_V0 + pair * 2;
                            let b = if pair * 2 + 1 < count { L_V0 + pair * 2 + 1 } else { a };
                            self.shuffle(a, b, mask);
                            if keep.iter().any(|&k| k == 0) {
                                self.f.v128c(keep);
                                self.f.simd(simd::V128_AND);
                            }
                            // Straight into the register, not through `setv`: that is where the
                            // 64-bit forms zero the top half, and its temporary is one of the
                            // scratch locals the structure is still being gathered out of. The
                            // masks leave the lanes above the register's own bytes zero anyway.
                            if pair == 0 {
                                self.f.ls(NVEC0 + (rt + i) % 32);
                            } else {
                                self.getv((rt + i) % 32);
                                self.f.simd(simd::V128_OR);
                                self.f.ls(NVEC0 + (rt + i) % 32);
                            }
                        }
                    }
                } else {
                    self.f.lg(L_T1);
                    self.f.ls(L_T3);
                    for p in 0..count {
                        for pair in 0..count.div_ceil(2) {
                            let (mask, keep) = struct_store_mask(count, e, p, pair, bytes);
                            let a = NVEC0 + (rt + pair * 2) % 32;
                            let b = NVEC0 + (rt + pair * 2 + 1) % 32;
                            self.shuffle(a, b, mask);
                            if keep.iter().any(|&k| k == 0) {
                                self.f.v128c(keep);
                                self.f.simd(simd::V128_AND);
                            }
                            if pair == 0 {
                                self.f.ls(L_V0);
                            } else {
                                self.f.lg(L_V0);
                                self.f.simd(simd::V128_OR);
                                self.f.ls(L_V0);
                            }
                        }
                        self.vstore_local(bytes, L_T3, L_V0);
                        if p + 1 < count {
                            self.f.lg(L_T3);
                            self.f.i64c(bytes as i64);
                            self.f.op(I64_ADD);
                            self.f.ls(L_T3);
                        }
                    }
                }
                if let Some(index) = post {
                    match index {
                        PostIndex::Imm(imm) => self.writeback(rn, L_T2, imm),
                        PostIndex::Reg(r) => {
                            self.f.lg(L_T2);
                            self.get(r, true);
                            self.f.op(I64_ADD);
                            self.f.ls(rn);
                        }
                    }
                }
            }
            Insn::VecLane { is_load, nregs, size, index, post, rn, rt } => {
                let ebytes = 1u32 << size;
                let index = index as u8;
                self.addr_base_off(rn, 0);
                self.f.lg(L_T1);
                self.f.ls(L_T2);
                for i in 0..nregs {
                    if i > 0 {
                        self.f.lg(L_T1);
                        self.f.i64c(ebytes as i64);
                        self.f.op(I64_ADD);
                        self.f.ls(L_T1);
                    }
                    let r = (rt + i) % 32;
                    self.check_byte(L_T1, ebytes as u64);
                    if is_load {
                        self.getv(r);
                        self.f.lg(L_T1);
                        self.f.wrap_i64();
                        match size {
                            0 => {
                                self.f.mem(I32_LOAD8_U, 0, 0);
                                self.f.simd_lane(simd::I8X16_REPLACE_LANE, index);
                            }
                            1 => {
                                self.f.mem(I32_LOAD16_U, 1, 0);
                                self.f.simd_lane(simd::I16X8_REPLACE_LANE, index);
                            }
                            2 => {
                                self.f.mem(I32_LOAD, 2, 0);
                                self.f.simd_lane(simd::I32X4_REPLACE_LANE, index);
                            }
                            _ => {
                                self.f.mem(I64_LOAD, 3, 0);
                                self.f.simd_lane(simd::I64X2_REPLACE_LANE, index);
                            }
                        }
                        self.setv(r);
                    } else {
                        self.f.lg(L_T1);
                        self.f.wrap_i64();
                        self.getv(r);
                        match size {
                            0 => {
                                self.f.simd_lane(simd::I8X16_EXTRACT_LANE_U, index);
                                self.f.mem(I32_STORE8, 0, 0);
                            }
                            1 => {
                                self.f.simd_lane(simd::I16X8_EXTRACT_LANE_U, index);
                                self.f.mem(I32_STORE16, 1, 0);
                            }
                            2 => {
                                self.f.simd_lane(simd::I32X4_EXTRACT_LANE, index);
                                self.f.mem(I32_STORE, 2, 0);
                            }
                            _ => {
                                self.f.simd_lane(simd::I64X2_EXTRACT_LANE, index);
                                self.f.mem(I64_STORE, 3, 0);
                            }
                        }
                    }
                }
                if let Some(index) = post {
                    match index {
                        PostIndex::Imm(imm) => self.writeback(rn, L_T2, imm),
                        PostIndex::Reg(r) => {
                            self.f.lg(L_T2);
                            self.get(r, true);
                            self.f.op(I64_ADD);
                            self.f.ls(rn);
                        }
                    }
                }
            }
            Insn::VecLd1r { q, size, post, rn, rt } => {
                let bits = 8u32 << size;
                self.addr_base_off(rn, 0);
                self.f.lg(L_T1);
                self.f.ls(L_T2);
                self.check_byte(L_T1, (bits / 8) as u64);
                self.f.lg(L_T1);
                self.f.wrap_i64();
                let op = match bits {
                    8 => simd::V128_LOAD8_SPLAT,
                    16 => simd::V128_LOAD16_SPLAT,
                    32 => simd::V128_LOAD32_SPLAT,
                    _ => simd::V128_LOAD64_SPLAT,
                };
                self.f.simd_mem(op, size, 0);
                if !q {
                    self.f.v128c(low_half_mask());
                    self.f.simd(simd::V128_AND);
                }
                self.setv(rt);
                if let Some(index) = post {
                    match index {
                        PostIndex::Imm(imm) => self.writeback(rn, L_T2, imm),
                        PostIndex::Reg(r) => {
                            self.f.lg(L_T2);
                            self.get(r, true);
                            self.f.op(I64_ADD);
                            self.f.ls(rn);
                        }
                    }
                }
            }
            Insn::VecModImm { q, op, cmode, imm8, rd } => {
                // An odd cmode below the masking-shift forms is the same lane layout as the even one
                // under it, but the immediate is combined with the destination: `orr` keeps the bits
                // it names and `bic` clears them, where `movi` writes the immediate on its own.
                if cmode & 1 != 0 && (cmode >> 1) < 0b110 {
                    let mask = modified_immediate(q, false, cmode & !1, imm8);
                    self.getv(rd);
                    self.f.v128c(mask);
                    self.f.simd(if op { simd::V128_ANDNOT } else { simd::V128_OR });
                    self.setv(rd);
                } else if cmode == 0b1111 && op {
                    // `fmov v.4s, #imm` and `fmov v.2d, #imm`: the eight-bit FP immediate, once per
                    // lane, widened to the lane width the Q bit picks.
                    let (lane, lanes) = (vfp_expand_imm(imm8, if q { 64 } else { 32 }), 2);
                    let mut bytes = [0u8; 16];
                    let width = 16 / lanes;
                    for i in 0..lanes {
                        bytes[i * width..i * width + width]
                            .copy_from_slice(&lane.to_le_bytes()[..width]);
                    }
                    self.f.v128c(bytes);
                    self.setv(rd);
                } else {
                    let bytes = modified_immediate(q, op, cmode, imm8);
                    self.f.v128c(bytes);
                    self.setv(rd);
                }
            }
            Insn::VecThreeSame { q, u, size, op, rn, rm, rd } => {
                let _ = q;
                match (u, size, op) {
                    (false, 0, 0b00011) => self.vec3(rn, rm, rd, simd::V128_AND),
                    (false, 1, 0b00011) => {
                        self.savev(rm, L_V0);
                        self.f.lg(L_V0);
                        self.f.simd(simd::V128_NOT);
                        self.f.ls(L_V0);
                        self.getv(rn);
                        self.f.lg(L_V0);
                        self.f.simd(simd::V128_AND);
                        self.setv(rd);
                    }
                    (false, 2, 0b00011) => self.vec3(rn, rm, rd, simd::V128_OR),
                    (false, 3, 0b00011) => {
                        self.savev(rm, L_V0);
                        self.f.lg(L_V0);
                        self.f.simd(simd::V128_NOT);
                        self.f.ls(L_V0);
                        self.getv(rn);
                        self.f.lg(L_V0);
                        self.f.simd(simd::V128_OR);
                        self.setv(rd);
                    }
                    (true, 0, 0b00011) => self.vec3(rn, rm, rd, simd::V128_XOR),
                    (true, 1, 0b00011) => {
                        self.getv(rn);
                        self.getv(rm);
                        self.getv(rd);
                        self.f.simd(simd::V128_BITSELECT);
                        self.setv(rd);
                    }
                    (true, 2, 0b00011) => {
                        self.getv(rn);
                        self.getv(rd);
                        self.getv(rm);
                        self.f.simd(simd::V128_BITSELECT);
                        self.setv(rd);
                    }
                    (true, 3, 0b00011) => {
                        self.getv(rd);
                        self.getv(rn);
                        self.getv(rm);
                        self.f.simd(simd::V128_BITSELECT);
                        self.setv(rd);
                    }
                    (false, _, 0b10000) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_ADD, simd::I16X8_ADD, simd::I32X4_ADD, simd::I64X2_ADD]) {
                            self.vec3(rn, rm, rd, o);
                        } else {
                            return self.refuse(format!("unsupported vector add at 0x{addr:x}"));
                        }
                    }
                    (true, _, 0b10000) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_SUB, simd::I16X8_SUB, simd::I32X4_SUB, simd::I64X2_SUB]) {
                            self.vec3(rn, rm, rd, o);
                        } else {
                            return self.refuse(format!("unsupported vector sub at 0x{addr:x}"));
                        }
                    }
                    (false, 0, 0b10011) => {
                        self.byte_mul(rn, rm, L_V0);
                        self.f.lg(L_V0);
                        self.setv(rd);
                    }
                    (false, 1, 0b10011) => self.vec3(rn, rm, rd, simd::I16X8_MUL),
                    (false, 2, 0b10011) => self.vec3(rn, rm, rd, simd::I32X4_MUL),
                    (false, 3, 0b10011) => self.vec3(rn, rm, rd, simd::I64X2_MUL),
                    (false, _, 0b10010) => {
                        let add = self.lanes_op(size, [simd::I8X16_ADD, simd::I16X8_ADD, simd::I32X4_ADD, simd::I64X2_ADD]);
                        let mul = self.lanes_op(size, [simd::I16X8_MUL, simd::I16X8_MUL, simd::I32X4_MUL, simd::I64X2_MUL]);
                        let (Some(a), Some(m)) = (add, mul) else {
                            return self.refuse(format!("unsupported mla at 0x{addr:x}"));
                        };
                        if size == 0 {
                            self.byte_mul(rn, rm, L_V1);
                            self.getv(rd);
                            self.f.lg(L_V1);
                        } else {
                            self.getv(rn);
                            self.getv(rm);
                            self.f.simd(m);
                            self.getv(rd);
                        }
                        self.f.simd(a);
                        self.setv(rd);
                    }
                    (true, _, 0b10010) => {
                        let sub = self.lanes_op(size, [simd::I8X16_SUB, simd::I16X8_SUB, simd::I32X4_SUB, simd::I64X2_SUB]);
                        let mul = self.lanes_op(size, [simd::I16X8_MUL, simd::I16X8_MUL, simd::I32X4_MUL, simd::I64X2_MUL]);
                        let (Some(sub), Some(m)) = (sub, mul) else {
                            return self.refuse(format!("unsupported mls at 0x{addr:x}"));
                        };
                        // mls is rd - rn*rm: the destination is the minuend.
                        self.getv(rd);
                        if size == 0 {
                            self.byte_mul(rn, rm, L_V1);
                            self.f.lg(L_V1);
                        } else {
                            self.getv(rn);
                            self.getv(rm);
                            self.f.simd(m);
                        }
                        self.f.simd(sub);
                        self.setv(rd);
                    }
                    (true, _, 0b10001) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_EQ, simd::I16X8_EQ, simd::I32X4_EQ, simd::I64X2_EQ]) {
                            self.vec3(rn, rm, rd, o);
                        }
                    }
                    (false, _, 0b10001) => {
                        // cmtst: (a & b) != 0, lane by lane.
                        let and = simd::V128_AND;
                        let eq = self.lanes_op(size, [simd::I8X16_EQ, simd::I16X8_EQ, simd::I32X4_EQ, simd::I64X2_EQ]);
                        let Some(eq) = eq else { return self.refuse(format!("unsupported cmtst at 0x{addr:x}")); };
                        self.getv(rn);
                        self.getv(rm);
                        self.f.simd(and);
                        self.f.v128c([0; 16]);
                        self.f.simd(eq);
                        self.f.simd(simd::V128_NOT);
                        self.setv(rd);
                    }
                    (false, _, 0b00110) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_GT_S, simd::I16X8_GT_S, simd::I32X4_GT_S, simd::I64X2_GT_S]) {
                            self.vec3(rn, rm, rd, o);
                        }
                    }
                    (true, 3, 0b00110) => self.vec_cmp_64_unsigned(rn, rm, rd, true),
                    (true, _, 0b00110) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_GT_U, simd::I16X8_GT_U, simd::I32X4_GT_U, simd::I64X2_GT_S]) {
                            self.vec3(rn, rm, rd, o);
                        }
                    }
                    (false, _, 0b00111) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_GE_S, simd::I16X8_GE_S, simd::I32X4_GE_S, simd::I64X2_GT_S]) {
                            self.vec3(rn, rm, rd, o);
                        }
                    }
                    (true, 3, 0b00111) => self.vec_cmp_64_unsigned(rn, rm, rd, false),
                    (true, _, 0b00111) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_GE_U, simd::I16X8_GE_U, simd::I32X4_GE_U, simd::I64X2_GE_S]) {
                            self.vec3(rn, rm, rd, o);
                        }
                    }
                    (_, _, 0b01000) => return self.vec_shift_by_lane(addr, size, u, rn, rm, rd),
                    (false, _, 0b01100) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_MAX_S, simd::I16X8_MAX_S, simd::I32X4_MAX_S, simd::I8X16_MAX_S]) {
                            self.vec3(rn, rm, rd, o);
                        }
                    }
                    (true, _, 0b01100) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_MAX_U, simd::I16X8_MAX_U, simd::I32X4_MAX_U, simd::I8X16_MAX_U]) {
                            self.vec3(rn, rm, rd, o);
                        }
                    }
                    (false, _, 0b01101) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_MIN_S, simd::I16X8_MIN_S, simd::I32X4_MIN_S, simd::I8X16_MIN_S]) {
                            self.vec3(rn, rm, rd, o);
                        }
                    }
                    (true, _, 0b01101) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_MIN_U, simd::I16X8_MIN_U, simd::I32X4_MIN_U, simd::I8X16_MIN_U]) {
                            self.vec3(rn, rm, rd, o);
                        }
                    }
                    (true, _, 0b10100) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_MAX_U, simd::I16X8_MAX_U, simd::I32X4_MAX_U, simd::I8X16_MAX_U]) {
                            self.vec_pairwise(size, o, rn, rm, rd);
                        }
                    }
                    (false, _, 0b10100) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_MAX_S, simd::I16X8_MAX_S, simd::I32X4_MAX_S, simd::I8X16_MAX_S]) {
                            self.vec_pairwise(size, o, rn, rm, rd);
                        }
                    }
                    (true, _, 0b10101) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_MIN_U, simd::I16X8_MIN_U, simd::I32X4_MIN_U, simd::I8X16_MIN_U]) {
                            self.vec_pairwise(size, o, rn, rm, rd);
                        }
                    }
                    (false, _, 0b10101) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_MIN_S, simd::I16X8_MIN_S, simd::I32X4_MIN_S, simd::I8X16_MIN_S]) {
                            self.vec_pairwise(size, o, rn, rm, rd);
                        }
                    }
                    (false, _, 0b10111) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_ADD, simd::I16X8_ADD, simd::I32X4_ADD, simd::I64X2_ADD]) {
                            self.vec_pairwise(size, o, rn, rm, rd);
                        }
                    }
                    // The pairwise forms of the FP group: the lane pairs of the two sources, added
                    // or compared. The same opcodes as the elementwise ones, with the U bit set, and
                    // without the lane width in the size field - bit 1 is the min half of min/max.
                    (true, _, 0b11010) if size < 2 => {
                        let (even, odd) = fp_pair_masks(if size & 1 == 1 { 8 } else { 4 }, if !q { 2 } else if size & 1 == 1 { 2 } else { 4 });
                        self.shuffle(NVEC0 + rn, NVEC0 + rm, even);
                        self.f.ls(L_V0);
                        self.shuffle(NVEC0 + rn, NVEC0 + rm, odd);
                        self.f.ls(L_V1);
                        self.f.lg(L_V0);
                        self.f.lg(L_V1);
                        self.f.simd(if size & 1 == 1 { simd::F64X2_ADD } else { simd::F32X4_ADD });
                        self.setv(rd);
                    }
                    (true, _, 0b11110) => {
                        let (even, odd) = fp_pair_masks(if size & 1 == 1 { 8 } else { 4 }, if size & 2 != 0 || q { 4 } else { 2 });
                        self.shuffle(NVEC0 + rn, NVEC0 + rm, even);
                        self.f.ls(L_V0);
                        self.shuffle(NVEC0 + rn, NVEC0 + rm, odd);
                        self.f.ls(L_V1);
                        self.minmax_into(size & 1 == 1, size & 2 == 0, false);
                        self.f.lg(L_V2);
                        self.setv(rd);
                    }
                    // The FP group. Bit 22 is the lane type and bit 23 the low bit of the opcode
                    // where the operation has a pair, so the size field carries both: an odd size
                    // is double, and the pairs (add/sub, mla/mls) take the second when it is set.
                    // fmax/fmin and their `nm` pair: the larger or the smaller of the two, and the
                    // one that is not a NaN where only one of them is.
                    (false, _, 0b11110) | (false, _, 0b11000) => {
                        self.vec_minmax(rn, rm, rd, size & 1 == 1, size & 2 == 0, op == 0b11000);
                    }
                    (false, 0 | 1, 0b11010) => {
                        self.vec3(rn, rm, rd, if size & 1 == 1 { simd::F64X2_ADD } else { simd::F32X4_ADD })
                    }
                    (false, 2 | 3, 0b11010) => {
                        self.vec3(rn, rm, rd, if size & 1 == 1 { simd::F64X2_SUB } else { simd::F32X4_SUB })
                    }
                    (true, 2 | 3, 0b11010) => {
                        // fabd: the absolute value of the difference.
                        self.getv(rn);
                        self.getv(rm);
                        self.f.simd(if size & 1 == 1 { simd::F64X2_SUB } else { simd::F32X4_SUB });
                        self.f.simd(if size & 1 == 1 { simd::F64X2_ABS } else { simd::F32X4_ABS });
                        self.setv(rd);
                    }
                    (false, 0 | 1, 0b11011) | (true, 0 | 1, 0b11011) => {
                        // fmul and fmulx, which differ only for zero times infinity.
                        self.vec3(rn, rm, rd, if size & 1 == 1 { simd::F64X2_MUL } else { simd::F32X4_MUL })
                    }
                    (true, 0 | 1, 0b11111) => {
                        self.vec3(rn, rm, rd, if size & 1 == 1 { simd::F64X2_DIV } else { simd::F32X4_DIV })
                    }
                    (false, 0 | 1, 0b11001) | (false, 2 | 3, 0b11001) => {
                        // fmla and fmls multiply into the destination rather than into a product of
                        // its own, so the rounding of the sum is the one place they differ from a
                        // separate multiply and add.
                        let (mul, add) = if size & 1 == 1 {
                            (simd::F64X2_MUL, simd::F64X2_ADD)
                        } else {
                            (simd::F32X4_MUL, simd::F32X4_ADD)
                        };
                        let op = if size & 2 != 0 {
                            if size & 1 == 1 { simd::F64X2_SUB } else { simd::F32X4_SUB }
                        } else {
                            add
                        };
                        self.getv(rd);
                        self.getv(rn);
                        self.getv(rm);
                        self.f.simd(mul);
                        self.f.simd(op);
                        self.setv(rd);
                    }
                    _ => return self.refuse(format!("unsupported vector operation {op:05b} u={u} size={size} at 0x{addr:x}")),
                }
            }
            Insn::VecTwoMisc { q, u, size, op, rn, rd } => {
                match (u, size, op) {
                    (false, 1, 0b10110) => {
                        // fcvtn / fcvtn2: two doubles narrowed to two singles, in the low half or
                        // above the ones the destination keeps. Half precision is the size 0 form.
                        self.getv(rn);
                        self.f.simd(simd::F32X4_DEMOTE_F64X2_ZERO);
                        if q {
                            self.f.ls(L_V1);
                            self.getv(rd);
                            self.f.lg(L_V1);
                            self.f.simd(simd::I8X16_SHUFFLE);
                            self.f.body.extend_from_slice(&[
                                0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23,
                            ]);
                        }
                        self.setv(rd);
                    }
                    (false, 1, 0b10111) => {
                        // fcvtl / fcvtl2: two singles widened to two doubles, from the low half of
                        // the source or from the high one. The whole destination is written.
                        self.getv(rn);
                        if q {
                            self.f.ls(L_V1);
                            self.shuffle(L_V1, L_V1, swap_halves_mask());
                        }
                        self.f.simd(simd::F64X2_PROMOTE_LOW_F32X4);
                        self.setv(rd);
                    }
                    (false, _, 0b10010) => {
                        // xtn / xtn2
                        self.getv(rn);
                        self.f.ls(L_V0);
                        self.vec_narrow(size, L_V0, rd, q);
                    }
                    (true, _, 0b00101) => self.vec2(rn, rd, simd::V128_NOT),
                    (false, 0, 0b00101) => self.vec2(rn, rd, simd::I8X16_POPCNT),
                    (false, _, 0b01011) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_ABS, simd::I16X8_ABS, simd::I32X4_ABS, simd::I64X2_ABS]) {
                            self.vec2(rn, rd, o);
                        }
                    }
                    (true, _, 0b01011) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_NEG, simd::I16X8_NEG, simd::I32X4_NEG, simd::I64X2_NEG]) {
                            self.vec2(rn, rd, o);
                        }
                    }
                    (false, _, 0b01001) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_EQ, simd::I16X8_EQ, simd::I32X4_EQ, simd::I64X2_EQ]) {
                            self.getv(rn);
                            self.f.v128c([0; 16]);
                            self.f.simd(o);
                            self.setv(rd);
                        }
                    }
                    (false, _, 0b01000) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_GT_S, simd::I16X8_GT_S, simd::I32X4_GT_S, simd::I64X2_GT_S]) {
                            self.getv(rn);
                            self.f.v128c([0; 16]);
                            self.f.simd(o);
                            self.setv(rd);
                        }
                    }
                    (false, _, 0b01010) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_LE_S, simd::I16X8_LE_S, simd::I32X4_LE_S, simd::I32X4_LE_S]) {
                            self.getv(rn);
                            self.f.v128c([0; 16]);
                            self.f.simd(o);
                            self.setv(rd);
                        }
                    }
                    (false, _, 0b00000) => {
                        // rev64: reverse the elements within each 64-bit half.
                        let mask = rev64_mask(size);
                        self.getv(rn);
                        self.f.ls(L_V0);
                        self.shuffle(L_V0, L_V0, mask);
                        self.setv(rd);
                    }
                    (true, _, 0b00000) => {
                        // rev32: bytes reverse within every 4-byte group, halfwords swap within it.
                        let mask = if size == 0 { rev_group_mask(4) } else { swap_halfword_mask() };
                        self.getv(rn);
                        self.f.ls(L_V0);
                        self.shuffle(L_V0, L_V0, mask);
                        self.setv(rd);
                    }
                    (false, 0, 0b00001) => {
                        // rev16 on bytes: swap the bytes of every 16-bit element.
                        let mask = rev_group_mask(2);
                        self.getv(rn);
                        self.f.ls(L_V0);
                        self.shuffle(L_V0, L_V0, mask);
                        self.setv(rd);
                    }
                    // The FP forms of the two-register group, whose type field has bit 23 set.
                    (false, 2 | 3, 0b01111) => {
                        // fabs: clear the sign bit of every lane.
                        self.getv(rn);
                        self.f.v128c(sign_mask(size & 1 == 1));
                        self.f.simd(simd::V128_ANDNOT);
                        self.setv(rd);
                    }
                    (true, 2 | 3, 0b01111) => {
                        // fneg: flip it. A NaN keeps its payload, which is what the instruction does.
                        self.getv(rn);
                        self.f.v128c(sign_mask(size & 1 == 1));
                        self.f.simd(simd::V128_XOR);
                        self.setv(rd);
                    }
                    (true, 2 | 3, 0b11111) => self.vec2(
                        rn,
                        rd,
                        if size & 1 == 1 { simd::F64X2_SQRT } else { simd::F32X4_SQRT },
                    ),
                    // The rounding family: to integral, in the mode the opcode names. Bit 23 picks
                    // the second of each mode's pair and bit 22 is the lane width, which is why
                    // `frintp` reads as `frintn` one lane width up until both bits are taken.
                    (u, _, 0b11000) | (u, _, 0b11001) => {
                        let double = size & 1 == 1;
                        let upper = size & 2 != 0;
                        if u && op == 0b11000 && !upper {
                            // frinta: ties away from zero, which wasm has no form of.
                            self.vec_round_away(rn, rd, double);
                        } else {
                            let (narrow, wide) = match (u, op, upper) {
                                (false, 0b11000, false) => (simd::F32X4_NEAREST, simd::F64X2_NEAREST),
                                (false, 0b11000, true) => (simd::F32X4_CEIL, simd::F64X2_CEIL),
                                (false, 0b11001, false) => (simd::F32X4_FLOOR, simd::F64X2_FLOOR),
                                (false, 0b11001, true) => (simd::F32X4_TRUNC, simd::F64X2_TRUNC),
                                // frintx and frinti round in the mode FPCR holds; nothing here
                                // changes the default, so they are the nearest the others are.
                                (true, 0b11001, _) => (simd::F32X4_NEAREST, simd::F64X2_NEAREST),
                                _ => {
                                    return self.refuse(format!(
                                        "unsupported rounding u={u} size={size} op={op:05b} at 0x{addr:x}"
                                    ))
                                }
                            };
                            self.vec2(rn, rd, if double { wide } else { narrow });
                        }
                    }
                    // The conversions between an integer vector and a float one, which only the
                    // 4s and 2d widths have: the 2d form has no wasm equivalent, so its two lanes
                    // convert one at a time.
                    (false, 0, 0b11101) => {
                        self.getv(rn);
                        self.f.simd(simd::F32X4_CONVERT_I32X4_S);
                        self.setv(rd);
                    }
                    (true, 0, 0b11101) => {
                        self.getv(rn);
                        self.f.simd(simd::F32X4_CONVERT_I32X4_U);
                        self.setv(rd);
                    }
                    (false, 1, 0b11101) | (true, 1, 0b11101) => {
                        self.f.v128c([0; 16]);
                        for lane in 0..2 {
                            self.getv(rn);
                            self.f.simd_lane(simd::I64X2_EXTRACT_LANE, lane);
                            self.f.op(if u { F64_CONVERT_I64_U } else { F64_CONVERT_I64_S });
                            self.f.simd_lane(simd::F64X2_REPLACE_LANE, lane);
                        }
                        self.setv(rd);
                    }
                    // sadalp/uaddlp: the pairs of one lane width added into the next one up.
                    (u, 0, 0b00010) | (u, 1, 0b00010) => {
                        let op = if u {
                            self.lanes_op(size, [
                                simd::I16X8_EXTADD_PAIRWISE_I8X16_U,
                                simd::I32X4_EXTADD_PAIRWISE_I16X8_U,
                                0,
                                0,
                            ])
                        } else {
                            self.lanes_op(size, [
                                simd::I16X8_EXTADD_PAIRWISE_I8X16_S,
                                simd::I32X4_EXTADD_PAIRWISE_I16X8_S,
                                0,
                                0,
                            ])
                        };
                        let op = op.ok_or_else(|| format!("bad pairwise add at 0x{addr:x}"))?;
                        self.vec2(rn, rd, op);
                    }
                    (true, 0..=2, 0b10011) => {
                        // shll: widen one half of the source and shift it up by the width of the
                        // destination's lanes, which is what the alias of ushll by the element size
                        // means. The widened bits fall off the top, so whether the widening kept
                        // the sign is not visible.
                        let widen = match (size, q) {
                            (0, false) => simd::I16X8_EXTEND_LOW_I8X16_U,
                            (0, true) => simd::I16X8_EXTEND_HIGH_I8X16_U,
                            (1, false) => simd::I32X4_EXTEND_LOW_I16X8_U,
                            (1, true) => simd::I32X4_EXTEND_HIGH_I16X8_U,
                            (2, false) => simd::I64X2_EXTEND_LOW_I32X4_U,
                            _ => simd::I64X2_EXTEND_HIGH_I32X4_U,
                        };
                        let shl = self
                            .lanes_op(size, [simd::I16X8_SHL, simd::I32X4_SHL, simd::I64X2_SHL, simd::I64X2_SHL])
                            .ok_or_else(|| format!("bad widening shift at 0x{addr:x}"))?;
                        self.getv(rn);
                        self.f.simd(widen);
                        self.f.i32c(8 << size);
                        self.f.simd(shl);
                        self.setv(rd);
                    }
                    _ => return self.refuse(format!("unsupported two-register vector op {op:05b} u={u} size={size} at 0x{addr:x}")),
                }
            }
            Insn::VecAcross { q, u, size, op, rn, rd } => {
                let _ = q;
                match (u, op) {
                    (false, 0b11011) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_ADD, simd::I16X8_ADD, simd::I32X4_ADD, simd::I64X2_ADD]) {
                            self.vec_across(size, o, rn, rd);
                        }
                    }
                    (false, 0b01010) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_MAX_S, simd::I16X8_MAX_S, simd::I32X4_MAX_S, simd::I8X16_MAX_S]) {
                            self.vec_across(size, o, rn, rd);
                        }
                    }
                    (true, 0b01010) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_MAX_U, simd::I16X8_MAX_U, simd::I32X4_MAX_U, simd::I8X16_MAX_U]) {
                            self.vec_across(size, o, rn, rd);
                        }
                    }
                    (false, 0b11010) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_MIN_S, simd::I16X8_MIN_S, simd::I32X4_MIN_S, simd::I8X16_MIN_S]) {
                            self.vec_across(size, o, rn, rd);
                        }
                    }
                    (true, 0b11010) => {
                        if let Some(o) = self.lanes_op(size, [simd::I8X16_MIN_U, simd::I16X8_MIN_U, simd::I32X4_MIN_U, simd::I8X16_MIN_U]) {
                            self.vec_across(size, o, rn, rd);
                        }
                    }
                    // fmaxp/fminp and the nm pair, from two lanes or four. Bit 0 of the size field
                    // is the lane width, bit 1 the choice between the two of each pair.
                    (true, 0b01111) => self.vec_across_fp(rn, rd, size & 1 == 1, size & 2 == 0),
                    // faddp: the lanes added.
                    (true, 0b01101) => self.vec_across_fp_add(rn, rd, size & 1 == 1),
                    _ => return self.refuse(format!("unsupported across-lane op {op:05b} u={u} at 0x{addr:x}")),
                }
            }
            Insn::VecThreeDiff { q, u, size, op, rn, rm, rd } => {
                // saddw/uaddw and ssubw/usubw: a half of the source widens into lanes as wide as
                // the destination's and is added to it. Opcode bit 2 subtracts, and the q bit takes
                // the high half of the source.
                if op == 0b00010 || op == 0b00110 {
                    let (ext, acc) = match (size, q, u, op == 0b00110) {
                        (1, false, false, false) => (simd::I32X4_EXTEND_LOW_I16X8_S, simd::I32X4_ADD),
                        (1, true, false, false) => (simd::I32X4_EXTEND_HIGH_I16X8_S, simd::I32X4_ADD),
                        (1, false, true, false) => (simd::I32X4_EXTEND_LOW_I16X8_U, simd::I32X4_ADD),
                        (1, true, true, false) => (simd::I32X4_EXTEND_HIGH_I16X8_U, simd::I32X4_ADD),
                        (2, false, false, false) => (simd::I64X2_EXTEND_LOW_I32X4_S, simd::I64X2_ADD),
                        (2, true, false, false) => (simd::I64X2_EXTEND_HIGH_I32X4_S, simd::I64X2_ADD),
                        (2, false, true, false) => (simd::I64X2_EXTEND_LOW_I32X4_U, simd::I64X2_ADD),
                        (2, true, true, false) => (simd::I64X2_EXTEND_HIGH_I32X4_U, simd::I64X2_ADD),
                        (1, false, false, true) => (simd::I32X4_EXTEND_LOW_I16X8_S, simd::I32X4_SUB),
                        (1, true, false, true) => (simd::I32X4_EXTEND_HIGH_I16X8_S, simd::I32X4_SUB),
                        (1, false, true, true) => (simd::I32X4_EXTEND_LOW_I16X8_U, simd::I32X4_SUB),
                        (1, true, true, true) => (simd::I32X4_EXTEND_HIGH_I16X8_U, simd::I32X4_SUB),
                        (2, false, false, true) => (simd::I64X2_EXTEND_LOW_I32X4_S, simd::I64X2_SUB),
                        (2, true, false, true) => (simd::I64X2_EXTEND_HIGH_I32X4_S, simd::I64X2_SUB),
                        (2, false, true, true) => (simd::I64X2_EXTEND_LOW_I32X4_U, simd::I64X2_SUB),
                        (2, true, true, true) => (simd::I64X2_EXTEND_HIGH_I32X4_U, simd::I64X2_SUB),
                        _ => {
                            return self.refuse(format!("widening add of size {size} at 0x{addr:x}"))
                        }
                    };
                    self.getv(rm);
                    self.f.simd(ext);
                    self.f.ls(L_V0);
                    self.getv(rn);
                    self.f.lg(L_V0);
                    self.f.simd(acc);
                    self.setv(rd);
                    return Ok(());
                }

                // The long multiplies: half-width lanes multiply into full-width ones. opcode bit
                // 3 is what says the destination is overwritten rather than added to, which is the
                // whole of the difference between umull and umlal; bit 2 subtracts instead of
                // adding. The q bit takes the high half of each source, the way the `2` suffix
                // says, and the destination is the whole register whatever q says.
                if op & 0b10011 == 0b10000 {
                    let high = q;
                    let accumulate = op & 0b01000 == 0;
                    let sub = op & 0b00100 != 0;
                    let (mul, acc) = match (size, high, u) {
                        (1, false, false) => (simd::I32X4_EXTMUL_LOW_I16X8_S, simd::I32X4_ADD),
                        (1, true, false) => (simd::I32X4_EXTMUL_HIGH_I16X8_S, simd::I32X4_ADD),
                        (1, false, true) => (simd::I32X4_EXTMUL_LOW_I16X8_U, simd::I32X4_ADD),
                        (1, true, true) => (simd::I32X4_EXTMUL_HIGH_I16X8_U, simd::I32X4_ADD),
                        (2, false, false) => (simd::I64X2_EXTMUL_LOW_I32X4_S, simd::I64X2_ADD),
                        (2, true, false) => (simd::I64X2_EXTMUL_HIGH_I32X4_S, simd::I64X2_ADD),
                        (2, false, true) => (simd::I64X2_EXTMUL_LOW_I32X4_U, simd::I64X2_ADD),
                        (2, true, true) => (simd::I64X2_EXTMUL_HIGH_I32X4_U, simd::I64X2_ADD),
                        _ => {
                            return self.refuse(format!(
                                "long multiply of size {size} at 0x{addr:x}"
                            ))
                        }
                    };
                    let acc = match (sub, size) {
                        (false, _) => acc,
                        (true, 1) => simd::I32X4_SUB,
                        (true, _) => simd::I64X2_SUB,
                    };
                    self.getv(rn);
                    self.getv(rm);
                    self.f.simd(mul);
                    if accumulate {
                        self.f.ls(L_V0);
                        self.getv(rd);
                        self.f.lg(L_V0);
                        self.f.simd(acc);
                    }
                    self.setv(rd);
                    return Ok(());
                }
                match (u, op) {
                    (false, 0b01000) | (true, 0b01000) => {
                        // addhn / raddhn: add, take the high half of each lane.
                        let half = size + 1;
                        let add = self.lanes_op(half, [simd::I8X16_ADD, simd::I16X8_ADD, simd::I32X4_ADD, simd::I64X2_ADD])
                            .ok_or_else(|| format!("unsupported addhn at 0x{addr:x}"))?;
                        self.getv(rn);
                        self.getv(rm);
                        self.f.simd(add);
                        self.f.ls(L_V0);
                        let mask = high_half_mask(half);
                        self.f.v128c([0; 16]);
                        self.f.lg(L_V0);
                        self.f.simd(simd::I8X16_SHUFFLE);
                        self.f.body.extend_from_slice(&mask);
                        self.setv(rd);
                        if u {
                            // raddhn rounds by adding half of the discarded bits first; the rounding
                            // is folded in by the caller's idiom closely enough only for exact halves,
                            // so it is refused rather than mistranslated.
                            return self.refuse(format!("raddhn is not translated (0x{addr:x})"));
                        }
                    }
                    _ => return self.refuse(format!("unsupported three-different op {op:05b} at 0x{addr:x}")),
                }
            }

            Insn::VecShiftImm { q, u, immh, immb, op, rn, rd } => {
                let _ = q;
                let size = 31 - immh.leading_zeros(); // 0 for 8-bit lanes through 3 for 64-bit
                let esize = 8u32 << size;
                let immhb = (immh << 3) | immb;
                let rshift = (2 * esize).wrapping_sub(immhb) as u32;
                let lshift = immhb.wrapping_sub(esize) as u32;
                let shr = self.lanes_op(size, [simd::I8X16_SHR_U, simd::I16X8_SHR_U, simd::I32X4_SHR_U, simd::I64X2_SHR_U]);
                let shr_s = self.lanes_op(size, [simd::I8X16_SHR_S, simd::I16X8_SHR_S, simd::I32X4_SHR_S, simd::I64X2_SHR_S]);
                let shl = self.lanes_op(size, [simd::I8X16_SHL, simd::I16X8_SHL, simd::I32X4_SHL, simd::I64X2_SHL]);
                let add = self.lanes_op(size, [simd::I8X16_ADD, simd::I16X8_ADD, simd::I32X4_ADD, simd::I64X2_ADD]);
                match op {
                    0b00000 => {
                        let o = if u { shr } else { shr_s }.ok_or_else(|| format!("bad shift at 0x{addr:x}"))?;
                        self.getv(rn);
                        self.f.i32c(rshift as i32);
                        self.f.simd(o);
                        self.setv(rd);
                    }
                    0b00010 => {
                        // usra/ssra: accumulate the shifted value into the destination.
                        let o = if u { shr } else { shr_s }.ok_or_else(|| format!("bad shift at 0x{addr:x}"))?;
                        let a = add.ok_or_else(|| format!("bad shift at 0x{addr:x}"))?;
                        self.getv(rn);
                        self.f.i32c(rshift as i32);
                        self.f.simd(o);
                        self.f.ls(L_V0);
                        self.getv(rd);
                        self.f.lg(L_V0);
                        self.f.simd(a);
                        self.setv(rd);
                    }
                    0b01010 => {
                        if u {
                            // sli: keep the destination's low bits, take the shift from the source.
                            self.getv(rn);
                            self.f.i32c(lshift as i32);
                            self.f.simd(shl.ok_or_else(|| format!("bad shift at 0x{addr:x}"))?);
                            self.f.ls(L_V0);
                            self.getv(rd);
                            self.f.v128c(low_bits_mask(esize, lshift));
                            self.f.simd(simd::V128_AND);
                            self.f.lg(L_V0);
                            self.f.simd(simd::V128_OR);
                            self.setv(rd);
                        } else {
                            self.getv(rn);
                            self.f.i32c(lshift as i32);
                            self.f.simd(shl.ok_or_else(|| format!("bad shift at 0x{addr:x}"))?);
                            self.setv(rd);
                        }
                    }
                    0b01000 => {
                        // sri: the shifted source fills the low bits of the result, the top bits of
                        // the destination stay.
                        self.getv(rn);
                        self.f.i32c(rshift as i32);
                        self.f.simd(shr.ok_or_else(|| format!("bad shift at 0x{addr:x}"))?);
                        self.f.ls(L_V0);
                        self.getv(rd);
                        self.f.v128c(high_bits_mask(esize, esize - rshift));
                        self.f.simd(simd::V128_AND);
                        self.f.lg(L_V0);
                        self.f.simd(simd::V128_OR);
                        self.setv(rd);
                    }
                    0b10000 | 0b10001 => {
                        // shrn/rshrn: shift then narrow, taking the low half of each lane.
                        let src_size = size + 1;
                        let o = if u {
                            self.lanes_op(src_size, [simd::I8X16_SHR_U, simd::I16X8_SHR_U, simd::I32X4_SHR_U, simd::I64X2_SHR_U])
                        } else {
                            self.lanes_op(src_size, [simd::I8X16_SHR_S, simd::I16X8_SHR_S, simd::I32X4_SHR_S, simd::I64X2_SHR_S])
                        };
                        let add_wide = self.lanes_op(src_size, [simd::I8X16_ADD, simd::I16X8_ADD, simd::I32X4_ADD, simd::I64X2_ADD]);
                        let o = o.ok_or_else(|| format!("bad narowing shift at 0x{addr:x}"))?;
                        self.getv(rn);
                        if op == 0b10001 {
                            let round = 1u64 << (rshift - 1);
                            self.f.v128c(round_mask(8 << src_size, round));
                            self.f.simd(add_wide.ok_or_else(|| format!("bad shift at 0x{addr:x}"))?);
                        }
                        self.f.i32c(rshift as i32);
                        self.f.simd(o);
                        self.f.ls(L_V0);
                        self.vec_narrow(size, L_V0, rd, false);
                    }
                    0b10100 => {
                        // sshll/ushll widen one half of the source, and the q bit, which is what
                        // the `2` suffix says, picks the high half.
                        let low_u = [
                            simd::I16X8_EXTEND_LOW_I8X16_U,
                            simd::I32X4_EXTEND_LOW_I16X8_U,
                            simd::I64X2_EXTEND_LOW_I32X4_U,
                            simd::I64X2_EXTEND_LOW_I32X4_U,
                        ];
                        let high_u = [
                            simd::I16X8_EXTEND_HIGH_I8X16_U,
                            simd::I32X4_EXTEND_HIGH_I16X8_U,
                            simd::I64X2_EXTEND_HIGH_I32X4_U,
                            simd::I64X2_EXTEND_HIGH_I32X4_U,
                        ];
                        let low_s = [
                            simd::I16X8_EXTEND_LOW_I8X16_S,
                            simd::I32X4_EXTEND_LOW_I16X8_S,
                            simd::I64X2_EXTEND_LOW_I32X4_S,
                            simd::I64X2_EXTEND_LOW_I32X4_S,
                        ];
                        let high_s = [
                            simd::I16X8_EXTEND_HIGH_I8X16_S,
                            simd::I32X4_EXTEND_HIGH_I16X8_S,
                            simd::I64X2_EXTEND_HIGH_I32X4_S,
                            simd::I64X2_EXTEND_HIGH_I32X4_S,
                        ];
                        let wide = match (u, q) {
                            (true, false) => self.lanes_op(size, low_u),
                            (true, true) => self.lanes_op(size, high_u),
                            (false, false) => self.lanes_op(size, low_s),
                            (false, true) => self.lanes_op(size, high_s),
                        };
                        let wide = wide.ok_or_else(|| format!("bad widening shift at 0x{addr:x}"))?;
                        let shl_wide = self.lanes_op(size, [simd::I16X8_SHL, simd::I32X4_SHL, simd::I64X2_SHL, simd::I64X2_SHL]);
                        self.getv(rn);
                        self.f.simd(wide);
                        if lshift != 0 {
                            self.f.i32c(lshift as i32);
                            self.f.simd(shl_wide.ok_or_else(|| format!("bad widening shift at 0x{addr:x}"))?);
                        }
                        self.setv(rd);
                    }
                    _ => return self.refuse(format!("unsupported shift-immediate op {op:05b} at 0x{addr:x}")),
                }
            }
            Insn::ScalarShift { u, op, imm, rn, rd } => {
                let right = 128u32.wrapping_sub(imm);
                let left = imm.wrapping_sub(64);
                let shr = if u { simd::I64X2_SHR_U } else { simd::I64X2_SHR_S };
                // The shifted source, rounded first when the form asks for it: the bias is half a
                // unit in the last place of the result.
                let mut shift_in = |this: &mut Self, round: bool| {
                    this.getv(rn);
                    if round {
                        this.f.v128c(round_mask(64, 1u64 << (right - 1)));
                        this.f.simd(simd::I64X2_ADD);
                    }
                    this.f.i32c(right as i32);
                    this.f.simd(shr);
                };
                match op {
                    0b000001 => {
                        shift_in(self, false);
                        self.setv(rd);
                    }
                    0b001001 => {
                        shift_in(self, true);
                        self.setv(rd);
                    }
                    0b000101 | 0b001101 => {
                        let round = op == 0b001101;
                        shift_in(self, round);
                        self.f.ls(L_V0);
                        self.getv(rd);
                        self.f.lg(L_V0);
                        self.f.simd(simd::I64X2_ADD);
                        self.setv(rd);
                    }
                    0b010001 => {
                        // sri: the shifted source fills the low bits and the destination keeps the
                        // top ones, which are as many as the shift.
                        shift_in(self, false);
                        self.f.ls(L_V0);
                        self.getv(rd);
                        self.f.v128c(high_bits_mask(64, right));
                        self.f.simd(simd::V128_AND);
                        self.f.lg(L_V0);
                        self.f.simd(simd::V128_OR);
                        self.setv(rd);
                    }
                    0b010101 => {
                        self.getv(rn);
                        self.f.i32c(left as i32);
                        self.f.simd(simd::I64X2_SHL);
                        if u {
                            // sli: the destination keeps its low bits, and the source's shifted
                            // bits are the top ones.
                            self.f.ls(L_V0);
                            self.getv(rd);
                            self.f.v128c(low_bits_mask(64, left));
                            self.f.simd(simd::V128_AND);
                            self.f.lg(L_V0);
                            self.f.simd(simd::V128_OR);
                        }
                        self.setv(rd);
                    }
                    _ => return self.refuse(format!("unsupported scalar shift op {op:06b} at 0x{addr:x}")),
                }
            }
            Insn::FpDupElement { size, index, rn, rd } => {
                self.f.v128c([0; 16]);
                self.getv(rn);
                let extract = match size {
                    0 => simd::I8X16_EXTRACT_LANE_U,
                    1 => simd::I16X8_EXTRACT_LANE_U,
                    2 => simd::I32X4_EXTRACT_LANE,
                    _ => simd::I64X2_EXTRACT_LANE,
                };
                self.f.simd_lane(extract, index as u8);
                let insert = match size {
                    0 => simd::I8X16_REPLACE_LANE,
                    1 => simd::I16X8_REPLACE_LANE,
                    2 => simd::I32X4_REPLACE_LANE,
                    _ => simd::I64X2_REPLACE_LANE,
                };
                self.f.simd_lane(insert, 0);
                self.setv(rd);
            }
            Insn::VecCopy { q, op, imm5, imm4, rn, rd } => {
                let size = imm5.trailing_zeros();
                let index = imm5 >> (size + 1);
                let lane = 1u32 << size;
                match (op, imm4, size) {
                    // dup from a general register
                    (false, 0b0001, _) => {
                        self.get(rn, size == 3);
                        let splat = match size {
                            0 => simd::I8X16_SPLAT,
                            1 => simd::I16X8_SPLAT,
                            2 => simd::I32X4_SPLAT,
                            _ => simd::I64X2_SPLAT,
                        };
                        self.f.simd(splat);
                        self.setv(rd);
                    }
                    // dup from an element
                    (false, 0b0000, _) => {
                        self.getv(rn);
                        let ext = match size {
                            0 => simd::I8X16_EXTRACT_LANE_U,
                            1 => simd::I16X8_EXTRACT_LANE_U,
                            2 => simd::I32X4_EXTRACT_LANE,
                            _ => simd::I64X2_EXTRACT_LANE,
                        };
                        self.f.simd_lane(ext, index as u8);
                        let splat = match size {
                            0 => simd::I8X16_SPLAT,
                            1 => simd::I16X8_SPLAT,
                            2 => simd::I32X4_SPLAT,
                            _ => simd::I64X2_SPLAT,
                        };
                        self.f.simd(splat);
                        self.setv(rd);
                    }
                    // ins from a general register
                    (false, 0b0011, _) => {
                        self.getv(rd);
                        self.get(rn, size == 3);
                        let insert = match size {
                            0 => simd::I8X16_REPLACE_LANE,
                            1 => simd::I16X8_REPLACE_LANE,
                            2 => simd::I32X4_REPLACE_LANE,
                            _ => simd::I64X2_REPLACE_LANE,
                        };
                        self.f.simd_lane(insert, index as u8);
                        self.setv(rd);
                    }
                    // ins from an element
                    (true, _, _) => {
                        self.getv(rn);
                        let ext = match size {
                            0 => simd::I8X16_EXTRACT_LANE_U,
                            1 => simd::I16X8_EXTRACT_LANE_U,
                            2 => simd::I32X4_EXTRACT_LANE,
                            _ => simd::I64X2_EXTRACT_LANE,
                        };
                        let tmp = if size == 3 { L_T0 } else { L_TI };
                        self.f.simd_lane(ext, (imm4 >> size) as u8);
                        self.f.ls(tmp);
                        self.getv(rd);
                        self.f.lg(tmp);
                        let insert = match size {
                            0 => simd::I8X16_REPLACE_LANE,
                            1 => simd::I16X8_REPLACE_LANE,
                            2 => simd::I32X4_REPLACE_LANE,
                            _ => simd::I64X2_REPLACE_LANE,
                        };
                        self.f.simd_lane(insert, index as u8);
                        self.setv(rd);
                    }
                    // umov/smov: a lane into a general register
                    (false, 0b0111, _) | (false, 0b0101, _) => {
                        let signed = imm4 == 0b0101;
                        self.getv(rn);
                        let ext = match (size, signed) {
                            (0, false) => simd::I8X16_EXTRACT_LANE_U,
                            (0, true) => simd::I8X16_EXTRACT_LANE_S,
                            (1, false) => simd::I16X8_EXTRACT_LANE_U,
                            (1, true) => simd::I16X8_EXTRACT_LANE_S,
                            (2, _) => simd::I32X4_EXTRACT_LANE,
                            _ => simd::I64X2_EXTRACT_LANE,
                        };
                        self.f.simd_lane(ext, index as u8);
                        // The lane arrives as i32 (or i64 for the doubleword form); a W destination
                        // keeps the register's upper half clear, and X destinations extend the way
                        // the operation says (smov sign, umov zero).
                        if size == 3 {
                            // already 64 bits
                        } else if q && signed {
                            self.f.op(I64_EXTEND_I32_S);
                        } else {
                            self.f.op(I64_EXTEND_I32_U);
                        }
                        self.set(rd, true);
                        let _ = lane;
                    }
                    _ => return self.refuse(format!("unsupported copy op at 0x{addr:x}")),
                }
            }
            Insn::VecPermute { q, size, op, rn, rm, rd } => {
                let _ = q;
                let mask = permute_mask(size, op)
                    .ok_or_else(|| format!("unsupported permute {op:05b} at 0x{addr:x}"))?;
                self.shuffle(NVEC0 + rn, NVEC0 + rm, mask);
                self.setv(rd);
            }
            Insn::VecExt { q, imm4, rn, rm, rd } => {
                let mut mask = [0u8; 16];
                for i in 0..16u32 {
                    let src = imm4 + i;
                    mask[i as usize] = if src < 16 { src as u8 } else { (16 + src - 16) as u8 };
                }
                self.shuffle(NVEC0 + rn, NVEC0 + rm, mask);
                if !q {
                    self.f.v128c(low_half_mask());
                    self.f.simd(simd::V128_AND);
                }
                self.setv(rd);
            }
            Insn::VecTbl { q, tbx, len, rn, rm, rd } => {
                let _ = q;
                // result = bits from the table where the index is in range, else the destination
                // (tbx) or zero (tbl). One register of the table at a time, because a wasm swizzle
                // only reaches 16 bytes.
                if tbx {
                    self.getv(rd);
                } else {
                    self.f.v128c([0; 16]);
                }
                self.f.ls(L_V0);
                for k in 0..=len {
                    self.getv(rm);
                    self.f.i32c((16 * k) as i32);
                    self.f.simd(simd::I8X16_SPLAT);
                    self.f.simd(simd::I8X16_SUB);
                    self.f.ls(L_V1);
                    self.getv((rn + k) % 32);
                    self.f.lg(L_V1);
                    self.f.simd(simd::I8X16_SWIZZLE);
                    self.f.ls(L_V2);
                    self.f.lg(L_V1);
                    self.f.v128c([16; 16]);
                    self.f.simd(simd::I8X16_LT_U);
                    self.f.ls(L_V3);
                    self.f.lg(L_V2);
                    self.f.lg(L_V0);
                    self.f.lg(L_V3);
                    self.f.simd(simd::V128_BITSELECT);
                    self.f.ls(L_V0);
                }
                self.f.lg(L_V0);
                self.setv(rd);
            }
            Insn::Atomic { is_load, exclusive, size, rn, rt, rs } => {
                let width = 1u32 << size;
                self.addr_base_off(rn, 0);
                if is_load {
                    self.emit_load(L_T1, size, 1, rt);
                } else {
                    self.emit_store(L_T1, size, rt);
                    if exclusive {
                        // The exclusive always succeeds on one thread: the status is zero.
                        self.f.i64c(0);
                        self.f.ls(rs);
                    }
                }
                let _ = width;
            }
            Insn::AtomicCas { size, rn, rt, rs } => {
                // tmp = [rn]; if tmp == Rs then [rn] = Rt; Rs = tmp. One thread, so this is a
                // plain compare followed by a plain store.
                self.addr_base_off(rn, 0);
                self.emit_load(L_T1, size, 1, L_T0);
                self.f.lg(L_T0);
                self.get(rs, true);
                self.f.op(I64_EQ);
                self.open_if();
                self.emit_store(L_T1, size, rt);
                self.close_if();
                self.set_loaded(rs, L_T0);
            }
            Insn::FpToGpr { sf, signed, size, round, fmov, rn, rd } => {
                // `fmov Wd, Sn` reinterprets the bits; the conversions round first and then
                // saturate to the integer range, which is what the truncating conversion does.
                let double = size == 1;
                match (fmov, round) {
                    (true, _) | (_, round::ZERO) => {
                        self.getv(rn);
                        self.f.simd_lane(
                            if double { simd::F64X2_EXTRACT_LANE } else { simd::F32X4_EXTRACT_LANE },
                            0,
                        );
                    }
                    // Ties away from zero is a round of its own, which the scalar sequence builds.
                    (false, round::AWAY) => self.fp_round_away(rn, double),
                    (false, _) => {
                        self.getv(rn);
                        self.f.simd_lane(
                            if double { simd::F64X2_EXTRACT_LANE } else { simd::F32X4_EXTRACT_LANE },
                            0,
                        );
                        self.f.op(match (double, round) {
                            (true, round::UP) => F64_CEIL,
                            (true, round::DOWN) => F64_FLOOR,
                            (true, _) => F64_NEAREST,
                            (false, round::UP) => F32_CEIL,
                            (false, round::DOWN) => F32_FLOOR,
                            (false, _) => F32_NEAREST,
                        });
                    }
                }
                if fmov {
                    self.f.op(if double { I64_REINTERPRET_F64 } else { I32_REINTERPRET_F32 });
                    if !double {
                        self.f.op(I64_EXTEND_I32_U);
                    }
                } else {
                    self.f.sat(if double {
                        if sf {
                            if signed { sat::I64_TRUNC_SAT_F64_S } else { sat::I64_TRUNC_SAT_F64_U }
                        } else if signed {
                            sat::I32_TRUNC_SAT_F64_S
                        } else {
                            sat::I32_TRUNC_SAT_F64_U
                        }
                    } else if sf {
                        if signed { sat::I64_TRUNC_SAT_F32_S } else { sat::I64_TRUNC_SAT_F32_U }
                    } else if signed {
                        sat::I32_TRUNC_SAT_F32_S
                    } else {
                        sat::I32_TRUNC_SAT_F32_U
                    });
                    if !sf {
                        self.f.op(I64_EXTEND_I32_U);
                    }
                }
                self.set(rd, true);
            }
            Insn::FpToGprFixed { sf, unsigned, size, fbits, rn, rd } => {
                let double = size == 1;
                if size > 1 || fbits == 0 || fbits > if double { 64 } else { 32 } {
                    return self.refuse(format!("fixed-point conversion at 0x{addr:x}"));
                }
                self.getv(rn);
                self.f.simd_lane(if double { simd::F64X2_EXTRACT_LANE } else { simd::F32X4_EXTRACT_LANE }, 0);
                // Scaling by a power of two is exact, and an overflow to infinity still saturates
                // to the end of the integer range, which is what the instruction does.
                let scale: u64 = if double {
                    ((1023 + fbits) as u64) << 52
                } else {
                    (((127 + fbits) as u32) << 23) as u64
                };
                self.fp_const(scale, double);
                self.f.op(if double { F64_MUL } else { F32_MUL });
                self.f.sat(if double {
                    if sf {
                        if unsigned { sat::I64_TRUNC_SAT_F64_U } else { sat::I64_TRUNC_SAT_F64_S }
                    } else if unsigned {
                        sat::I32_TRUNC_SAT_F64_U
                    } else {
                        sat::I32_TRUNC_SAT_F64_S
                    }
                } else if sf {
                    if unsigned { sat::I64_TRUNC_SAT_F32_U } else { sat::I64_TRUNC_SAT_F32_S }
                } else if unsigned {
                    sat::I32_TRUNC_SAT_F32_U
                } else {
                    sat::I32_TRUNC_SAT_F32_S
                });
                if !sf {
                    self.f.op(I64_EXTEND_I32_U);
                }
                self.set(rd, true);
            }
            Insn::GprToFp { sf, signed, size, opcode, rn, rd, .. } => {
                let double = size == 1;
                self.f.v128c([0; 16]);
                if opcode == 7 {
                    // fmov: the bits go across unchanged.
                    if sf {
                        self.get(rn, true);
                        self.f.op(F64_REINTERPRET_I64);
                        self.f.simd_lane(simd::F64X2_REPLACE_LANE, 0);
                    } else {
                        self.get(rn, false);
                        self.f.op(F32_REINTERPRET_I32);
                        self.f.simd_lane(simd::F32X4_REPLACE_LANE, 0);
                    }
                } else {
                    // scvtf/ucvtf: an integer converted to FP.
                    if sf {
                        self.get(rn, true);
                        self.f.op(if double {
                            if signed { F64_CONVERT_I64_S } else { F64_CONVERT_I64_U }
                        } else if signed {
                            F32_CONVERT_I64_S
                        } else {
                            F32_CONVERT_I64_U
                        });
                    } else {
                        self.get(rn, false);
                        self.f.op(if double {
                            if signed { F64_CONVERT_I32_S } else { F64_CONVERT_I32_U }
                        } else if signed {
                            F32_CONVERT_I32_S
                        } else {
                            F32_CONVERT_I32_U
                        });
                    }
                    self.f.simd_lane(if double { simd::F64X2_REPLACE_LANE } else { simd::F32X4_REPLACE_LANE }, 0);
                }
                self.setv(rd);
            }
            Insn::FpTwoSource { size, opcode, rn, rm, rd } => {
                if size > 1 {
                    return self.refuse(format!("half precision floating point at 0x{addr:x}"));
                }
                let double = size == 1;
                self.fp_base();
                if (4..=7).contains(&opcode) {
                    self.fp_minmax(rn, rm, double, opcode & 1 == 0, opcode >= 6);
                } else {
                    self.fp_get(rn, double);
                    self.fp_get(rm, double);
                    let op = match opcode {
                        0 | 8 => if double { F64_MUL } else { F32_MUL },
                        1 => if double { F64_DIV } else { F32_DIV },
                        2 => if double { F64_ADD } else { F32_ADD },
                        3 => if double { F64_SUB } else { F32_SUB },
                        _ => return self.refuse(format!("floating point opcode {opcode} at 0x{addr:x}")),
                    };
                    self.f.op(op);
                    if opcode == 8 {
                        // fnmul: the product, then the sign flipped.
                        self.f.op(if double { F64_NEG } else { F32_NEG });
                    }
                }
                self.fp_put(rd, double);
            }
            Insn::FpScalarSame { double, multiply, rn, rm, rd } => {
                self.fp_base();
                self.fp_get(rn, double);
                self.fp_get(rm, double);
                if multiply {
                    // `fmulx` differs from a plain multiply only for zero times infinity, which it
                    // answers with 2.0 where a multiply gives a NaN.
                    self.f.op(if double { F64_MUL } else { F32_MUL });
                } else {
                    // `fabd`: the absolute value of the difference.
                    self.f.op(if double { F64_SUB } else { F32_SUB });
                    self.f.op(if double { F64_ABS } else { F32_ABS });
                }
                self.fp_put(rd, double);
            }
            Insn::FpFused { size, negate_product, subtract, rn, rm, ra, rd } => {
                if size > 1 {
                    return self.refuse(format!("half precision floating point at 0x{addr:x}"));
                }
                let double = size == 1;
                // There is no fused multiply-add in wasm, so this rounds twice and can differ from
                // the instruction in the last bit. docs/poc-results.md records that.
                self.fp_base();
                // All four forms are the accumulator plus the product with a sign each: bit 21
                // negates the accumulator and bit 15 the product, so FMSUB is `Va - Vn*Vm` and
                // FNMSUB is `-Va + Vn*Vm`. The accumulator goes on the stack first because that is
                // the NaN a result of two carries, as the hardware reports it.
                self.fp_get(ra, double);
                if negate_product {
                    self.f.op(if double { F64_NEG } else { F32_NEG });
                }
                self.fp_get(rn, double);
                self.fp_get(rm, double);
                self.f.op(if double { F64_MUL } else { F32_MUL });
                if negate_product != subtract {
                    self.f.op(if double { F64_NEG } else { F32_NEG });
                }
                self.f.op(if double { F64_ADD } else { F32_ADD });
                self.fp_put(rd, double);
            }
            Insn::FpCompareZero { double, op, integer, rn, rd } => {
                // A comparison against zero that leaves a mask in the lane instead of flags: all
                // ones where it holds, and the rest of the register clear.
                self.getv(rn);
                if integer {
                    self.f.simd_lane(simd::I64X2_EXTRACT_LANE, 0);
                    self.f.i64c(0);
                    self.f.op(match op {
                        0 => I64_EQ,
                        1 => I64_GE_S,
                        2 => I64_GT_S,
                        3 => I64_LE_S,
                        _ => I64_LT_S,
                    });
                } else if double {
                    self.f.simd_lane(simd::F64X2_EXTRACT_LANE, 0);
                    self.f.f64c(0f64.to_bits());
                    self.f.op(match op {
                        0 => F64_EQ,
                        1 => F64_GE,
                        2 => F64_GT,
                        3 => F64_LE,
                        _ => F64_LT,
                    });
                } else {
                    self.f.simd_lane(simd::F32X4_EXTRACT_LANE, 0);
                    self.f.f32c(0f32.to_bits());
                    self.f.op(match op {
                        0 => F32_EQ,
                        1 => F32_GE,
                        2 => F32_GT,
                        3 => F32_LE,
                        _ => F32_LT,
                    });
                }
                let width = if double || integer { 8 } else { 4 };
                let mut yes = [0u8; 16];
                for b in yes.iter_mut().take(width) {
                    *b = 0xff;
                }
                // The typed if is what wasm gives a vector result: `select` on its own is numeric.
                self.f.op(IF);
                self.f.body.push(V128);
                self.f.v128c(yes);
                self.f.op(ELSE);
                self.f.v128c([0u8; 16]);
                self.f.end();
                self.setv(rd);
            }
            Insn::FpCompare { size, zero, rn, rm, .. } => {
                if size > 1 {
                    return self.refuse(format!("half precision floating point at 0x{addr:x}"));
                }
                self.fp_compare_flags(rn, rm, zero, size == 1);
            }
            Insn::FpCondCompare { size, cond, nzcv, rn, rm } => {
                // The flags come from the comparison when the condition holds and from the
                // instruction otherwise, which is how a chain of comparisons short-circuits.
                if size > 1 {
                    return self.refuse(format!("half precision floating point at 0x{addr:x}"));
                }
                self.push_cond(cond);
                self.open_if();
                self.fp_compare_flags(rn, rm, false, size == 1);
                self.f.op(ELSE);
                self.f.i64c(nzcv as i64);
                self.f.ls(32);
                self.close_if();
            }
            Insn::ScalarThree { u, size, op, rn, rm, rd } => {
                // One 64-bit lane, and the rest of the register cleared: a write in a scalar form
                // sets every bit above the value it produces to zero. `add d0, d1, d2` is the
                // 64-bit integer add a program's own number code reaches for.
                if size != 3 {
                    return self.refuse(format!("half precision floating point at 0x{addr:x}"));
                }
                let want = match (u, op) {
                    (false, 0b10000) => I64_ADD,
                    (true, 0b10000) => I64_SUB,
                    _ => {
                        return self.refuse(format!(
                            "unsupported scalar three same u={u} op={op:05b} at 0x{addr:x}"
                        ))
                    }
                };
                self.f.v128c([0; 16]);
                self.getv(rn);
                self.f.simd_lane(simd::I64X2_EXTRACT_LANE, 0);
                self.getv(rm);
                self.f.simd_lane(simd::I64X2_EXTRACT_LANE, 0);
                self.f.op(want);
                self.f.simd_lane(simd::I64X2_REPLACE_LANE, 0);
                self.setv(rd);
            }
            Insn::ScalarTwoMisc { size, negate, rn, rd } => {
                // One lane of the register, as wide as the instruction names, and the rest of the
                // register cleared, as every scalar write does.
                if size < 2 {
                    return self.refuse(format!("scalar two-register width {size} at 0x{addr:x}"));
                }
                let wide = size == 3;
                self.f.v128c([0; 16]);
                if negate {
                    // The zero goes under the lane: both subtracts take the lane off it, and the
                    // other order leaves the lane as it was.
                    if wide {
                        self.f.i64c(0);
                    } else {
                        self.f.i32c(0);
                    }
                    self.getv(rn);
                    self.f.simd_lane(if wide { simd::I64X2_EXTRACT_LANE } else { simd::I32X4_EXTRACT_LANE }, 0);
                    self.f.op(if wide { I64_SUB } else { I32_SUB });
                } else if wide {
                    self.getv(rn);
                    self.f.simd_lane(simd::I64X2_EXTRACT_LANE, 0);
                    // `abs` as `(x ^ (x >> 63)) - (x >> 63)`, which is the value without its sign
                    // bit and wraps the same way the instruction does for the most negative one.
                    self.f.ls(L_T2);
                    self.f.lg(L_T2);
                    self.f.i64c(63);
                    self.f.op(I64_SHR_S);
                    self.f.ls(L_T3);
                    self.f.lg(L_T2);
                    self.f.lg(L_T3);
                    self.f.op(I64_XOR);
                    self.f.lg(L_T3);
                    self.f.op(I64_SUB);
                } else {
                    self.getv(rn);
                    self.f.simd_lane(simd::I32X4_EXTRACT_LANE, 0);
                    self.f.ls(L_TI);
                    self.f.lg(L_TI);
                    self.f.i32c(31);
                    self.f.op(I32_SHR_S);
                    self.f.ls(L_T2);
                    self.f.lg(L_TI);
                    self.f.lg(L_T2);
                    self.f.op(I32_XOR);
                    self.f.lg(L_T2);
                    self.f.op(I32_SUB);
                }
                self.f.simd_lane(if wide { simd::I64X2_REPLACE_LANE } else { simd::I32X4_REPLACE_LANE }, 0);
                self.setv(rd);
            }
            Insn::VecHighToGpr { rn, rd } => {
                self.getv(rn);
                self.f.simd_lane(simd::I64X2_EXTRACT_LANE, 1);
                self.f.ls(rd);
            }
            Insn::GprToVecHigh { rn, rd } => {
                self.getv(rd);
                self.f.lg(rn);
                self.f.simd_lane(simd::I64X2_REPLACE_LANE, 1);
                self.setv(rd);
            }
            Insn::FpCondSelect { size, cond, rn, rm, rd } => {
                if size > 1 {
                    return self.refuse(format!("half precision floating point at 0x{addr:x}"));
                }
                let double = size == 1;
                self.push_cond(cond);
                self.f.op(IF);
                self.f.body.push(V128);
                self.fp_base();
                self.fp_get(rn, double);
                self.f.simd_lane(if double { simd::F64X2_REPLACE_LANE } else { simd::F32X4_REPLACE_LANE }, 0);
                self.f.op(ELSE);
                self.fp_base();
                self.fp_get(rm, double);
                self.f.simd_lane(if double { simd::F64X2_REPLACE_LANE } else { simd::F32X4_REPLACE_LANE }, 0);
                self.f.end();
                self.setv(rd);
            }
            Insn::FpOneSource { size, opcode, rn, rd } => {
                if size > 1 {
                    return self.refuse(format!("half precision floating point at 0x{addr:x}"));
                }
                let double = size == 1;
                // fcvt changes the width of the register it writes, so it does not share the tail.
                match (opcode, double) {
                    (0b000101, false) => {
                        self.fp_base();
                        self.fp_get(rn, false);
                        self.f.op(F64_PROMOTE_F32);
                        self.fp_put(rd, true);
                        return Ok(());
                    }
                    (0b000100, true) => {
                        self.fp_base();
                        self.fp_get(rn, true);
                        self.f.op(F32_DEMOTE_F64);
                        self.fp_put(rd, false);
                        return Ok(());
                    }
                    _ => {}
                }
                if opcode == 12 {
                    self.fp_base();
                    self.fp_round_away(rn, double);
                    self.fp_put(rd, double);
                    return Ok(());
                }
                self.fp_base();
                self.fp_get(rn, double);
                let op = match opcode {
                    0b000000 => None, // fmov: the bits move unchanged
                    0b000001 => Some(if double { F64_ABS } else { F32_ABS }),
                    0b000010 => Some(if double { F64_NEG } else { F32_NEG }),
                    0b000011 => Some(if double { F64_SQRT } else { F32_SQRT }),
                    0b001000 => Some(if double { F64_NEAREST } else { F32_NEAREST }),
                    0b001001 => Some(if double { F64_CEIL } else { F32_CEIL }),
                    0b001010 => Some(if double { F64_FLOOR } else { F32_FLOOR }),
                    0b001011 => Some(if double { F64_TRUNC } else { F32_TRUNC }),
                    // frintx and frinti round in the mode the FPCR holds; the default is the same
                    // nearest-even that frintn asks for, and nothing here changes the mode.
                    0b001110 | 0b001111 => Some(if double { F64_NEAREST } else { F32_NEAREST }),
                    _ => return self.refuse(format!("floating point opcode {opcode} at 0x{addr:x}")),
                };
                if let Some(op) = op {
                    self.f.op(op);
                }
                self.fp_put(rd, double);
            }
            Insn::FpFromInt { double, unsigned, rn, rd } => {
                // The register holds an integer in its low lane, which becomes a float. The
                // conversion is exact up to the mantissa, which is what the instruction does.
                self.fp_base();
                self.getv(rn);
                if double {
                    self.f.simd_lane(simd::I64X2_EXTRACT_LANE, 0);
                    self.f.op(if unsigned { F64_CONVERT_I64_U } else { F64_CONVERT_I64_S });
                } else if unsigned {
                    self.f.simd_lane(simd::I32X4_EXTRACT_LANE, 0);
                    self.f.op(F32_CONVERT_I32_U);
                } else {
                    self.f.simd_lane(simd::I32X4_EXTRACT_LANE, 0);
                    self.f.op(F32_CONVERT_I32_S);
                }
                self.fp_put(rd, double);
            }
            Insn::FpFromIntFixed { sf, unsigned, size, fbits, rn, rd } => {
                // The integer becomes a float, then scales by a power of two: scaling moves the
                // significand without changing it, so the one rounding the instruction asks for is
                // the one that happens.
                if size > 1 {
                    return self.refuse(format!("half precision floating point at 0x{addr:x}"));
                }
                let double = size == 1;
                self.fp_base();
                self.get(rn, sf);
                self.f.op(match (sf, double, unsigned) {
                    (true, true, false) => F64_CONVERT_I64_S,
                    (true, true, true) => F64_CONVERT_I64_U,
                    (true, false, false) => F32_CONVERT_I64_S,
                    (true, false, true) => F32_CONVERT_I64_U,
                    (false, true, false) => F64_CONVERT_I32_S,
                    (false, true, true) => F64_CONVERT_I32_U,
                    (false, false, false) => F32_CONVERT_I32_S,
                    (false, false, true) => F32_CONVERT_I32_U,
                });
                if double {
                    self.f.f64c(2f64.powi(-(fbits as i32)).to_bits());
                    self.f.op(F64_MUL);
                } else {
                    self.f.f32c(2f32.powi(-(fbits as i32)).to_bits());
                    self.f.op(F32_MUL);
                }
                self.fp_put(rd, double);
            }
            Insn::FpToInt { double, unsigned, rmode, rn, rd } => {
                // The scalar becomes an integer in the same register, saturating at the ends of the
                // range for a value out of it, which is what the instruction does with those and
                // with a NaN. Rounding first is what tells the members of the family apart, and
                // the saturating conversion truncates the rest of the way.
                self.fp_base();
                match rmode {
                    round::AWAY => self.fp_round_away(rn, double),
                    round::ZERO | round::DOWN | round::UP | round::NEAREST => {
                        self.fp_get(rn, double);
                        let pre = match (rmode, double) {
                            (round::DOWN, true) => Some(F64_FLOOR),
                            (round::DOWN, false) => Some(F32_FLOOR),
                            (round::UP, true) => Some(F64_CEIL),
                            (round::UP, false) => Some(F32_CEIL),
                            (round::NEAREST, true) => Some(F64_NEAREST),
                            (round::NEAREST, false) => Some(F32_NEAREST),
                            _ => None,
                        };
                        if let Some(op) = pre {
                            self.f.op(op);
                        }
                    }
                    _ => return self.refuse(format!("floating point rounding {rmode} at 0x{addr:x}")),
                }
                self.f.sat(if double {
                    if unsigned {
                        sat::I64_TRUNC_SAT_F64_U
                    } else {
                        sat::I64_TRUNC_SAT_F64_S
                    }
                } else if unsigned {
                    sat::I32_TRUNC_SAT_F32_U
                } else {
                    sat::I32_TRUNC_SAT_F32_S
                });
                self.f.op(if double { F64_REINTERPRET_I64 } else { F32_REINTERPRET_I32 });
                self.fp_put(rd, double);
            }
            Insn::FpImm { size, imm8, rd } => {
                if size > 1 {
                    return self.refuse(format!("half precision floating point at 0x{addr:x}"));
                }
                let double = size == 1;
                let bits = vfp_expand_imm(imm8, if double { 64 } else { 32 });
                self.fp_base();
                self.fp_const(bits, double);
                self.fp_put(rd, double);
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

// ---------------------------------------------------------------- pages translated at run time

/// One region a page module carries, in the order its dispatch slots were assigned.
pub struct PageRegion {
    pub entry: u64,
    /// Block start addresses, in block index order.
    pub blocks: Vec<u64>,
}

pub struct PageOutput {
    pub wasm: Vec<u8>,
    pub regions: Vec<PageRegion>,
    pub unsupported: Vec<(u64, String)>,
}

/// Translate the code around one address into a module that can be added to a running image.
///
/// The module has no memory and no dispatch table of its own: it imports the host's memory and
/// exports its regions, which the host puts in the running image's table and then dispatches to.
pub fn translate_page(
    elf: &Elf,
    site: &Site,
    at: u64,
    cfg: &Config,
) -> Result<PageOutput, String> {
    let page = at & !0xfff;
    let insns = &site.insns;
    let mut entries = site.entries.clone();
    let pointer_entries = &site.pointer_entries;
    if !insns.contains_key(&at) {
        return Err(format!("0x{at:x} is not an instruction of this image"));
    }
    // The address that was reached is an entry point by definition: nothing else in the image has
    // to branch to it for it to be executed.
    entries.insert(at);

    let starts: Vec<u64> = std::iter::once(at)
        .chain(
            entries
                .iter()
                .chain(pointer_entries.iter())
                .filter(|&&e| e != at && e & !0xfff == page)
                .copied(),
        )
        .collect();

    let mut regions: Vec<Region> = Vec::new();
    for start in starts {
        if regions.iter().any(|r| r.blocks[0].addr == start) {
            continue;
        }
        let region = discover_region(start, insns, &entries);
        if region.blocks.is_empty() {
            continue;
        }
        regions.extend(split_region(region));
    }
    if regions.len() >= TABLE_SLOTS_MAX as usize {
        return Err(format!("{} regions in one page exceeds the table", regions.len()));
    }

    let mut m = Module::new();
    m.mem_import = Some(("env".into(), "mem".into()));
    let Prelude { ids, ty_region } = prelude(&mut m, cfg);
    let layout = Layout {
        table_mask: 0,
        stack_floor: 0,
        bounds_check: cfg.bounds_check,
        trace: cfg.trace,
        trace_loops: cfg.trace_loops,
        allow_undefined: cfg.allow_undefined,
        mem_size: cfg.mem_pages as u64 * 65536,
    };
    let mut unsupported: Vec<(u64, String)> = Vec::new();
    let (bodies, failed) = emit_regions(&regions, &layout, &ids, ty_region, &mut unsupported);
    let mut out_regions = Vec::new();
    for (i, (region, body)) in regions.iter().zip(bodies).enumerate() {
        let id = m.add_func(ty_region);
        *m.func_mut(id) = body;
        m.exports.push((format!("r{i}"), 0, id));
        // A region that only became a trap claims its first block and nothing else.
        let blocks: Vec<u64> = region
            .blocks
            .iter()
            .take(if failed[i] { 1 } else { region.blocks.len() })
            .map(|b| b.addr)
            .collect();
        out_regions.push(PageRegion { entry: region.blocks[0].addr, blocks });
    }
    unsupported.sort();
    Ok(PageOutput { wasm: m.encode(), regions: out_regions, unsupported })
}
