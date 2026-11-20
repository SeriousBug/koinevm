// The guest's address space, from the kernel's side.
//
// The map is real: one byte per 4 KiB page in the guest's own linear memory (the translator puts the
// page table there), and this class is what maintains it when the guest asks for memory. Guest
// virtual addresses are linear-memory offsets, so mapping a range is bookkeeping plus the bytes the
// range starts with.

import fs from "node:fs";

export const PAGE = 4096;
/// The size of one guest memory. A wasm32 memory holds at most this, so the guest's address space
/// is a sequence of them and the top bits of an address name the one it is in.
export const CHUNK = 2 ** 32;

export const PTE = {
  /// There is a mapping on the page, whatever it allows: `PROT_NONE` is mapped and nothing else.
  MAPPED: 1,
  WRITABLE: 2,
  EXECUTABLE: 4,
  TRANSLATED: 8,
  READABLE: 16,
};

export const PROT = { READ: 1, WRITE: 2, EXEC: 4 };
export const MAP = { SHARED: 0x01, PRIVATE: 0x02, FIXED: 0x10, ANONYMOUS: 0x20, POPULATE: 0x8000 };

export const MREMAP = { MAYMOVE: 1, FIXED: 2, DONTUNMAP: 4 };

/// The advices this kernel acts on, which are the ones that let it take a page back.
export const MADV = { DONTNEED: 4, FREE: 8, REMOVE: 9, DONTNEED_LOCKED: 24 };
const DROP = new Set(Object.values(MADV));

export const EINVAL = 22;
export const ENOMEM = 12;
export const EFAULT = 14;

/// Rounding and page numbers are arithmetic, not shifts and masks: an address above 4 GiB does not
/// fit in the 32 bits those keep.
const roundUp = (x, a) => Math.ceil(x / a) * a;
const pageOf = (addr) => Math.floor(Number(addr) / PAGE);

export class AddressSpace {
  constructor(memories, map) {
    /// The guest's memories, low chunk first. The first also holds the engine's own state, which is
    /// why everything that is not guest data is written through `memory` and never `memoryOf`.
    this.memories = memories;
    this.memory = memories[0];
    this.chunks = memories.length;
    this.pteBase = map.pte_base;
    this.brkBase = map.heap_base;
    this.brkLimit = map.heap_limit;
    this.brk = map.heap_base;
    this.arenaLo = map.mmap_base;
    this.arenaHi = map.stack_floor;
    // Everything from mmap_base to the page table is available for mmap, and every chunk above the
    // first is all of it: the stack and the page table live at the top of the first, so a mapping
    // never has to cross into another memory.
    this.free = [{ lo: map.mmap_base, hi: map.pte_base }];
    for (let k = 1; k < this.chunks; k++) this.free.push({ lo: k * CHUNK, hi: (k + 1) * CHUNK });
    /// What a program may allocate over the whole run: the heap up to its limit, the first chunk's
    /// arena up to the page table, and every chunk above the first. It does not move as things are
    /// mapped, which is what a program sizing itself by the machine asks for.
    this.total = map.pte_base - map.mmap_base + (map.heap_limit - map.heap_base);
    for (let k = 1; k < this.chunks; k++) this.total += memories[k].buffer.byteLength;
    // One table for every chunk: a chunk is exactly 2^20 pages, so an address indexes it with
    // `addr >> 12` and the high bits are already that chunk's part of it.
    this.ptes = new Uint8Array(this.memory.buffer, this.pteBase, this.chunks << 20);
    /// Per chunk, the first page above every page that has ever been mapped. Nothing above it has
    /// been written, so it is already zero and does not have to be written zero: a reservation of
    /// gigabytes costs the bytes a program touches, not the bytes it names.
    this.touched = new Array(this.chunks).fill(0);
    /// The same mark without the reuse: a fork copies what a chunk has mapped, and this is how far
    /// it has to look. It starts at what the image and the stack already claim, which the page
    /// table in memory says.
    this.mapped = new Array(this.chunks).fill(0);
    /// How many pages have a mapping on them, kept as the table changes: a space this machine does
    /// not swap, so every page a program has mapped is a page that is there. `/proc` calls it
    /// resident.
    this.resident = 0;
    for (let k = 0; k < this.chunks; k++) {
      const base = k << 20;
      for (let p = base + (1 << 20) - 1; p >= base; p--) {
        if (this.ptes[p] !== 0) {
          this.mapped[k] = p - base + 1;
          break;
        }
      }
      for (let p = base; p < base + this.mapped[k]; p++) {
        if (this.ptes[p] & PTE.MAPPED) this.resident++;
      }
    }
    // Which file each mapping came from. A jump into one of these is a page this machine has not
    // translated yet, and the file is what it has to translate it from.
    this.images = [];
    /// Called with a range whose bytes or permissions changed, so a translation made from what was
    /// there before is dropped. The host sets it; nothing here knows what a translation is.
    this.forget = () => {};
  }

  /// The memory an address is in. Everything a guest can touch lives in one chunk, because a
  /// chunk is the largest range the address space holds contiguously.
  memoryOf(addr) {
    return this.memories[Math.floor(Number(addr) / CHUNK)];
  }

  /// A view of `len` bytes at `addr`, which has to be inside one chunk.
  bytes(addr, len) {
    const at = Number(addr);
    return new Uint8Array(this.memoryOf(at).buffer, at % CHUNK, len);
  }

  /// A copy of the guest's bytes, wherever they are: what a syscall argument is read through.
  copyOut(addr, len) {
    const out = Buffer.alloc(len);
    let done = 0;
    while (done < len) {
      const at = Number(addr) + done;
      const room = Math.min(CHUNK - (at % CHUNK), len - done);
      out.set(new Uint8Array(this.memoryOf(at).buffer, at % CHUNK, room), done);
      done += room;
    }
    return out;
  }

  /// The same the other way, for what a syscall writes into the guest's memory.
  copyIn(addr, bytes) {
    let done = 0;
    while (done < bytes.length) {
      const at = Number(addr) + done;
      const room = Math.min(CHUNK - (at % CHUNK), bytes.length - done);
      new Uint8Array(this.memoryOf(at).buffer, at % CHUNK, room).set(bytes.subarray(done, done + room));
      done += room;
    }
  }

  /// Clears a range that is about to be readable again: only the part of it that was mapped before
  /// has anything in it, because a page nothing has ever mapped is still zero. The mark moves with
  /// the mapping, so a page handed out twice is cleared the second time.
  clear(addr, len) {
    const at = Number(addr);
    let done = 0;
    while (done < len) {
      const lo = at + done;
      const chunk = Math.floor(lo / CHUNK);
      const room = Math.min(CHUNK - (lo % CHUNK), len - done);
      const first = pageOf(lo);
      const mark = this.touched[chunk];
      if (mark > first) {
        const pages = Math.min(pageOf(roundUp(lo + room, PAGE)), mark) - first;
        if (pages > 0) this.zero(lo, pages * PAGE);
      }
      const last = pageOf(roundUp(lo + room, PAGE));
      if (last > this.touched[chunk]) this.touched[chunk] = last;
      done += room;
    }
  }

  /// Fills a range with zeros, page by page across the chunks it spans.
  zero(addr, len) {
    let done = 0;
    while (done < len) {
      const at = Number(addr) + done;
      const room = Math.min(CHUNK - (at % CHUNK), len - done);
      new Uint8Array(this.memoryOf(at).buffer, at % CHUNK, room).fill(0);
      done += room;
    }
  }

  /// The whole guest address space, which is what a 64-bit address is checked against.
  get size() {
    let total = 0;
    for (const memory of this.memories) total += memory.buffer.byteLength;
    return total;
  }

  protBits(prot) {
    let bits = PTE.MAPPED;
    if (prot & PROT.READ) bits |= PTE.READABLE;
    if (prot & PROT.WRITE) bits |= PTE.WRITABLE;
    if (prot & PROT.EXEC) bits |= PTE.EXECUTABLE;
    return bits;
  }

  /// Remember the file behind a mapping, with the base its addresses are relative to.
  noteImage(lo, hi, host, off) {
    // Segments of one image overlap, because a later segment is mapped over part of the range an
    // earlier one claimed. Both stay, and `imageOf` takes the nearest one below the address.
    this.images.push({ lo, hi, host, base: lo - (off & ~(PAGE - 1)) });
  }

  /// The image a guest address belongs to, if it belongs to one.
  imageOf(pc) {
    let best = null;
    for (const m of this.images) {
      if (pc >= m.lo && pc < m.hi && (!best || m.lo >= best.lo)) best = m;
    }
    return best;
  }

  forgetImages(lo, hi) {
    this.images = this.images.filter((m) => m.hi <= lo || m.lo >= hi);
  }

  /// Remember that a page holds translated code. A `mprotect` that makes such a page writable is a
  /// guest about to put new code there, and the translation of the old code has to go first.
  markTranslated(at) {
    this.ptes[pageOf(at)] |= PTE.TRANSLATED;
  }

  /// Forget that a page holds translated code, for when it no longer does.
  unmarkTranslated(at) {
    this.ptes[pageOf(at)] &= ~PTE.TRANSLATED;
  }

  /// Drop `[lo, hi)` from the free spans, keeping whatever lies outside it.
  subtract(lo, hi) {
    const out = [];
    for (const s of this.free) {
      if (s.hi <= lo || s.lo >= hi) {
        out.push(s);
        continue;
      }
      if (s.lo < lo) out.push({ lo: s.lo, hi: lo });
      if (s.hi > hi) out.push({ lo: hi, hi: s.hi });
    }
    return out;
  }

  setPtes(lo, hi, bits) {
    const first = pageOf(lo);
    const last = pageOf(roundUp(hi, PAGE));
    for (let p = first; p < last; p++) {
      if (bits & PTE.MAPPED && (this.ptes[p] & PTE.MAPPED) === 0) this.resident++;
      this.ptes[p] |= bits;
    }
    for (let p = first; p < last; ) {
      const chunk = Math.floor(p / (1 << 20));
      const stop = Math.min(last, (chunk + 1) << 20);
      if (stop - (chunk << 20) > this.mapped[chunk]) this.mapped[chunk] = stop - (chunk << 20);
      p = stop;
    }
  }

  clearPtes(lo, hi) {
    for (let p = pageOf(lo); p < pageOf(roundUp(hi, PAGE)); p++) {
      if (this.ptes[p] & PTE.MAPPED) this.resident--;
      this.ptes[p] = 0;
    }
  }

  /// Whether every byte of `[lo, hi)` is unmapped. A span never crosses from one memory into the
  /// next, so a range that does is a question about each memory's part of it.
  isFree(lo, hi) {
    for (let at = lo; at < hi; ) {
      const end = Math.min(hi, (Math.floor(at / CHUNK) + 1) * CHUNK);
      if (!this.free.some((s) => s.lo <= at && end <= s.hi)) return false;
      at = end;
    }
    return true;
  }

  /// Takes `[at, at + len)` out of the free list.
  take(at, len) {
    this.free = this.subtract(at, at + len);
    return at;
  }

  /// Take `len` bytes of the free list, at `addr` when it is fixed, else as low as it fits.
  reserve(len, addr, fixed) {
    if (addr !== 0 && fixed) {
      // MAP_FIXED puts the mapping where it says even when something else is already there, which
      // is how a loader maps each segment over the reservation it just made for the whole library.
      // The arena is the first chunk below the page table, and every chunk above it.
      const insideFirst = addr >= this.arenaLo && addr + len <= this.arenaHi;
      const aboveFirst = addr >= CHUNK && addr + len <= this.size;
      if (!insideFirst && !aboveFirst) return -ENOMEM;
      return this.take(addr, len);
    }
    // More than one memory can hold in one piece: only the chunks above the first have the room,
    // because the first ends in the page table and the stack, and a range is only free where every
    // chunk it crosses has its part of it free.
    if (len > CHUNK) return this.reserveSpanning(len, addr);
    let best = -1;
    for (let i = 0; i < this.free.length; i++) {
      const s = this.free[i];
      if (s.hi - s.lo < len) continue;
      // Honour the hint when it fits there, otherwise take the lowest span that fits.
      if (addr !== 0 && s.lo <= addr && addr + len <= s.hi) {
        best = i;
        break;
      }
      if (best < 0 || s.hi - s.lo < this.free[best].hi - this.free[best].lo) best = i;
    }
    if (best < 0) return -ENOMEM;
    const span = this.free[best];
    const at = addr !== 0 && span.lo <= addr && addr + len <= span.hi ? addr : span.lo;
    const rest = [];
    if (span.lo < at) rest.push({ lo: span.lo, hi: at });
    if (span.hi > at + len) rest.push({ lo: at + len, hi: span.hi });
    this.free.splice(best, 1, ...rest);
    return at;
  }

  /// A range larger than one memory: the lowest address the whole of it is free at, or the hint
  /// when the whole of it is free there. Nothing can cross out of the first chunk, so a range that
  /// big starts at the second one or above.
  reserveSpanning(len, hint) {
    if (hint !== 0 && hint >= CHUNK && hint + len <= this.size && this.isFree(hint, hint + len)) {
      return this.take(hint, len);
    }
    let best = -1;
    for (const span of this.free) {
      if (span.lo < CHUNK) continue;
      if (best >= 0 && span.lo >= best) continue;
      if (span.lo + len > this.size) continue;
      if (this.isFree(span.lo, span.lo + len)) best = span.lo;
    }
    if (best < 0) return -ENOMEM;
    return this.take(best, len);
  }

  /// mmap(2) with eager contents: a file-backed mapping reads its range in now rather than on fault.
  mmap({ addr = 0, len, prot = PROT.READ | PROT.WRITE, flags = 0, contents = null }) {
    len = roundUp(len, PAGE);
    if (len <= 0) return -EINVAL;
    const at = this.reserve(len, addr, flags & MAP.FIXED);
    if (at < 0) return at;
    this.clear(at, len);
    if (contents) this.copyIn(at, contents.subarray(0, Math.min(contents.length, len)));
    this.setPtes(at, at + len, this.protBits(prot));
    return at;
  }

  munmap(addr, len) {
    if (addr % PAGE !== 0) return -EINVAL;
    len = roundUp(len, PAGE);
    this.forgetImages(addr, addr + len);
    this.forget(addr, addr + len);
    this.clearPtes(addr, addr + len);
    // A span per memory: one that crossed a boundary would be a range a program could not start
    // inside, because a mapping is only free where each of its chunks is.
    for (let at = addr; at < addr + len; ) {
      const end = Math.min(addr + len, (Math.floor(at / CHUNK) + 1) * CHUNK);
      this.free.push({ lo: at, hi: end });
      at = end;
    }
    this.free.sort((a, b) => a.lo - b.lo);
    const merged = [];
    for (const s of this.free) {
      const last = merged[merged.length - 1];
      const sameChunk = last && Math.floor((s.hi - 1) / CHUNK) === Math.floor(last.lo / CHUNK);
      if (last && sameChunk && s.lo <= last.hi) last.hi = Math.max(last.hi, s.hi);
      else merged.push({ ...s });
    }
    this.free = merged;
    return 0;
  }

  /// mremap(2): a mapping that has to be bigger, and the bytes it already holds. A move is a new
  /// reservation with the old contents in it; in place is the same only when the range that would
  /// follow the old one is free, which is what `apt`'s cache grows into when it can.
  mremap(oldAddr, oldLen, newLen, flags, newAddr) {
    oldLen = roundUp(oldLen, PAGE);
    newLen = roundUp(newLen, PAGE);
    if (oldAddr % PAGE !== 0) return -EINVAL;
    if (newLen <= 0) return -EINVAL;
    const fixed = (flags & MREMAP.FIXED) !== 0;
    const mayMove = fixed || (flags & MREMAP.MAYMOVE) !== 0;
    if (newLen === oldLen && !fixed) return oldAddr;
    // Growing where it stands: everything from the end of the old range has to be nobody's.
    if (!fixed && newLen > oldLen) {
      if (this.isFree(oldAddr + oldLen, oldAddr + newLen)) {
        this.take(oldAddr + oldLen, newLen - oldLen);
        this.clear(oldAddr + oldLen, newLen - oldLen);
        this.setPtes(oldAddr + oldLen, oldAddr + newLen, this.ptes[pageOf(oldAddr)] & ~PTE.TRANSLATED);
        return oldAddr;
      }
    }
    if (!mayMove) return -ENOMEM;
    const at = this.reserve(newLen, fixed ? newAddr : 0, fixed);
    if (at < 0) return at;
    const keep = Math.min(oldLen, newLen);
    const moved = this.copyOut(oldAddr, keep);
    this.clear(at, newLen);
    this.copyIn(at, moved);
    this.setPtes(at, at + newLen, this.ptes[pageOf(oldAddr)] & ~PTE.TRANSLATED);
    this.munmap(oldAddr, oldLen);
    return at;
  }

  mprotect(addr, len, prot) {
    if (addr % PAGE !== 0) return -EINVAL;
    len = roundUp(len, PAGE);
    for (let p = pageOf(addr); p < pageOf(addr + len); p++) {
      if (!(this.ptes[p] & PTE.MAPPED)) return -ENOMEM;
    }
    // A page that was executable and is asked to be writable is a guest that means to change its
    // own code, which is the one thing a translation cannot survive: drop it and translate again
    // when the page is next run.
    let writable = false;
    for (let p = pageOf(addr); p < pageOf(addr + len); p++) {
      if (this.ptes[p] & PTE.TRANSLATED) writable = true;
    }
    if (writable && prot & PROT.WRITE) this.forget(addr, addr + len);
    for (let p = pageOf(addr); p < pageOf(addr + len); p++) {
      this.ptes[p] = this.protBits(prot);
    }
    return 0;
  }

  /// madvise(2). The advices a kernel acts on are the ones that give a page back, and what the page
  /// reads as afterwards is what a fresh mapping of the same thing holds: zeros for anonymous
  /// memory, the file for a page of one. The rest are hints, with nothing here to hint at.
  madvise(addr, len, advice) {
    if (!DROP.has(advice)) return 0;
    if (len < 0 || addr % PAGE !== 0) return -EINVAL;
    const hi = Math.min(addr + roundUp(len, PAGE), this.size);
    for (let p = pageOf(addr); p < pageOf(hi); p++) {
      // A page that is not writable is code or a read-only mapping of a file: a program cannot
      // have changed it, so there is nothing to give back.
      if ((this.ptes[p] & (PTE.MAPPED | PTE.WRITABLE)) !== (PTE.MAPPED | PTE.WRITABLE)) continue;
      const at = p * PAGE;
      const back = this.imageBytes(this.imageOf(at), at);
      if (back) this.bytes(at, PAGE).set(back);
      else this.bytes(at, PAGE).fill(0);
      // Giving a page back that held translated code changes what is there, which is the same
      // reason a `mprotect` that makes a page writable drops it.
      if (this.ptes[p] & PTE.TRANSLATED) {
        this.ptes[p] &= ~PTE.TRANSLATED;
        this.forget(at, at + PAGE);
      }
    }
    return 0;
  }

  /// The file's own bytes for a page of an image, which is what a page given back and faulted again
  /// shows. A page past the end of the file, or one whose file is gone, reads as zeros either way.
  imageBytes(image, at) {
    if (!image || !image.host) return null;
    const off = at - image.base;
    if (off < 0) return null;
    try {
      const fd = fs.openSync(image.host, "r");
      try {
        const buf = Buffer.alloc(PAGE);
        fs.readSync(fd, buf, 0, PAGE, off);
        return buf;
      } finally {
        fs.closeSync(fd);
      }
    } catch {
      return null;
    }
  }

  /// What `sysinfo` can say about this machine's memory: the ranges a program may still grow into,
  /// which are the heap up to its limit and the arena `mmap` fills, and how much of them is free.
  /// Not `memory`: that name is the wasm memory this space is the map of.
  capacity() {
    let free = Math.max(0, this.brkLimit - this.brk);
    for (const s of this.free) free += s.hi - s.lo;
    return { total: this.total, free };
  }

  /// brk(2): the break is a byte address, not a page address, and moving it maps or unmaps pages.
  setBrk(want) {
    if (want === 0) return this.brk;
    if (want < this.brkBase || want > this.brkLimit) return this.brk;
    const old = this.brk;
    if (want > old) {
      this.clear(old, want - old);
      this.setPtes(old, want, PTE.MAPPED | PTE.READABLE | PTE.WRITABLE);
    }
    else if (want < old) this.clearPtes(want, old);
    this.brk = want;
    return want;
  }
}
