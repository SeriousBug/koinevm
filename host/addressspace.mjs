// The guest's address space, from the kernel's side.
//
// The map is real: one byte per 4 KiB page in the guest's own linear memory (the translator puts the
// page table there), and this class is what maintains it when the guest asks for memory. Guest
// virtual addresses are linear-memory offsets, so mapping a range is bookkeeping plus the bytes the
// range starts with.

export const PAGE = 4096;

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

export const EINVAL = 22;
export const ENOMEM = 12;
export const EFAULT = 14;

const roundUp = (x, a) => (x + a - 1) & ~(a - 1);

export class AddressSpace {
  constructor(memory, map) {
    this.memory = memory;
    this.pteBase = map.pte_base;
    this.brkBase = map.heap_base;
    this.brkLimit = map.heap_limit;
    this.brk = map.heap_base;
    this.arenaLo = map.mmap_base;
    this.arenaHi = map.stack_floor;
    // Everything from mmap_base to the stack is available for mmap. Freed ranges go back here.
    this.free = [{ lo: map.mmap_base, hi: map.stack_floor }];
    this.ptes = new Uint8Array(memory.buffer, this.pteBase, 1 << 20);
    // Which file each mapping came from. A jump into one of these is a page this machine has not
    // translated yet, and the file is what it has to translate it from.
    this.images = [];
    /// Called with a range whose bytes or permissions changed, so a translation made from what was
    /// there before is dropped. The host sets it; nothing here knows what a translation is.
    this.forget = () => {};
  }

  bytes(addr, len) {
    return new Uint8Array(this.memory.buffer, Number(addr), len);
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
    for (let p = lo >> 12; p < roundUp(hi, PAGE) >> 12; p++) this.ptes[p] |= bits;
  }

  clearPtes(lo, hi) {
    for (let p = lo >> 12; p < roundUp(hi, PAGE) >> 12; p++) this.ptes[p] = 0;
  }

  /// Take `len` bytes of the free list, at `addr` when it is fixed, else as low as it fits.
  reserve(len, addr, fixed) {
    if (addr !== 0 && fixed) {
      // MAP_FIXED puts the mapping where it says even when something else is already there, which
      // is how a loader maps each segment over the reservation it just made for the whole library.
      if (addr < this.arenaLo || addr + len > this.arenaHi) return -ENOMEM;
      this.free = this.subtract(addr, addr + len);
      return addr;
    }
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

  /// mmap(2) with eager contents: a file-backed mapping reads its range in now rather than on fault.
  mmap({ addr = 0, len, prot = PROT.READ | PROT.WRITE, flags = 0, contents = null }) {
    len = roundUp(len, PAGE);
    if (len <= 0) return -EINVAL;
    const at = this.reserve(len, addr, flags & MAP.FIXED);
    if (at < 0) return at;
    const view = this.bytes(at, len);
    view.fill(0);
    if (contents) view.set(contents.subarray(0, Math.min(contents.length, len)));
    this.setPtes(at, at + len, this.protBits(prot));
    return at;
  }

  munmap(addr, len) {
    if (addr % PAGE !== 0) return -EINVAL;
    len = roundUp(len, PAGE);
    this.forgetImages(addr, addr + len);
    this.forget(addr, addr + len);
    this.clearPtes(addr, addr + len);
    this.free.push({ lo: addr, hi: addr + len });
    this.free.sort((a, b) => a.lo - b.lo);
    const merged = [];
    for (const s of this.free) {
      const last = merged[merged.length - 1];
      if (last && s.lo <= last.hi) last.hi = Math.max(last.hi, s.hi);
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
    // Growing where it stands: the pages just past the old range have to be nobody's.
    if (!fixed && newLen > oldLen) {
      const tail = this.free.find((s) => s.lo === oldAddr + oldLen);
      if (tail && tail.lo + (newLen - oldLen) <= tail.hi) {
        this.reserve(newLen - oldLen, oldAddr + oldLen, true);
        this.bytes(oldAddr + oldLen, newLen - oldLen).fill(0);
        this.setPtes(oldAddr + oldLen, oldAddr + newLen, this.ptes[oldAddr >> 12] & ~PTE.TRANSLATED);
        return oldAddr;
      }
    }
    if (!mayMove) return -ENOMEM;
    const at = this.reserve(newLen, fixed ? newAddr : 0, fixed);
    if (at < 0) return at;
    const keep = Math.min(oldLen, newLen);
    const view = this.bytes(at, newLen);
    view.fill(0);
    view.set(this.bytes(oldAddr, keep));
    this.setPtes(at, at + newLen, this.ptes[oldAddr >> 12] & ~PTE.TRANSLATED);
    this.munmap(oldAddr, oldLen);
    return at;
  }

  mprotect(addr, len, prot) {
    if (addr % PAGE !== 0) return -EINVAL;
    len = roundUp(len, PAGE);
    for (let p = addr >> 12; p < (addr + len) >> 12; p++) {
      if (!(this.ptes[p] & PTE.MAPPED)) return -ENOMEM;
    }
    // A page that was executable and is asked to be writable is a guest that means to change its
    // own code, which is the one thing a translation cannot survive: drop it and translate again
    // when the page is next run.
    let writable = false;
    for (let p = addr >> 12; p < (addr + len) >> 12; p++) {
      if (this.ptes[p] & PTE.TRANSLATED) writable = true;
    }
    if (writable && prot & PROT.WRITE) this.forget(addr, addr + len);
    for (let p = addr >> 12; p < (addr + len) >> 12; p++) {
      this.ptes[p] = this.protBits(prot);
    }
    return 0;
  }

  /// brk(2): the break is a byte address, not a page address, and moving it maps or unmaps pages.
  setBrk(want) {
    if (want === 0) return this.brk;
    if (want < this.brkBase || want > this.brkLimit) return this.brk;
    const old = this.brk;
    if (want > old) this.setPtes(old, want, PTE.MAPPED | PTE.READABLE | PTE.WRITABLE);
    else if (want < old) this.clearPtes(want, old);
    this.brk = want;
    return want;
  }
}
