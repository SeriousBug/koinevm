// Translation on demand, host side.
//
// The translator emits the program, and then only the code that runs. A jump into a library page
// nothing has translated stops the run loop with the pc in the shadow; this asks the translator for
// that page, puts the module's regions in the running image's table, records where each block starts
// in its dispatch table, and resumes the same run.

import { spawn } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PTE } from "./addressspace.mjs";

/// Distinguishes the module files of one host from another's, since they share a temporary folder.
let imageSerial = 0;

const SHADOW_PC = 0x108;
/// One helper per access shape, which the image exports and a page module imports: `N_ACCESS` in
/// src/emit.rs.
const ACCESS_HELPERS = 23;
const TABLE_SLOT = 16;
/// Bits of a dispatch word's payload the block index takes, and therefore the bits a region slot has
/// above it: `BLOCK_BITS` in src/emit.rs.
const BLOCK_BITS = 12;
const SLOT_MAX = (1 << (32 - BLOCK_BITS)) - 1;

/// The pages translated for one image generation, as modules: the same image at the same base
/// always translates to the same bytes, and a fork or a second run must not pay for it again.
const pageModules = new Map();

/// What a fork shares with its parent: the region slots of the dispatch table, which are baked
/// into the guest's memory and therefore into the copy the child starts from, and the page module
/// each one came from. An exec starts a new lineage, because its dispatch table starts over.
export class Lineage {
  constructor(initialSlots) {
    this.slots = initialSlots;
    this.slotOf = new Map();
  }
}

/// The translator, kept alive: a page costs one request, and the process is not restarted for it.
export class Translator {
  constructor(bin) {
    this.child = spawn(bin, ["page"], { stdio: ["pipe", "pipe", "inherit"] });
    this.pending = [];
    this.buffer = "";
    this.dead = null;
    this.child.stdout.setEncoding("utf8");
    this.child.stdout.on("data", (chunk) => {
      this.buffer += chunk;
      let nl;
      while ((nl = this.buffer.indexOf("\n")) >= 0) {
        const line = this.buffer.slice(0, nl);
        this.buffer = this.buffer.slice(nl + 1);
        const resolve = this.pending.shift();
        if (resolve) resolve(JSON.parse(line));
      }
    });
    this.child.on("exit", (code) => {
      this.dead = code;
      for (const resolve of this.pending.splice(0)) resolve({ ok: false, error: `translator exited ${code}` });
    });
  }

  ask(request) {
    if (this.dead !== null) return Promise.resolve({ ok: false, error: "translator is gone" });
    return new Promise((resolve) => {
      this.pending.push(resolve);
      this.child.stdin.write(request + "\n");
    });
  }

  configure({ bounds, trace, traceLoops, memPages, rootfs }) {
    const root = rootfs ? rootfs : "-";
    return this.ask(
      `cfg bounds=${bounds ? "check" : "trust"} trace=${trace ? 1 : 0} trace-loops=${traceLoops ? 1 : 0}` +
        ` mem-pages=${memPages} rootfs=${root}`,
    );
  }

  page(image, base, at, bytes = null) {
    const tail = bytes ? ` ${bytes}` : "";
    // No image is a page the guest generated: the bytes it holds are the whole of what there is.
    const from = image || "-";
    const where = image ? base.toString(16) : "0";
    return this.ask(`page ${from} ${where} ${at.toString(16)}${tail}`);
  }

  /// A whole image, which is what `execve` needs: the program, its loader, and the stack built for
  /// the arguments it was given. The module comes back in a file rather than in the answer, because
  /// a program the size of `cc1` translates to more wasm than a line of hex can carry.
  async image(path, argv, envp) {
    const hex = (bytes) => (bytes.length ? Buffer.from(bytes).toString("hex") : "-");
    const args = [...argv.map(hex), String(envp.length), ...envp.map(hex)].join(" ");
    const out = join(tmpdir(), `koinevm-image-${process.pid}-${(imageSerial += 1)}.wasm`);
    const answer = await this.ask(`image ${path} ${out} ${argv.length} ${args}`);
    if (!answer.ok) return answer;
    try {
      answer.wasm = readFileSync(out);
    } finally {
      rmSync(out, { force: true });
    }
    return answer;
  }

  stop() {
    this.child.stdin.end();
  }
}

/// One guest run: the module, the table its code lives in, and the dispatch table behind it.
export class Mach {
  constructor({ instance, memory, meta, kernel, translator, imports }) {
    // A dispatch word is packed by a convention the translator and this host both hold, and a module
    // from a build that held a different one misreads every entry it holds: a cached module from an
    // older build is stale, and saying so is better than running it.
    if (meta.block_bits !== BLOCK_BITS) {
      throw new Error(
        `the module was translated with ${meta.block_bits} block bits in a dispatch word, this host ` +
          `reads ${BLOCK_BITS}: it is from another build, and has to be translated again`,
      );
    }
    this.instance = instance;
    this.memory = memory;
    this.meta = meta;
    this.kernel = kernel;
    this.translator = translator;
    this.imports = imports;
    this.table = instance.exports.tbl;
    this.lineage = new Lineage(this.table.length);
    this.pageInstances = new Map();
    /// Pages the guest has written to since they were translated: the file no longer says what
    /// they hold, so the next translation of one is taken from memory instead. Held as merged
    /// ranges, because the ranges a program names are its whole arenas: a munmap of a 4 GiB heap
    /// would otherwise put a million pages in a set.
    this.patched = [];
    /// The image pages that hold a block, from the translation: the dispatch words of those pages
    /// are the translator's, so forgetting one means clearing the slots it wrote.
    this.imagePages = meta.pages ?? [];
    this.view = new DataView(memory.buffer);
  }

  /// The table a fork's child needs: the same slots holding regions that write to its own memory.
  adopt(lineage, parent) {
    this.lineage = lineage;
    this.growTo(lineage.slots);
    for (const [key, page] of parent.pageInstances) {
      this.instantiate(key, page.source, lineage.slotOf.get(key));
    }
  }

  instantiate(key, source, base) {
    // The page module imports the same memories the image got: the engine's state in the first and
    // a chunk of the guest's address space in each of the rest. It also imports the image's chunk
    // helpers, which is why it carries none of its own: an arm per chunk in each of twenty-three
    // functions is most of a page module's bytes at a big address space, and it is dead code in
    // every page whose code stays below the first memory.
    const env = { ...this.imports, mem: this.kernel.space.memories[0] };
    this.kernel.space.memories.forEach((memory, k) => {
      if (k > 0) env[`g${k}`] = memory;
    });
    if (this.kernel.space.chunks > 1) {
      for (let i = 0; i < ACCESS_HELPERS; i++) {
        const helper = this.instance.exports[`chunk${i}`];
        if (!helper) throw new Error(`the image exports no chunk${i} helper for a page module`);
        env[`chunk${i}`] = helper;
      }
    }
    const inst = new WebAssembly.Instance(source.module, { env });
    for (let i = 0; i < source.regions.length; i++) {
      this.table.set(base + i, inst.exports[`r${i}`]);
    }
    this.pageInstances.set(key, { source, instance: inst });
    return inst;
  }

  /// Where a pc's entry is, or the empty slot it would take: open addressing with linear probing,
  /// the same probe the translator uses to build the table. The probe is bounded by the table, so a
  /// table with no room left reports itself instead of searching for an empty slot forever.
  ///
  /// A slot's tag is the whole key, and a key is `pc >> 2` for a pc that may be above 4 GiB: the
  /// arithmetic is a division and a modulo rather than a shift and a mask, because the bitwise
  /// operators of this host are 32-bit and would fold two pcs 4 GiB apart into one slot.
  probe(pc) {
    const key = Math.floor(pc / 4);
    const want = key + 1;
    const slots = (this.meta.table_mask >>> 0) + 1;
    let at = key % slots;
    for (let n = 0; n < slots; n++) {
      const addr = this.meta.table_base + at * TABLE_SLOT;
      const tag = this.view.getBigUint64(addr + 8, true);
      if (tag === BigInt(want) || tag === 0n) return { addr, tag, want };
      at = (at + 1) % slots;
    }
    throw new Error(`no room in the dispatch table for 0x${pc.toString(16)}`);
  }

  /// What the dispatch table says about a pc, for checking an insert against the answer.
  lookup(pc) {
    const { addr, tag, want } = this.probe(pc);
    return tag === BigInt(want) ? this.view.getUint32(addr, true) : 0;
  }

  dispatch(pc, slot, block) {
    const { addr, tag, want } = this.probe(pc);
    if (tag === BigInt(want)) return; // another page already claimed this address
    this.view.setUint32(addr, (((slot + 1) << BLOCK_BITS) | block) >>> 0, true);
    this.view.setBigUint64(addr + 8, BigInt(want), true);
    if (process.env.KOINEVM_DISPATCH_PC && pc === Number(process.env.KOINEVM_DISPATCH_PC)) {
      console.error(`dispatch 0x${pc.toString(16)} -> slot 0x${slot.toString(16)} block ${block}`);
    }
  }

  /// Drop the translation of a block, so the next jump to it goes through the translator again.
  clearDispatch(pc) {
    const { addr, tag, want } = this.probe(pc);
    if (tag !== BigInt(want)) return;
    this.view.setUint32(addr, 0, true);
    this.view.setBigUint64(addr + 8, 0n, true);
  }

  /// Whether the guest has written to the page at `at` since it was translated.
  isPatched(at) {
    let lo = 0;
    let hi = this.patched.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const span = this.patched[mid];
      if (at < span.lo) hi = mid - 1;
      else if (at >= span.hi) lo = mid + 1;
      else return true;
    }
    return false;
  }

  /// Mark every page in `[lo, hi)` as holding what the guest put there rather than what the file
  /// did, as one merged range: the ranges a program names are its arenas.
  markPatched(lo, hi) {
    const out = [];
    let start = lo;
    let end = hi;
    let placed = false;
    for (const span of this.patched) {
      if (span.hi < lo) {
        out.push(span);
        continue;
      }
      if (span.lo > end) {
        if (!placed) {
          out.push({ lo: start, hi: end });
          placed = true;
        }
        out.push(span);
        continue;
      }
      start = Math.min(start, span.lo);
      end = Math.max(end, span.hi);
    }
    if (!placed) out.push({ lo: start, hi: end });
    this.patched = out;
  }

  /// Without a dispatch word of its own, the first four-byte pc at or after `at`.
  firstImagePage(at) {
    let lo = 0;
    let hi = this.imagePages.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (this.imagePages[mid] < at) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }

  /// Forget every page whose code lies in `[lo, hi)`: the guest changed what is there, so the
  /// module that was translated from it is a translation of bytes that no longer exist. The slots
  /// stay in use - a fork's parent may still be running them - and the next translation of the page
  /// takes a range of its own.
  forgetRange(lo, hi) {
    // A range can be a program's whole arena, four gigabytes of it, so the pages are marked as one
    // span and the words cleared are the ones a page is known to own: the image's, which the
    // translator listed, and the ones this host dispatched. Walking every four-byte slot the range
    // covers would be a billion probes to find the handful of blocks that were in it.
    this.markPatched(lo, hi);
    const space = this.kernel.space;
    for (let p = Math.floor(lo / 0x1000); p < Math.ceil(hi / 0x1000); p++) {
      space.ptes[p] &= ~PTE.TRANSLATED;
    }
    for (let i = this.firstImagePage(lo); i < this.imagePages.length && this.imagePages[i] < hi; i++) {
      const page = this.imagePages[i];
      for (let pc = page; pc < page + 0x1000; pc += 4) this.clearDispatch(pc);
    }
    for (const key of [...this.lineage.slotOf.keys()]) {
      const at = key.lastIndexOf(":");
      const pc = Number(key.slice(at + 1));
      if (!(pc >= lo && pc < hi)) continue;
      const page = this.pageInstances.get(key);
      if (page) {
        for (const region of page.source.regions) {
          for (const block of region.blocks) this.clearDispatch(block);
        }
        this.pageInstances.delete(key);
      }
      this.lineage.slotOf.delete(key);
      pageModules.delete(key);
    }
  }

  hasDispatch(pc) {
    const { tag, want } = this.probe(pc);
    return tag === BigInt(want);
  }

  growTo(want) {
    if (want <= this.table.length) return;
    this.table.grow(want - this.table.length);
  }

  async translateAndResume(pc) {
    const T = [performance.now()];
    const image = this.kernel.space.imageOf(pc);
    const imageBase = image ? image.base : 0;
    const host = image ? image.host : "-";
    const where = (at) =>
      `${image ? host.split("/").pop() : "generated code"}+0x${(at - imageBase).toString(16)}`;

    const key = `${host}:${imageBase}:${pc}`;
    T.push(performance.now());
    // A page the guest wrote to is translated from what it holds now: the file says what the loader
    // put there, and a guest that patches its own code has moved past that. A page with no file
    // behind it is code the guest generated, so every translation of it comes from memory.
    const from = Math.floor(pc / 0x1000) * 0x1000;
    const patched = !image || this.isPatched(from);
    let page = patched ? null : pageModules.get(key);
    if (!page) {
      const bytes = patched
        ? Buffer.from(this.kernel.space.bytes(from, 0x1000)).toString("hex")
        : null;
      const answer = await this.translator.page(image ? image.host : null, imageBase, pc, bytes);
      if (!answer.ok) throw new Error(`translating 0x${pc.toString(16)}: ${answer.error}`);
      let module;
      try {
        module = new WebAssembly.Module(Buffer.from(answer.wasm, "hex"));
      } catch (e) {
        throw new Error(`the page at ${where(pc)} does not validate: ${e.message}`);
      }
      page = { module, regions: answer.regions, unsupported: answer.unsupported };
      if (!patched) pageModules.set(key, page);
      // A refusal costs an instruction, so a guest that meets one traps there and the run stops.
      // What the log is for is knowing which are met at all: `KOINEVM_LOG_GAPS=1` leaves the pages
      // out and prints the refusals alone.
      if (page.unsupported.length && process.env.KOINEVM_LOG_GAPS && !process.env.KOINEVM_TRACE_PAGES) {
        for (const [at, word, why] of page.unsupported) {
          console.error(`gap at ${where(at)} (${word}): ${why}`);
        }
      }
      if (process.env.KOINEVM_TRACE_PAGES) {
        console.error(
          `page ${where(pc)}: ${page.regions.length} regions, ${answer.wasm.length / 2} bytes wasm` +
            (page.unsupported.length ? `, ${page.unsupported.length} gaps` : ""),
        );
        for (const [at, word, why] of page.unsupported) {
          console.error(`  gap at ${where(at)} (${word}): ${why}`);
        }
        if (process.env.KOINEVM_TRACE_REGIONS) {
          for (const region of page.regions) {
            const blocks = region.blocks.map((b) => b.toString(16)).join(" ");
            console.error(`  region 0x${region.entry.toString(16)}: ${blocks}`);
          }
        }
      }
    }

    T.push(performance.now());
    // The slot a page's regions take is a property of the lineage, not of this run: the fork's
    // memory holds dispatch words that name them.
    let base = this.lineage.slotOf.get(key);
    if (base === undefined) {
      base = this.lineage.slots;
      // A dispatch word holds the region slot above the block index, so a run that needs more slots
      // than those bits hold would corrupt every entry it writes.
      if (base + page.regions.length > SLOT_MAX) {
        throw new Error(
          `region slots exhausted: ${base} in use, ${page.regions.length} more for 0x${pc.toString(16)}`,
        );
      }
      this.lineage.slots += page.regions.length;
      this.lineage.slotOf.set(key, base);
    }
    if (!this.pageInstances.has(key)) {
      this.growTo(this.lineage.slots);
      this.instantiate(key, page, base);
    }
    // The page holds translated code now, so a `mprotect` that makes it writable is a guest about
    // to write new code there and the translation of what it held before has to go.
    this.kernel.space.markTranslated(from);

    for (let i = 0; i < page.regions.length; i++) {
      const region = page.regions[i];
      for (let b = 0; b < region.blocks.length; b++) {
        this.dispatch(region.blocks[b], base + i, b);
      }
    }
    T.push(performance.now());
    if (!this.hasDispatch(pc)) {
      throw new Error(`translated 0x${pc.toString(16)} but no block starts there`);
    }
    const out = this.kernel.usage.run(() => this.instance.exports.run(0n, 0n, 1));
    T.push(performance.now());
    if (process.env.KOINEVM_TRACE_PAGES)
      console.error(`  phases ${T.slice(1).map((t, i) => (t - T[i]).toFixed(1)).join(" ")} status ${out}`);
    return out;
  }
}
