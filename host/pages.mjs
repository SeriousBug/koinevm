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

/// Distinguishes the module files of one host from another's, since they share a temporary folder.
let imageSerial = 0;

const SHADOW_PC = 0x108;
const TABLE_SLOT = 8;

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
    return this.ask(`page ${image} ${base.toString(16)} ${at.toString(16)}${tail}`);
  }

  /// A whole image, which is what `execve` needs: the program, its loader, and the stack built for
  /// the arguments it was given. The module comes back in a file rather than in the answer, because
  /// a program the size of `cc1` translates to more wasm than a line of hex can carry.
  async image(path, argv, envp) {
    const hex = (bytes) => (bytes.length ? Buffer.from(bytes).toString("hex") : "-");
    const args = [...argv.map(hex), String(envp.length), ...envp.map(hex)].join(" ");
    const out = join(tmpdir(), `armjit-image-${process.pid}-${(imageSerial += 1)}.wasm`);
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
    /// they hold, so the next translation of one is taken from memory instead.
    this.patched = new Set();
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
    const inst = new WebAssembly.Instance(source.module, {
      env: { ...this.imports, mem: this.memory },
    });
    for (let i = 0; i < source.regions.length; i++) {
      this.table.set(base + i, inst.exports[`r${i}`]);
    }
    this.pageInstances.set(key, { source, instance: inst });
    return inst;
  }

  /// Where a pc's entry is, or the empty slot it would take: open addressing with linear probing,
  /// the same probe the translator uses to build the table. The probe is bounded by the table, so a
  /// table with no room left reports itself instead of searching for an empty slot forever.
  probe(pc) {
    const key = pc >>> 2;
    const want = key + 1;
    const mask = this.meta.table_mask >>> 0;
    let at = (key & mask) >>> 0;
    for (let n = 0; n <= mask; n++) {
      const addr = this.meta.table_base + at * TABLE_SLOT;
      const tag = this.view.getUint32(addr + 4, true);
      if (tag === want || tag === 0) return { addr, tag, want };
      at = (at + 1) & mask;
    }
    throw new Error(`no room in the dispatch table for 0x${pc.toString(16)}`);
  }

  /// What the dispatch table says about a pc, for checking an insert against the answer.
  lookup(pc) {
    const { addr, tag, want } = this.probe(pc);
    return tag === want ? this.view.getUint32(addr, true) : 0;
  }

  dispatch(pc, slot, block) {
    const { addr, tag, want } = this.probe(pc);
    if (tag === want) return; // another page already claimed this address
    this.view.setUint32(addr, ((slot + 1) | (block << 16)) >>> 0, true);
    this.view.setUint32(addr + 4, want, true);
    if (process.env.ARMJIT_DISPATCH_PC && pc === Number(process.env.ARMJIT_DISPATCH_PC)) {
      console.error(`dispatch 0x${pc.toString(16)} -> slot 0x${slot.toString(16)} block ${block}`);
    }
  }

  /// Drop the translation of a block, so the next jump to it goes through the translator again.
  clearDispatch(pc) {
    const { addr, tag, want } = this.probe(pc);
    if (tag !== want) return;
    this.view.setUint32(addr, 0, true);
    this.view.setUint32(addr + 4, 0, true);
  }

  /// Forget every page whose code lies in `[lo, hi)`: the guest changed what is there, so the
  /// module that was translated from it is a translation of bytes that no longer exist. The slots
  /// stay in use - a fork's parent may still be running them - and the next translation of the page
  /// takes a range of its own.
  forgetRange(lo, hi) {
    // Every entry the page could have claimed, since the table is keyed by pc and a block can start
    // anywhere in it: the probe is what says whether that pc was a block start at all.
    for (let page = lo & ~0xfff; page < hi; page += 0x1000) {
      this.patched.add(page);
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
    return tag === want;
  }

  growTo(want) {
    if (want <= this.table.length) return;
    this.table.grow(want - this.table.length);
  }

  async translateAndResume(pc) {
    const T = [performance.now()];
    const image = this.kernel.space.imageOf(pc);
    if (!image) throw new Error(`nothing to translate 0x${pc.toString(16)} from`);

    const key = `${image.host}:${image.base}:${pc}`;
    T.push(performance.now());
    // A page the guest wrote to is translated from what it holds now: the file says what the loader
    // put there, and a guest that patches its own code has moved past that.
    const from = pc & ~0xfff;
    const patched = this.patched.has(from);
    let page = patched ? null : pageModules.get(key);
    if (!page) {
      const bytes = patched
        ? Buffer.from(new Uint8Array(this.memory.buffer, from, 0x1000)).toString("hex")
        : null;
      const answer = await this.translator.page(image.host, image.base, pc, bytes);
      if (!answer.ok) throw new Error(`translating 0x${pc.toString(16)}: ${answer.error}`);
      let module;
      try {
        module = new WebAssembly.Module(Buffer.from(answer.wasm, "hex"));
      } catch (e) {
        const where = `${image.host.split("/").pop()}+0x${(pc - image.base).toString(16)}`;
        throw new Error(`the page at ${where} does not validate: ${e.message}`);
      }
      page = { module, regions: answer.regions, unsupported: answer.unsupported };
      if (!patched) pageModules.set(key, page);
      // A refusal costs an instruction, so a guest that meets one traps there and the run stops.
      // What the log is for is knowing which are met at all: `ARMJIT_LOG_GAPS=1` leaves the pages
      // out and prints the refusals alone.
      if (page.unsupported.length && process.env.ARMJIT_LOG_GAPS && !process.env.ARMJIT_TRACE_PAGES) {
        for (const [at, word, why] of page.unsupported) {
          const file = image.host.split("/").pop();
          console.error(`gap at ${file}+0x${at.toString(16)} (${word}): ${why}`);
        }
      }
      if (process.env.ARMJIT_TRACE_PAGES) {
        const where = `${image.host.split("/").pop()}+0x${(pc - image.base).toString(16)}`;
        console.error(
          `page ${where}: ${page.regions.length} regions, ${answer.wasm.length / 2} bytes wasm` +
            (page.unsupported.length ? `, ${page.unsupported.length} gaps` : ""),
        );
        for (const [at, word, why] of page.unsupported) {
          const file = image.host.split("/").pop();
          console.error(`  gap at ${file}+0x${at.toString(16)} (${word}): ${why}`);
        }
        if (process.env.ARMJIT_TRACE_REGIONS) {
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
      // The dispatch entry packs the region slot and the block index into 16 bits each, so a run
      // that translates enough pages to need more than 65535 slots corrupts every later entry.
      if (base + page.regions.length > 0xffff) {
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
    const out = this.instance.exports.run(0, 0n, 1);
    T.push(performance.now());
    if (process.env.ARMJIT_TRACE_PAGES)
      console.error(`  phases ${T.slice(1).map((t, i) => (t - T[i]).toFixed(1)).join(" ")} status ${out}`);
    return out;
  }
}
