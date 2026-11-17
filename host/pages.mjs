// Translation on demand, host side.
//
// The translator emits the program, and then only the code that runs. A jump into a library page
// nothing has translated stops the run loop with the pc in the shadow; this asks the translator for
// that page, puts the module's regions in the running image's table, records where each block starts
// in its dispatch table, and resumes the same run.

import { spawn } from "node:child_process";

const SHADOW_PC = 0x108;
const TABLE_SLOT = 8;

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

  configure({ bounds, trace, memPages }) {
    return this.ask(`cfg bounds=${bounds ? "check" : "trust"} trace=${trace ? 1 : 0} mem-pages=${memPages}`);
  }

  page(image, base, at) {
    return this.ask(`page ${image} ${base.toString(16)} ${at.toString(16)}`);
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
    this.slots = this.table.length;
    this.pages = new Map();
    this.view = new DataView(memory.buffer);
  }

  /// What the dispatch table says about a pc, for checking an insert against the answer.
  lookup(pc) {
    const key = pc >>> 2;
    const want = key + 1;
    const mask = this.meta.table_mask >>> 0;
    let at = (key & mask) >>> 0;
    for (;;) {
      const addr = this.meta.table_base + at * TABLE_SLOT;
      const tag = this.view.getUint32(addr + 4, true);
      if (tag === want) return this.view.getUint32(addr, true);
      if (tag === 0) return 0;
      at = (at + 1) & mask;
    }
  }

  /// Open-addressing insert, the same probe the translator uses to build the table.
  dispatch(pc, slot, block) {
    const key = pc >>> 2;
    const want = key + 1;
    const mask = this.meta.table_mask >>> 0;
    let at = (key & mask) >>> 0;
    for (;;) {
      const addr = this.meta.table_base + at * TABLE_SLOT;
      const tag = this.view.getUint32(addr + 4, true);
      if (tag === want) return; // another page already claimed this address
      if (tag === 0) {
        this.view.setUint32(addr, ((slot + 1) | (block << 16)) >>> 0, true);
        this.view.setUint32(addr + 4, want, true);
        if (process.env.ARMJIT_DISPATCH_PC && pc === Number(process.env.ARMJIT_DISPATCH_PC)) {
          console.error(`dispatch 0x${pc.toString(16)} -> slot 0x${slot.toString(16)} block ${block}`);
        }
        return;
      }
      at = (at + 1) & mask;
    }
  }

  hasDispatch(pc) {
    const key = pc >>> 2;
    const want = key + 1;
    const mask = this.meta.table_mask >>> 0;
    let at = (key & mask) >>> 0;
    for (;;) {
      const tag = this.view.getUint32(this.meta.table_base + at * TABLE_SLOT + 4, true);
      if (tag === want) return true;
      if (tag === 0) return false;
      at = (at + 1) & mask;
    }
  }

  growTo(want) {
    if (want <= this.table.length) return;
    this.table.grow(want - this.table.length);
  }

  async translateAndResume(pc) {
    const image = this.kernel.space.imageOf(pc);
    if (!image) throw new Error(`nothing to translate 0x${pc.toString(16)} from`);

    const key = `${image.host}:${image.base}:${pc}`;
    let page = this.pages.get(key);
    if (!page) {
      const answer = await this.translator.page(image.host, image.base, pc);
      if (!answer.ok) throw new Error(`translating 0x${pc.toString(16)}: ${answer.error}`);
      page = answer;
      this.pages.set(key, page);
      if (process.env.ARMJIT_TRACE_PAGES) {
        const where = `${image.host.split("/").pop()}+0x${(pc - image.base).toString(16)}`;
        console.error(
          `page ${where}: ${page.regions.length} regions, ${page.wasm.length / 2} bytes wasm` +
            (page.unsupported.length ? `, ${page.unsupported.length} gaps` : ""),
        );
        for (const [at, why] of page.unsupported) console.error(`  gap at 0x${at.toString(16)}: ${why}`);
        if (process.env.ARMJIT_TRACE_REGIONS) {
          for (const region of page.regions) {
            const blocks = region.blocks.map((b) => b.toString(16)).join(" ");
            console.error(`  region 0x${region.entry.toString(16)}: ${blocks}`);
          }
        }
      }
    }

    if (!page.instance) {
      const mod = new WebAssembly.Module(Buffer.from(page.wasm, "hex"));
      page.instance = new WebAssembly.Instance(mod, {
        env: { ...this.imports, mem: this.memory },
      });
      // The dispatch entry packs the region slot and the block index into 16 bits each, so a run
      // that translates enough pages to need more than 65535 slots corrupts every later entry.
      if (this.slots + page.regions.length > 0xffff) {
        throw new Error(
          `region slots exhausted: ${this.slots} in use, ${page.regions.length} more for 0x${pc.toString(16)}`,
        );
      }
      this.growTo(this.slots + page.regions.length);
      page.base = this.slots;
      for (let i = 0; i < page.regions.length; i++) {
        this.table.set(this.slots + i, page.instance.exports[`r${i}`]);
      }
      this.slots += page.regions.length;
    }

    for (let i = 0; i < page.regions.length; i++) {
      const region = page.regions[i];
      for (let b = 0; b < region.blocks.length; b++) {
        this.dispatch(region.blocks[b], page.base + i, b);
      }
    }
    if (!this.hasDispatch(pc)) {
      throw new Error(`translated 0x${pc.toString(16)} but no block starts there`);
    }
    return this.instance.exports.run(0, 0n, 1);
  }

  /// Run until the guest exits, or a jump lands where nothing has been translated yet.
  async run() {
    const after = process.env.ARMJIT_WATCHDOG ? Number(process.env.ARMJIT_WATCHDOG) * 1000 : 0;
    const startedAt = Date.now();
    let status = this.instance.exports.run(this.meta.entry, BigInt(this.meta.sp), 0);
    while (status === 2) {
      // A run that never ends is only observable from here: the guest's wasm call does not return
      // while it spins, so the loop that translates pages is the one place time can be checked.
      if (after && Date.now() - startedAt > after) return 4;
      const pc = this.view.getUint32(SHADOW_PC, true) >>> 0;
      if (process.env.ARMJIT_TRACE_PAGES) {
      console.error(`images: ${JSON.stringify(this.kernel.space.images.map((m) => [m.lo.toString(16), m.hi.toString(16), m.base.toString(16), m.host]))}`);
    }
    if (!this.kernel.space.imageOf(pc)) {
        console.error(`armjit: guest jumped to untranslated address 0x${pc.toString(16)}`);
        return 1;
      }
      if (process.env.ARMJIT_TRACE_PAGES) console.error(`miss at 0x${pc.toString(16)}`);
      status = await this.translateAndResume(pc);
    }
    if (status !== 0) {
      console.error(`armjit: stopped with status ${status}`);
      return 1;
    }
    return 0;
  }
}
