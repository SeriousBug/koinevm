// The kernel's own files: a program that asks the machine about itself reads `/proc`, and a kernel
// answers out of the process table, the address space and the clock. This does the same, so a
// program that sizes itself by what the machine says sees the machine it is really running on.

import path from "node:path";

const PAGE = 4096;
/// The stack the translator laid out at the top of the first memory, and how much of it is reserved.
const STACK_BYTES = 8 * 1024 * 1024;
/// The release and the other words of `uname`, which a program is entitled to find in the same
/// spelling in both places.
const SYSNODE = "koinevm";
const RELEASE = "6.1.0-koinevm";
const VERSION = "#1";
/// The features the guest is told about in `AT_HWCAP`, as `/proc/cpuinfo` lists them.
const FEATURES = "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp";

/// Which process a name is about: `/proc/self` is this one, and a number is whichever process the
/// registry knows by it, so a program reads another process's files the way it does on a kernel.
function subject(kernel, name) {
  const m = /^\/proc\/(self|\d+)(\/.*)?$/.exec(name);
  if (!m) return null;
  const pid = m[1] === "self" ? kernel.pid : Number(m[1]);
  const target = pid === kernel.pid ? kernel : (kernel.peers?.(pid) ?? null);
  if (!target) return null;
  return { kernel: target, rest: m[2] ?? "" };
}

/// The argv a process was started with, read back out of the stack a kernel built it on: a program
/// is allowed to write to those words, and what it wrote is what it should read back.
function argv(kernel) {
  const sp = Number(kernel.meta.sp);
  const space = kernel.space;
  const count = Number(space.copyOut(sp, 8).readBigUInt64LE(0));
  const out = [];
  if (count <= 0 || count > 4096) return out;
  const ptrs = space.copyOut(sp + 8, count * 8);
  for (let i = 0; i < count; i++) out.push(kernel.str(ptrs.readBigUInt64LE(i * 8)));
  return out;
}

/// The environment, at the same place: past the argv pointers and the null that ends them.
function envp(kernel) {
  const sp = Number(kernel.meta.sp);
  const space = kernel.space;
  const count = Number(space.copyOut(sp, 8).readBigUInt64LE(0));
  const first = sp + 8 + (count + 1) * 8;
  const out = [];
  for (let i = 0; i < 4096; i++) {
    const at = Number(space.copyOut(first + i * 8, 8).readBigUInt64LE(0));
    if (at === 0) break;
    out.push(kernel.str(BigInt(at)));
  }
  return out;
}

/// The name a kernel shows for a process: the last component of argv[0], fifteen characters of it.
function comm(kernel) {
  const first = argv(kernel)[0] ?? kernel.space.images[0]?.host ?? SYSNODE;
  const base = first.slice(first.lastIndexOf("/") + 1) || SYSNODE;
  return base.slice(0, 15);
}

/// The pages the address space has mapped, which is what resident means in a space this machine
/// does not swap.
function residentPages(space) {
  return BigInt(space.resident);
}

/// The top of the stack: the top of the first memory, which is where the translator put it.
function stackTop(space) {
  return space.memories[0].buffer.byteLength;
}

function utimeTicks(usage) {
  return Number((usage.user + usage.childUser) / 10_000_000n);
}

function stimeTicks(usage) {
  return Number((usage.sys + usage.childSys) / 10_000_000n);
}

function threads() {
  return 1;
}

/// `/proc/<pid>/stat`: fifty-two fields, and the twenty-fourth is the resident pages. A program
/// that finds a value here counts fields up to the one it wants, so the whole line has to be there.
function stat(kernel) {
  const space = kernel.space;
  const { total } = space.capacity();
  const fields = [
    kernel.pid, // 1 pid
    `(${comm(kernel)})`, // 2 comm
    "R", // 3 state
    kernel.ppid, // 4 ppid
    kernel.pid, // 5 pgrp
    kernel.pid, // 6 session
    0, // 7 tty_nr
    -1, // 8 tpgid
    0x400000, // 9 flags
    0, 0, 0, 0, // 10..13 faults
    utimeTicks(kernel.usage), // 14 utime
    stimeTicks(kernel.usage), // 15 stime
    0, 0, // 16,17 cutime, cstime
    20, // 18 priority
    0, // 19 nice
    threads(), // 20 num_threads
    0, // 21 itrealvalue
    0, // 22 starttime
    space.size, // 23 vsize
    Number(residentPages(space)), // 24 rss
    0xffffffffffffffffn, // 25 rsslim, unlimited
    0, 0, // 26,27 startcode, endcode
    stackTop(space), // 28 startstack
    0, 0, // 29,30 kstkesp, kstkeip
    0, 0, 0, 0, // 31..34 signals
    0, // 35 wchan
    0, 0, // 36,37 nswap, cnswap
    17, // 38 exit_signal, which is SIGCHLD
    0, // 39 processor
    0, // 40 rt_priority
    0, // 41 policy
    0, // 42 delayacct_blkio_ticks
    0, 0, // 43,44 guest_time, cguest_time
    0, 0, // 45,46 start_data, end_data
    space.brkBase ?? 0, // 47 start_brk
    Number(kernel.meta.sp) + 8, // 48 arg_start
    0, // 49 arg_end
    0, // 50 env_start
    0, // 51 env_end
    0, // 52 exit_code
  ];
  return `${fields.join(" ")}\n`;
}

function statm(kernel) {
  const space = kernel.space;
  const size = Math.round(space.size / PAGE);
  const resident = Number(residentPages(space));
  return `${size} ${resident} 0 0 0 ${resident} 0\n`;
}

function status(kernel) {
  const space = kernel.space;
  const { total } = space.capacity();
  const rss = residentPages(space) * BigInt(PAGE);
  return [
    `Name:\t${comm(kernel)}`,
    "Umask:\t0022",
    "State:\tR (running)",
    `Tgid:\t${kernel.pid}`,
    "Ngid:\t0",
    `Pid:\t${kernel.pid}`,
    `PPid:\t${kernel.ppid}`,
    "TracerPid:\t0",
    "Uid:\t0\t0\t0\t0",
    "Gid:\t0\t0\t0\t0",
    "FDSize:\t64",
    `Threads:\t${threads()}`,
    `VmSize:\t${Math.round(space.size / 1024)} kB`,
    "VmLck:\t0 kB",
    "VmPin:\t0 kB",
    `VmHWM:\t${rss / 1024n} kB`,
    `VmRSS:\t${rss / 1024n} kB`,
    `VmData:\t0 kB`,
    `VmStk:\t${STACK_BYTES / 1024} kB`,
    `VmExe:\t0 kB`,
    `VmLib:\t0 kB`,
    `VmPTE:\t0 kB`,
    `VmSwap:\t0 kB`,
    `RssAnon:\t${rss / 1024n} kB`,
    "RssFile:\t0 kB",
    "RssShmem:\t0 kB",
    `VmPeak:\t${Math.round(space.size / 1024)} kB`,
    `HugetlbPages:\t0 kB`,
    `SigQ:\t0/1`,
    `SigPnd:\t0000000000000000`,
    `ShdPnd:\t0000000000000000`,
    `SigBlk:\t${kernel.sigblock.toString(16).padStart(16, "0")}`,
    "SigIgn:\t0000000000000000",
    "SigCgt:\t0000000000000000",
    "Cpus_allowed:\t1",
    "Cpus_allowed_list:\t0",
    "Mems_allowed:\t1",
    "Mems_allowed_list:\t0",
    "voluntary_ctxt_switches:\t0",
    "nonvoluntary_ctxt_switches:\t0",
    "",
  ].join("\n");
}

/// The guest path of a host path inside the rootfs, so a program that reads a name out of here can
/// open it again.
function guestPath(kernel, host) {
  const root = kernel.files?.rootfs;
  if (!root) return host;
  const absolute = host.startsWith("/") ? host : path.resolve(host);
  const inside = path.relative(root, absolute);
  return inside.startsWith("..") ? host : `/${inside}`;
}

function maps(kernel) {
  const space = kernel.space;
  const out = [];
  const perm = (bits) => `${bits & 1 ? "r" : "-"}${bits & 2 ? "w" : "-"}${bits & 4 ? "x" : "-"}p`;
  for (const image of space.images) {
    out.push(
      `${image.lo.toString(16).padStart(8, "0")}-${image.hi.toString(16).padStart(8, "0")} ` +
        `${perm(5)} 00000000 00:00 0 ${guestPath(kernel, image.host)}`,
    );
  }
  if (space.heapBase) {
    out.push(
      `${space.heapBase.toString(16).padStart(8, "0")}-${space.brk.toString(16).padStart(8, "0")} ` +
        `rw-p 00000000 00:00 0 [heap]`,
    );
  }
  {
    const top = stackTop(space);
    const floor = top - STACK_BYTES;
    out.push(
      `${floor.toString(16).padStart(8, "0")}-${top.toString(16).padStart(8, "0")} ` +
        `rw-p 00000000 00:00 0 [stack]`,
    );
  }
  return out.length ? `${out.join("\n")}\n` : "";
}

function cpuinfo() {
  return [
    "processor\t: 0",
    "BogoMIPS\t: 100.00",
    `Features\t: ${FEATURES}`,
    "CPU implementer\t: 0x61",
    "CPU architecture: 8",
    "CPU variant\t: 0x0",
    "CPU part\t: 0x000",
    "CPU revision\t: 0",
    "",
    "model name\t: aarch64 (koinevm)",
    "",
  ].join("\n");
}

/// One CPU, because that is what `sched_getaffinity` answers and what runs guest code at a time:
/// the counters are the machine's own CPU time in hundredths of a second.
function statCPU(kernel) {
  const ticks = (ns) => Number(ns / 10_000_000n);
  const user = ticks(kernel.usage.user);
  const sys = ticks(kernel.usage.sys);
  const idle = Math.round(process.uptime() * 100);
  return [
    `cpu  ${user} 0 ${sys} ${idle} 0 0 0 0 0 0`,
    `cpu0 ${user} 0 ${sys} ${idle} 0 0 0 0 0 0`,
    "intr 0",
    "ctxt 0",
    `btime ${Math.round(Date.now() / 1000 - process.uptime())}`,
    "processes 1",
    "procs_running 1",
    "procs_blocked 0",
    "softirq 0 0 0 0 0 0 0 0 0 0",
    "",
  ].join("\n");
}

function meminfo(kernel) {
  const { total, free } = kernel.space.capacity();
  const kb = (bytes) => Math.round(Number(bytes) / 1024);
  return [
    `MemTotal:       ${kb(total)} kB`,
    `MemFree:        ${kb(free)} kB`,
    `MemAvailable:   ${kb(free)} kB`,
    "Buffers:        0 kB",
    "Cached:         0 kB",
    "SwapCached:     0 kB",
    "Active:         0 kB",
    "Inactive:       0 kB",
    "SwapTotal:      0 kB",
    "SwapFree:       0 kB",
    "Dirty:          0 kB",
    "Writeback:      0 kB",
    "AnonPages:      0 kB",
    "Mapped:         0 kB",
    "Shmem:          0 kB",
    "Slab:           0 kB",
    "SReclaimable:   0 kB",
    "SUnreclaim:     0 kB",
    "PageTables:     0 kB",
    "CommitLimit:    " + kb(total) + " kB",
    "Committed_AS:   0 kB",
    "VmallocTotal:   0 kB",
    "VmallocUsed:    0 kB",
    "HugePages_Total: 0",
    "Hugepagesize:   2048 kB",
    "",
  ].join("\n");
}

const FILES = {
  "/stat": stat,
  "/statm": statm,
  "/status": status,
  "/cmdline": (kernel) => {
    const list = argv(kernel);
    return list.length ? `${list.join("\0")}\0` : "";
  },
  "/environ": (kernel) => {
    const list = envp(kernel);
    return list.length ? `${list.join("\0")}\0` : "";
  },
  "/maps": maps,
};

const MACHINE = {
  "/proc/cpuinfo": cpuinfo,
  "/proc/stat": statCPU,
  "/proc/meminfo": meminfo,
  "/proc/uptime": () => `${process.uptime().toFixed(2)} ${Math.round(process.uptime() * 100)}.00\n`,
  "/proc/version": () => `Linux version ${RELEASE} (koinevm@localhost) (gcc (Debian 12.2.0-14) 12.2.0) ${VERSION} SMP\n`,
  "/proc/loadavg": (kernel) => `0.00 0.00 0.00 ${threads()}/${threads()} ${kernel.pid}\n`,
  "/proc/sys/kernel/ostype": () => "Linux\n",
  "/proc/sys/kernel/osrelease": () => `${RELEASE}\n`,
  "/proc/sys/kernel/hostname": () => `${SYSNODE}\n`,
  "/proc/sys/kernel/pid_max": () => "4194304\n",
  "/proc/sys/kernel/threads-max": () => "60000\n",
  "/proc/sys/vm/overcommit_memory": () => "0\n",
};

/// The contents of a file this machine synthesizes, or null for a name it does not have.
export function procFile(kernel, name) {
  const at = subject(kernel, name);
  if (at) {
    const make = FILES[at.rest];
    return make ? Buffer.from(make(at.kernel), "utf8") : null;
  }
  const make = MACHINE[name];
  return make ? Buffer.from(make(kernel), "utf8") : null;
}

/// Where one of the links a kernel keeps in `/proc` points, or null.
export function procLink(kernel, name) {
  const at = subject(kernel, name);
  if (!at) return null;
  const program = at.kernel.space.images[0]?.host;
  if (at.rest === "/exe") return program ? guestPath(at.kernel, program) : null;
  if (at.rest === "/cwd") return at.kernel.files?.cwd ?? "/";
  if (at.rest === "/root") return "/";
  return null;
}

const MACHINE_FILES = ["cpuinfo", "loadavg", "meminfo", "stat", "uptime", "version"];
const PROCESS_FILES = ["cmdline", "environ", "maps", "stat", "statm", "status"];
const PROCESS_LINKS = ["cwd", "exe", "root"];

/// The names in one of the directories `/proc` has, or null for a name that is not one. `dir` says
/// which of them are directories themselves, because a listing has to say so.
export function procEntries(kernel, name) {
  if (name === "/proc") {
    const out = MACHINE_FILES.map((n) => ({ name: n, dir: false }));
    out.push({ name: "self", dir: true }, { name: "sys", dir: true });
    for (const pid of kernel.pids?.() ?? []) out.push({ name: String(pid), dir: true });
    return out;
  }
  if (name === "/proc/sys") return [{ name: "kernel", dir: true }, { name: "vm", dir: true }];
  if (name.startsWith("/proc/sys/")) {
    const dir = `${name}/`;
    return Object.keys(MACHINE)
      .filter((n) => n.startsWith(dir) && !n.slice(dir.length).includes("/"))
      .map((n) => ({ name: n.slice(dir.length), dir: false }));
  }
  const at = subject(kernel, name);
  if (at) {
    if (at.rest === "") {
      return [
        ...PROCESS_FILES.map((n) => ({ name: n, dir: false })),
        ...PROCESS_LINKS.map((n) => ({ name: n, dir: false })),
        { name: "fd", dir: true },
      ];
    }
    if (at.rest === "/fd") {
      const files = at.kernel.files;
      if (!files) return [];
      return [...files.map.keys()].map((fd) => ({ name: String(fd), dir: false }));
    }
  }
  return null;
}
