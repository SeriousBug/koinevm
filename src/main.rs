mod decode;
mod elf;
mod emit;
mod wasm;

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("armjit: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> String {
    "usage: armjit translate <elf> -o <out.wasm> [--bounds=check|trust] [--mem-pages=N] [--trace]\n       \
     [--argv=a,b] [--env=k=v,...] [--rootfs=<dir>] [--interp=<elf>] [--interp-base=0xADDR]\n       \
     armjit dump <elf>".into()
}

/// Parse an image and place it: `ET_EXEC` stays at its link addresses, `ET_DYN` lands at `base`.
fn load_image(path: &str, base: Option<u64>) -> Result<elf::Elf, String> {
    let image = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let elf = elf::Elf::parse(image)?;
    let base = base.unwrap_or(if elf.etype == elf::ET_DYN { emit::IMAGE_BASE } else { elf.load_offset() });
    elf.relocated(base).map_err(|e| format!("{path}: {e}"))
}

fn run(args: &[String]) -> Result<(), String> {
    let Some(cmd) = args.first() else { return Err(usage()) };
    match cmd.as_str() {
        "translate" => {
            let path = args.get(1).ok_or(usage())?;
            let mut out = None;
            let mut bounds_check = true;
            let mut trace = false;
            let mut mem_pages = emit::DEFAULT_MEM_PAGES;
            let mut argv: Vec<String> = Vec::new();
            let mut envp: Vec<String> = Vec::new();
            let mut rootfs: Option<String> = None;
            let mut interp_path: Option<String> = None;
            let mut interp_base = emit::INTERP_BASE;
            let mut i = 2;
            while i < args.len() {
                let a = &args[i];
                if a == "-o" {
                    out = Some(args.get(i + 1).ok_or("missing path after -o")?.clone());
                    i += 2;
                } else if let Some(v) = a.strip_prefix("--mem-pages=") {
                    mem_pages = v.parse().map_err(|_| format!("bad page count {v}"))?;
                    i += 1;
                } else if a == "--trace" {
                    trace = true;
                    i += 1;
                } else if let Some(v) = a.strip_prefix("--bounds=") {
                    bounds_check = match v {
                        "check" => true,
                        "trust" => false,
                        _ => return Err(format!("unknown bounds mode {v}")),
                    };
                    i += 1;
                } else if let Some(v) = a.strip_prefix("--argv=") {
                    argv = v.split(',').map(|s| s.to_string()).collect();
                    i += 1;
                } else if let Some(v) = a.strip_prefix("--env=") {
                    envp = v.split(',').map(|s| s.to_string()).collect();
                    i += 1;
                } else if let Some(v) = a.strip_prefix("--rootfs=") {
                    rootfs = Some(v.to_string());
                    i += 1;
                } else if let Some(v) = a.strip_prefix("--interp=") {
                    interp_path = Some(v.to_string());
                    i += 1;
                } else if let Some(v) = a.strip_prefix("--interp-base=") {
                    interp_base = u64::from_str_radix(v.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad interp base {v}"))?;
                    i += 1;
                } else {
                    return Err(format!("unknown argument {a}"));
                }
            }
            let out_path = out.ok_or("missing -o <out.wasm>")?;
            let main = load_image(path, None)?;
            let interp = match &main.interp {
                None => None,
                Some(want) => {
                    let resolved = interp_path.clone().or_else(|| {
                        rootfs.as_ref().map(|root| format!("{root}{want}"))
                    });
                    let resolved = resolved.ok_or_else(|| {
                        format!("{path} wants {want} as its interpreter: pass --rootfs=<dir> or --interp=<elf>")
                    })?;
                    Some(load_image(&resolved, Some(interp_base))?)
                }
            };
            let cfg = emit::Config { bounds_check, trace, mem_pages };
            let started = std::time::Instant::now();
            let res =
                emit::translate(emit::Images { main: &main, interp: interp.as_ref() }, &cfg, &argv, &envp)?;
            let elapsed = started.elapsed();

            std::fs::write(&out_path, &res.wasm).map_err(|e| format!("{out_path}: {e}"))?;
            let meta = format!(
                "{{\"entry\":{},\"sp\":{},\"mem_pages\":{},\"code_lo\":{},\"code_hi\":{}}}\n",
                res.entry, res.sp, res.mem_pages, res.code_lo, res.code_hi
            );
            let meta_path = format!("{out_path}.json");
            let mut f = std::fs::File::create(&meta_path).map_err(|e| e.to_string())?;
            f.write_all(meta.as_bytes()).map_err(|e| e.to_string())?;

            println!(
                "translated {} instructions of {} regions in {:?}: {} bytes wasm ({} bytes guest)",
                res.stats.instructions, res.stats.regions, elapsed, res.stats.wasm_bytes,
                main.image.len() + interp.as_ref().map(|i| i.image.len()).unwrap_or(0)
            );
            if let Some(interp) = &interp {
                println!("  interpreter at 0x{:x}, entry 0x{:x}", interp.load_offset(), interp.entry);
            }
            for (addr, why) in &res.unsupported {
                eprintln!("  unsupported at 0x{addr:x}: {why}");
            }
            Ok(())
        }
        "dump" => {
            let path = args.get(1).ok_or(usage())?;
            let image = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
            let elf = elf::Elf::parse(image)?;
            let (lo, hi) = elf.code_range().ok_or("no executable segment")?;
            let mut a = lo;
            while a + 4 <= hi {
                let Some(w) = elf.vaddr_bytes(a, 4) else { break };
                let raw = u32::from_le_bytes(w.try_into().unwrap());
                println!("0x{a:x}  {raw:08x}  {:?}", decode::decode(raw));
                a += 4;
            }
            Ok(())
        }
        "-h" | "--help" => {
            println!("{}", usage());
            Ok(())
        }
        other => Err(format!("unknown command {other}\n{}", usage())),
    }
}
