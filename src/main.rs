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
     armjit page      (a request per line on stdin, a module back on stdout)\n       \
     armjit gaps <elf> [--rootfs=<dir>]\n       \
     armjit dump <elf>".into()
}

/// Parse an image and place it: `ET_EXEC` stays at its link addresses, `ET_DYN` lands at `base`.
fn load_image(path: &str, base: Option<u64>) -> Result<elf::Elf, String> {
    let image = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let elf = elf::Elf::parse(image)?;
    let base = base.unwrap_or(if elf.etype == elf::ET_DYN { emit::IMAGE_BASE } else { elf.load_offset() });
    elf.relocated(base).map_err(|e| format!("{path}: {e}"))
}

/// Hex, because the module travels over the same pipe as the request that asked for it.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A JSON string literal, with the escaping the messages in this program need.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn run(args: &[String]) -> Result<(), String> {
    let Some(cmd) = args.first() else { return Err(usage()) };
    match cmd.as_str() {
        "translate" => {
            let path = args.get(1).ok_or(usage())?;
            let mut out = None;
            let mut bounds_check = true;
            let mut allow_undefined = false;
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
                } else if a == "--allow-undefined" {
                    allow_undefined = true;
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
            let cfg = emit::Config { bounds_check, trace, mem_pages, allow_undefined };
            let started = std::time::Instant::now();
            let res =
                emit::translate(emit::Images { main: &main, interp: interp.as_ref() }, &cfg, &argv, &envp)?;
            let elapsed = started.elapsed();

            std::fs::write(&out_path, &res.wasm).map_err(|e| format!("{out_path}: {e}"))?;
            let meta = format!(
                concat!(
                    "{{\"entry\":{},\"sp\":{},\"mem_pages\":{},\"code_lo\":{},\"code_hi\":{},",
                    "\"pte_base\":{},\"table_base\":{},\"table_mask\":{},",
                    "\"heap_base\":{},\"heap_limit\":{},\"mmap_base\":{},",
                    "\"stack_floor\":{},\"bounds\":{},\"trace\":{}}}\n"
                ),
                res.entry,
                res.sp,
                res.mem_pages,
                res.code_lo,
                res.code_hi,
                res.map.pte_base,
                res.map.table_base,
                res.map.table_mask,
                res.map.heap_base,
                res.map.heap_limit,
                res.map.mmap_base,
                res.map.stack_floor,
                if cfg.bounds_check { 1 } else { 0 },
                if cfg.trace { 1 } else { 0 }
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
        "page" => {
            // Which pages a guest runs is only known while it runs, so the host asks for one page at
            // a time and gets a module that joins the image already running.
            //
            //   cfg bounds=check|trust trace=0|1 mem-pages=N
            //   page <elf> <base-hex> <address-hex>
            //
            // A page answer is one JSON object on one line, with the module in hex.
            let mut cfg = emit::Config {
                bounds_check: true,
                trace: false,
                mem_pages: emit::DEFAULT_MEM_PAGES,
                allow_undefined: true,
            };
            // Decoding an image's text costs more than translating one page of it, so the sites
            // of every image asked about are kept.
            let mut cache: std::collections::HashMap<(String, u64), (elf::Elf, emit::Site)> =
                std::collections::HashMap::new();
            let stdin = std::io::stdin();
            let mut line = String::new();
            loop {
                line.clear();
                if stdin.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
                    return Ok(());
                }
                let req: Vec<&str> = line.split_whitespace().collect();
                let mut reply = String::new();
                match req.first().copied() {
                    Some("cfg") => {
                        for a in &req[1..] {
                            if let Some(v) = a.strip_prefix("bounds=") {
                                cfg.bounds_check = v == "check";
                            } else if let Some(v) = a.strip_prefix("trace=") {
                                cfg.trace = v == "1";
                            } else if let Some(v) = a.strip_prefix("mem-pages=") {
                                cfg.mem_pages = v.parse().map_err(|_| format!("bad page count {v}"))?;
                            }
                        }
                        reply.push_str("{\"ok\":true}");
                    }
                    Some("page") => {
                        let parsed = (|| -> Result<String, String> {
                            let path = req.get(1).ok_or("page needs an image")?.to_string();
                            let base = u64::from_str_radix(req.get(2).ok_or("page needs a base")?, 16)
                                .map_err(|_| "bad base")?;
                            let at = u64::from_str_radix(req.get(3).ok_or("page needs an address")?, 16)
                                .map_err(|_| "bad address")?;
                            if !cache.contains_key(&(path.clone(), base)) {
                                let image = load_image(&path, Some(base))?;
                                let site = emit::sites(&[&image]);
                                cache.insert((path.clone(), base), (image, site));
                            }
                            let (image, site) = &cache[&(path.clone(), base)];
                            let res = emit::translate_page(image, site, at, &cfg)?;
                            let regions: Vec<String> = res
                                .regions
                                .iter()
                                .map(|r| {
                                    let blocks: Vec<String> =
                                        r.blocks.iter().map(|b| b.to_string()).collect();
                                    format!("{{\"entry\":{},\"blocks\":[{}]}}", r.entry, blocks.join(","))
                                })
                                .collect();
                            let gaps: Vec<String> = res
                                .unsupported
                                .iter()
                                .map(|(a, why)| format!("[{a},{}]", json_str(why)))
                                .collect();
                            Ok(format!(
                                "{{\"ok\":true,\"wasm\":\"{}\",\"regions\":[{}],\"unsupported\":[{}]}}",
                                hex(&res.wasm),
                                regions.join(","),
                                gaps.join(",")
                            ))
                        })();
                        match parsed {
                            Ok(text) => reply.push_str(&text),
                            Err(e) => {
                                reply.push_str(&format!("{{\"ok\":false,\"error\":{}}}", json_str(&e)))
                            }
                        }
                    }
                    _ => reply.push_str("{\"ok\":false,\"error\":\"bad request\"}"),
                }
                println!("{reply}");
                std::io::stdout().flush().map_err(|e| e.to_string())?;
            }
        }
        "gaps" => {
            // Translate what decodes and trap at what does not, then group the gaps by encoding: the
            // size of the work, not one instruction per attempt.
            let path = args.get(1).ok_or(usage())?;
            let mut rootfs: Option<String> = None;
            let mut interp_path: Option<String> = None;
            let mut interp_base = emit::INTERP_BASE;
            for a in &args[2..] {
                if let Some(v) = a.strip_prefix("--rootfs=") {
                    rootfs = Some(v.to_string());
                } else if let Some(v) = a.strip_prefix("--interp=") {
                    interp_path = Some(v.to_string());
                } else if let Some(v) = a.strip_prefix("--interp-base=") {
                    interp_base = u64::from_str_radix(v.trim_start_matches("0x"), 16)
                        .map_err(|_| format!("bad interp base {v}"))?;
                } else {
                    return Err(format!("unknown argument {a}"));
                }
            }
            let main = load_image(path, None)?;
            let interp = match &main.interp {
                None => None,
                Some(want) => {
                    let resolved = interp_path.clone().or_else(|| {
                        rootfs.as_ref().map(|root| format!("{root}{want}"))
                    });
                    match resolved {
                        Some(p) => Some(load_image(&p, Some(interp_base))?),
                        None => None,
                    }
                }
            };
            let cfg = emit::Config {
                bounds_check: true,
                trace: false,
                mem_pages: emit::DEFAULT_MEM_PAGES,
                allow_undefined: true,
            };
            let started = std::time::Instant::now();
            let res = emit::translate(
                emit::Images { main: &main, interp: interp.as_ref() },
                &cfg,
                &[],
                &[],
            )?;
            let images = [Some(&main), interp.as_ref()];
            let mut grouped: std::collections::BTreeMap<u32, (usize, u64)> =
                std::collections::BTreeMap::new();
            for (addr, _) in &res.unsupported {
                let word = images
                    .iter()
                    .flatten()
                    .find_map(|i| i.vaddr_bytes(*addr, 4))
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                    .unwrap_or(0);
                let e = grouped.entry(word).or_insert((0, *addr));
                e.0 += 1;
            }
            let mut rows: Vec<(u32, usize, u64)> =
                grouped.into_iter().map(|(w, (n, at))| (w, n, at)).collect();
            rows.sort_by(|a, b| b.1.cmp(&a.1));
            println!(
                "{} instructions translated, {} unreachable/dead, {} undecoded in {} encodings, {:?}",
                res.stats.instructions,
                res.unsupported.len(),
                res.unsupported.len(),
                rows.len(),
                started.elapsed()
            );
            for (word, n, at) in &rows {
                println!("  {n:5}  {word:08x}  first at 0x{at:x}");
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
