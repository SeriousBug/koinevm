//! ELF64 AArch64 reader: the parts a loader needs, and nothing else.

pub const PT_LOAD: u32 = 1;
pub const PT_INTERP: u32 = 3;
pub const EM_AARCH64: u16 = 183;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

#[derive(Debug, Clone)]
pub struct Segment {
    pub vaddr: u64,
    pub file_offset: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: u32,
}

impl Segment {
    pub fn end(&self) -> u64 {
        self.vaddr + self.memsz
    }
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub is_func: bool,
    pub shndx: u16,
}

pub struct Elf {
    pub entry: u64,
    pub phoff: u64,
    pub phentsize: u16,
    pub phnum: u16,
    pub segments: Vec<Segment>,
    pub symbols: Vec<Symbol>,
    pub image: Vec<u8>,
}

fn u16at(b: &[u8], o: usize) -> Result<u16, String> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or_else(|| "truncated ELF".into())
}
fn u32at(b: &[u8], o: usize) -> Result<u32, String> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or_else(|| "truncated ELF".into())
}
fn u64at(b: &[u8], o: usize) -> Result<u64, String> {
    b.get(o..o + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or_else(|| "truncated ELF".into())
}

impl Elf {
    pub fn parse(image: Vec<u8>) -> Result<Elf, String> {
        if image.len() < 64 || &image[0..4] != b"\x7fELF" {
            return Err("not an ELF image".into());
        }
        if image[4] != 2 {
            return Err(format!("ELF class {} is not 64-bit", image[4]));
        }
        if image[5] != 1 {
            return Err("ELF is not little-endian".into());
        }
        let e_type = u16at(&image, 16)?;
        if e_type != 2 {
            return Err(format!(
                "ELF type {} is not ET_EXEC; static non-PIE only for now (ET_DYN needs a loader)",
                e_type
            ));
        }
        let machine = u16at(&image, 18)?;
        if machine != EM_AARCH64 {
            return Err(format!("e_machine {} is not AArch64", machine));
        }
        let entry = u64at(&image, 24)?;
        let phoff = u64at(&image, 32)?;
        let shoff = u64at(&image, 40)?;
        let phentsize = u16at(&image, 54)?;
        let phnum = u16at(&image, 56)?;

        let mut segments = Vec::new();
        for i in 0..phnum as usize {
            let o = (phoff as usize) + i * phentsize as usize;
            let p_type = u32at(&image, o)?;
            if p_type == PT_INTERP {
                return Err("image has PT_INTERP: dynamically linked, needs ld.so, not supported yet".into());
            }
            if p_type != PT_LOAD {
                continue;
            }
            segments.push(Segment {
                flags: u32at(&image, o + 4)?,
                file_offset: u64at(&image, o + 8)?,
                vaddr: u64at(&image, o + 16)?,
                filesz: u64at(&image, o + 32)?,
                memsz: u64at(&image, o + 40)?,
            });
        }
        if segments.is_empty() {
            return Err("no PT_LOAD segments".into());
        }
        if !segments.iter().any(|s| s.flags & PF_X != 0) {
            return Err("no executable segment".into());
        }
        for s in &segments {
            if s.memsz < s.filesz {
                return Err("segment has p_memsz < p_filesz".into());
            }
            if (s.file_offset + s.filesz) > image.len() as u64 {
                return Err("segment extends past end of file".into());
            }
        }

        let mut symbols = Vec::new();
        if shoff != 0 {
            let shentsize = u16at(&image, 58)? as usize;
            let shnum = u16at(&image, 60)? as usize;
            let mut symtab = None;
            for i in 0..shnum {
                let o = shoff as usize + i * shentsize;
                let sh_type = u32at(&image, o + 4)?;
                if sh_type == 2 {
                    symtab = Some((u64at(&image, o + 24)?, u64at(&image, o + 32)?, u32at(&image, o + 40)?));
                }
            }
            if let Some((off, size, link)) = symtab {
                let stro = shoff as usize + link as usize * shentsize;
                let str_off = u64at(&image, stro + 24)? as usize;
                let str_size = u64at(&image, stro + 32)? as usize;
                let strtab = image.get(str_off..str_off + str_size).unwrap_or(&[]);
                let mut o = off as usize;
                while o + 24 <= off as usize + size as usize {
                    let name_off = u32at(&image, o)? as usize;
                    let info = image[o + 4];
                    let shndx = u16at(&image, o + 6)?;
                    let value = u64at(&image, o + 8)?;
                    let size = u64at(&image, o + 16)?;
                    let end = strtab.iter().skip(name_off).position(|&c| c == 0).map(|p| p + name_off).unwrap_or(strtab.len());
                    let name = String::from_utf8_lossy(strtab.get(name_off..end).unwrap_or(&[])).into_owned();
                    symbols.push(Symbol { name, value, size, is_func: info & 0xf == 2 && shndx != 0, shndx });
                    o += 24;
                }
            }
        }

        Ok(Elf { entry, phoff, phentsize, phnum, segments, symbols, image })
    }

    /// Bytes at a guest virtual address, when a segment's file contents cover it.
    pub fn vaddr_bytes(&self, vaddr: u64, len: usize) -> Option<&[u8]> {
        for s in &self.segments {
            if vaddr >= s.vaddr && vaddr + len as u64 <= s.vaddr + s.filesz {
                let off = (s.file_offset + (vaddr - s.vaddr)) as usize;
                return self.image.get(off..off + len);
            }
        }
        None
    }

    pub fn code_range(&self) -> Option<(u64, u64)> {
        let mut lo = u64::MAX;
        let mut hi = 0;
        for s in &self.segments {
            if s.flags & PF_X != 0 {
                lo = lo.min(s.vaddr);
                hi = hi.max(s.end());
            }
        }
        if lo == u64::MAX { None } else { Some((lo, hi)) }
    }

    pub fn image_end(&self) -> u64 {
        self.segments.iter().map(|s| s.end()).max().unwrap_or(0)
    }

    pub fn data_limit(&self) -> u64 {
        self.segments.iter().filter(|s| s.flags & PF_W != 0).map(|s| s.end()).max().unwrap_or(self.image_end())
    }
}
