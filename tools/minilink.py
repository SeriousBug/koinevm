#!/usr/bin/env python3
"""Link a relocatable aarch64 Linux object into a static non-PIE executable.

There is no lld on this machine, and the guest objects we build need only a handful of
relocation types. Layout: .text at TEXT_VADDR, all remaining allocatable data at
RODATA_VADDR, one PT_LOAD each.
"""
import struct
import sys

TEXT_VADDR = 0x400000
RODATA_VADDR = 0x410000

R_ABS64 = 257
R_PREL64 = 260
R_ADR_PREL_LO21 = 274
R_ADR_PREL_PG_HI21 = 275
R_ADR_PREL_PG_HI21_NC = 276
R_ADD_ABS_LO12_NC = 277
R_LDST8_ABS_LO12_NC = 278
R_TSTBR14 = 279
R_CONDBR19 = 280
R_JUMP26 = 282
R_CALL26 = 283
R_LDST16_ABS_LO12_NC = 284
R_LDST32_ABS_LO12_NC = 285
R_LDST64_ABS_LO12_NC = 286


def read_elf(buf):
    assert buf[:4] == b"\x7fELF" and buf[4] == 2 and buf[5] == 1, "want ELF64 LE"
    e_shoff, = struct.unpack_from("<Q", buf, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 0x3A)
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, flags, addr, offset, size, link, info, align, entsize = struct.unpack_from(
            "<IIQQQQIIQQ", buf, off)
        secs.append(dict(name_off=name, type=typ, flags=flags, addr=addr, offset=offset,
                         size=size, link=link, info=info, align=align, entsize=entsize,
                         data=buf[offset:offset + size]))
    shstr = secs[e_shstrndx]["data"]
    for s in secs:
        end = shstr.find(b"\0", s["name_off"])
        s["name"] = shstr[s["name_off"]:end].decode()
    return secs


def read_syms(buf, secs, symtab):
    out = []
    strtab = secs[symtab["link"]]["data"]
    for off in range(0, symtab["size"], 24):
        name, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", symtab["data"], off)
        end = strtab.find(b"\0", name)
        out.append(dict(name=strtab[name:end].decode(), info=info, shndx=shndx, value=value,
                        size=size))
    return out


def patch32(buf, off, value):
    struct.pack_into("<I", buf, off, value & 0xFFFFFFFF)


def apply_relocs(secs, text, section_vaddr, syms):
    """Patch relocated instruction words in `text` (a bytearray)."""
    for s in secs:
        if s["type"] != 4:  # SHT_RELA
            continue
        target = secs[s["info"]]
        if target["name"] != ".text":
            continue
        base = section_vaddr[target["name"]]
        for off in range(0, s["size"], 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", s["data"], off)
            rtype, rsym = r_info & 0xFFFFFFFF, r_info >> 32
            sym = syms[rsym]
            if sym["shndx"] == 0:
                S = 0
            else:
                S = section_vaddr[secs[sym["shndx"]]["name"]] + sym["value"]
            A = r_addend
            P = base + r_offset
            word, = struct.unpack_from("<I", text, r_offset)
            if rtype in (R_ADR_PREL_PG_HI21, R_ADR_PREL_PG_HI21_NC):
                delta = ((S + A) & ~0xFFF) - (P & ~0xFFF)
                assert -(1 << 32) <= delta < (1 << 32), "adrp out of range"
                immlo = (delta >> 12) & 3
                immhi = (delta >> 14) & 0x7FFFF
                word = (word & ~((3 << 29) | (0x7FFFF << 5))) | (immlo << 29) | (immhi << 5)
                patch32(text, r_offset, word)
            elif rtype == R_ADR_PREL_LO21:
                delta = (S + A) - P
                immlo = delta & 3
                immhi = (delta >> 2) & 0x7FFFF
                word = (word & ~((3 << 29) | (0x7FFFF << 5))) | (immlo << 29) | (immhi << 5)
                patch32(text, r_offset, word)
            elif rtype in (R_ADD_ABS_LO12_NC, R_LDST8_ABS_LO12_NC, R_LDST16_ABS_LO12_NC,
                           R_LDST32_ABS_LO12_NC, R_LDST64_ABS_LO12_NC):
                imm = ((S + A) & 0xFFF) >> {R_LDST16_ABS_LO12_NC: 1, R_LDST32_ABS_LO12_NC: 2,
                                            R_LDST64_ABS_LO12_NC: 3}.get(rtype, 0)
                word = (word & ~(0xFFF << 10)) | ((imm & 0xFFF) << 10)
                patch32(text, r_offset, word)
            elif rtype in (R_CALL26, R_JUMP26):
                delta = (S + A) - P
                assert delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27), "branch out of range"
                word = (word & ~(0x3FFFFFF)) | ((delta >> 2) & 0x3FFFFFF)
                patch32(text, r_offset, word)
            elif rtype == R_CONDBR19:
                delta = (S + A) - P
                word = (word & ~(0x7FFFF << 5)) | (((delta >> 2) & 0x7FFFF) << 5)
                patch32(text, r_offset, word)
            elif rtype == R_TSTBR14:
                delta = (S + A) - P
                word = (word & ~(0x3FFF << 5)) | (((delta >> 2) & 0x3FFF) << 5)
                patch32(text, r_offset, word)
            elif rtype == R_ABS64:
                struct.pack_into("<q", text, r_offset, S + A)
            elif rtype == R_PREL64:
                struct.pack_into("<q", text, r_offset, S + A - P)
            else:
                raise SystemExit(f"unhandled relocation type {rtype} in {s['name']}")


def emit_elf(text, rodata, entry):
    phoff = 64
    nph = 2
    data_off = phoff + nph * 56
    text_off = data_off
    rodata_off = (text_off + len(text) + 0xFFF) & ~0xFFF

    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4], ehdr[5], ehdr[6] = 2, 1, 1  # ELF64, LE, version
    struct.pack_into("<HHI", ehdr, 16, 2, 0xB7, 1)  # ET_EXEC, EM_AARCH64, version
    struct.pack_into("<QQQ", ehdr, 24, entry, phoff, 0)  # entry, phoff, shoff
    struct.pack_into("<IHHHHHH", ehdr, 48, 0, 64, 56, nph, 64, 0, 0)  # flags, ehsize, phentsize

    ph = bytearray()
    ph += struct.pack("<IIQQQQQQ", 1, 5, text_off, TEXT_VADDR, TEXT_VADDR, len(text),
                      len(text), 0x1000)  # PT_LOAD, R+X
    ph += struct.pack("<IIQQQQQQ", 1, 6, rodata_off, RODATA_VADDR, RODATA_VADDR, len(rodata),
                      len(rodata), 0x1000)  # PT_LOAD, R+W

    out = bytearray(ehdr + ph)
    out += text
    out += b"\0" * (rodata_off - len(out))
    out += rodata
    return bytes(out)


def main():
    src, dst = sys.argv[1], sys.argv[2]
    entry_name = sys.argv[3] if len(sys.argv) > 3 else "_start"
    buf = open(src, "rb").read()
    secs = read_elf(buf)
    symtab = next(s for s in secs if s["type"] == 2)
    syms = read_syms(buf, secs, symtab)

    section_vaddr = {}
    rodata_blobs = bytearray()
    for s in secs:
        if not (s["flags"] & 0x2) or s["size"] == 0:  # SHF_ALLOC
            continue
        if s["name"] == ".text":
            section_vaddr[s["name"]] = TEXT_VADDR
        elif s["name"].startswith(".text"):
            section_vaddr[s["name"]] = TEXT_VADDR + len(secs_by_name(secs, ".text")["data"])
        else:
            section_vaddr[s["name"]] = RODATA_VADDR + len(rodata_blobs)
            rodata_blobs += s["data"]
            rodata_blobs += b"\0" * ((-len(rodata_blobs)) % 8)

    text = bytearray(secs_by_name(secs, ".text")["data"])
    apply_relocs(secs, text, section_vaddr, syms)

    entry_sym = next(s for s in syms if s["name"] == entry_name)
    entry = section_vaddr[secs[entry_sym["shndx"]]["name"]] + entry_sym["value"]

    open(dst, "wb").write(emit_elf(bytes(text), bytes(rodata_blobs), entry))
    print(f"{dst}: entry=0x{entry:x} text={len(text)}B rodata={len(rodata_blobs)}B")


def secs_by_name(secs, name):
    return next(s for s in secs if s["name"] == name)


if __name__ == "__main__":
    main()
