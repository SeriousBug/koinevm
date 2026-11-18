#!/usr/bin/env python3
"""Link a relocatable aarch64 Linux object into a static executable or a PIE image.

There is no lld on this machine, and the guest objects we build need only a handful of
relocation types. Layout: .text at TEXT_VADDR, all remaining allocatable data at
RODATA_VADDR, one PT_LOAD each.

`--type=dyn` emits ET_DYN with the same sections laid out from 0, so a loader can pick the base:
nothing in the output holds an absolute address that a bias would invalidate, which is the same
restriction real PIE code has before `ld.so` applies its relative relocations.
"""
import struct
import sys

TEXT_VADDR = 0x1000000
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
R_LDST128_ABS_LO12_NC = 299


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
        if s["type"] == 8:  # SHT_NOBITS: reserved space, contents are zero
            s["data"] = b"\0" * s["size"]
        elif len(s["data"]) < s["size"]:
            s["data"] = s["data"] + b"\0" * (s["size"] - len(s["data"]))
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


def apply_relocs(secs, blobs, section_vaddr, syms, blob_base):
    """Patch relocated words in every allocatable section, not just .text: a pointer table in
    .rodata needs its ABS64 relocations applied or the guest dereferences zeroes."""
    for s in secs:
        if s["type"] != 4:  # SHT_RELA
            continue
        target = secs[s["info"]]
        if target["name"] not in blobs:
            continue
        text = blobs[target["name"]]
        base = section_vaddr[target["name"]]
        r_offset_bias = 0
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
                           R_LDST32_ABS_LO12_NC, R_LDST64_ABS_LO12_NC, R_LDST128_ABS_LO12_NC):
                imm = ((S + A) & 0xFFF) >> {R_LDST16_ABS_LO12_NC: 1, R_LDST32_ABS_LO12_NC: 2,
                                            R_LDST64_ABS_LO12_NC: 3,
                                            R_LDST128_ABS_LO12_NC: 4}.get(rtype, 0)
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


def file_layout(interp):
    """Header, interp string and .text offsets in the output file. The first PT_LOAD starts at file
    offset 0 so the headers are mapped, as real linkers arrange: AT_PHDR must name readable memory."""
    nph = 3 if interp else 2
    hdr_size = 64 + nph * 56
    interp_off = hdr_size
    tail = interp_off + (len(interp) + 1 if interp else 0)
    text_off = (tail + 0xFFF) & ~0xFFF
    return nph, hdr_size, interp_off, text_off


def emit_elf(text, rodata, entry, symbols=(), etype=2, text_base=TEXT_VADDR,
             rodata_base=RODATA_VADDR, interp=None):
    nph, hdr_size, interp_off, text_off = file_layout(interp)
    rodata_off = (text_off + len(text) + 0xFFF) & ~0xFFF
    payload_end = rodata_off + len(rodata)

    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4], ehdr[5], ehdr[6] = 2, 1, 1  # ELF64, LE, version

    # .symtab so the translator can see function boundaries, as it would in a real binary
    strtab = bytearray(b"\0")
    symtab = bytearray(24)  # first symbol is the null symbol
    for name, value, size, info in symbols:
        name_off = len(strtab)
        strtab += name.encode() + b"\0"
        symtab += struct.pack("<IBBHQQ", name_off, info, 0, 1, value, size)
    symtab_off = payload_end
    strtab_off = symtab_off + len(symtab)
    shstr_off = strtab_off + len(strtab)
    shstr = bytearray(b"\0")
    names = {}
    for n in (".text", ".rodata", ".symtab", ".strtab", ".shstrtab"):
        names[n] = len(shstr)
        shstr += n.encode() + b"\0"
    shoff = (shstr_off + len(shstr) + 7) & ~7

    struct.pack_into("<HHI", ehdr, 16, etype, 0xB7, 1)  # e_type, EM_AARCH64, version
    struct.pack_into("<QQQ", ehdr, 24, entry, 64, shoff)  # entry, phoff, shoff
    struct.pack_into("<IHHHHHH", ehdr, 48, 0, 64, 56, nph, 64, 6, 5)  # flags, ehsize, shnum, shstrndx

    ph = bytearray()
    if interp:
        ph += struct.pack("<IIQQQQQQ", 3, 4, interp_off, text_base + interp_off,
                          text_base + interp_off, len(interp) + 1, len(interp) + 1, 1)  # PT_INTERP
    ph += struct.pack("<IIQQQQQQ", 1, 5, 0, text_base, text_base, text_off + len(text),
                      text_off + len(text), 0x1000)  # PT_LOAD, R+X
    ph += struct.pack("<IIQQQQQQ", 1, 6, rodata_off, rodata_base, rodata_base, len(rodata),
                      len(rodata), 0x1000)  # PT_LOAD, R+W

    out = bytearray(ehdr + ph)
    if interp:
        out += interp.encode() + b"\0"
    out += b"\0" * (text_off - len(out))
    out += text
    out += b"\0" * (rodata_off - len(out))
    out += rodata
    out += symtab
    out += strtab
    out += shstr
    out += b"\0" * (shoff - len(out))

    def sh(name, typ, flags, addr, off, size, link=0, info=0, align=1, entsize=0):
        return struct.pack("<IIQQQQIIQQ", names[name], typ, flags, addr, off, size,
                           link, info, align, entsize)

    out += struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)  # SHN_UNDEF
    out += sh(".text", 1, 0x6, text_base + text_off, text_off, len(text))
    out += sh(".rodata", 1, 0x2, rodata_base, rodata_off, len(rodata))
    out += sh(".symtab", 2, 0, 0, symtab_off, len(symtab), link=4, info=1, align=8, entsize=24)
    out += sh(".strtab", 3, 0, 0, strtab_off, len(strtab))
    out += sh(".shstrtab", 3, 0, 0, shstr_off, len(shstr))
    return bytes(out)


def main():
    positional = []
    opts = {}
    for a in sys.argv[1:]:
        if a.startswith("--"):
            k, _, v = a[2:].partition("=")
            opts[k] = v
        else:
            positional.append(a)
    src, dst = positional[0], positional[1]
    entry_name = positional[2] if len(positional) > 2 else "_start"

    etype = 3 if opts.get("type") == "dyn" else 2
    base = int(opts.get("base", "0x1000000" if etype == 2 else "0"), 0)
    interp = opts.get("interp")
    _, _, _, text_off = file_layout(interp)
    text_vaddr = base + text_off
    rodata_vaddr = base + 0x10000

    buf = open(src, "rb").read()
    secs = read_elf(buf)
    symtab = next(s for s in secs if s["type"] == 2)
    syms = read_syms(buf, secs, symtab)

    # Lay out allocatable sections: .text in the executable segment, everything else packed after it.
    # vaddrs and the output blobs must be built in the same pass, or a relocation would be applied
    # at a different address than the one the code was linked against.
    section_vaddr = {}
    blobs = {}
    rodata_blobs = bytearray()
    for s in secs:
        if not (s["flags"] & 0x2):  # SHF_ALLOC
            continue
        blobs[s["name"]] = bytearray(s["data"])
        if s["name"] == ".text":
            section_vaddr[s["name"]] = text_vaddr
        elif s["name"].startswith(".text"):
            section_vaddr[s["name"]] = text_vaddr + len(blobs[".text"])
        else:
            section_vaddr[s["name"]] = rodata_vaddr + len(rodata_blobs)
            rodata_blobs += blobs[s["name"]]
            rodata_blobs += b"\0" * ((-len(rodata_blobs)) % 8)

    text = blobs[".text"]
    apply_relocs(secs, blobs, section_vaddr, syms, {})
    rodata_blobs = bytearray()
    for s in secs:
        if s["name"] in section_vaddr and s["name"] != ".text":
            rodata_blobs += blobs[s["name"]]
            rodata_blobs += b"\0" * ((-len(rodata_blobs)) % 8)

    entry_sym = next(s for s in syms if s["name"] == entry_name)
    entry = section_vaddr[secs[entry_sym["shndx"]]["name"]] + entry_sym["value"]

    out_syms = []
    for sym in syms:
        if sym["shndx"] == 0 or sym["info"] & 0xF != 2:
            continue
        sec = secs[sym["shndx"]]["name"]
        if sec not in section_vaddr:
            continue
        out_syms.append((sym["name"], section_vaddr[sec] + sym["value"], sym["size"], sym["info"]))

    out = emit_elf(bytes(text), bytes(rodata_blobs), entry, out_syms,
                   etype=etype, text_base=base, rodata_base=rodata_vaddr, interp=interp)
    open(dst, "wb").write(out)
    kind = "ET_DYN" if etype == 3 else "ET_EXEC"
    print(f"{dst}: {kind} entry=0x{entry:x} text={len(text)}B rodata={len(rodata_blobs)}B"
          + (f" interp={interp}" if interp else ""))


def secs_by_name(secs, name):
    return next(s for s in secs if s["name"] == name)


if __name__ == "__main__":
    main()
