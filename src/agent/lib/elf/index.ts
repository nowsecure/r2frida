import * as utils from "../utils.js";
import {
    dynamicEntries,
    dynamicTags,
    ELF_HEADER,
    EM_AARCH64,
    EM_X86_64,
} from "./elf_h.js";

class Section {
    name: string;
    vmaddr: NativePointer;
    vmsize: string | number;
    perm: string;
    constructor(
        name: string,
        vmaddr: NativePointer,
        vmsize: number,
        perm: string,
    ) {
        this.name = name;
        this.vmaddr = vmaddr;
        this.vmsize = `0x${vmsize.toString(16)}`;
        this.perm = perm !== null ? perm : "---";
    }
}

function listElfSegments(baseAddr: NativePointer) {
    if (!_isElfHeaderAtOffset(baseAddr)) {
        throw new Error(`Not a valid ELF module found at ${baseAddr}`);
    }
    const elfHeader = parseElfHeader(baseAddr);
    return parseSegmentHeaders(
        baseAddr,
        elfHeader.phOff,
        elfHeader.phentSize,
        elfHeader.phNum,
    );
}

function listElfSections(baseAddr: NativePointer) {
    if (!_isElfHeaderAtOffset(baseAddr)) {
        throw new Error(`Not a valid ELF module found at ${baseAddr}`);
    }
    const elfHeader = parseElfHeader(baseAddr);
    const segments = parseSegmentHeaders(
        baseAddr,
        elfHeader.phOff,
        elfHeader.phentSize,
        elfHeader.phNum,
    );
    for (const segment of segments) {
        if (segment.name === "PT_DYNAMIC") {
            return parseSectionHeaders(
                baseAddr,
                segment.vmaddr,
                segment.vmsize,
                segments,
            );
        }
    }
    return [];
}

function _isElfHeaderAtOffset(offset: NativePointer): boolean {
    const cursor = utils.trunc4k(offset);
    if (cursor.readU32() === ELF_HEADER) {
        return true;
    }
    return false;
}

function permOf(segments: any, addr: NativePointer): string {
    const owners = utils.belongsTo(segments, addr);
    if (owners.length > 0 && owners[0].perm) {
        return owners[0].perm;
    }
    return "---";
}

function gnuHashSymbolCount(hashTablePtr: NativePointer): number {
    const nbuckets = hashTablePtr.readU32();
    const symoffset = hashTablePtr.add(4).readU32();
    const bloomSize = hashTablePtr.add(8).readU32();
    const bucketsPtr = hashTablePtr.add(16 + (bloomSize * 8));
    const chainPtr = bucketsPtr.add(nbuckets * 4);
    let maxBucket = 0;
    for (let i = 0; i < nbuckets; i++) {
        const v = bucketsPtr.add(i * 4).readU32();
        if (v > maxBucket) {
            maxBucket = v;
        }
    }
    if (maxBucket < symoffset) {
        return symoffset;
    }
    let idx = maxBucket - symoffset;
    // walk chain until terminator (LSB set)
    while ((chainPtr.add(idx * 4).readU32() & 1) === 0) {
        idx++;
        if (idx > 0x100000) {
            break; // safety cap
        }
    }
    return symoffset + idx + 1;
}

function verneedSize(
    tablePtr: NativePointer,
    count: number,
): number {
    // Walk Elf_Verneed chain to compute total size in bytes.
    // Each Elf_Verneed: u16 vn_version, u16 vn_cnt, u32 vn_file,
    //                   u32 vn_aux, u32 vn_next  (16 bytes)
    // Each Elf_Vernaux: 16 bytes; vn_cnt of them per Verneed entry.
    let offset = 0;
    for (let i = 0; i < count; i++) {
        const cur = tablePtr.add(offset);
        const vnCnt = cur.add(2).readU16();
        const vnAux = cur.add(8).readU32();
        const vnNext = cur.add(12).readU32();
        if (vnNext === 0 || i === count - 1) {
            return offset + Math.max(vnAux + (vnCnt * 16), 16);
        }
        offset += vnNext;
        if (offset > 0x10000000) {
            break; // safety cap
        }
    }
    return offset;
}

function verdefSize(
    tablePtr: NativePointer,
    count: number,
): number {
    // Walk Elf_Verdef chain to compute total size in bytes.
    // Each Elf_Verdef (20 bytes):
    //   u16 vd_version, u16 vd_flags, u16 vd_ndx, u16 vd_cnt,
    //   u32 vd_hash, u32 vd_aux, u32 vd_next
    // Each Elf_Verdaux (8 bytes):
    //   u32 vda_name, u32 vda_next
    let offset = 0;
    for (let i = 0; i < count; i++) {
        const cur = tablePtr.add(offset);
        const vdCnt = cur.add(6).readU16();
        const vdAux = cur.add(12).readU32();
        const vdNext = cur.add(16).readU32();
        if (vdNext === 0 || i === count - 1) {
            return offset + Math.max(vdAux + (vdCnt * 8), 20);
        }
        offset += vdNext;
        if (offset > 0x10000000) {
            break; // safety cap
        }
    }
    return offset;
}

function resetDynamicEntries() {
    for (const k of Object.keys(dynamicEntries)) {
        dynamicEntries[k].value = null;
    }
}

function parseSectionHeaders(
    baseAddr: NativePointer,
    PTDynamicAddr: NativePointer,
    PTDynamicSize: any,
    segments: any,
) {
    resetDynamicEntries();
    let cursor = PTDynamicAddr;
    const sections = [];
    const end = PTDynamicAddr.add(PTDynamicSize);
    // .dynamic itself
    sections.push(
        new Section(
            "DYNAMIC",
            PTDynamicAddr,
            typeof PTDynamicSize === "number"
                ? PTDynamicSize
                : Number(PTDynamicSize),
            permOf(segments, PTDynamicAddr),
        ),
    );

    while (cursor.compare(end) < 0) {
        const dTag = cursor.readU64().toNumber();
        if (dTag === 0) {
            break; // DT_NULL terminator
        }
        if (dynamicEntries[dTag] !== undefined) {
            if (dynamicEntries[dTag].type === "val") {
                dynamicEntries[dTag].value = cursor.add(8).readU64();
            } else if (dynamicEntries[dTag].type === "ptr") {
                dynamicEntries[dTag].value = baseAddr.add(
                    cursor.add(8).readPointer(),
                );
            }
        }
        cursor = cursor.add(16);
    }
    // HASH Section
    let nchain = 0;
    const hashTablePtr = dynamicEntries[dynamicTags.DT_HASH].value;
    if (hashTablePtr) {
        const nbucket = hashTablePtr.readU32();
        nchain = hashTablePtr.add(4).readU32();
        sections.push(
            new Section(
                dynamicEntries[dynamicTags.DT_HASH].name,
                hashTablePtr,
                (nbucket * 4) + (nchain * 4) + 8,
                permOf(segments, hashTablePtr),
            ),
        );
    }
    // GNU_HASH Section (modern ELFs use this instead of DT_HASH)
    const gnuHashPtr = dynamicEntries[dynamicTags.DT_GNU_HASH].value;
    if (gnuHashPtr) {
        const symCount = gnuHashSymbolCount(gnuHashPtr);
        if (nchain === 0) {
            nchain = symCount;
        }
        const nbuckets = gnuHashPtr.readU32();
        const bloomSize = gnuHashPtr.add(8).readU32();
        // header(16) + bloom(bloomSize*8) + buckets(nbuckets*4) + chain(symCount-symoffset)*4
        const symoffset = gnuHashPtr.add(4).readU32();
        const chainEntries = symCount > symoffset ? symCount - symoffset : 0;
        const gnuHashSize = 16 + (bloomSize * 8) + (nbuckets * 4) +
            (chainEntries * 4);
        sections.push(
            new Section(
                dynamicEntries[dynamicTags.DT_GNU_HASH].name,
                gnuHashPtr,
                gnuHashSize,
                permOf(segments, gnuHashPtr),
            ),
        );
    }
    // STRTAB Section
    if (dynamicEntries[dynamicTags.DT_STRTAB].value !== null) {
        sections.push(
            new Section(
                dynamicEntries[dynamicTags.DT_STRTAB].name,
                dynamicEntries[dynamicTags.DT_STRTAB].value,
                dynamicEntries[dynamicTags.DT_STRSZ].value,
                permOf(segments, dynamicEntries[dynamicTags.DT_STRTAB].value),
            ),
        );
    }
    // DYNSYM Section
    if (
        dynamicEntries[dynamicTags.DT_SYMTAB].value !== null &&
        dynamicEntries[dynamicTags.DT_SYMENT].value !== null && nchain > 0
    ) {
        const symTabSize = nchain *
            dynamicEntries[dynamicTags.DT_SYMENT].value;
        sections.push(
            new Section(
                dynamicEntries[dynamicTags.DT_SYMTAB].name,
                dynamicEntries[dynamicTags.DT_SYMTAB].value,
                symTabSize,
                permOf(segments, dynamicEntries[dynamicTags.DT_SYMTAB].value),
            ),
        );
    }
    // DT_PREINIT_ARRAY Section (Optional)
    if (dynamicEntries[dynamicTags.DT_PREINIT_ARRAY].value !== null) {
        sections.push(
            new Section(
                dynamicEntries[dynamicTags.DT_PREINIT_ARRAY].name,
                dynamicEntries[dynamicTags.DT_PREINIT_ARRAY].value,
                dynamicEntries[dynamicTags.DT_PREINIT_ARRAYSZ].value,
                permOf(
                    segments,
                    dynamicEntries[dynamicTags.DT_PREINIT_ARRAY].value,
                ),
            ),
        );
    }
    // DT_INIT_ARRAY Section (Optional)
    if (dynamicEntries[dynamicTags.DT_INIT_ARRAY].value !== null) {
        sections.push(
            new Section(
                dynamicEntries[dynamicTags.DT_INIT_ARRAY].name,
                dynamicEntries[dynamicTags.DT_INIT_ARRAY].value,
                dynamicEntries[dynamicTags.DT_INIT_ARRAYSZ].value,
                permOf(
                    segments,
                    dynamicEntries[dynamicTags.DT_INIT_ARRAY].value,
                ),
            ),
        );
    }
    // DT_FINI_ARRAY Section (Optional)
    if (dynamicEntries[dynamicTags.DT_FINI_ARRAY].value !== null) {
        sections.push(
            new Section(
                dynamicEntries[dynamicTags.DT_FINI_ARRAY].name,
                dynamicEntries[dynamicTags.DT_FINI_ARRAY].value,
                dynamicEntries[dynamicTags.DT_FINI_ARRAYSZ].value,
                permOf(
                    segments,
                    dynamicEntries[dynamicTags.DT_FINI_ARRAY].value,
                ),
            ),
        );
    }
    // DT_REL Section (Optional)
    if (dynamicEntries[dynamicTags.DT_REL].value !== null) {
        sections.push(
            new Section(
                dynamicEntries[dynamicTags.DT_REL].name,
                dynamicEntries[dynamicTags.DT_REL].value,
                dynamicEntries[dynamicTags.DT_RELSZ].value,
                permOf(segments, dynamicEntries[dynamicTags.DT_REL].value),
            ),
        );
    }
    // DT_RELA Section (Optional)
    if (dynamicEntries[dynamicTags.DT_RELA].value !== null) {
        sections.push(
            new Section(
                dynamicEntries[dynamicTags.DT_RELA].name,
                dynamicEntries[dynamicTags.DT_RELA].value,
                dynamicEntries[dynamicTags.DT_RELASZ].value,
                permOf(segments, dynamicEntries[dynamicTags.DT_RELA].value),
            ),
        );
    }
    // DT_JMPREL Section (.rela.plt / .rel.plt) (Optional)
    if (
        dynamicEntries[dynamicTags.DT_JMPREL].value !== null &&
        dynamicEntries[dynamicTags.DT_PLTRELSZ].value !== null
    ) {
        sections.push(
            new Section(
                dynamicEntries[dynamicTags.DT_JMPREL].name,
                dynamicEntries[dynamicTags.DT_JMPREL].value,
                dynamicEntries[dynamicTags.DT_PLTRELSZ].value,
                permOf(segments, dynamicEntries[dynamicTags.DT_JMPREL].value),
            ),
        );
    }
    // DT_VERSYM Section (Optional)
    if (
        dynamicEntries[dynamicTags.DT_VERSYM].value !== null && nchain > 0
    ) {
        sections.push(
            new Section(
                dynamicEntries[dynamicTags.DT_VERSYM].name,
                dynamicEntries[dynamicTags.DT_VERSYM].value,
                nchain * 2,
                permOf(segments, dynamicEntries[dynamicTags.DT_VERSYM].value),
            ),
        );
    }
    // DT_VERNEED Section (.gnu.version_r) (Optional)
    if (
        dynamicEntries[dynamicTags.DT_VERNEED].value !== null &&
        dynamicEntries[dynamicTags.DT_VERNEEDNUM].value !== null
    ) {
        const vnPtr = dynamicEntries[dynamicTags.DT_VERNEED].value;
        const vnCount = Number(
            dynamicEntries[dynamicTags.DT_VERNEEDNUM].value,
        );
        sections.push(
            new Section(
                dynamicEntries[dynamicTags.DT_VERNEED].name,
                vnPtr,
                verneedSize(vnPtr, vnCount),
                permOf(segments, vnPtr),
            ),
        );
    }
    // DT_VERDEF Section (.gnu.version_d) (Optional)
    if (
        dynamicEntries[dynamicTags.DT_VERDEF].value !== null &&
        dynamicEntries[dynamicTags.DT_VERDEFNUM].value !== null
    ) {
        const vdPtr = dynamicEntries[dynamicTags.DT_VERDEF].value;
        const vdCount = Number(
            dynamicEntries[dynamicTags.DT_VERDEFNUM].value,
        );
        sections.push(
            new Section(
                dynamicEntries[dynamicTags.DT_VERDEF].name,
                vdPtr,
                verdefSize(vdPtr, vdCount),
                permOf(segments, vdPtr),
            ),
        );
    }
    return sections;
}

function parseSegmentHeaders(
    baseAddr: NativePointer,
    phOffset: number,
    entrySize: number,
    entries: number,
) {
    let cursor = baseAddr.add(phOffset);
    const segments: any[] = [];
    while (entries-- > 0) {
        const segment = {
            name: parseHeaderType(cursor.readU32()),
            perm: utils.rwxstr(cursor.add(0x4).readU32()),
            fileoff: cursor.add(0x8).readPointer(),
            vmaddr: (cursor.add(0x10).readPointer()).add(baseAddr),
            filesize: cursor.add(0x20).readPointer(),
            vmsize: cursor.add(0x28).readPointer(),
            align: cursor.add(0x30).readPointer(),
        };
        cursor = cursor.add(entrySize);
        if (segment.name !== null) {
            segments.push(segment);
        }
    }
    return segments;
}

function parseHeaderType(value: number): string | null {
    switch (value) {
        case 0:
            return "PT_NULL";
        case 1:
            return "PT_LOAD";
        case 2:
            return "PT_DYNAMIC";
        case 3:
            return "PT_INTERP";
        case 4:
            return "PT_NOTE";
        case 5:
            return "PT_SHLIB";
        case 6:
            return "PT_PHDR";
        case 7:
            return "PT_TLS";
        case 0x6474e550:
            return "PT_GNU_EH_FRAME";
        case 0x6474e551:
            return "PT_GNU_STACK";
        case 0x6474e552:
            return "PT_GNU_RELRO";
        case 0x6474e553:
            return "PT_GNU_PROPERTY";
        case 0x60000000:
            return "PT_LOOS";
        case 0x6FFFFFFF:
            return "PT_HIOS";
        case 0x70000000:
            return "PT_LOPROC";
        case 0x7FFFFFFF:
            return "PT_HIPROC";
    }
    return null;
}

function parseElfHeader(offset: NativePointer): any {
    const header = {
        magic: offset.readU32(),
        class: offset.add(0x4).readU8(),
        data: offset.add(0x5).readU8(),
        hdrVersion: offset.add(0x6).readU8(),
        type: offset.add(0x10).readU16(),
        machine: offset.add(0x12).readU16(),
        objVersion: offset.add(0x14).readU32(),
        entrypoint: offset.add(0x18).readU64(),
        phOff: offset.add(0x20).readU64().toNumber(),
        shOff: offset.add(0x28).readU64(),
        flags: offset.add(0x30).readU32(),
        ehSize: offset.add(0x34).readU16(),
        phentSize: offset.add(0x36).readU16(),
        phNum: offset.add(0x38).readU16(),
        shentSize: offset.add(0x3a).readU16(),
        shNum: offset.add(0x3c).readU16(),
        shrStrndx: offset.add(0x3e).readU16(),
    };
    switch (header.machine) {
        case EM_AARCH64:
        case EM_X86_64:
            return header;
    }
    throw new Error("Only works on 64-bit arm/intel apps");
}

export { listElfSections };
export { listElfSegments };
export { parseElfHeader };
export default { listElfSections, listElfSegments };
