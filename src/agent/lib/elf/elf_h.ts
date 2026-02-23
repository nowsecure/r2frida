export const ELF_HEADER = 0x464c457f;
export const EM_AARCH64 = 0xb7;
export const EM_X86_64 = 0x3e;

export class Elf64Dyn {
    name: string;
    type: string | null;
    value: string | null;
    constructor(name: string, type: string | null) {
        this.name = name;
        this.type = type;
        this.value = null;
    }
}

export const dynamicTags: any = {
    DT_NULL: 0,
    DT_NEEDED: 1,
    DT_PLTRELSZ: 2,
    DT_PLTGOT: 3,
    DT_HASH: 4,
    DT_STRTAB: 5,
    DT_SYMTAB: 6,
    DT_RELA: 7,
    DT_RELASZ: 8,
    DT_RELAENT: 9,
    DT_STRSZ: 10,
    DT_SYMENT: 11,
    DT_INIT: 12,
    DT_FINI: 13,
    DT_SONAME: 14,
    DT_RPATH: 15,
    DT_SYMBOLIC: 16,
    DT_REL: 17,
    DT_RELSZ: 18,
    DT_RELENT: 19,
    DT_PLTREL: 20,
    DT_DEBUG: 21,
    DT_TEXTREL: 22,
    DT_JMPREL: 23,
    DT_BIND_NOW: 24,
    DT_INIT_ARRAY: 25,
    DT_FINI_ARRAY: 26,
    DT_INIT_ARRAYSZ: 27,
    DT_FINI_ARRAYSZ: 28,
    DT_RUNPATH: 29,
    DT_FLAGS: 30,
    DT_PREINIT_ARRAY: 32,
    DT_PREINIT_ARRAYSZ: 33,
};

/* ELF Dynamic Array Tags */
export const dynamicEntries: any = {
    0: new Elf64Dyn("DT_NULL", null),
    1: new Elf64Dyn("DT_NEEDED", "val"),
    2: new Elf64Dyn("DT_PLTRELSZ", "val"),
    3: new Elf64Dyn("DT_PLTGOT", "ptr"),
    4: new Elf64Dyn("DT_HASH", "ptr"),
    5: new Elf64Dyn("DT_STRTAB", "ptr"),
    6: new Elf64Dyn("DT_SYMTAB", "ptr"),
    7: new Elf64Dyn("DT_RELA", "ptr"),
    8: new Elf64Dyn("DT_RELASZ", "val"),
    9: new Elf64Dyn("DT_RELAENT", "val"),
    10: new Elf64Dyn("DT_STRSZ", "val"),
    11: new Elf64Dyn("DT_SYMENT", "val"),
    12: new Elf64Dyn("DT_INIT", "ptr"),
    13: new Elf64Dyn("DT_FINI", "ptr"),
    14: new Elf64Dyn("DT_SONAME", "val"),
    15: new Elf64Dyn("DT_RPATH", "val"),
    16: new Elf64Dyn("DT_SYMBOLIC", null),
    17: new Elf64Dyn("DT_REL", "ptr"),
    18: new Elf64Dyn("DT_RELSZ", "val"),
    19: new Elf64Dyn("DT_RELENT", "val"),
    20: new Elf64Dyn("DT_PLTREL", "val"),
    21: new Elf64Dyn("DT_DEBUG", "ptr"),
    22: new Elf64Dyn("DT_TEXTREL", null),
    23: new Elf64Dyn("DT_JMPREL", "ptr"),
    24: new Elf64Dyn("DT_BIND_NOW", null),
    25: new Elf64Dyn("DT_INIT_ARRAY", "ptr"),
    26: new Elf64Dyn("DT_FINI_ARRAY", "ptr"),
    27: new Elf64Dyn("DT_INIT_ARRAYSZ", "val"),
    28: new Elf64Dyn("DT_FINI_ARRAYSZ", "val"),
    29: new Elf64Dyn("DT_RUNPATH", "val"),
    30: new Elf64Dyn("DT_FLAGS", "val"),
    32: new Elf64Dyn("DT_PREINIT_ARRAY", "ptr"),
    33: new Elf64Dyn("DT_PREINIT_ARRAYSZ", "val"),
};

export default {
    ELF_HEADER,
    EM_AARCH64,
    EM_X86_64,
    dynamicTags,
    dynamicEntries,
};
