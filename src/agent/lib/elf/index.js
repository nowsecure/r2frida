'use strict';

import utils from '../utils.js';
import { dynamicEntries, dynamicTags, ELF_HEADER, EM_AARCH64 } from './elf_h.js';

class Section {
  constructor (name, vmaddr, vmsize, perm) {
    this.name = name;
    this.vmaddr = vmaddr;
    this.vmsize = `0x${vmsize.toString(16)}`;
    this.perm = perm !== null ? perm : '---';
  }
}

function listElfSegments (baseAddr) {
  if (!_isElfHeaderAtOffset(baseAddr)) {
    throw new Error(`Not a valid ELF module found at ${baseAddr}`);
  }
  const elfHeader = parseElfHeader(baseAddr);
  return parseSegmentHeaders(baseAddr, elfHeader.phOff, elfHeader.phentSize, elfHeader.phNum);
}

function listElfSections (baseAddr) {
  if (!_isElfHeaderAtOffset(baseAddr)) {
    throw new Error(`Not a valid ELF module found at ${baseAddr}`);
  }
  const elfHeader = parseElfHeader(baseAddr);
  const segments = parseSegmentHeaders(baseAddr, elfHeader.phOff, elfHeader.phentSize, elfHeader.phNum);
  for (const segment of segments) {
    if (segment.name === 'PT_DYNAMIC') {
      return parseSectionHeaders(baseAddr, segment.vmaddr, segment.vmsize, segments);
    }
  }
}

function _isElfHeaderAtOffset (offset) {
  const cursor = utils.trunc4k(offset);
  if (cursor.readU32() === ELF_HEADER) {
    return true;
  }
  return false;
}

function parseSectionHeaders (baseAddr, PTDynamicAddr, PTDynamicSize, segments) {
  let cursor = PTDynamicAddr;
  const sections = [];

  while (cursor < PTDynamicAddr.add(PTDynamicSize)) {
    const dTag = cursor.readU64();
    if (dynamicEntries[parseInt(dTag)] !== undefined) {
      if (dynamicEntries[parseInt(dTag)].type === 'val') {
        dynamicEntries[parseInt(dTag)].value = cursor.add(8).readU64();
      } else {
        dynamicEntries[parseInt(dTag)].value = baseAddr.add(cursor.add(8).readPointer());
      }
    }
    cursor = cursor.add(16);
  }
  // HASH Section
  const hashTablePtr = dynamicEntries[dynamicTags.DT_HASH].value;
  const nbucket = hashTablePtr.readU32();
  const nchain = hashTablePtr.add(4).readU32();
  sections.push(new Section(
    dynamicEntries[dynamicTags.DT_HASH].name,
    hashTablePtr,
    (nbucket * 4) + (nchain * 4) + 8,
    utils.belongsTo(segments, hashTablePtr).map(x => x.perm)
  ));
  // STRTAB Section
  sections.push(new Section(
    dynamicEntries[dynamicTags.DT_STRTAB].name,
    dynamicEntries[dynamicTags.DT_STRTAB].value,
    dynamicEntries[dynamicTags.DT_STRSZ].value,
    utils.belongsTo(segments, dynamicEntries[dynamicTags.DT_STRTAB].value).map(x => x.perm)
  ));
  // DYNSYM Section
  const symTabSize = nchain * dynamicEntries[dynamicTags.DT_SYMENT].value;
  sections.push(new Section(
    dynamicEntries[dynamicTags.DT_SYMTAB].name,
    dynamicEntries[dynamicTags.DT_SYMTAB].value,
    symTabSize,
    utils.belongsTo(segments, dynamicEntries[dynamicTags.DT_SYMTAB].value).map(x => x.perm)
  ));
  // DT_PREINIT_ARRAY Section (Optional)
  if (dynamicEntries[dynamicTags.DT_PREINIT_ARRAY].value !== null) {
    sections.push(new Section(
      dynamicEntries[dynamicTags.DT_PREINIT_ARRAY].name,
      dynamicEntries[dynamicTags.DT_PREINIT_ARRAY].value,
      dynamicEntries[dynamicTags.DT_PREINIT_ARRAYSZ].value,
      utils.belongsTo(segments, dynamicEntries[dynamicTags.DT_PREINIT_ARRAY].value).map(x => x.perm)
    ));
  }
  // DT_INIT_ARRAY Section (Optional)
  if (dynamicEntries[dynamicTags.DT_INIT_ARRAY].value !== null) {
    sections.push(new Section(
      dynamicEntries[dynamicTags.DT_INIT_ARRAY].name,
      dynamicEntries[dynamicTags.DT_INIT_ARRAY].value,
      dynamicEntries[dynamicTags.DT_INIT_ARRAYSZ].value,
      utils.belongsTo(segments, dynamicEntries[dynamicTags.DT_INIT_ARRAY].value).map(x => x.perm)
    ));
  }
  // DT_FINI_ARRAY Section (Optional)
  if (dynamicEntries[dynamicTags.DT_FINI_ARRAY].value !== null) {
    sections.push(new Section(
      dynamicEntries[dynamicTags.DT_FINI_ARRAY].name,
      dynamicEntries[dynamicTags.DT_FINI_ARRAY].value,
      dynamicEntries[dynamicTags.DT_FINI_ARRAYSZ].value,
      utils.belongsTo(segments, dynamicEntries[dynamicTags.DT_FINI_ARRAY].value).map(x => x.perm)
    ));
  }
  // DT_REL Section (Optional)
  if (dynamicEntries[dynamicTags.DT_REL].value !== null) {
    sections.push(new Section(
      dynamicEntries[dynamicTags.DT_REL].name,
      dynamicEntries[dynamicTags.DT_REL].value,
      dynamicEntries[dynamicTags.DT_RELSZ].value,
      utils.belongsTo(segments, dynamicEntries[dynamicTags.DT_REL].value).map(x => x.perm)
    ));
  }
  // DT_RELA Section (Optional)
  if (dynamicEntries[dynamicTags.DT_RELA].value !== null) {
    sections.push(new Section(
      dynamicEntries[dynamicTags.DT_RELA].name,
      dynamicEntries[dynamicTags.DT_RELA].value,
      dynamicEntries[dynamicTags.DT_RELASZ].value,
      utils.belongsTo(segments, dynamicEntries[dynamicTags.DT_RELA].value).map(x => x.perm)
    ));
  }
  return sections;
}

function parseSegmentHeaders (baseAddr, phOffset, entrySize, entries) {
  let cursor = baseAddr.add(phOffset);
  const segments = [];
  while (entries-- > 0) {
    const segment = {
      name: parseHeaderType(cursor.readU32()),
      perm: utils.rwxstr(cursor.add(0x4).readU32()),
      fileoff: cursor.add(0x8).readPointer(),
      vmaddr: (cursor.add(0x10).readPointer()).add(baseAddr),
      filesize: cursor.add(0x20).readPointer(),
      vmsize: cursor.add(0x28).readPointer(),
      align: cursor.add(0x30).readPointer()
    };
    cursor = cursor.add(entrySize);
    segments.push(segment);
  }
  return segments;
}

function parseHeaderType (value) {
  switch (value) {
    case 0:
      return 'PT_NULL';
    case 1:
      return 'PT_LOAD';
    case 2:
      return 'PT_DYNAMIC';
    case 3:
      return 'PT_INTERP';
    case 4:
      return 'PT_NOTE';
    case 5:
      return 'PT_SHLIB';
    case 6:
      return 'PT_PHDR';
    case 7:
      return 'PT_TLS';
    case 0x60000000:
      return 'PT_LOOS';
    case 0x6FFFFFFF:
      return 'PT_HIOS';
    case 0x70000000:
      return 'PT_LOPROC';
    case 0x7FFFFFFF:
      return 'PT_HIPROC';
  }
}

function parseElfHeader (offset) {
  const header = {
    magic: offset.readU32(),
    class: offset.add(0x4).readU8(),
    data: offset.add(0x5).readU8(),
    hdrVersion: offset.add(0x6).readU8(),
    type: offset.add(0x10).readU16(),
    machine: offset.add(0x12).readU16(),
    objVersion: offset.add(0x14).readU32(),
    entrypoint: offset.add(0x18).readU64(),
    phOff: offset.add(0x20).readU64(),
    shOff: offset.add(0x28).readU64(),
    flags: offset.add(0x30).readU32(),
    ehSize: offset.add(0x34).readU16(),
    phentSize: offset.add(0x36).readU16(),
    phNum: offset.add(0x38).readU16(),
    shentSize: offset.add(0x3a).readU16(),
    shNum: offset.add(0x3c).readU16(),
    shrStrndx: offset.add(0x3e).readU16()
  };
  if (header.machine === EM_AARCH64) {
    return header;
  }
  throw new Error('Only support for 64-bit apps');
}

export { listElfSections };
export { listElfSegments };
export default { listElfSections, listElfSegments };
