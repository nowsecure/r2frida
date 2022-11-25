'use strict';

import utils from '../utils.js';

const ELF_HEADER = 0x464c457f;
const EM_AARCH64 = 0xb7;

function listElfSections (baseAddr) {
  if (!_isElfHeaderAtOffset(baseAddr)) {
    throw new Error(`Not a valid ELF module found at ${baseAddr}`);
  }
  const elfHeader = parseElfHeader(baseAddr);
  return parseSegmentHeaders(baseAddr, elfHeader.phOff, elfHeader.phentSize, elfHeader.phNum);
}

function _isElfHeaderAtOffset (offset) {
  const cursor = utils.trunc4k(offset);
  if (cursor.readU32() === ELF_HEADER) {
    return true;
  }
  return false;
}

function parseSegmentHeaders (baseAddr, phOffset, entrySize, entries) {
  let cursor = baseAddr.add(phOffset);
  const segments = [];
  while (entries-- > 0) {
    const segment = {
      name: parseHeaderType(cursor.readU32()),
      perm: parseFlags(cursor.add(0x4).readU32()),
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

function parseFlags (mask) {
  let perm = '';
  if (mask & 0x4) {
    perm = perm.concat('r');
  } else {
    perm = perm.concat('-');
  }
  if (mask & 0x2) {
    perm = perm.concat('w');
  } else {
    perm = perm.concat('-');
  }
  if (mask & 0x1) {
    perm = perm.concat('x');
  } else {
    perm = perm.concat('-');
  }
  return perm;
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

function parseSectionHeaders (baseAddr, shOffset, entrySize, entries) {
  let cursor = baseAddr.add(shOffset);
  const sections = [];
  while (entries-- > 0) {
    const section = {
      name: cursor.readU32(),
      type: cursor.add(0x4).readU32(),
      flags: cursor.add(0x8).readU64(),
      addr: cursor.add(0x10).readU64(),
      offset: cursor.add(0x18).readU64(),
      size: cursor.add(0x20).readU64(),
      link: cursor.add(0x28).readU32(),
      info: cursor.add(0x2c).readU32(),
      addrAlign: cursor.add(0x30).readU64(),
      entSize: cursor.add(0x38).readU64()
    };
    cursor = cursor.add(entrySize);
    sections.push(section);
  }
  return sections;
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
export default { listElfSections };
