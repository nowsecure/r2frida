'use strict';

const expr = require('../expr');
const globals = require('../globals');
const utils = require('../utils');

function listMemoryRanges () {
  return listMemoryRangesJson()
    .map(({ base, size, protection, file }) =>
      [utils.padPointer(base), '-', utils.padPointer(base.add(size)), protection]
        .concat((file !== undefined) ? [file.path] : [])
        .join(' ')
    )
    .join('\n') + '\n';
}

function listMemoryRangesR2 () {
  return listMemoryRangesJson()
    .map(({ base, size, protection, file }) =>
      [
        'f', 'map.' + utils.padPointer(base) + '.' + protection.replace(/-/g, '_'), size, base,
        '#', protection
      ]
        .concat((file !== undefined) ? [file.path] : [])
        .join(' ')
    )
    .join('\n') + '\n';
}

function listMemoryRangesJson () {
  return _getMemoryRanges('---');
}

async function changeMemoryProtection (args) {
  const [addr, size, protection] = args;
  if (args.length !== 3 || protection.length > 3) {
    return 'Usage: :dmp [address] [size] [rwx]';
  }
  const address = utils.getPtr(addr);
  const mapsize = await expr.numEval(size);
  Memory.protect(address, ptr(mapsize).toInt32(), protection);
  return '';
}

function listMemoryRangesHere (args) {
  if (args.length !== 1) {
    args = [ptr(global.r2frida.offset)];
  }
  const addr = ptr(args[0]);
  return listMemoryRangesJson()
    .filter(({ base, size }) => addr.compare(base) >= 0 && addr.compare(base.add(size)) < 0)
    .map(({ base, size, protection, file }) =>
      [
        utils.padPointer(base),
        '-',
        utils.padPointer(base.add(size)),
        protection
      ]
        .concat((file !== undefined) ? [file.path] : [])
        .join(' ')
    )
    .join('\n') + '\n';
}

function listMemoryMaps () {
  return _squashRanges(listMemoryRangesJson())
    .filter(_ => _.file)
    .map(({ base, size, protection, file }) =>
      [utils.padPointer(base), '-', utils.padPointer(base.add(size)), protection]
        .concat((file !== undefined) ? [file.path] : [])
        .join(' ')
    )
    .join('\n') + '\n';
}

function listMemoryMapsR2 () {
  return _squashRanges(listMemoryRangesJson())
    .filter(_ => _.file)
    .map(({ base, size, protection, file }) =>
      [
        'f',
        'dmm.' + utils.sanitizeString(file.path),
        '=',
        utils.padPointer(base)
      ]
        .join(' ')
    )
    .join('\n') + '\n';
}

function listMallocRanges (args) {
  return _squashRanges(listMallocRangesJson(args))
    .map(_ => '' + _.base + ' - ' + _.base.add(_.size) + '  (' + _.size + ')').join('\n') + '\n';
}

function listMallocRangesJson (args) {
  return Process.enumerateMallocRanges();
}

function listMallocRangesR2 (args) {
  const chunks = listMallocRangesJson(args)
    .map(_ => 'f chunk.' + _.base + ' ' + _.size + ' ' + _.base).join('\n');
  return chunks + _squashRanges(listMallocRangesJson(args))
    .map(_ => 'f heap.' + _.base + ' ' + _.size + ' ' + _.base).join('\n');
}

function listMemoryMapsHere (args) {
  if (args.length !== 1) {
    args = [ptr(global.r2frida.offset)];
  }
  const addr = ptr(args[0]);
  return _squashRanges(listMemoryRangesJson())
    .filter(({ base, size }) => addr.compare(base) >= 0 && addr.compare(base.add(size)) < 0)
    .map(({ base, size, protection, file }) => {
      return [
        utils.padPointer(base),
        '-',
        utils.padPointer(base.add(size)),
        protection,
        file.path
      ].join(' ');
    })
    .join('\n') + '\n';
}

function listMallocMaps (args) {
  const heaps = _squashRanges(listMallocRangesJson(args));
  function inRange (x) {
    for (const heap of heaps) {
      if (x.base.compare(heap.base) >= 0 &&
      x.base.add(x.size).compare(heap.base.add(heap.size))) {
        return true;
      }
    }
    return false;
  }
  return _squashRanges(listMemoryRangesJson())
    .filter(inRange)
    .map(({ base, size, protection, file }) =>
      [utils.padPointer(base), '-', utils.padPointer(base.add(size)), protection]
        .concat((file !== undefined) ? [file.path] : [])
        .join(' ')
    )
    .join('\n') + '\n';
}

function allocSize (args) {
  const size = +args[0];
  if (size > 0) {
    const a = Memory.alloc(size);
    return _addAlloc(a);
  }
  return 0;
}

function allocString (args) {
  const theString = args.join(' ');
  if (theString.length > 0) {
    const a = Memory.allocUtf8String(theString);
    return _addAlloc(a);
  }
  throw new Error('Usage: dmas [string]');
}

function allocWstring (args) {
  const theString = args.join(' ');
  if (theString.length > 0) {
    const a = Memory.allocUtf16String(theString);
    return _addAlloc(a);
  }
  throw new Error('Usage: dmaw [string]');
}

function allocDup (args) {
  if (args.length < 2) {
    throw new Error('Missing argument');
  }
  const addr = +args[0];
  const size = +args[1];
  if (addr > 0 && size > 0) {
    const a = Memory.dup(ptr(addr), size);
    return _addAlloc(a);
  }
  return 0;
}

function listAllocs (args) {
  return Object.values(globals.allocPool)
    .sort()
    .map((x) => {
      const bytes = Memory.readByteArray(x, 60);
      const printables = utils.filterPrintable(bytes);
      return `${x}\t"${printables}"`;
    })
    .join('\n') + '\n';
}

function removeAlloc (args) {
  if (args.length === 0) {
    _clearAllocs();
  } else {
    for (const addr of args) {
      _delAlloc(addr);
    }
  }
  return '';
}

function _getMemoryRanges (protection) {
  if (global.r2frida.hookedRanges !== null) {
    return global.r2frida.hookedRanges(protection);
  }
  return Process.enumerateRangesSync({
    protection,
    coalesce: false
  });
}

function _delAlloc (addr) {
  delete globals.allocPool[addr];
}

function _clearAllocs () {
  Object.keys(globals.allocPool)
    .forEach(addr => delete globals.allocPool[addr]);
}

function _addAlloc (allocPtr) {
  const key = allocPtr.toString();
  if (!allocPtr.isNull()) {
    globals.allocPool[key] = allocPtr;
  }
  return key;
}

function _squashRanges (ranges) {
  const res = [];
  let begin = ptr(0);
  let end = ptr(0);
  let lastPerm = 0;
  let lastFile = '';
  for (const r of ranges) {
    lastPerm |= utils.rwxint(r.protection);
    // console.log("-", r.base, range.base.add(range.size));
    if (r.base.equals(end)) {
      // enlarge segment
      end = end.add(r.size);
      // console.log("enlarge", begin, end);
    } else {
      if (begin.equals(ptr(0))) {
        begin = r.base;
        end = begin.add(r.size);
        // console.log("  set", begin, end);
      } else {
        // console.log("  append", begin, end);
        res.push({
          base: begin,
          size: end.sub(begin),
          protection: utils.rwxstr(lastPerm),
          file: lastFile
        });
        end = ptr(0);
        begin = ptr(0);
        lastPerm = 0;
        lastFile = '';
      }
    }
    if (r.file) {
      lastFile = r.file;
    }
  }
  if (!begin.equals(ptr(0))) {
    res.push({ base: begin, size: end.sub(begin), protection: utils.rwxstr(lastPerm), file: lastFile });
  }
  return res;
}

module.exports = {
  listMemoryRanges,
  listMemoryRangesR2,
  listMemoryRangesJson,
  changeMemoryProtection,
  listMemoryRangesHere,
  listMemoryMaps,
  listMemoryMapsR2,
  listMemoryMapsHere,
  listMallocRanges,
  listMallocRangesR2,
  listMallocRangesJson,
  listMallocMaps,
  allocSize,
  allocString,
  allocWstring,
  allocDup,
  listAllocs,
  removeAlloc
};
