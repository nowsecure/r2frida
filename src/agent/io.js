'use strict';

const r2frida = require('./plugin'); // eslint-disable-line
const config = require('./config');

function read (params) {
  const { offset, count, fast } = params;
  if (r2frida.hookedRead !== null) {
    return r2frida.hookedRead(offset, count);
  }
  if (offset < 0) {
    return [{}, []];
  }
  try {
    const bytes = Memory.readByteArray(ptr(offset), count);
    // console.log("FAST", offset);
    return [{}, (bytes !== null) ? bytes : []];
  } catch (e) {
    if (!fast) {
      try {
      // console.log("SLOW", offset);
        const readStarts = ptr(offset);
        const readEnds = readStarts.add(count);
        const currentRange = Process.getRangeByAddress(readStarts); // this is very slow
        const moduleEnds = currentRange.base.add(currentRange.size);
        const left = (readEnds.compare(moduleEnds) > 0
          ? readEnds : moduleEnds).sub(offset);
        const bytes = Memory.readByteArray(ptr(offset), +left);
        return [{}, (bytes !== null) ? bytes : []];
      } catch (e) {
      // do nothing
      }
    }
  }
  return [{}, []];
}

function isExecutable (address) {
  const currentRange = Process.getRangeByAddress(address);
  return currentRange.protection.indexOf('x') !== -1;
}

function write (params, data) {
  if (typeof r2frida.hookedWrite === 'function') {
    return r2frida.hookedWrite(params.offset, data);
  }
  if (config.getBoolean('patch.code') && isExecutable(params.offset)) {
    if (typeof Memory.patchCode === 'function') {
      Memory.patchCode(ptr(params.offset), 1, function (ptr) {
        Memory.writeByteArray(ptr, data);
      });
    } else {
      Memory.writeByteArray(ptr(params.offset), data);
    }
  } else {
    Memory.writeByteArray(ptr(params.offset), data);
  }
  return [{}, null];
}

module.exports = {
  read: read,
  write: write
};
