'use strict';

function printHexdump (lenstr) {
  const len = +lenstr || 32;
  try {
    return hexdump(ptr(global.r2frida.offset), len) || '';
  } catch (e) {
    return 'Cannot read memory.';
  }
}

module.exports = {
  printHexdump
};
