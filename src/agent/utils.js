'use strict';

const minPrintable = ' '.charCodeAt(0);
const maxPrintable = '~'.charCodeAt(0);

function sanitizeString (str) {
  const specialChars = '/\\`+-${}~|*,;:\"\'#@&<> ()[]!?%';
  return str.split('').map(c => specialChars.indexOf(c) === -1 ? c : '_').join('');
}

function wrapStanza (name, stanza) {
  return {
    name: name,
    stanza: stanza
  };
}

function hexPtr (p) {
  if (p instanceof UInt64) {
    return `0x${p.toString(16)}`;
  }
  return p.toString();
}

function ptrMax (a, b) {
  return a.compare(b) > 0 ? a : b;
}

function ptrMin (a, b) {
  return a.compare(b) < 0 ? a : b;
}

function toHexPairs (raw) {
  const isString = typeof raw === 'string';
  const pairs = [];
  for (let i = 0; i !== raw.length; i += 1) {
    const code = (isString ? raw.charCodeAt(i) : raw[i]) & 0xff;
    const h = code.toString(16);
    pairs.push((h.length === 2) ? h : `0${h}`);
  }
  return pairs.join(' ');
}

function toWidePairs (raw) {
  const pairs = [];
  for (let i = 0; i !== raw.length; i += 1) {
    const code = raw.charCodeAt(i) & 0xff;
    const h = code.toString(16);
    pairs.push((h.length === 2) ? h : `0${h}`);
    pairs.push('00');
  }
  return pairs.join(' ');
}

function normHexPairs (raw) {
  const norm = raw.replace(/ /g, '');
  if (_isHex(norm)) {
    return _toPairs(norm.replace(/\./g, '?'));
  }
  throw new Error('Invalid hex string');
}

function filterPrintable (arr) {
  const u8arr = new Uint8Array(arr);
  const printable = [];
  for (let i = 0; i !== u8arr.length; i += 1) {
    const c = u8arr[i];
    if (c === 0) {
      break;
    }
    if (c >= minPrintable && c <= maxPrintable) {
      printable.push(String.fromCharCode(c));
    }
  }
  return printable.join('');
}

function byteArrayToHex (arr) {
  const u8arr = new Uint8Array(arr);
  const hexs = [];
  for (let i = 0; i !== u8arr.length; i += 1) {
    const h = u8arr[i].toString(16);
    hexs.push((h.length === 2) ? h : `0${h}`);
  }
  return hexs.join('');
}

function renderEndian (value, bigEndian, width) {
  const bytes = [];
  for (let i = 0; i !== width; i++) {
    if (bigEndian) {
      bytes.push(value.shr((width - i - 1) * 8).and(0xff).toNumber());
    } else {
      bytes.push(value.shr(i * 8).and(0xff).toNumber());
    }
  }
  return bytes;
}

function padPointer (value) {
  let result = value.toString(16);
  const paddedLength = 2 * pointerSize;
  while (result.length < paddedLength) {
    result = '0' + result;
  }
  return '0x' + result;
}

function _toPairs (hex) {
  if ((hex.length % 2) !== 0) {
    throw new Error('Odd-length string');
  }

  const pairs = [];
  for (let i = 0; i !== hex.length; i += 2) {
    pairs.push(hex.substr(i, 2));
  }
  return pairs.join(' ').toLowerCase();
}

function _isHex (raw) {
  const hexSet = new Set(Array.from('abcdefABCDEF0123456789?.'));
  const inSet = new Set(Array.from(raw));
  for (const h of hexSet) {
    inSet.delete(h);
  }
  return inSet.size === 0;
}

module.exports = {
  sanitizeString,
  wrapStanza,
  hexPtr,
  ptrMax,
  ptrMin,
  toHexPairs,
  toWidePairs,
  normHexPairs,
  filterPrintable,
  byteArrayToHex,
  renderEndian,
  padPointer
};
