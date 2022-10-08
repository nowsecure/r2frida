export function Hexdump (lenstr) {
  const len = +lenstr || 32;
  try {
    return hexdump(ptr(global.r2frida.offset), len) || '';
  } catch (e) {
    return 'Cannot read memory.';
  }
}
