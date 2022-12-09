// TODO move into utils.ts

import r2frida from '../plugin.js';

declare var global : any;

export default function Hexdump (lenstr: number) : string {
  const len = +lenstr || 32;
  try {
    const ptroff = ptr(global.r2frida.offset);
    const options : HexdumpOptions = {
      // offset: global.r2frida.offset,
      length: len,
    };
    return hexdump(ptroff, options) || '';
  } catch (e: any) {
    return 'Cannot read memory';
  }
}
