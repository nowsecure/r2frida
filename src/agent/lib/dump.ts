// TODO move into utils.ts

declare let global: any;

export function Hexdump(lenstr: number): string {
    const len = +lenstr || 32;
    try {
        const ptroff = ptr(global.r2frida.offset);
        const options: HexdumpOptions = {
            // offset: global.r2frida.offset,
            length: len,
        };
        return hexdump(ptroff, options) || '';
    } catch (e: any) {
        return 'Cannot read memory';
    }
}


export default {
    Hexdump
}
