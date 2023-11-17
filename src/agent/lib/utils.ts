import { SwiftAvailable } from "./darwin/swift.js";
import { r2frida } from "../plugin.js";

declare let Swift: any;

const minPrintable = ' '.charCodeAt(0);
const maxPrintable = '~'.charCodeAt(0);
let globalSymCounter = 0;

export function sanitizeString(str: string): string {
    if (str) {
        const specialChars = "^/\\`+-${}~|*,;:\"'#@&<> ()[]!?%";
        return str.split('').map(c => specialChars.indexOf(c) === -1 ? c : '_').join('');
    } else {
        globalSymCounter++;
        return 'noname.' + globalSymCounter;
    }
}

export function wrapStanza(name: string, stanza: any) {
    return {
        name: name,
        stanza: stanza
    };
}

export function hexPtr(p: UInt64 | any): string {
    if (p instanceof UInt64) {
        return `0x${p.toString(16)}`;
    }
    return p.toString();
}

export function ptrMax(a: NativePointer, b: NativePointer): NativePointer {
    return a.compare(b) > 0 ? a : b;
}

export function ptrMin(a: NativePointer, b: NativePointer): NativePointer {
    return a.compare(b) < 0 ? a : b;
}

export function toHexPairs(raw: string | any) {
    const isString = typeof raw === 'string';
    const pairs = [];
    for (let i = 0; i !== raw.length; i += 1) {
        const code = (isString ? raw.charCodeAt(i) : raw[i]) & 0xff;
        const h = code.toString(16);
        pairs.push((h.length === 2) ? h : `0${h}`);
    }
    return pairs.join(' ');
}

export function toWidePairs(raw: string): string {
    const pairs = [];
    for (let i = 0; i !== raw.length; i += 1) {
        const code = raw.charCodeAt(i) & 0xff;
        const h = code.toString(16);
        pairs.push((h.length === 2) ? h : `0${h}`);
        pairs.push('00');
    }
    return pairs.join(' ');
}

export function normHexPairs(raw: string) {
    const norm = raw.replace(/ /g, '');
    if (_isHex(norm)) {
        return _toPairs(norm.replace(/\./g, '?'));
    }
    throw new Error('Invalid hex string');
}

export function filterPrintable(arr: any) {
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

export function byteArrayToHex(arr: any) {
    const u8arr = new Uint8Array(arr);
    const hexs = [];
    for (let i = 0; i !== u8arr.length; i += 1) {
        const h = u8arr[i].toString(16);
        hexs.push((h.length === 2) ? h : `0${h}`);
    }
    return hexs.join('');
}

export function renderEndian(value: NativePointer, bigEndian: boolean, width: number) {
    const bytes = [];
    for (let i = 0; i !== width; i++) {
        if (bigEndian) {
            bytes.push(value.shr((width - i - 1) * 8).and(0xff).toUInt32());
        } else {
            bytes.push(value.shr(i * 8).and(0xff).toUInt32());
        }
    }
    return bytes;
}

export function padString(text: string, length: number) {
    const rest = length - text.length + 1;
    const pad = (rest > 0) ? Array(rest).join(' ') : '';
    return text + pad;
}

export function padPointer(value: string | NativePointer) {
    if (value.toString().indexOf('ArrayBuffer') !== -1) {
        value = arrayBufferToHex(value);
    }
    let result = (+value).toString(16);
    const paddedLength = 2 * Process.pointerSize;
    while (result.length < paddedLength) {
        result = '0' + result;
    }
    return '0x' + result;
}

function _toPairs(hex: string): string {
    if ((hex.length % 2) !== 0) {
        throw new Error('Odd-length string');
    }
    const pairs = [];
    for (let i = 0; i !== hex.length; i += 2) {
        pairs.push(hex.substring(i, i + 2));
    }
    return pairs.join(' ').toLowerCase();
}

function _isHex(raw: any) {
    const hexSet = new Set(Array.from('abcdefABCDEF0123456789?.'));
    const inSet = new Set(Array.from(raw));
    for (const h of hexSet) {
        inSet.delete(h);
    }
    return inSet.size === 0;
}

export function trunc4k(x: NativePointer) {
    return x.and(ptr('0xfff').not());
}

export function rwxstr(x: number): string {
    let str = '';
    str += (x & 4) ? 'r' : '-';
    str += (x & 2) ? 'w' : '-';
    str += (x & 1) ? 'x' : '-';
    return str;
}

export function rwxint(x: string): number {
    const ops = ['---', '--x', '-w-', '-wx', 'r--', 'r-x', 'rw-', 'rwx'];
    return ops.indexOf(x);
}

// TODO: make return optional
export function getPtr(p: any) : NativePointer {
    if (typeof p === 'string') {
        p = p.trim();
    }
    if (!p || p === '$$') {
        return ptr(r2frida.offset);
    }
    if (p.startsWith('swift:')) {
        if (!SwiftAvailable()) {
            return ptr(0);
        }
        // swift:CLASSNAME.method
        const km = p.substring(6).split('.');
        if (km.length !== 2) {
            return ptr(0);
        }
        const klass = km[0];
        const method = km[1];
        if (!Swift.classes[klass]) {
            console.error('Missing class ' + klass);
            return ptr(0);
        }
        const klassDefinition = Swift.classes[klass];
        let targetAddress = ptr(0);
        for (const kd of klassDefinition.$methods) {
            if (method === kd.name) {
                targetAddress = kd.address;
            }
        }
        return p;
    }
    if (p.startsWith('java:')) {
        return p;
    }
    if (p.startsWith('objc:')) {
        const hatSign = p.indexOf('^') !== -1;
        if (hatSign) {
            p = p.replace('^', '');
        }
        const endsWith = p.endsWith('$');
        if (endsWith) {
            p = p.substring(0, p.length - 1);
        }
        p = p.substring(5);
        let dot = p.indexOf('.');
        if (dot === -1) {
            dot = p.indexOf(':');
            if (dot === -1) {
                throw new Error('r2frida\'s ObjC class syntax is: objc:CLASSNAME.METHOD');
            }
        }
        const kv0 = p.substring(0, dot);
        const kv1 = p.substring(dot + 1);
        const klass = ObjC.classes[kv0];
        if (klass === undefined) {
            throw new Error('Class ' + kv0 + ' not found');
        }
        let found = null;
        let firstFail = false;
        let oldMethodName = null;
        for (const methodName of klass.$ownMethods) {
            const method = klass[methodName];
            if (methodName.indexOf(kv1) !== -1) {
                if (hatSign && !methodName.substring(2).startsWith(kv1)) {
                    continue;
                }
                if (endsWith && !methodName.endsWith(kv1)) {
                    continue;
                }
                if (found) {
                    if (!firstFail) {
                        console.error(found.implementation, oldMethodName);
                        firstFail = true;
                    }
                    console.error(method.implementation, methodName);
                }
                found = method;
                oldMethodName = methodName;
            }
        }
        if (firstFail) {
            return ptr(0);
        }
        return found ? found.implementation : ptr(0);
    }
    try {
        if (p.substring(0, 2) === '0x') {
            return ptr(p);
        }
    } catch (e) {
        // console.error(e);
    }
    // return DebugSymbol.fromAddress(ptr_p) || '' + ptr_p;
    const res = Module.findExportByName(null, p);
    if (res === null) {
      return ptr(0);
    }
    return res;
}

export function autoType(args: string[]) {
    const nfArgs = [];
    const nfArgsData = [];
    // push arguments
    for (let i = 0; i < args.length; i++) {
        if (args[i].substring(0, 2) === '0x') {
            nfArgs.push('pointer');
            nfArgsData.push(ptr(args[i]));
        } else if (args[i][0] === '"') {
            // string.. join args
            nfArgs.push('pointer');
            const str = args[i].substring(1, args[i].length - 1);
            const buf = Memory.allocUtf8String(str.replace(/\\n/g, '\n'));
            nfArgsData.push(buf);
        } else if (args[i].endsWith('f')) {
            nfArgs.push('float');
            nfArgsData.push(0.0 + args[i]);
        } else if (args[i].endsWith('F')) {
            nfArgs.push('double');
            nfArgsData.push(0.0 + args[i]);
        } else if (+args[i] > 0 || args[i] === '0') {
            nfArgs.push('int');
            nfArgsData.push(+args[i]);
        } else {
            nfArgs.push('pointer');
            const address = Module.getExportByName(null, args[i]);
            nfArgsData.push(address);
        }
    }
    return [nfArgs, nfArgsData];
}

export function requireFridaVersion(major: number, minor: number, patch: number) {
    const required = [major, minor, patch];
    const actual = Frida.version.split('.').map((x: string) => Number(x));
    for (let i = 0; i < actual.length; i++) {
        if (actual[i] > required[i]) {
            return;
        }
        if (actual[i] < required[i]) {
            throw new Error(`Frida v${major}.${minor}.${patch} or higher required for this (you have v${Frida.version}).`);
        }
    }
}

export function arrayBufferToHex(arrayBuffer: any) {
    if (typeof arrayBuffer !== 'object' || arrayBuffer === null || typeof arrayBuffer.byteLength !== 'number') {
        throw new TypeError('Expected input to be an ArrayBuffer');
    }
    const view = new Uint8Array(arrayBuffer);
    let result = '';
    let value;
    for (let i = 0; i < view.length; i++) {
        value = view[i].toString(16);
        result += (value.length === 1 ? '0' + value : value);
    }
    return result;
}

export function belongsTo(modules: any[], addr: NativePointer) {
    return modules.filter(m => addr.compare(m.vmaddr) >= 0 && addr.compare(m.vmaddr.add(m.vmsize)) < 0);
}

export function Hexdump(lenstr: number): string {
    const len = +lenstr || 32;
    try {
        const ptroff = ptr(r2frida.offset);
        const options: HexdumpOptions = {
            // offset: global.r2frida.offset,
            length: len,
        };
        return hexdump(ptroff, options) || '';
    } catch (e: any) {
        return "Cannot read memory";
    }
}

export default {
    Hexdump
}
