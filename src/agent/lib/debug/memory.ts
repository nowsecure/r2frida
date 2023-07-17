import expr from '../expr.js';
import { r2frida } from "../../plugin.js";

import { filterPrintable, rwxstr, padPointer, sanitizeString, getPtr, rwxint } from '../utils.js';


const allocPool = new Map<any, any>(); // : MapNativePointer[] = [];

export function listMemoryRanges(): string {
    return listMemoryRangesJson()
        .map((a: any) => [padPointer(a.base), '-', padPointer(a.base.add(a.size)), a.protection]
            .concat((a.file !== undefined) ? [a.file.path] : [])
            .join(' '))
        .join('\n') + '\n';
}

export function listMemoryRangesR2(): string {
    return listMemoryRangesJson()
        .map((a: any) => [
            'f', 'map.' + padPointer(a.base) + '.' + a.protection.replace(/-/g, '_'), a.size, a.base,
            '#', a.protection
        ].concat((a.file !== undefined) ? [a.file.path] : []).join(' '))
        .join('\n') + '\n';
}

export function listMemoryRangesJson() {
    return getMemoryRanges('---');
}

export async function changeMemoryProtection(args: string[]) {
    const [addr, size, protection] = args;
    if (args.length !== 3 || protection.length > 3) {
        return 'Usage: :dmp [address] [size] [rwx]';
    }
    const address = getPtr(addr);
    const mapsize = await expr.numEval(size);
    Memory.protect(address, mapsize.toUInt32(), protection);
    return '';
}

export function listMemoryRangesHere(args: string[]) {
    if (args.length !== 1) {
        args = [r2frida.offset];
    }
    const addr = ptr(args[0]);
    return listMemoryRangesJson()
        .filter((a: any) => addr.compare(a.base) >= 0 && addr.compare(a.base.add(a.size)) < 0)
        .map((a: any) => [
            padPointer(a.base),
            '-',
            padPointer(a.base.add(a.size)),
            a.protection
        ].concat((a.file !== undefined) ? [a.file.path] : [])
            .join(' '))
        .join('\n') + '\n';
}

export function listMemoryMaps() {
    return _squashRanges(listMemoryRangesJson())
        .filter(_ => _.file)
        .map(({ base, size, protection, file }) => [padPointer(base), '-', padPointer(base.add(size)), protection]
            .concat((file !== undefined) ? [(file as any).path] : [])
            .join(' '))
        .join('\n') + '\n';
}

export function listMemoryMapsR2() {
    return _squashRanges(listMemoryRangesJson())
        .filter(_ => _.file)
        .map(({ base, size, protection, file }) => [
            'f',
            'dmm.' + sanitizeString((file as any).path),
            '=',
            padPointer(base)
        ]
            .join(' '))
        .join('\n') + '\n';
}

export function listMallocRanges(args: string[]) {
    return _squashRanges(listMallocRangesJson(args))
        .map(_ => '' + _.base + ' - ' + _.base.add(_.size) + '  (' + _.size + ')').join('\n') + '\n';
}

export function listMallocRangesJson(args: string[]) {
    return Process.enumerateMallocRanges();
}

export function listMallocRangesR2(args: string[]) {
    const chunks = listMallocRangesJson(args)
        .map(_ => 'f chunk.' + _.base + ' ' + _.size + ' ' + _.base).join('\n');
    return chunks + _squashRanges(listMallocRangesJson(args))
        .map(_ => 'f heap.' + _.base + ' ' + _.size + ' ' + _.base).join('\n');
}

export function listMemoryMapsHere(args: string[]) {
    if (args.length !== 1) {
        args = [r2frida.offset];
    }
    const addr = ptr(args[0]);
    return _squashRanges(listMemoryRangesJson())
        .filter(({ base, size }) => addr.compare(base) >= 0 && addr.compare(base.add(size)) < 0)
        .map(({ base, size, protection, file }) => {
            return [
                padPointer(base), '-', padPointer(base.add(size)),
                protection,
                (file as any).path
            ].join(' ');
        })
        .join('\n') + '\n';
}

export function listMallocMaps(args: string[]) {
    const heaps = _squashRanges(listMallocRangesJson(args));
    function inRange(x: any) {
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
        .map((a: any) =>
            [padPointer(a.base), '-', padPointer(a.base.add(a.size)), a.protection]
                .concat((a.file !== undefined) ? [a.file.path] : [])
                .join(' '))
        .join('\n') + '\n';
}

export function allocSize(args: string[]) {
    const size = +args[0];
    if (size > 0) {
        const a = Memory.alloc(size);
        return _addAlloc(a);
    }
    return 0;
}

export function allocString(args: string[]) {
    const theString = args.join(' ');
    if (theString.length > 0) {
        const a = Memory.allocUtf8String(theString);
        return _addAlloc(a);
    }
    throw new Error('Usage: dmas [string]');
}

export function allocWstring(args: string[]) {
    const theString = args.join(' ');
    if (theString.length > 0) {
        const a = Memory.allocUtf16String(theString);
        return _addAlloc(a);
    }
    throw new Error('Usage: dmaw [string]');
}

export function allocDup(args: string[]) {
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

export function listAllocs(args: string[]) {
    return Object.values(allocPool)
        .sort()
        .map((x: NativePointer) => {
            const bytes = x.readByteArray(60);
            const printables = filterPrintable(bytes);
            return `${x}\t"${printables}"`;
        })
        .join('\n') + '\n';
}

export function removeAlloc(args: string[]) {
    if (args.length === 0) {
        _clearAllocs();
    } else {
        for (const addr of args) {
            _delAlloc(ptr(addr));
        }
    }
    return '';
}

export function getMemoryRanges(protection: string): RangeDetails[] {
    if (r2frida.hookedRanges !== null) {
        return r2frida.hookedRanges(protection);
    }
    return Process.enumerateRanges({
        protection,
        coalesce: false
    });
}

function _delAlloc(addr: NativePointer) {
    allocPool.delete(addr);
}

function _clearAllocs() {
    Object.keys(allocPool)
        .forEach(addr => allocPool.delete(addr));
}

function _addAlloc(allocPtr: NativePointer) {
    const key = allocPtr.toString();
    if (!allocPtr.isNull()) {
        allocPool.set(key, allocPtr);
    }
    return key;
}

function _squashRanges(ranges: any): RangeDetails[] {
    const res: RangeDetails[] = [];
    let begin = ptr(0);
    let end = ptr(0);
    let lastPerm = 0;
    let lastFile = {path:"", size:0, offset: 0};
    let first = true;
    for (const r of ranges) {
        if (begin.equals(ptr(0))) {
            begin = r.base;
            end = r.base.add(r.size);
            lastFile = r.file;
        }
        if (first || r.file.path === lastFile.path) {
            // do nothing
            if (end.equals(r.base)) {
                end = r.base.add(r.size);
            } else {
                end = r.base.add(r.size);
                // gap
            }
            lastFile = r.file;
        } else {
            // append
            res.push({
                base: begin,
                size: end.sub(begin).toUInt32(),
                protection: rwxstr(lastPerm),
                file: lastFile
            });
            begin = r.base;
            end = r.base.add(r.size);
            lastFile = r.file;
            first = true;
            lastPerm = 0;
        }
        // lastFile = r.file;
        lastPerm |= rwxint(r.protection);
        first = false;
    }
    if (!begin.equals(ptr(0))) {
        res.push({ base: begin, size: end.sub(begin).toUInt32(), protection: rwxstr(lastPerm), file: lastFile });
    }
    return res;
}
