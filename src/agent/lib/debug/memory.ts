import expr from "../expr.js";
import { r2frida } from "../../plugin.js";

import {
    filterPrintable,
    getPtr,
    padPointer,
    rwxint,
    rwxstr,
    sanitizeString,
} from "../utils.js";

const allocPool: Map<string, NativePointer> = new Map<string, NativePointer>();

export function listMemoryRanges(): string {
    return listMemoryRangesJson()
        .map((a: any) =>
            [
                padPointer(a.base),
                "-",
                padPointer(a.base.add(a.size)),
                a.protection,
            ]
                .concat((a.file !== undefined) ? [a.file.path] : [])
                .join(" ")
        )
        .join("\n");
}

export function listMemoryRangesR2(): string {
    return listMemoryRangesJson()
        .map((a: any) =>
            [
                "f",
                "map." + padPointer(a.base) + "." +
                a.protection.replace(/-/g, "_"),
                a.size,
                a.base,
                "#",
                a.protection,
            ].concat((a.file !== undefined) ? [a.file.path] : []).join(" ")
        )
        .join("\n");
}

export function listMemoryRangesJson(): RangeDetails[] {
    return getMemoryRanges("---");
}

export function getMemoryRanges(protection: string): RangeDetails[] {
    return Process.enumerateRanges({
        protection,
        coalesce: false,
    });
}

export async function changeMemoryProtection(args: string[]): Promise<string> {
    const [addr, size, protection] = args;
    if (args.length !== 3 || protection.length > 3) {
        return "Usage: :dmp [address] [size] [rwx]";
    }
    const address = getPtr(addr);
    const mapsize = await expr.numEval(size);
    Memory.protect(address, mapsize.toUInt32(), protection);
    return "";
}

export function listMemoryRangesHere(args: string[]): string {
    if (args.length !== 1) {
        args = [r2frida.offset];
    }
    const addr = ptr(args[0]);
    return listMemoryRangesJson()
        .filter((range: RangeDetails) =>
            addr.compare(range.base) >= 0 &&
            addr.compare(range.base.add(range.size)) < 0
        )
        .map((range: RangeDetails) =>
            [
                padPointer(range.base),
                "-",
                padPointer(range.base.add(range.size)),
                range.protection,
            ].concat((range.file !== undefined) ? [range.file.path] : [])
                .join(" ")
        )
        .join("\n");
}

export function listMemoryMaps(): string {
    return _squashRanges(listMemoryRangesJson())
        .filter((_) => _.file)
        .map(({ base, size, protection, file }) =>
            [padPointer(base), "-", padPointer(base.add(size)), protection]
                .concat((file !== undefined) ? [(file as any).path] : [])
                .join(" ")
        )
        .join("\n");
}

export function listMemoryMapsR2(): string {
    const maps = _squashRanges(listMemoryRangesJson())
        .filter((_) => _.file)
        .map(({ base, size, protection, file }) =>
            [
                "f",
                "dmm." + sanitizeString((file as any).path),
                size,
                padPointer(base),
            ]
                .join(" ")
        )
        .join("\n");
    return "fs+maps\n" + maps + "fs-";
}

export function listMemoryMapsJson(): RangeDetails[] {
    return _squashRanges(listMemoryRangesJson()).filter((_) => _.file);
}

export function listMemoryMapsHere(args: string[]) {
    if (args.length !== 1) {
        args = [r2frida.offset];
    }
    const addr = ptr(args[0]);
    return _squashRanges(listMemoryRangesJson())
        .filter(({ base, size }) =>
            addr.compare(base) >= 0 && addr.compare(base.add(size)) < 0
        )
        .map(({ base, size, protection, file }) => {
            return [
                padPointer(base),
                "-",
                padPointer(base.add(size)),
                protection,
                (file as any).path,
            ].join(" ");
        })
        .join("\n");
}

export function listMallocRangesJson(): RangeDetails[] {
    return Process.enumerateMallocRanges();
}

export function listMallocRanges(args: string[]): string {
    return _squashRanges(listMallocRangesJson())
        .map((_) =>
            "" + _.base + " - " + _.base.add(_.size) + "  (" + _.size + ")"
        ).join("\n") + "\n";
}

export function listMallocRangesR2(args: string[]): string {
    const chunks = listMallocRangesJson()
        .map((_) => "f chunk." + _.base + " " + _.size + " " + _.base).join(
            "\n",
        );
    return chunks + _squashRanges(listMallocRangesJson())
        .map((_) => "f heap." + _.base + " " + _.size + " " + _.base).join(
            "\n",
        );
}

export function listMallocMaps(args: string[]): string {
    const heaps = _squashRanges(listMallocRangesJson());
    function inRange(memoryRange: RangeDetails) {
        for (const heap of heaps) {
            if (
                memoryRange.base.compare(heap.base) >= 0 &&
                memoryRange.base.add(memoryRange.size).compare(
                    heap.base.add(heap.size),
                )
            ) {
                return true;
            }
        }
        return false;
    }
    return _squashRanges(listMemoryRangesJson())
        .filter(inRange)
        .map((a: any) =>
            [
                padPointer(a.base),
                "-",
                padPointer(a.base.add(a.size)),
                a.protection,
            ]
                .concat((a.file !== undefined) ? [a.file.path] : [])
                .join(" ")
        )
        .join("\n");
}

export function allocSize(args: string[]): string {
    const size = +args[0];
    if (size > 0) {
        const a = Memory.alloc(size);
        return _addAlloc(a);
    }
    return "";
}

export function allocString(args: string[]): string {
    const strToAllocate = args.join(" ");
    if (strToAllocate.length > 0) {
        const allocPtr = Memory.allocUtf8String(strToAllocate);
        return _addAlloc(allocPtr);
    }
    throw new Error("Usage: dmas [string]");
}

export function allocWstring(args: string[]): string {
    const strToAllocate = args.join(" ");
    if (strToAllocate.length > 0) {
        const allocPtr = Memory.allocUtf16String(strToAllocate);
        return _addAlloc(allocPtr);
    }
    throw new Error("Usage: dmaw [string]");
}

export function allocDup(args: string[]): string {
    if (args.length < 2) {
        throw new Error("Missing argument");
    }
    const addr = +args[0];
    const size = +args[1];
    if (addr > 0 && size > 0) {
        const a = Memory.dup(ptr(addr), size);
        return _addAlloc(a);
    }
    return "";
}

export function listAllocs(): string {
    if (allocPool === null) {
        return "";
    }
    let res = "";
    for (let [addr, allocPtr] of allocPool) {
        const bytes = allocPtr.readByteArray(60);
        const printables = filterPrintable(bytes);
        res += `${addr}\t"${printables}"\n`;
    }

    return res;
}

export function removeAlloc(args: string[]): string {
    if (args.length === 0) {
        _clearAllocs();
    } else {
        for (const addr of args) {
            _delAlloc(addr);
        }
    }
    return "";
}

function _delAlloc(addr: string) {
    allocPool.delete(addr);
}

function _clearAllocs(): void {
    allocPool.clear();
}

function _addAlloc(allocPtr: NativePointer): string {
    const key = allocPtr.toString();
    if (!allocPtr.isNull()) {
        allocPool.set(key, allocPtr);
    }
    return key;
}

function _squashRanges(ranges: any): RangeDetails[] {
    const squashedRanges: RangeDetails[] = [];
    if (ranges.length === 0) {
        return ranges;
    }
    const firstRange = ranges.shift();
    let begin = firstRange.base;
    let end = firstRange.base.add(firstRange.size);
    let storedRangeProtection = rwxint(firstRange.protection);
    let storedRangeFile: FileMapping = firstRange.file;
    for (const range of ranges) {
        let shouldSquash = false;
        if (range.file && storedRangeFile) {
            shouldSquash = range.file.path === storedRangeFile.path;
        }
        if (shouldSquash) {
            storedRangeProtection |= rwxint(range.protection);
        } else {
            // add the previous range to the squash list and update beginning of the range and file information
            squashedRanges.push({
                base: begin,
                size: end.sub(begin).toUInt32(),
                protection: rwxstr(storedRangeProtection),
                file: storedRangeFile,
            } as RangeDetails);
            begin = range.base;
            storedRangeFile = range.file;
            storedRangeProtection = rwxint(range.protection);
        }
        end = range.base.add(range.size);
    }
    squashedRanges.push({
        base: begin,
        size: end.sub(begin).toUInt32(),
        protection: rwxstr(storedRangeProtection),
        file: storedRangeFile,
    });
    return squashedRanges;
}
