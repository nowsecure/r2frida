import config from '../config.js';
import { ObjCAvailable } from './darwin/index.js';
import io from '../io.js';
import r2, { r2Config } from './r2.js';
import { r2frida } from "../plugin.js";
import { getMemoryRanges, listMallocRangesJson } from './debug/memory.js';
import { normHexPairs, filterPrintable, toWidePairs, byteArrayToHex, ptrMin, ptrMax, padPointer, toHexPairs, renderEndian, hexPtr } from './utils.js';
import ObjC from "frida-objc-bridge";
import Java from "frida-java-bridge";

export function search(args: string[]): string {
    const hits = searchJson(args);
    return _getReadableHitsToString(hits);
}

export function searchInstances(args: string[]): string {
    return _getReadableHitsToString(searchInstancesJson(args));
}

export function searchInstancesJson(args: string[]): SearchHit[] {
    const className = args.join('');
    if (ObjCAvailable) {
        const instances: ObjC.Object[] = ObjC.chooseSync(ObjC.classes[className]);
        return instances.map(function (res: ObjC.Object) {
            return { address: res.handle, content: className, size: 0 } as SearchHit;
        });
    } else {
        Java.performNow(function () {
             const instances: SearchHit[] = [];
             Java.choose(className, {
                onMatch: function(instance){
                    instances.push({ address: instance.$h, content: instance.className, size: 0 } as SearchHit);
                },
                onComplete:function() {
                    console.log("search done");
                }
            });
            return instances;
        });
    }
    return [];
}

export function searchJson(args: string[]): SearchHit[] {
    const pattern = toHexPairs(args.join(' '));
    const hits = _searchPatternJson(pattern);
    hits.forEach(hit => {
        try {
            const bytes = io.read({
                offset: hit.address.toString(),
                count: 60,
                fast : false
            })[1];
            hit.content = filterPrintable(bytes);
        } catch (e) {
        }
    });
    return hits.filter((hit: SearchHit) => hit.content !== undefined);
}

export function searchStrings(args: string[]): string {
    const hits = searchStringsJson(args.join(''));
    return _getReadableHitsToString(hits);
}

export function searchHex(args: string[]): string {
    const hits = searchHexJson(args.join(''));
    return _getReadableHitsToString(hits);
}

export function searchWide(args: string[]) {
    const hits = searchWideJson(args);
    return _getReadableHitsToString(hits);
}

export function searchWideJson(args: string[]): SearchHit[] {
    const pattern = toWidePairs(args.join(' '));
    return searchHexJson(pattern);
}

class StringFinder {
    results : SearchHit[] = [];
    minLen = 0;
    maxLen = 0;
    curstr = "";
    curaddr = ptr(0);
    nth = 0;

    constructor (minLen: number = 0, maxLen: number = 128) {
       this.minLen = minLen;
       this.maxLen = maxLen;
    }

    feed(cur: NativePointer, data: Uint8Array) {
       for (let i = 0; i < data.byteLength; i++) {
           this.feedByte(cur, data[i]);
       }
    }

    possibleEndOfString() {
        const strlen = this.curstr.length;
        if (strlen >= this.minLen && strlen <= this.maxLen) {
            this.results.push({
                address: this.curaddr,
                content: this.curstr,
                size: strlen,
                flag: "hit.string." + this.results.length
            });
        }
        this.curstr = "";
    }

    feedByte(cur: NativePointer, char: number) {
        if (char > 0x20 && char < 0x7f) {
            if (this.curstr === "") {
                this.curaddr = cur;
            }
            this.curstr += String.fromCharCode(char);
        } else if (char == 0) {
            this.possibleEndOfString();
        }
    }

    hits(): SearchHit[] {
        return this.results;
    }
}

export function searchStringsJson(args: string): SearchHit[]{
	console.log("search string");
    const prefix = "hit";
    let searchHits: SearchHit[] = [];
    const fromAddress = new NativePointer(config.getString('search.from'));
    const toAddress = new NativePointer(config.getString('search.to'));
    const ranges = _getRangesToSearch(fromAddress, toAddress);
    const kwidx = config.getNumber("search.kwidx");
    const align = config.getNumber('search.align');
    const blockSize = 4096;
    let count = 0;
    for (const range of ranges) {
        if (range.size === 0) {
            continue;
        }
        const rangeStr = `[${padPointer(range.address)}-${padPointer(range.address.add(range.size))}]`;
        let cur = range.address;
        const end = range.address.add (range.size);
        const sf = new StringFinder(9, 128);
        while (cur.compare(end)) {
            const data = cur.readByteArray(blockSize);
            if (data === null) {
                break;
            }
            const bytes = new Uint8Array(data);
            sf.feed(cur, bytes);
            cur = cur.add(blockSize);
        }
        sf.hits().forEach((hit) => {
            if (align > 1) {
                const base = Number(hit.address.and(0xffff));
                if ((base % align) !== 0) {
                    return;
                }
            }
            r2.hostCmd(`fs+search; f ${hit.flag} ${hit.size} ${hexPtr(hit.address)};fs-`);
            searchHits.push(hit);
        });
    }
    config.set("search.kwidx", kwidx + 1);
    qlog(`hits: ${searchHits.length}`);
    return searchHits;
}

export function searchHexJson(args: string): SearchHit[]{
    const pattern = normHexPairs(args);
    if (pattern === null) {
        console.error("Invalid hex string");
        return [];
    }
    const hits = _searchPatternJson(pattern);
    hits.forEach((hit: SearchHit) => {
        const bytes = hit.address.readByteArray(hit.size);
        hit.content = byteArrayToHex(bytes);
    });
    return hits;
}

export function searchValue1(args: string[]): string {
    return searchValueImpl(1, args);
}

export function searchValue2(args: string[]): string {
    return searchValueImpl(2, args);
}

export function searchValue4(args: string[]): string {
    return searchValueImpl(4, args);
}

export function searchValue8(args: string[]): string {
    return searchValueImpl(8, args);
}

export function searchValueJson1(args: string[]): SearchHit[] {
    return _searchValueJson(1, args);
}

export function searchValueJson2(args: string[]): SearchHit[] {
    return _searchValueJson(2, args);
}
export function searchValueJson4(args: string[]): SearchHit[] {
    return _searchValueJson(4, args);
}
export function searchValueJson8(args: string[]): SearchHit[] {
    return _searchValueJson(8, args);
}

export function searchValueImpl(width: number, args: string[]): string {
    const hits = _searchValueJson(width,args);
    return _getReadableHitsToString(hits);
}

function _searchValueJson(width: number, args: string[]): SearchHit[] {
    const pattern = args.join('').slice(0, width * 2);
    //const bigEndian = config.getBoolean('search.bigendian');
    // TODO - refactor renderEndian
    //const bytes = renderEndian(pattern, bigEndian, width);
    return searchHexJson(pattern);
}

function _getReadableHitsToString(hits: SearchHit[]): string {
    const output = hits.map(hit => {
        if (typeof hit.flag === 'string') {
            return `${hexPtr(hit.address)} ${hit.flag} ${hit.content}`;
        }
        return `${hexPtr(hit.address)} ${hit.content}`;
    });
    return output.join('\n') + '\n';
}

function _searchPatternJson(pattern: string): SearchHit[] {
    const prefix = "hit";
    let searchHits: SearchHit[] = [];
    const align = config.getNumber('search.align');
    const fromAddress = new NativePointer(config.getString('search.from'));
    const toAddress = new NativePointer(config.getString('search.to'));
    const ranges = _getRangesToSearch(fromAddress, toAddress);
    const nBytes = pattern.split(' ').length;
    qlog(`Searching ${nBytes} bytes: ${pattern}`);
    const kwidx = config.getNumber("search.kwidx");
    let count = 0;
    let script = "";
    for (const range of ranges) {
        if (range.size === 0) {
            continue;
        }
        const rangeStr = `[${padPointer(range.address)}-${padPointer(range.address.add(range.size))}]`;
        qlog(`Searching ${nBytes} bytes in ${rangeStr}`);
        try {
            const {address, size} = range;
            const partial: MemoryScanMatch[] = Memory.scanSync(address, size, pattern);
            partial.forEach((match: MemoryScanMatch) => {
                if (align > 1) {
                    const base = Number(match.address.and(0xffff));
                    if ((base % align) !== 0) {
                        return;
                    }
                }
                const hit = {} as SearchHit;
                hit.flag = `${prefix}${kwidx}_${count}`;
                hit.address = match.address;
                hit.size = match.size;
                searchHits.push(hit);
                count++;
                script += `fs+search; f ${hit.flag} ${hit.size} ${hexPtr(hit.address)};fs-;\n`;
            });
        } catch (e) {
            console.error('Search error', e);
        }
    }
    r2.hostCmd(script);
    config.set("search.kwidx", kwidx + 1);
    qlog(`hits: ${searchHits.length}`);
    return searchHits;
};

function qlog(message: string) {
    if (!config.getBoolean('search.quiet')) {
        console.log(`${message}\n`);
    }
}

function _getRangesToSearch(fromAddress: NativePointer, toAddress: NativePointer): SearchRange[] {
    const searchIn = _getSearchResultFromConfig();
    const ranges = getMemoryRangesFilteredBySearchResult(searchIn);
    if (ranges.length === 0) {
        return [];
    }
    const first = ranges[0];
    const last = ranges[ranges.length - 1];
    const from = fromAddress.isNull() ? first.address : fromAddress;
    const to = toAddress.isNull() ? last.address.add(last.size) : toAddress;
    return ranges.filter((range: SearchRange) => {
        return range.address.compare(from) >= 0 && range.address.add(range.size).compare(to) <= 0;
    });
}

function getMemoryRangesFilteredBySearchResult(searchIn: SearchResult): SearchRange[] {
    let memoryRanges;
    if (searchIn.heap) {
        memoryRanges = listMallocRangesJson();
    } else {
        memoryRanges = getMemoryRanges(searchIn.perm).filter((range: RangeDetails) => {
            const start = range.base;
            const end = start.add(range.size);
            const offPtr = ptr(r2frida.offset);
            if (searchIn.current) {
                return offPtr.compare(start) >= 0 && offPtr.compare(end) < 0;
            }
            if (searchIn.path !== null) {
                if (range.file !== undefined) {
                    return range.file.path.indexOf(searchIn.path) >= 0;
                }
                return false;
            }
            return true;
        });
    }
    return memoryRanges.map((range) => {
        return {
            address: range.base,
            size: range.size
        } as SearchRange;
    });
}

function _getSearchResultFromConfig(): SearchResult {
    const res: SearchResult = {
        current: false,
        perm: 'r--',
        path: null,
        heap: false
    };
    const searchConfig = config.getString('search.in');
    const [scope, param] = searchConfig.split(':');
    switch (scope) {
        case "current":
            res.current = true;
            break;
        case "heap":
            res.heap = true;
            break;
        case "perm":
            res.perm = param;
            break;
        case "path":
            res.path = param;
            break;
        default:
            res.current = true;
            break;
    }
    return res;
}

export interface SearchHit {
    address: NativePointer;
    size: number;
    content: string;
    flag: string | undefined;
}

export interface SearchResult {
    current: boolean,
    perm: string,
    path: string | null,
    heap: boolean
}

export interface SearchRange {
    address: NativePointer;
    size: number;
}
