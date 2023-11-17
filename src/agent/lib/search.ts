import config from '../config.js';
import { ObjCAvailable } from './darwin/index.js';
import io from '../io.js';
import r2, { r2Config } from './r2.js';
import { r2frida } from "../plugin.js";
import { getMemoryRanges, listMallocRangesJson } from './debug/memory.js';
import { normHexPairs, filterPrintable, toWidePairs, byteArrayToHex, ptrMin, ptrMax, padPointer, toHexPairs, renderEndian, hexPtr } from './utils.js';

export async function search(args: string[]): Promise<string> {
    const hits = await searchJson(args);
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
                    instances.push({ address: ptr(0x0), content: instance.className, size: 0 } as SearchHit);
                },
                onComplete:function() {
                    console.log("search done");
                }
            });
            //const results: any = Java.use(className);
            return instances;
        });
    }
    return [];
}

export async function searchJson(args: string[]): Promise<SearchHit[]> {
    const pattern = toHexPairs(args.join(' '));
    const hits = await _searchPatternJson(pattern);
    hits.forEach(hit => {
        try {
            const bytes = io.read({
                offset: hit.address,
                count: 60
            })[1];
            hit.content = filterPrintable(bytes);
        } catch (e) {
        }
    });
    return hits.filter((hit: SearchHit) => hit.content !== undefined);
}

export async function searchHex(args: string[]): Promise<string> {
    const hits = await searchHexJson(args);
    return _getReadableHitsToString(hits);
}

export async function searchHexJson(args: string[]): Promise<SearchHit[]> {
    const pattern = normHexPairs(args.join(''));
    const hits = await _searchPatternJson(pattern);
    hits.forEach((hit: SearchHit) => {
        const bytes = hit.address.readByteArray(hit.size);
        hit.content = byteArrayToHex(bytes);
    });
    return hits;
}

export function searchWide(args: string[]) {
    return searchWideJson(args).then(hits => {
        return _getReadableHitsToString(hits);
    });
}

export function searchWideJson(args: string[]): Promise<SearchHit[]> {
    const pattern = toWidePairs(args.join(' '));
    return searchHexJson([pattern]);
}

export function searchValueImpl(width: number) {
    return function (args: string[]) {
        return _searchValueJson(args, width).then((hits: any) => {
            return _getReadableHitsToString(hits);
        });
    };
}

export function searchValueImplJson(width: number) {
    return function (args: string[]) {
        return _searchValueJson(args, width);
    };
}

async function _searchValueJson(args: string[], width: number) {
    let value = args.join('');
    const r2Config =  await r2.hostCmdj('ej') as unknown as r2Config;
    const bigEndian = r2Config.cfg.bigendian;
    const bytes = renderEndian(ptr(value), bigEndian, width);
    return searchHexJson([toHexPairs(bytes)]);
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

async function getr2Config(): Promise<r2Config> {
    const r2cfg = await r2.hostCmdj('ej') as unknown as r2Config;
    return r2cfg;
}

function  _searchPatternJson(pattern: string): Promise<SearchHit[]> {
    let searchHits: SearchHit[] = [];
    return getr2Config().then((r2cfg: r2Config)  => {
        const fromAddress = new NativePointer(r2cfg.search.from);
        const toAddress = new NativePointer(r2cfg.search.to);
        const flags = r2cfg.search.flags;
        const prefix = r2cfg.search.prefix || 'hit';
        const count = r2cfg.search.count || 0;
        const kwidx = r2cfg.search.kwidx || 0;
        const ranges = _getRangesToSearch(fromAddress, toAddress);
        const nBytes = pattern.split(' ').length;
        qlog(`Searching ${nBytes} bytes: ${pattern}`);
        const commands: string[] = [];
        let idx = 0;
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
                    const hit = {} as SearchHit;
                    hit.flag = `${prefix}${kwidx}_${idx + count}`;
                    hit.address = match.address;
                    hit.size = match.size;
                    if (flags) {
                        commands.push('fs+searches');
                        commands.push(`f ${hit.flag} ${hit.size} ${hexPtr(hit.address)}`);
                        commands.push('fs-');
                    }
                    idx += 1;
                    searchHits.push(hit);
                });
            } catch (e) {
                console.error('Search error', e);
            }
        }
        qlog(`hits: ${searchHits.length}`);
        commands.push(`e search.kwidx=${kwidx + 1}`);
        r2.hostCmds(commands);
        return searchHits;
    });
};

function qlog(message: string) {
    if (!config.getBoolean('search.quiet')) {
        console.log(message);
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

