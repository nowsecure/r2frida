import config from '../config.js';
import { ObjCAvailable } from './darwin/index.js';
import io from '../io.js';
import r2 from './r2.js';
import { r2frida } from "../plugin.js";
import { getMemoryRanges } from './debug/memory.js';
import { normHexPairs, filterPrintable, toWidePairs, byteArrayToHex, ptrMin, ptrMax, padPointer, toHexPairs, renderEndian, hexPtr } from './utils.js';

export function search(args: string[]) {
    return searchJson(args).then((hits: any) => {
        return _readableHits(hits);
    });
}

export function searchInstances(args: string[]) {
    return _readableHits(searchInstancesJson(args));
}

export function searchInstancesJson(args: string[]) {
    const className = args.join('');
    if (ObjCAvailable) {
        const results = JSON.parse(JSON.stringify(ObjC.chooseSync(ObjC.classes[className])));
        return results.map(function (res: any) {
            return { address: res.handle, content: className };
        });
    } else {
        Java.performNow(function () {
            // const results: any = Java.choose(Java.classes[className]);
            const results: any = Java.use(className);
            return results.map(function (res: any) {
                return { address: res, content: className };
            });
        });
    }
}

export function searchJson(args: string[]) {
    const pattern = toHexPairs(args.join(' '));
    return _searchPatternJson(pattern).then((hits: SearchHit[]) => {
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
    });
}

export function searchHex(args: string[]) {
    return searchHexJson(args).then(hits => {
        return _readableHits(hits);
    });
}

export function searchHexJson(args: string[]): Promise<SearchHit[]> {
    const pattern = normHexPairs(args.join(''));
    return _searchPatternJson(pattern).then((hits: SearchHit[]) => {
        hits.forEach((hit: SearchHit) => {
            const bytes = ptr(hit.address).readByteArray(hit.size);
            hit.content = byteArrayToHex(bytes);
        });
        return hits;
    });
}

export function searchWide(args: string[]) {
    return searchWideJson(args).then(hits => {
        return _readableHits(hits);
    });
}

export function searchWideJson(args: string[]) {
    const pattern = toWidePairs(args.join(' '));
    return searchHexJson([pattern]);
}

export function searchValueImpl(width: number) {
    return function (args: string[]) {
        return _searchValueJson(args, width).then((hits: any) => {
            return _readableHits(hits);
        });
    };
}

export function searchValueImplJson(width: number) {
    return function (args: string[]) {
        return _searchValueJson(args, width);
    };
}

function _searchValueJson(args: string[], width: number) {
    let value: string;
    try {
        value = args.join('');
    } catch (e) {
        return new Promise((resolve, reject) => reject(e));
    }
    return r2.hostCmdj('ej')
        .then((r2cfg: any) => {
            const bigEndian = r2cfg['cfg.bigendian'];
            const bytes = renderEndian(ptr(value), bigEndian, width);
            return searchHexJson([toHexPairs(bytes)]);
        });
}

function _readableHits(hits: SearchHit[]) {
    const output = hits.map(hit => {
        if (typeof hit.flag === 'string') {
            return `${hexPtr(hit.address)} ${hit.flag} ${hit.content}`;
        }
        return `${hexPtr(hit.address)} ${hit.content}`;
    });
    return output.join('\n') + '\n';
}

function _searchPatternJson(pattern: string) {
    return r2.hostCmdj('ej')
        .then((r2cfg: any) => {
            const fromAddress = new NativePointer(r2cfg['search.from']);
            const toAddress = new NativePointer(r2cfg['search.to']);
            const flags = r2cfg['search.flags'];
            const prefix = r2cfg['search.prefix'] || 'hit';
            const count = r2cfg['search.count'] || 0;
            const kwidx = r2cfg['search.kwidx'] || 0;
            const ranges = _getRanges(fromAddress, toAddress);
            const nBytes = pattern.split(' ').length;
            qlog(`Searching ${nBytes} bytes: ${pattern}`);
            let results: SearchResult[] = [];
            const commands: string[] = [];
            let idx = 0;
            for (const range of ranges) {
                if (range.size === 0) {
                    continue;
                }
                const rangeStr = `[${padPointer(range.address)}-${padPointer(range.address.add(range.size))}]`;
                qlog(`Searching ${nBytes} bytes in ${rangeStr}`);
                try {
                    const partial = _scanForPattern(range.address, range.size, pattern);
                    partial.forEach((hit: SearchHit) => {
                        if (flags) {
                            hit.flag = `${prefix}${kwidx}_${idx + count}`;
                            commands.push('fs+searches');
                            commands.push(`f ${hit.flag} ${hit.size} ${hexPtr(hit.address)}`);
                            commands.push('fs-');
                        }
                        idx += 1;
                    });
                    results = results.concat(partial);
                } catch (e) {
                    console.error('Oops', e);
                }
            }
            qlog(`hits: ${results.length}`);
            commands.push(`e search.kwidx=${kwidx + 1}`);
            return r2.hostCmds(commands).then(() => {
                return results;
            });
        });

    function qlog(message: string) {
        if (!config.getBoolean('search.quiet')) {
            console.log(message);
        }
    }
}

function _scanForPattern(address: any, size: any, pattern: any) {
    if (r2frida.hookedScan !== null) {
        return r2frida.hookedScan(address, size, pattern);
    }
    return Memory.scanSync(address, size, pattern);
}

function _getRanges(fromAddress: NativePointer, toAddress: NativePointer) {
    const searchIn = _configParseSearchIn();
    if (searchIn.heap) {
        return Process.enumerateMallocRanges()
            .map(_ => {
                return {
                    address: _.base,
                    size: _.size
                };
            });
    }
    const ranges = getMemoryRanges(searchIn.perm).filter((range: any) => {
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
    if (ranges.length === 0) {
        return [];
    }
    const first = ranges[0];
    const last = ranges[ranges.length - 1];
    const from = fromAddress.isNull() ? first.base : fromAddress;
    const to = toAddress.isNull() ? last.base.add(last.size) : toAddress;
    return ranges.filter((range: any) => {
        return range.base.compare(to) <= 0 && range.base.add(range.size).compare(from) >= 0;
    }).map((range: any) => {
        const start = ptrMax(range.base, from);
        const end = ptrMin(range.base.add(range.size), to);
        return {
            address: start,
            size: uint64(end.sub(start).toString()).toNumber()
        };
    });
}

function _configParseSearchIn(): SearchResult {
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
    address: string;
    size: number;
    content: string;
    flag: string;
}

export interface SearchResult {
    current: boolean,
    perm: string,
    path: string | null,
    heap: boolean
}
