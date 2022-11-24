import config from "../config.js";
import darwin from "./darwin/index.js";
import io from "../io.js";
import r2 from "./r2.js";
import { getMemoryRanges } from "./debug/memory.js";
import utils from "./utils.js";
'use strict';
function search(args) {
    return searchJson(args).then(hits => {
        return _readableHits(hits);
    });
}
function searchInstances(args) {
    return _readableHits(searchInstancesJson(args));
}
function searchInstancesJson(args) {
    const className = args.join('');
    if (darwin.ObjCAvailable) {
        const results = JSON.parse(JSON.stringify(ObjC.chooseSync(ObjC.classes[className])));
        return results.map(function (res) {
            return { address: res.handle, content: className };
        });
    }
    else {
        Java.performNow(function () {
            const results = Java.choose(Java.classes[className]);
            return results.map(function (res) {
                return { address: res, content: className };
            });
        });
    }
}
function searchJson(args) {
    const pattern = utils.toHexPairs(args.join(' '));
    return _searchPatternJson(pattern).then(hits => {
        hits.forEach(hit => {
            try {
                const bytes = io.read({
                    offset: hit.address,
                    count: 60
                })[1];
                hit.content = utils.filterPrintable(bytes);
            }
            catch (e) {
            }
        });
        return hits.filter(hit => hit.content !== undefined);
    });
}
function searchHex(args) {
    return searchHexJson(args).then(hits => {
        return _readableHits(hits);
    });
}
function searchHexJson(args) {
    const pattern = utils.normHexPairs(args.join(''));
    return _searchPatternJson(pattern).then(hits => {
        hits.forEach(hit => {
            const bytes = Memory.readByteArray(hit.address, hit.size);
            hit.content = utils.byteArrayToHex(bytes);
        });
        return hits;
    });
}
function searchWide(args) {
    return searchWideJson(args).then(hits => {
        return _readableHits(hits);
    });
}
function searchWideJson(args) {
    const pattern = utils.toWidePairs(args.join(' '));
    return searchHexJson([pattern]);
}
function searchValueImpl(width) {
    return function (args) {
        return _searchValueJson(args, width).then(hits => {
            return _readableHits(hits);
        });
    };
}
function searchValueImplJson(width) {
    return function (args) {
        return _searchValueJson(args, width);
    };
}
function _searchValueJson(args, width) {
    let value;
    try {
        value = uint64(args.join(''));
    }
    catch (e) {
        return new Promise((resolve, reject) => reject(e));
    }
    return r2.hostCmdj('ej')
        .then((r2cfg) => {
        const bigEndian = r2cfg['cfg.bigendian'];
        const bytes = utils.renderEndian(value, bigEndian, width);
        return searchHexJson([utils.toHexPairs(bytes)]);
    });
}
function _readableHits(hits) {
    const output = hits.map(hit => {
        if (typeof hit.flag === 'string') {
            return `${utils.hexPtr(hit.address)} ${hit.flag} ${hit.content}`;
        }
        return `${utils.hexPtr(hit.address)} ${hit.content}`;
    });
    return output.join('\n') + '\n';
}
function _searchPatternJson(pattern) {
    return r2.hostCmdj('ej')
        .then(r2cfg => {
        const flags = r2cfg['search.flags'];
        const prefix = r2cfg['search.prefix'] || 'hit';
        const count = r2cfg['search.count'] || 0;
        const kwidx = r2cfg['search.kwidx'] || 0;
        const ranges = _getRanges(r2cfg['search.from'], r2cfg['search.to']);
        const nBytes = pattern.split(' ').length;
        qlog(`Searching ${nBytes} bytes: ${pattern}`);
        let results = [];
        const commands = [];
        let idx = 0;
        for (const range of ranges) {
            if (range.size === 0) {
                continue;
            }
            const rangeStr = `[${utils.padPointer(range.address)}-${utils.padPointer(range.address.add(range.size))}]`;
            qlog(`Searching ${nBytes} bytes in ${rangeStr}`);
            try {
                const partial = _scanForPattern(range.address, range.size, pattern);
                partial.forEach((hit) => {
                    if (flags) {
                        hit.flag = `${prefix}${kwidx}_${idx + count}`;
                        commands.push('fs+searches');
                        commands.push(`f ${hit.flag} ${hit.size} ${utils.hexPtr(hit.address)}`);
                        commands.push('fs-');
                    }
                    idx += 1;
                });
                results = results.concat(partial);
            }
            catch (e) {
                console.error('Oops', e);
            }
        }
        qlog(`hits: ${results.length}`);
        commands.push(`e search.kwidx=${kwidx + 1}`);
        return r2.hostCmds(commands).then(() => {
            return results;
        });
    });
    function qlog(message) {
        if (!config.getBoolean('search.quiet')) {
            console.log(message);
        }
    }
}
function _scanForPattern(address, size, pattern) {
    if (global.r2frida.hookedScan !== null) {
        return global.r2frida.hookedScan(address, size, pattern);
    }
    return Memory.scanSync(address, size, pattern);
}
function _getRanges(fromNum, toNum) {
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
    const ranges = getMemoryRanges(searchIn.perm).filter(range => {
        const start = range.base;
        const end = start.add(range.size);
        const offPtr = ptr(global.r2frida.offset);
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
    const from = (fromNum === -1) ? first.base : ptr(fromNum);
    const to = (toNum === -1) ? last.base.add(last.size) : ptr(toNum);
    return ranges.filter(range => {
        return range.base.compare(to) <= 0 && range.base.add(range.size).compare(from) >= 0;
    }).map(range => {
        const start = utils.ptrMax(range.base, from);
        const end = utils.ptrMin(range.base.add(range.size), to);
        return {
            address: start,
            size: uint64(end.sub(start).toString()).toNumber()
        };
    });
}
function _configParseSearchIn() {
    const res = {
        current: false,
        perm: 'r--',
        path: null,
        heap: false
    };
    const c = config.getString('search.in');
    const cSplit = c.split(':');
    const [scope, param] = cSplit;
    if (scope === 'current') {
        res.current = true;
    }
    if (scope === 'heap') {
        res.heap = true;
    }
    if (scope === 'perm') {
        res.perm = param;
    }
    if (scope === 'path') {
        cSplit.shift();
        res.path = cSplit.join('');
    }
    return res;
}
export { search };
export { searchInstances };
export { searchInstancesJson };
export { searchJson };
export { searchHex };
export { searchHexJson };
export { searchWide };
export { searchWideJson };
export { searchValueImpl };
export { searchValueImplJson };
export default {
    search,
    searchInstances,
    searchInstancesJson,
    searchJson,
    searchHex,
    searchHexJson,
    searchWide,
    searchWideJson,
    searchValueImpl,
    searchValueImplJson
};
