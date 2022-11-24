import r2frida from "./plugin.js";
import config from "./config.js";
'use strict';
let cachedRanges = [];
function read(params) {
    const { offset, count, fast } = params;
    if (typeof r2frida.hookedRead === 'function') {
        return r2frida.hookedRead(offset, count);
    }
    if (r2frida.safeio) {
        try {
            if (cachedRanges.length === 0) {
                cachedRanges = Process.enumerateRanges('').map((map) => [map.base, ptr(map.base).add(map.size)]);
            }
            // TODO: invalidate ranges at some point to refresh
            // process.nextTick(() => { cachedRanges = null; }
            const o = ptr(offset);
            for (const map of cachedRanges) {
                if (o.compare(map[0]) >= 0 && o.compare(map[1]) < 0) {
                    let left = count;
                    if (o.add(count).compare(map[1]) > 0) {
                        const rest = o.add(count).sub(map[1]);
                        left = left.sub(rest);
                    }
                    const bytes = Memory.readByteArray(o, left);
                    return [{}, (bytes !== null) ? bytes : []];
                }
            }
            return [{}, []];
        }
        catch (e) {
            console.error('safeio-read', e);
        }
    }
    if (offset < 0) {
        return [{}, []];
    }
    try {
        const bytes = Memory.readByteArray(ptr(offset), count);
        // console.log("FAST", offset);
        return [{}, (bytes !== null) ? bytes : []];
    }
    catch (e) {
        if (!fast) {
            try {
                // console.log("SLOW", offset);
                const readStarts = ptr(offset);
                const readEnds = readStarts.add(count);
                const currentRange = Process.getRangeByAddress(readStarts); // this is very slow
                const moduleEnds = currentRange.base.add(currentRange.size);
                const left = (readEnds.compare(moduleEnds) > 0
                    ? readEnds
                    : moduleEnds).sub(offset);
                const bytes = Memory.readByteArray(ptr(offset), +left);
                return [{}, (bytes !== null) ? bytes : []];
            }
            catch (e) {
                // do nothing
            }
        }
    }
    return [{}, []];
}
function isExecutable(address) {
    const currentRange = Process.getRangeByAddress(address);
    return currentRange.protection.indexOf('x') !== -1;
}
function write(params, data) {
    if (typeof r2frida.hookedWrite === 'function') {
        return r2frida.hookedWrite(params.offset, data);
    }
    if (config.getBoolean('patch.code') && isExecutable(ptr(params.offset))) {
        if (typeof Memory.patchCode === 'function') {
            Memory.patchCode(ptr(params.offset), 1, function (ptr) {
                Memory.writeByteArray(ptr, data);
            });
        }
        else {
            Memory.writeByteArray(ptr(params.offset), data);
        }
    }
    else {
        Memory.writeByteArray(ptr(params.offset), data);
    }
    return [{}, null];
}
export { read };
export { write };
export default {
    read: read,
    write: write
};
