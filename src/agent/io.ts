import r2frida from './plugin.js';
import config from './config.js';


let cachedRanges: any[] = [];

export function read(params: any) {
    const { offset, count, fast } = params;
    if (typeof r2frida.hookedRead === 'function') {
        return r2frida.hookedRead(offset, count);
    }
    if (r2frida.safeio) {
        try {
            if (cachedRanges.length === 0) {
                const foo = (map: any) => [map.base, ptr(map.base).add(map.size)];
                cachedRanges = Process.enumerateRanges('').map(foo);
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
                    const bytes = o.readByteArray(left);
                    return [{}, (bytes !== null) ? bytes : []];
                }
            }
            return [{}, []];
        } catch (e) {
            console.error('safeio-read', e);
        }
    }
    if (offset < 0) {
        return [{}, []];
    }
    try {
        const bytes = ptr(offset).readByteArray(count);
        // console.log("FAST", offset);
        return [{}, (bytes !== null) ? bytes : []];
    } catch (e) {
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
                const bytes = ptr(offset).readByteArray(+left);
                return [{}, (bytes !== null) ? bytes : []];
            } catch (e) {
                // do nothing
            }
        }
    }
    return [{}, []];
}

function isExecutable(address: NativePointer) {
    const currentRange = Process.getRangeByAddress(address);
    return currentRange.protection.indexOf('x') !== -1;
}

export function write(params: any, data: any) {
    const ptroff = ptr(params.offset);
    if (typeof r2frida.hookedWrite === 'function') {
        return r2frida.hookedWrite(ptroff, data);
    }
    if (config.getBoolean('patch.code') && isExecutable(ptroff)) {
        if (typeof Memory.patchCode === 'function') {
            Memory.patchCode(ptroff, 1, function (p: NativePointer) {
                p.writeByteArray(data);
            });
        } else {
            ptr(params.offset).writeByteArray(data);
        }
    } else {
        ptr(params.offset).writeByteArray(data);
    }
    return [{}, null];
}

export default { read, write };
