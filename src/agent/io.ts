import r2frida from './plugin.js';
import config from './config.js';

export default { read, write };

type PointerPair = NativePointer[];
let cachedRanges: PointerPair[] = [];

// TODO: cached ranges are never invalidated. add a command for it?
function invalidateCachedRanges() {
    Script.nextTick(() => { cachedRanges = [] ; });
}

export function read(params: any) {
    const { offset, count, fast } = params;
    if (typeof r2frida.hookedRead === 'function') {
        return r2frida.hookedRead(offset, count);
    }
    if (config.getBoolean('io.volatile')) {
        const np = new NativePointer(offset) as any;
	try {
          const data = np.readVolatile(count);
          return [{}, data];
	} catch(err) {
	  // config.set("io.volatile", false);
	}
        return [{}, []];
    }
    if (config.getBoolean('io.safe')) {
        try {
            if (cachedRanges.length === 0) {
                const foo = (map: RangeDetails) : PointerPair => [map.base, map.base.add(map.size)];
                cachedRanges = Process.enumerateRanges('').map(foo);
            }
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
            // console.error('safeio-read', e);
        }
    }
    if (offset < 2) {
        return [{}, []];
    }
    try {
        const bytes = ptr(offset).readByteArray(count);
        return [{}, (bytes !== null) ? bytes : []];
    } catch (e) {
        if (!fast) {
            try {
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

function isExecutable(address: NativePointer) : boolean {
    const currentRange = Process.getRangeByAddress(address);
    return currentRange.protection.indexOf('x') !== -1;
}

export function write(params: any, data: any) {
    const ptroff = params.offset;
    if (typeof r2frida.hookedWrite === 'function') {
        return r2frida.hookedWrite(ptroff, data);
    }
    if (config.getBoolean('patch.code') && isExecutable(ptroff)) {
        if (typeof Memory.patchCode === 'function') {
            Memory.patchCode(ptroff, 1, function (p: NativePointer) {
                p.writeByteArray(data);
            });
        } else {
            params.offset.writeByteArray(data);
        }
    } else {
        params.offset.writeByteArray(data);
    }
    return [{}, null];
}
