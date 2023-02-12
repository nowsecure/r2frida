import config from '../../config.js';
import * as utils from '../utils.js';

declare let global: any;

export function lookupDebugInfo(args: string[]) : void {
    const o = DebugSymbol.fromAddress(ptr('' + args));
    console.log(o);
}

export function lookupAddress(args: string[]) : string {
    if (args.length === 0) {
        args = [ptr(global.r2frida.offset).toString()];
    }
    return lookupAddressJson(args)
        .map(({ type, name, address }) => [type, name, address].join(' '))
        .join('\n');
}

export function lookupAddressR2(args: string[]) : string {
    return lookupAddressJson(args)
        .map(({ type, name, address }) => ['f', 'sym.' + utils.sanitizeString(name), '=', address].join(' '))
        .join('\n');
}

export function lookupAddressJson(args: string[]): any[] {
    const exportAddress = ptr(args[0]);
    const result: any[] = [];
    const modules = Process.enumerateModules().map(m => m.path);
    return modules.reduce((result, moduleName) => {
        const exports = Process.getModuleByName(moduleName)!.enumerateExports();
        return result.concat(exports as any);
    }, [])
        .reduce((type: any, obj: any) => {
            if (ptr(obj.address).compare(exportAddress) === 0) {
                result.push({
                    type: obj.type,
                    name: obj.name,
                    address: obj.address
                });
            }
            return result;
        }, []);
}

export function lookupSymbolHere(args: string[]) {
    return lookupAddress([global.r2frida.offset.toString()]);
}

export function lookupExport(args: string[]) {
    return lookupExportJson(args)
        // .map(({library, name, address}) => [library, name, address].join(' '))
        .map(({ address }) => '' + address)
        .join('\n');
}

export function lookupExportR2(args: string[]) {
    return lookupExportJson(args)
        .map(({ name, address }) => ['f', 'sym.' + name, '=', address].join(' '))
        .join('\n');
}

export function lookupExportJson(args: string[]) {
    if (args.length === 2) {
        const [moduleName, exportName] = args;
        const address = Module.findExportByName(moduleName, exportName);
        if (address === null) {
            return [];
        }
        const m = getModuleByAddress(address);
        return [{
            library: m.name,
            name: exportName,
            address: address
        }];
    } else {
        const exportName = args[0];
        let prevAddress: NativePointer | null = null;
        return Process.enumerateModules()
            .reduce((result: any[], m) => {
                const address = Module.findExportByName(m.path, exportName);
                if (address !== null && (prevAddress === null || address.compare(prevAddress))) {
                    result.push({
                        library: m.name,
                        name: exportName,
                        address: address
                    });
                    prevAddress = address;
                }
                return result;
            }, []);
    }
}

// lookup symbols
export function lookupSymbol(args: string[]) {
    return lookupSymbolJson(args)
        .map(({ address }) => '' + address)
        .join('\n');
}

export function lookupSymbolR2(args: string[]) {
    return lookupSymbolJson(args)
        .map(({ name, address }) => ['f', 'sym.' + utils.sanitizeString(name), '=', address].join(' '))
        .join('\n');
}

export function lookupSymbolManyJson(args: string[]) {
    const res = [];
    for (const arg of args) {
        res.push({ name: arg, address: lookupSymbol([arg]) });
    }
    return res;
}

export function lookupSymbolMany(args: string[]) {
    return lookupSymbolManyJson(args).map(({ address }) => address).join('\n');
}

export function lookupSymbolManyR2(args: string[]) {
    return lookupSymbolManyJson(args)
        .map(({ name, address }) => ['f', 'sym.' + utils.sanitizeString(name), '=', address].join(' '))
        .join('\n');
}

export function lookupSymbolJson(args: string[]) {
    if (args.length === 0) {
        return [];
    }
    if (args.length === 2) {
        let [moduleName] = args;
        const [symbolName] = args;
        try {
            const m = Process.getModuleByName(moduleName);
            // unused, this needs to be rewritten
        } catch (e) {
            const res = Process.enumerateModules().filter(function (x) {
                return x.name.indexOf(moduleName) !== -1;
            });
            if (res.length !== 1) {
                return [];
            }
            moduleName = res[0].name;
        }
        let address = ptr(0);
        const m = Process.getModuleByName(moduleName).enumerateSymbols().filter(function (s) {
            if (s.name === symbolName) {
                address = s.address;
            }
        });
        return [{
            library: moduleName,
            name: symbolName,
            address: address
        }];
    } else {
        const [symbolName] = args;
        const res = utils.getPtr(symbolName);
        const mod = _getModuleAt(res);
        if (res) {
            return [{
                library: mod ? mod.name : 'unknown',
                name: symbolName,
                address: res
            }];
        }
        const fcns = DebugSymbol.findFunctionsNamed(symbolName);
        if (fcns) {
            return fcns.map((f) => { return { name: symbolName, address: f }; });
        }
        return [];
        /*
        var at = DebugSymbol.fromName(symbolName);
        if (at.name) {
          return [{
            library: at.moduleName,
            name: symbolName,
            address: at.address
          }];
        }
        */
    }
}

function _getModuleAt(addr: NativePointer | null) {
    if (addr === null) {
        return null;
    }
    const modules = Process.enumerateModules()
        .filter((m) => {
            const a = m.base;
            const b = m.base.add(m.size);
            return addr.compare(a) >= 0 && addr.compare(b) < 0;
        });
    return modules.length > 0 ? modules[0] : null;
}

export function getModuleByAddress(addr: NativePointer): any {
    const m = config.getString('symbols.module');
    if (m !== '') {
        return Process.getModuleByName(m);
    }
    try {
        return Process.getModuleByAddress(addr);
    } catch (e) {
        return Process.getModuleByAddress(ptr(global.r2frida.offset));
    }
}

export default {
    lookupSymbol,
    lookupSymbolR2,
    lookupSymbolJson,
    lookupSymbolHere,
    lookupAddressJson,
    lookupSymbolMany,
    lookupSymbolManyJson,
    lookupSymbolManyR2,
    lookupExport,
    lookupExportJson,
    lookupExportR2,
    lookupDebugInfo,
    lookupAddress,
    lookupAddressR2,
    getModuleByAddress
};
