import { getModuleByAddress } from './lookup.js';
import config from '../../config.js';
import elf, { listElfSections, listElfSegments } from '../elf/index.js';
import { getCwd } from '../fs.js';
import {JavaAvailable, performOnJavaVM } from '../java/index.js';
import r2 from '../r2.js';
import sys from '../sys.js';
import { ObjCAvailable, getSections, getSegments, listMachoSections, listMachoSegments } from '../darwin/index.js';
import { SwiftAvailable } from '../darwin/swift.js';
import strings from '../strings.js';
import { belongsTo, padPointer, sanitizeString } from '../utils.js';
import { parseMachoHeader, hasMainLoop } from '../darwin/index.js';

declare let global: any;

export async function dumpInfo() {
    const padding = (x: number) => ''.padStart(20 - x, ' ');
    const properties: any = await dumpInfoJson();
    return Object.keys(properties)
        .map((k: any) => k + padding(k.length) + properties[k])
        .join('\n');
}

export async function dumpInfoR2() {
    const properties: any = await dumpInfoJson();
    const jnienv = properties.jniEnv !== undefined ? properties.jniEnv : '';
    return [
        'e asm.arch=' + properties.arch,
        'e asm.bits=' + properties.bits,
        'e asm.os=' + properties.os,
        'f r2f.modulebase=' + properties.modulebase
    ].join('\n') + jnienv;
}

export async function dumpInfoJson() {
    const res : any = {
        arch: r2.getArch(Process.arch),
        bits: Process.pointerSize * 8,
        os: Process.platform,
        pid: sys.getPid(),
        uid: sys._getuid!(),
        objc: ObjCAvailable,
        runtime: Script.runtime,
        swift: SwiftAvailable(),
        java: JavaAvailable,
        mainLoop: hasMainLoop(),
        pageSize: Process.pageSize,
        pointerSize: Process.pointerSize,
        codeSigningPolicy: Process.codeSigningPolicy,
        isDebuggerAttached: Process.isDebuggerAttached(),
        cwd: getCwd()
    };
    if (ObjCAvailable) {
        try {
            const mb = (ObjC && ObjC.classes && ObjC.classes.NSBundle) ? ObjC.classes.NSBundle.mainBundle() : '';
            const id = mb ? mb.infoDictionary() : '';
            const get = (k: string) => {
                const v = id ? id.objectForKey_(k) : '';
                return v ? v.toString() : '';
            }
            const NSHomeDirectory = new NativeFunction(Module.getExportByName(null, 'NSHomeDirectory'), 'pointer', []);
            const NSTemporaryDirectory = new NativeFunction(Module.getExportByName(null, 'NSTemporaryDirectory'), 'pointer', []);
            const bundleIdentifier = get('CFBundleIdentifier');
            if (bundleIdentifier) {
                res.bundle = bundleIdentifier;
                res.exename = get('CFBundleExecutable');
                res.appname = get('CFBundleDisplayName');
                res.appversion = get('CFBundleShortVersionString');
                res.appnumversion = get('CFBundleNumericVersion');
                res.minOS = get('MinimumOSVersion');
            }
            res.modulename = Process.enumerateModules()[0].name;
            res.modulebase = Process.enumerateModules()[0].base;
            res.homedir = (new ObjC.Object(NSHomeDirectory()).toString());
            res.tmpdir = (new ObjC.Object(NSTemporaryDirectory()).toString());
            res.bundledir = ObjC.classes.NSBundle.mainBundle().bundleURL().path();
        } catch (e) {
            console.error(e);
        }
    }
    if (JavaAvailable) {
        await performOnJavaVM(() => {
            const ActivityThread = Java.use('android.app.ActivityThread');
            const app = ActivityThread.currentApplication();
            if (app !== null) {
                const ctx = app.getApplicationContext();
                if (ctx !== null) {
                    const tryTo = (x: any) => {
                        let r = '';
                        try {
                            r = x();
                        } catch (e) {
                            // ignored
                        }
                        return r;
                    }
                    res.dataDir = tryTo(() => ctx.getDataDir().getAbsolutePath());
                    res.codeCacheDir = tryTo(() => ctx.getCodeCacheDir().getAbsolutePath());
                    res.extCacheDir = tryTo(() => ctx.getExternalCacheDir().getAbsolutePath());
                    res.obbDir = tryTo(() => ctx.getObbDir().getAbsolutePath());
                    res.filesDir = tryTo(() => ctx.getFilesDir().getAbsolutePath());
                    res.noBackupDir = tryTo(() => ctx.getNoBackupFilesDir().getAbsolutePath());
                    res.codePath = tryTo(() => ctx.getPackageCodePath());
                    res.packageName = tryTo(() => ctx.getPackageName());
                }
                try {
                    const getContext = () => {
                        return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext().getContentResolver();
                    }
                    res.androidId = Java.use('android.provider.Settings$Secure').getString(getContext(), 'android_id');
                } catch (ignoredError) {
                }
            }
            res.cacheDir = Java.classFactory.cacheDir;
            const jniEnv = ptr(Java.vm.getEnv());
            if (jniEnv) {
                res.jniEnv = jniEnv.toString();
            }
        });
    }
    return res;
}

export function listEntrypointJson(args?: string[]) {
    function isEntrypoint(s: any) {
        if (s.type === 'section') {
            switch (s.name) {
                case '_start':
                case 'start':
                case 'main':
                    return true;
            }
        }
        return false;
    }
    if (Process.platform === 'linux') {
        const at = DebugSymbol.fromName('main');
        if (at) {
            return [at];
        }
    }
    const firstModule = Process.enumerateModules()[0];
    return firstModule.enumerateSymbols()
        .filter((symbol) => {
            return isEntrypoint(symbol);
        }).map((symbol) => {
            (symbol as any).moduleName = getModuleByAddress(symbol.address).name;
            return symbol;
        });
}

export function listEntrypointR2(args: string[]) : string {
    let n = 0;
    return listEntrypointJson()
        .map((entry) => {
            return 'f entry' + (n++) + ' = ' + entry.address;
        }).join('\n');
}

export function listEntrypointQuiet(args: string[]) {
    return listEntrypointJson()
        .map((entry) => {
            return entry.address;
        }).join('\n');
}

export function listEntrypoint(args: string[]) {
    return listEntrypointJson()
        .map((entry) => {
            return entry.address + ' ' + entry.name; //  + '  # ' + entry.moduleName;
        }).join('\n');
}

export function listImports(args: string[]) {
    return listImportsJson(args)
        .map((a: any) => [a.address, a.type ? a.type[0] : ' ', a.name, a.module].join(' '))
        .join('\n');
}

export function listImportsR2(args: string[]) {
    const seen = new Set();
    let stubAddress = 0;
    const stubSize = Process.arch === 'x64' ? 6 : 8;
    if (Process.platform === 'darwin') {
        try {
            const baseAddr = Process.enumerateModules()[0].base;
            const machoHeader = parseMachoHeader(baseAddr);
            const segments = getSegments(baseAddr, machoHeader.ncmds);
            for (const seg of segments) {
                if (seg.name === '__TEXT') {
                    for (const sec of getSections(seg)) {
                        if (sec.name === '__TEXT.__stubs') {
                            stubAddress = sec.vmaddr;
                            break;
                        }
                    }
                    break;
                }
            }
        } catch (e) {
            console.error(e);
            // ignore
        }
    }
    return listImportsJson(args).map((x : any) => {
        const flags = [];
        if (!seen.has(x.address)) {
            seen.add(x.address);
            flags.push('f sym.' + sanitizeString(x.name) + ` = ${x.address}`);
        }
        if (x.slot !== undefined) {
            const tm = x.targetModuleName ? x.targetModuleName + '.' : '';
            const fn = sanitizeString(`reloc.${tm}${x.name}`); // _${x.index}`);
            flags.push(`f ${fn} = ${x.slot}`);
        }
        if (stubAddress) {
            if (x.index > 0) {
                const pltaddr = ptr(stubAddress).add(stubSize * (x.index - 1));
                flags.push('f sym.imp.' + sanitizeString(x.name) + ` = ${pltaddr}`);
            }
        }
        return flags.join('\n');
    }).join('\n');
}

export function listImportsJson(args: string[]) {
    const alen = args.length;
    let result = [];
    let moduleName : string | null = null;
    if (alen === 2) {
        moduleName = args[0];
        const importName = args[1];
        const imports = Process.getModuleByName(moduleName).enumerateImports();
        if (imports !== null) {
            result = imports.filter((x, i) => {
                (x as any).index = i; // XXX
                return x.name === importName;
            });
        }
    } else if (alen === 1) {
        moduleName = args[0];
        result = Process.getModuleByName(moduleName).enumerateImports() || [];
    } else {
        const currentModule = getModuleByAddress(global.r2frida.offset);
        if (currentModule) {
            result = currentModule.enumerateImports() || [];
        }
    }
    result.forEach((x:any, i:any) => {
        if (x.index === undefined) {
            x.index = i;
        }
        x.targetModuleName = moduleName;
    });
    return result;
}

export function listModules() {
    return Process.enumerateModules()
        .map(m => [padPointer(m.base), padPointer(m.base.add(m.size)), m.name].join(' '))
        .join('\n');
}

export function listModulesQuiet() {
    return Process.enumerateModules().map(m => m.name).join('\n');
}

export function listModulesR2() {
    return Process.enumerateModules()
        .map(m => 'f lib.' + sanitizeString(m.name) + ' = ' + padPointer(m.base))
        .join('\n');
}

export function listModulesJson() {
    return Process.enumerateModules();
}

export function listModulesHere() {
    const here = ptr(global.r2frida.offset);
    return Process.enumerateModules()
        .filter(m => here.compare(m.base) >= 0 && here.compare(m.base.add(m.size)) < 0)
        .map(m => padPointer(m.base.toString()) + ' ' + m.name)
        .join('\n');
}

export function listExports(args: string[]) {
    return listExportsJson(args)
        .map((a: any) => {
            return [a.address, a.type[0], a.name].join(' ');
        })
        .join('\n');
}

export function listExportsR2(args: string[]) {
    return listExportsJson(args)
        .map((a: any) => {
            return ['f', 'sym.' + a.type.substring(0, 3) + '.' + sanitizeString(a.name), '=', a.address].join(' ');
        })
        .join('\n');
}

export function listAllExportsJson(args: string[]) {
    const modules = (args.length === 0) ? Process.enumerateModules().map(m => m.path) : [args.join(' ')];
    return modules.reduce((result:any, moduleName: string) => {
        const exports = Process.getModuleByName(moduleName).enumerateExports();
        return result.concat(exports);
    }, []);
}

export function listAllExports(args:string[]) {
    return listAllExportsJson(args)
        .map((a:any) => {
            return [a.address, a.type[0], a.name].join(' ');
        })
        .join('\n');
}

export function listAllExportsR2(args: string[]) {
    return listAllExportsJson(args)
        .map((a: any) => {
            const type = (a.type as string).substring(0, 3);
            return ['f', 'sym.' + type + '.' + sanitizeString(a.name), '=', a.address].join(' ');
        })
        .join('\n');
}

export function listExportsJson(args: string[]) {
    const currentModule = (args.length > 0)
        ? Process.getModuleByName(args[0])
        : getModuleByAddress(ptr(global.r2frida.offset));
    return currentModule.enumerateExports();
}

export function listSegmentsHere() {
    const headers = 'vaddr    \tvsize\tperm\tname\n'.concat('――――――――――――――――――――――――――――――――――――――――――――――\n');
    const here = ptr(global.r2frida.offset);
    const moduleAddr = Process.enumerateModules()
        .filter(m => here.compare(m.base) >= 0 && here.compare(m.base.add(m.size)) < 0)
        .map(m => m.base);
    const segment = belongsTo(listSegmentsJson([moduleAddr.toString()]), here);
    return headers.concat(segment
        .map(({ vmaddr, vmsize, perm, name }) => {
            return [vmaddr, vmsize, perm, name].join('\t');
        })
        .join('\n'));
}

export function listSegmentsR2(args: string[]) {
    let i = 0;
    return listSegmentsJson(args)
        .filter((s:any) => s.name !== undefined)
        .map((a: any) => {
            return [`f segment.${i++}.${sanitizeString(a.name)} ${a.vmsize} ${a.vmaddr}`].join(' ');
        })
        .join('\n');
}

export function listSegments(args: string[]) {
    const headers = 'vaddr    \tvsize\tperm\tname\n'.concat('――――――――――――――――――――――――――――――――――――――――――――――\n');
    return headers.concat(listSegmentsJson(args)
        .map((a: any) => {
            return [a.vmaddr, a.vmsize, a.perm, a.name].join('\t');
        })
        .join('\n'));
}

export function listSegmentsJson(args: string[]) {
    let baseAddr: NativePointer = ptr(0);
    if (Process.platform === 'darwin') {
        const baseAddr = (args.length === 1) ? ptr(args[0]) : Process.enumerateModules()[0].base;
        return listMachoSegments(baseAddr);
    }
    if (Process.platform === 'linux') {
        if (args.length === 1) {
            baseAddr = ptr(args[0]);
        } else {
            const here = ptr(global.r2frida.offset);
            baseAddr = Process.enumerateModules()
                .filter(m => here.compare(m.base) >= 0 && here.compare(m.base.add(m.size)) < 0)
                .map(m => m.base)[0];
        }
        return listElfSegments(baseAddr);
    }
    throw new Error('Command only available on unix-based systems.');
}

export function listSectionsHere(): string {
    const headers = 'vaddr    \tvsize\tperm\tname\n'.concat('――――――――――――――――――――――――――――――――――――――――――――――\n');
    const here = ptr(global.r2frida.offset);
    const moduleAddr = Process.enumerateModules()
        .filter(m => here.compare(m.base) >= 0 && here.compare(m.base.add(m.size)) < 0)
        .map(m => m.base);
    const section = belongsTo(listSectionsJson([moduleAddr.toString()]), here);
    return headers.concat(section
        .map(({ vmaddr, vmsize, perm, name }) => {
            return [vmaddr, vmsize, perm, name].join('\t');
        })
        .join('\n'));
}

export function listSectionsR2(args: string[]) {
    let i = 0;
    return listSectionsJson(args)
        .map((a: any) => {
            return [`f section.${i++}.${sanitizeString(a.name)} ${a.vmsize} ${a.vmaddr}`].join(' ');
        })
        .join('\n');
}

export function listSections(args: string[]) : string {
    const headers = "vaddr    \tvsize\tperm\tname\n".concat('――――――――――――――――――――――――――――――――――――――――――――――\n');
    const data = listSectionsJson(args)
        .map((a: any) => {
            return [a.vmaddr, a.vmsize, a.perm, a.name].join('\t');
        })
        .join('\n');
    return headers.concat(data);
}

export function listSectionsJson(args: string[]): any {
    let baseAddr : NativePointer = ptr(0);
    if (Process.platform === 'darwin') {
        const baseAddr = (args.length === 1) ? ptr(args[0]) : Process.enumerateModules()[0].base;
        return listMachoSections(baseAddr);
    }
    if (Process.platform === 'linux') {
        if (args.length === 1) {
            baseAddr = ptr(args[0]);
        } else {
            const here = ptr(global.r2frida.offset);
            baseAddr = Process.enumerateModules()
                .filter(m => here.compare(m.base) >= 0 && here.compare(m.base.add(m.size)) < 0)
                .map(m => m.base)[0];
        }
        return listElfSections(baseAddr);
    }
    throw new Error('Command only available on unix-based systems.');
}

export function listAllSymbolsJson(args: string[]) {
    const argName = args[0];
    const modules = Process.enumerateModules().map(m => m.path);
    let res = [];
    for (const module of modules) {
        const symbols = Process.getModuleByName(module).enumerateSymbols()
            .filter((r) => r.address.compare(ptr('0')) > 0 && r.name);
        if (argName) {
            res.push(...symbols.filter((s) => s.name.indexOf(argName) !== -1));
        } else {
            res.push(...symbols);
        }
        if (res.length > 100000) {
            res.forEach((r) => {
                console.error([r.address, module, r.name].join(' '));
            });
            res = [];
        }
    }
    return res;
}

export function listAllSymbols(args: string[]) {
    return listAllSymbolsJson(args)
        .map(({ type, name, address }) => {
            return [address, type[0], name].join(' ');
        }).join('\n');
}

export function listAllSymbolsR2(args: string[]) {
    return listAllSymbolsJson(args)
        .map(({ type, name, address }) => {
            return ['f', 'sym.' + type.substring(0, 3) + '.' + sanitizeString(name), '=', address].join(' ');
        }).join('\n');
}

export function listSymbols(args: string[]) {
    return listSymbolsJson(args)
        .map(({ type, name, address }) => {
            return [address, type[0], name].join(' ');
        })
        .join('\n');
}

export function listSymbolsR2(args: string[]) {
    return listSymbolsJson(args)
        .filter(({ address }) => !address.isNull())
        .map(({ name, address }) => {
            return ['f', 'sym.' + sanitizeString(name), '=', address].join(' ');
        })
        .join('\n');
}

export function listSymbolsJson(args: string[]) {
    const currentModule = (args.length > 0)
        ? Process.getModuleByName(args[0])
        : getModuleByAddress(global.r2frida.offset);
    const symbols = Process.getModuleByName(currentModule.name).enumerateSymbols();
    return symbols.map(sym => {
        if (config.getBoolean('symbols.unredact') && sym.name.indexOf('redacted') !== -1) {
            const dbgSym = DebugSymbol.fromAddress(sym.address);
            if (dbgSym !== null && dbgSym.name !== null) {
                sym.name = dbgSym.name;
            }
        }
        return sym;
    });
}

export function listAllHelp(args: string[]) {
    return 'See :ia? for more information. Those commands may take a while to run.';
}

export function listStringsJson(args: string[]) {
    if (!args || args.length !== 1) {
        args = [global.r2frida.offset];
    }
    const base = ptr(args[0]);
    const currentRange = Process.findRangeByAddress(base);
    if (currentRange) {
        const options = { base: base }; // filter for urls?
        const length = Math.min(currentRange.size, 1024 * 1024 * 128);
        const block = 1024 * 1024; // 512KB
        if (length !== currentRange.size) {
            const curSize = currentRange.size / (1024 * 1024);
            console.error('Warning: this range is too big (' + curSize + 'MB), truncated to ' + length / (1024 * 1024) + 'MB');
        }
        try {
            const res = [];
            console.log('Reading ' + (length / (1024 * 1024)) + 'MB ...');
            for (let i = 0; i < length; i += block) {
                const addr = currentRange.base.add(i);
                const bytes = addr.readCString(block) as string;
                const blockResults = strings(bytes.split('').map(_ => _.charCodeAt(0)), options);
                res.push(...blockResults);
            }
            return res;
        } catch (e: any) {
            console.log(e.message);
        }
    }
    throw new Error('Memory not mapped here');
}

export function listStrings(args: string[]) {
    if (!args || args.length !== 1) {
        args = [global.r2frida.offset];
    }
    return listStringsJson(args).map(({ base, text }) => padPointer(base) + `  "${text}"`).join('\n');
}

export default {
    dumpInfo,
    dumpInfoR2,
    dumpInfoJson,
    listEntrypointJson,
    listEntrypointR2,
    listEntrypointQuiet,
    listEntrypoint,
    listImports,
    listImportsR2,
    listImportsJson,
    listModules,
    listModulesQuiet,
    listModulesR2,
    listModulesJson,
    listModulesHere,
    listExports,
    listExportsR2,
    listAllExportsJson,
    listAllExports,
    listAllExportsR2,
    listExportsJson,
    listSectionsHere,
    listSectionsR2,
    listSections,
    listSectionsJson,
    listSegmentsHere,
    listSegmentsR2,
    listSegments,
    listSegmentsJson,
    listAllSymbolsJson,
    listAllSymbols,
    listAllSymbolsR2,
    listSymbols,
    listSymbolsR2,
    listSymbolsJson,
    listAllHelp,
    listStringsJson,
    listStrings
};
