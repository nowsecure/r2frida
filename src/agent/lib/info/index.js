import { getModuleByAddress } from "./lookup.js";
import * as config from "../../config.js";
import * as debug from "../debug/index.js";
import * as darwin from "../darwin/index.js";
import * as fs from "../fs.js";
import * as java from "../java/index.js";
import * as r2 from "../r2.js";
import * as sys from "../sys.js";
import * as swift from "../darwin/swift.js";
import strings from "../strings.js";
import * as utils from "../utils.js";
import { global } from '../../global.js';
export async function dumpInfo() {
    const padding = (x) => ''.padStart(20 - x, ' ');
    const properties = await dumpInfoJson();
    return Object.keys(properties)
        .map(k => k + padding(k.length) + properties[k])
        .join('\n');
}
export async function dumpInfoR2() {
    const properties = await dumpInfoJson();
    const jnienv = properties.jniEnv !== undefined ? properties.jniEnv : '';
    return [
        'e asm.arch=' + properties.arch,
        'e asm.bits=' + properties.bits,
        'e asm.os=' + properties.os,
        'f r2f.modulebase=' + properties.modulebase
    ].join('\n') + jnienv;
}
export async function dumpInfoJson() {
    const res = {
        arch: r2.getR2Arch(Process.arch),
        bits: Process.pointerSize * 8,
        os: Process.platform,
        pid: sys.getPid(),
        uid: sys._getuid(),
        objc: darwin.ObjCAvailable,
        runtime: Script.runtime,
        swift: swift.SwiftAvailable(),
        java: java.JavaAvailable,
        mainLoop: darwin.hasMainLoop(),
        pageSize: Process.pageSize,
        pointerSize: Process.pointerSize,
        codeSigningPolicy: Process.codeSigningPolicy,
        isDebuggerAttached: Process.isDebuggerAttached(),
        cwd: fs.getCwd()
    };
    if (darwin.ObjCAvailable && !debug.suspended) {
        try {
            const mb = (ObjC && ObjC.classes && ObjC.classes.NSBundle) ? ObjC.classes.NSBundle.mainBundle() : '';
            const id = mb ? mb.infoDictionary() : '';
            function get(k) {
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
            res.modulename = Process.enumerateModulesSync()[0].name;
            res.modulebase = Process.enumerateModulesSync()[0].base;
            res.homedir = (new ObjC.Object(NSHomeDirectory()).toString());
            res.tmpdir = (new ObjC.Object(NSTemporaryDirectory()).toString());
            res.bundledir = ObjC.classes.NSBundle.mainBundle().bundleURL().path();
        }
        catch (e) {
            console.error(e);
        }
    }
    if (java.JavaAvailable) {
        await java.performOnJavaVM(() => {
            const ActivityThread = Java.use('android.app.ActivityThread');
            const app = ActivityThread.currentApplication();
            if (app !== null) {
                const ctx = app.getApplicationContext();
                if (ctx !== null) {
                    function tryTo(x) {
                        let r = '';
                        try {
                            r = x();
                        }
                        catch (e) {
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
                    function getContext() {
                        return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext().getContentResolver();
                    }
                    res.androidId = Java.use('android.provider.Settings$Secure').getString(getContext(), 'android_id');
                }
                catch (ignoredError) {
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
export function listEntrypointJson(args) {
    function isEntrypoint(s) {
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
    return Module.enumerateSymbols(firstModule.name)
        .filter((symbol) => {
        return isEntrypoint(symbol);
    }).map((symbol) => {
        symbol.moduleName = getModuleByAddress(symbol.address).name;
        return symbol;
    });
}
export function listEntrypointR2(args) {
    let n = 0;
    return listEntrypointJson()
        .map((entry) => {
        return 'f entry' + (n++) + ' = ' + entry.address;
    }).join('\n');
}
export function listEntrypointQuiet(args) {
    return listEntrypointJson()
        .map((entry) => {
        return entry.address;
    }).join('\n');
}
export function listEntrypoint(args) {
    return listEntrypointJson()
        .map((entry) => {
        return entry.address + ' ' + entry.name + '  # ' + entry.moduleName;
    }).join('\n');
}
export function listImports(args) {
    return listImportsJson(args)
        .map(({ type, name, module, address }) => [address, type ? type[0] : ' ', name, module].join(' '))
        .join('\n');
}
export function listImportsR2(args) {
    const seen = new Set();
    let stubAddress = 0;
    const stubSize = Process.arch === 'x64' ? 6 : 8;
    if (Process.platform === 'darwin') {
        try {
            const baseAddr = Process.enumerateModules()[0].base;
            const machoHeader = darwin.parseMachoHeader(baseAddr);
            const segments = darwin.getSegments(baseAddr, machoHeader.ncmds);
            for (const seg of segments) {
                if (seg.name === '__TEXT') {
                    for (const sec of darwin.getSections(seg)) {
                        if (sec.name === '__TEXT.__stubs') {
                            stubAddress = sec.vmaddr;
                            break;
                        }
                    }
                    break;
                }
            }
        }
        catch (e) {
            console.error(e);
            // ignore
        }
    }
    return listImportsJson(args).map((x) => {
        const flags = [];
        if (!seen.has(x.address)) {
            seen.add(x.address);
            flags.push('f sym.' + utils.sanitizeString(x.name) + ` = ${x.address}`);
        }
        if (x.slot !== undefined) {
            const tm = x.targetModuleName ? x.targetModuleName + '.' : '';
            const fn = utils.sanitizeString(`reloc.${tm}${x.name}`); // _${x.index}`);
            flags.push(`f ${fn} = ${x.slot}`);
        }
        if (stubAddress) {
            if (x.index > 0) {
                const pltaddr = ptr(stubAddress).add(stubSize * (x.index - 1));
                flags.push('f sym.imp.' + utils.sanitizeString(x.name) + ` = ${pltaddr}`);
            }
        }
        return flags.join('\n');
    }).join('\n');
}
export function listImportsJson(args) {
    const alen = args.length;
    let result = [];
    let moduleName = null;
    if (alen === 2) {
        moduleName = args[0];
        const importName = args[1];
        const imports = Module.enumerateImports(moduleName);
        if (imports !== null) {
            result = imports.filter((x, i) => {
                x.index = i;
                return x.name === importName;
            });
        }
    }
    else if (alen === 1) {
        moduleName = args[0];
        result = Module.enumerateImports(moduleName) || [];
    }
    else {
        const currentModule = getModuleByAddress(global.r2frida.offset);
        if (currentModule) {
            result = Module.enumerateImports(currentModule.name) || [];
        }
    }
    result.forEach((x, i) => {
        if (x.index === undefined) {
            x.index = i;
        }
        x.targetModuleName = moduleName;
    });
    return result;
}
export function listModules() {
    return Process.enumerateModules()
        .map(m => [utils.padPointer(m.base), utils.padPointer(m.base.add(m.size)), m.name].join(' '))
        .join('\n');
}
export function listModulesQuiet() {
    return Process.enumerateModules().map(m => m.name).join('\n');
}
export function listModulesR2() {
    return Process.enumerateModules()
        .map(m => 'f lib.' + utils.sanitizeString(m.name) + ' = ' + utils.padPointer(m.base))
        .join('\n');
}
export function listModulesJson() {
    return Process.enumerateModules();
}
export function listModulesHere() {
    const here = ptr(global.r2frida.offset);
    return Process.enumerateModules()
        .filter(m => here.compare(m.base) >= 0 && here.compare(m.base.add(m.size)) < 0)
        .map(m => utils.padPointer(m.base) + ' ' + m.name)
        .join('\n');
}
export function listExports(args) {
    return listExportsJson(args)
        .map(({ type, name, address }) => {
        return [address, type[0], name].join(' ');
    })
        .join('\n');
}
export function listExportsR2(args) {
    return listExportsJson(args)
        .map(({ type, name, address }) => {
        return ['f', 'sym.' + type.substring(0, 3) + '.' + utils.sanitizeString(name), '=', address].join(' ');
    })
        .join('\n');
}
export function listAllExportsJson(args) {
    const modules = (args.length === 0) ? Process.enumerateModules().map(m => m.path) : [args.join(' ')];
    return modules.reduce((result, moduleName) => {
        return result.concat(Module.enumerateExports(moduleName));
    }, []);
}
export function listAllExports(args) {
    return listAllExportsJson(args)
        .map(({ type, name, address }) => {
        return [address, type[0], name].join(' ');
    })
        .join('\n');
}
export function listAllExportsR2(args) {
    return listAllExportsJson(args)
        .map(({ type, name, address }) => {
        return ['f', 'sym.' + type.substring(0, 3) + '.' + utils.sanitizeString(name), '=', address].join(' ');
    })
        .join('\n');
}
export function listExportsJson(args) {
    const currentModule = (args.length > 0)
        ? Process.getModuleByName(args[0])
        : getModuleByAddress(ptr(global.r2frida.offset));
    return Module.enumerateExports(currentModule.name);
}
export function listSectionsHere() {
    const here = ptr(global.r2frida.offset);
    const moduleAddr = Process.enumerateModules()
        .filter(m => here.compare(m.base) >= 0 && here.compare(m.base.add(m.size)) < 0)
        .map(m => m.base);
    return listSections(moduleAddr);
}
export function listSectionsR2(args) {
    let i = 0;
    return listSectionsJson(args)
        .map(({ vmaddr, vmsize, name }) => {
        return [`f section.${i++}.${utils.sanitizeString(name)} ${vmsize} ${vmaddr}`].join(' ');
    })
        .join('\n');
}
export function listSections(args) {
    return listSectionsJson(args)
        .map(({ vmaddr, vmsize, name }) => {
        return [vmaddr, vmsize, name].join(' ');
    })
        .join('\n');
}
export function listSectionsJson(args) {
    if (Process.platform !== 'darwin') {
        return 'Only darwin-based systems supported.';
    }
    const baseAddr = (args.length === 1) ? ptr(args[0]) : Process.enumerateModules()[0].base;
    return darwin.listMachoSections(baseAddr);
}
export function listAllSymbolsJson(args) {
    const argName = args[0];
    const modules = Process.enumerateModules().map(m => m.path);
    let res = [];
    for (const module of modules) {
        const symbols = Module.enumerateSymbols(module)
            .filter((r) => r.address.compare(ptr('0')) > 0 && r.name);
        if (argName) {
            res.push(...symbols.filter((s) => s.name.indexOf(argName) !== -1));
        }
        else {
            res.push(...symbols);
        }
        if (res.length > 100000) {
            res.forEach((r) => {
                console.error([r.address, r.moduleName, r.name].join(' '));
            });
            res = [];
        }
    }
    return res;
}
export function listAllSymbols(args) {
    return listAllSymbolsJson(args)
        .map(({ type, name, address }) => {
        return [address, type[0], name].join(' ');
    }).join('\n');
}
export function listAllSymbolsR2(args) {
    return listAllSymbolsJson(args)
        .map(({ type, name, address }) => {
        return ['f', 'sym.' + type.substring(0, 3) + '.' + utils.sanitizeString(name), '=', address].join(' ');
    }).join('\n');
}
export function listSymbols(args) {
    return listSymbolsJson(args)
        .map(({ type, name, address }) => {
        return [address, type[0], name].join(' ');
    })
        .join('\n');
}
export function listSymbolsR2(args) {
    return listSymbolsJson(args)
        .filter(({ address }) => !address.isNull())
        .map(({ name, address }) => {
        return ['f', 'sym.' + utils.sanitizeString(name), '=', address].join(' ');
    })
        .join('\n');
}
export function listSymbolsJson(args) {
    const currentModule = (args.length > 0)
        ? Process.getModuleByName(args[0])
        : getModuleByAddress(global.r2frida.offset);
    const symbols = Module.enumerateSymbols(currentModule.name);
    return symbols.map(sym => {
        if (config.getBoolean('symbols.unredact') && sym.name.indexOf('redacted') !== -1) {
            const dbgSym = DebugSymbol.fromAddress(sym.address);
            if (dbgSym !== null) {
                sym.name = dbgSym.name;
            }
        }
        return sym;
    });
}
export function listAllHelp(args) {
    return 'See :ia? for more information. Those commands may take a while to run.';
}
export function listStringsJson(args) {
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
                const bytes = addr.readCString(block);
                const blockResults = strings(bytes.split('').map(_ => _.charCodeAt(0)), options);
                res.push(...blockResults);
            }
            return res;
        }
        catch (e) {
            console.log(e.message);
        }
    }
    throw new Error('Memory not mapped here');
}
export function listStrings(args) {
    if (!args || args.length !== 1) {
        args = [ptr(global.r2frida.offset)];
    }
    return listStringsJson(args).map(({ base, text }) => utils.padPointer(base) + `  "${text}"`).join('\n');
}
