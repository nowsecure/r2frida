import config from "./config.js";
import { r2pipe } from "./r2pipe-frida.js";
import * as anal from "./lib/anal.js";
import * as android from "./lib/java/android.js";
import * as classes from "./lib/info/classes.js";
import * as darwin from "./lib/darwin/index.js";
import * as debug from "./lib/debug/index.js";
import * as breakpoints from "./lib/debug/breakpoints.js";
import * as system from "./lib/debug/system.js";
import disasm from "./lib/disasm.js";
import expr from "./lib/expr.js";
import * as fs from "./lib/fs.js";
import info from "./lib/info/index.js";
import io from "./io.js";
import interceptor from "./lib/debug/interceptor.js";
import * as java from "./lib/java/index.js";
import log from "./log.js";
import lookup from "./lib/info/lookup.js";
import * as memory from "./lib/debug/memory.js";
import r2 from "./lib/r2.js";
import stalker from "./lib/debug/stalker.js";
import sys from "./lib/sys.js";
import * as swift from "./lib/darwin/swift.js";
import * as trace from "./lib/debug/trace.js";
import * as utils from "./lib/utils.js";
import {
    search,
    searchHex,
    searchHexJson,
    searchInstances,
    searchInstancesJson,
    searchJson,
    searchStrings,
    searchStringsJson,
    searchValue1,
    searchValue2,
    searchValue4,
    searchValue8,
    searchValueJson1,
    searchValueJson2,
    searchValueJson4,
    searchValueJson8,
    searchWide,
    searchWideJson,
} from "./lib/search.js";
import ObjC from "frida-objc-bridge";

import { PutsFunction, r2frida } from "./plugin.js";

// declare let global: any;
const global: any = {};

global.r2pipe = {
    open: () => {
        return {
            cmd: (s: string) => r2frida.cmd(s),
            log: console.log,
        };
    },
};

function r2pipe2(arg: string) {
    const query = JSON.parse(arg);
    const cmd = query.cmd;
    const res: any = perform({ command: cmd });
    const objres = {
        res: res[0].value,
        code: 0,
    };
    console.log(JSON.stringify(objres));
}

const commandHandlers = {
    ".": [null, "Run Frida script in agent side", "[path]"], // this is implemented in C
    eval: [expr.evalCode, "evaluate Javascript code in agent side", "[code]"],
    "!": [system.runSystemCommand, "execute program with system"],
    "?": [expr.evalNum, "evaluate number"],
    "?e": [echo, "print message"],
    "?E": [uiAlert, "popup alert dialog on target app"],
    "/": [search, "search string passed as argument", "[str]"],
    "/i": [searchInstances, "search instances of given type", "[type]"],
    "/ij": searchInstancesJson,
    "/j": [searchJson, "same as /, but output is in json"],
    "/z": [searchStrings, "find all strings", "[minlen] [maxlen]"],
    "/zj": [searchStringsJson, "find all strings", "[minlen] [maxlen]"],
    "/x": [searchHex, "find hexadecimal string", "[hexstr]"],
    "/xj": [searchHexJson, "same as /x but using json"],
    "/w": [searchWide, "same as / but for wide strings (utf16)", "[str]"],
    "/wj": searchWideJson,
    "/v1": [searchValue1, "search 1 byte of given numeric value"],
    "/v2": [searchValue2, "search 2 byte (little endian) number in memory"],
    "/v4": [searchValue4, "search 4 byte (dword, 32bit LE value in memory)"],
    "/v8": [searchValue8, "search 8 byte (qword 64bit LE value)"],
    "/v1j": searchValueJson1,
    "/v2j": searchValueJson2,
    "/v4j": searchValueJson4,
    "/v8j": searchValueJson8,
    "?V": [fridaVersion, "show frida version"],
    "?Vj": [fridaVersionJson, "show frida version in JSON"],
    afs: [
        anal.analFunctionSignature,
        "Show function signature",
        "[klass] [method]",
    ],
    cat: [fs.fsCat, "show contents of a file"],
    cd: [fs.chDir, "change directory"],
    chcon: [sys.changeSelinuxContext, "change selinux context"],
    db: [
        breakpoints.setBreakpoint,
        "list or add a native breakpoint",
        "[addr]",
    ],
    dbj: breakpoints.breakpointJson,
    dbwj: breakpoints.watchpointJson,
    dbw: [
        breakpoints.setWatchpoint,
        "list or add a native watchpoint",
        "[addr] [size] [r|w|rw]",
    ],
    "dbw-": [
        breakpoints.unsetWatchpoint,
        "unset the native watchpoint in the given address",
        "[addr]",
    ],
    "dbw-*": [breakpoints.watchpointUnsetAll, "unset all the breakpoints"],
    "dbws": [
        breakpoints.toggleWatchpoint,
        "Enable/Disable a watchpoint",
        "[addr]",
    ],
    dbwc: [
        breakpoints.setWatchpointCommand,
        "associate an r2 command when the native watchpoint is hit",
        "[addr] [cmd]",
    ],
    dbc: [
        breakpoints.setBreakpointCommand,
        "associate an r2 command when the native breakpoint is hit. It creates the breakpoint if it does not exist.",
        "[addr] [cmd]",
    ],
    dbs: [
        breakpoints.toggleBreakpoint,
        "Enable/Disable a breakpoint",
        "[addr]",
    ],
    "db-": [
        breakpoints.unsetBreakpoint,
        "unset the native breakpoint in the given address",
        "[addr]",
    ],
    "db-*": [breakpoints.breakpointUnsetAll, "unset all the breakpoints"],
    dc: [
        breakpoints.breakpointContinue,
        "continue execution of the interrupted child",
    ],
    dcu: [
        breakpoints.setBreakpointContinueUntil,
        "continue execution until given address",
        "[addr]",
    ],
    dk: [
        debug.sendSignal,
        "send signal to process in the target process",
        "[signal]|([pid] [signum])",
    ],
    dd: [
        fs.listFileDescriptors,
        "list filedescriptors in use in the target process",
    ],
    ddj: [fs.listFileDescriptorsJson, "same as `dd` but in json format"],
    "dd-": [fs.closeFileDescriptors, "close given file descriptor", "[fd]"],
    dm: [memory.listMemoryRanges, "list ranges of memory maps"],
    "dm*": [
        memory.listMemoryRangesR2,
        "add a flag in r2 for every memory range by name .:dm*",
    ],
    dmj: [
        memory.listMemoryRangesJson,
        "list memory ranges like `:dm` but in json format",
    ],
    dmp: [
        memory.changeMemoryProtection,
        "show or change the memory protection (rwx)",
        "[at] [sz] [rwx]",
    ],
    "dm.": [
        memory.listMemoryRangesHere,
        "show information about the memory map in the current offset",
    ],
    dmm: [
        memory.listMemoryMaps,
        "like :dm but easier to read as it groups consecutive maps",
    ],
    "dmm*": [memory.listMemoryMapsR2, "add a flag in r2 for every memory map"],
    "dmmj": [memory.listMemoryMapsJson, "list memory maps in json format"],
    "dmm.": [
        memory.listMemoryMapsHere,
        "show memory map name at current address (see `dm.`)",
    ],
    dmh: [memory.listMallocRanges, "list memory"],
    "dmh*": memory.listMallocRangesR2,
    dmhj: memory.listMallocRangesJson,
    dmhm: [memory.listMallocMaps, "print all heap allocations (EXPERIMENTAL)"],
    dma: [memory.allocSize, "allocate N bytes"],
    dmas: [
        memory.allocString,
        "allocate a string and print the address in heap",
        "[str]",
    ],
    dmaw: [
        memory.allocWstring,
        "allocate a string in utf16 / wide string",
        "[wstr]",
    ],
    dmad: [
        memory.allocDup,
        "create a new buffer of [size] with contents at given address",
        "[addr] [size]",
    ],
    dmal: [memory.listAllocs, "list all allocations"],
    "dma-": [memory.removeAlloc, "free given heap pointer", "[addr]"],
    dp: [sys.getPid, "get process id"],
    dpw: [debug.threadWait, "wait until a new thread is created"],
    dxc: [debug.dxCall, "call function with arguments", "[addr] [args..]"],
    dxo: [darwin.callObjcMethod, "call objc function with args", "[sym] [id]"],
    dxs: [debug.dxSyscall, "inject and execute a syscall", "[sysnum] [args..]"],
    dpj: [sys.getPidJson, "print target process id in json"],
    dpt: [debug.listThreads, "display threads of the target process"],
    dptj: [debug.listThreadsJson, "list threads in json format"],
    dr: [debug.dumpRegisters, "show register values"],
    "dr.": [
        debug.dumpRegistersHere,
        "show register values of the current thread",
    ],
    "dr*": [
        debug.dumpRegistersR2,
        "Import register values of target process as flags .:dr*",
    ],
    dre: [
        debug.dumpRegistersEsil,
        "Show register values as an esil expression",
    ],
    drr: [debug.dumpRegistersRecursively, "telescope registers dump"],
    drp: [
        debug.dumpRegisterProfile,
        "display register profile of target process cpu",
    ],
    dr8: [
        debug.dumpRegisterArena,
        "dump the register arena contents in hexpairs",
    ],
    drj: [debug.dumpRegistersJson, "display register values in json format"],
    "%": [sys.getOrSetEnv, "same as the :env command"],
    env: [sys.getOrSetEnv, "get or set environment variables", "[k] ([v])"],
    envj: [
        sys.getOrSetEnvJson,
        "display target process environment variables in json format",
    ],
    dl: [sys.dlopen, "dlopen a library in the target process", "[path/lib.so]"],
    dlf: [darwin.loadFrameworkBundle, "load Darwin framework bundle", "[path]"],
    "dlf-": [darwin.unloadFrameworkBundle, "unload Darwin framework"],
    dlw: [debug.dlopenWait, "wait until a specific library is loaded"],
    dtf: [
        trace.traceFormat,
        "add a trace parsing arguments using a format string",
        "[addr] [fmt]",
    ],
    dtm: [trace.traceModules, "show modules when loaded or unloaded"],
    "dtm-": [trace.untraceModules, "stop tracing modules"],
    dtt: [trace.traceThreads, "show threads when loaded or unloaded"],
    "dtt-": [trace.untraceThreads, "stop tracing threads"],
    dth: [trace.traceHook, "list or add trace hook"],
    dt: [
        trace.trace,
        "inject a trace in the given native address (or java:method)",
        "([addr])",
    ],
    dtj: trace.traceJson,
    dtq: trace.traceQuiet,
    "dt*": trace.traceR2,
    "dt.": [trace.traceHere, "show trace in current offset"],
    "dt-": [trace.clearTrace, "delete trace at given address", "[addr]"],
    "dt-*": [trace.clearAllTrace, "clear all traces"],
    dtr: [
        trace.traceRegs,
        "add a trace to show register value when calling a function",
        "[addr] [reg...]",
    ],
    dtl: [trace.traceLogDump, "trace log dump"],
    "dtl*": trace.traceLogDumpR2,
    dtlq: trace.traceLogDumpQuiet,
    dtlj: trace.traceLogDumpJson,
    "dtl-": [trace.traceLogClear, "clear trace logs"],
    "dtl-*": trace.traceLogClearAll,
    dts: [
        stalker.stalkTraceEverything,
        "trace everything using the stalker (EXPERIMENTAL)",
    ],
    "dts?": stalker.stalkTraceEverythingHelp,
    dtsj: stalker.stalkTraceEverythingJson,
    "dts*": stalker.stalkTraceEverythingR2,
    dtsf: [stalker.stalkTraceFunction, "stalk trace a function (EXPERIMENTAL)"],
    dtsfj: stalker.stalkTraceFunctionJson,
    "dtsf*": stalker.stalkTraceFunctionR2,
    di: [interceptor.interceptHelp, "debug replace commands"],
    dif: [interceptor.interceptFunHelp, "debug intercept commands"],
    // intercept ret function and dont call the function
    dis: [
        interceptor.interceptRetString,
        "replace the original implementation and return a string",
        "[addr] [str]",
    ],
    dibf: [
        interceptor.interceptRetFalse,
        "replace the original implementation and return a boolean false value",
        "[java:]",
    ],
    dibt: [
        interceptor.interceptRetTrue,
        "replace the original implementation and return a boolean true value",
        "[java:]",
    ],
    di0: [
        interceptor.interceptRet0,
        "replace the original implementation and return 0",
        "[addr|java:]",
    ],
    di1: [
        interceptor.interceptRet1,
        "replace the original implementation and return 1",
        "[addr|java:]",
    ],
    dii: [
        interceptor.interceptRetInt,
        "replace the original implementation and return an integer",
        "[addr] [num]",
    ],
    "di-1": [
        interceptor.interceptRet_1,
        "replace the original implementation and return -1",
    ],
    div: [
        interceptor.interceptRetVoid,
        "replace the original implementation and return void",
    ],
    "di-*": [
        interceptor.interceptDetachAll,
        "remove (detach) all interceptor handles",
    ],
    dir: [
        interceptor.interceptRevert,
        "revert a trace at the given function",
        "[addr|java:]",
    ],
    // intercept ret after calling the function
    difs: [
        interceptor.interceptFunRetString,
        "intercept the return value and replace it with the specified string",
        "[addr] [str]",
    ],
    dif0: [
        interceptor.interceptFunRet0,
        "intercept the return value and replace it with 0",
        "[addr]",
    ],
    dif1: [
        interceptor.interceptFunRet1,
        "intercept the return value and replace it with 1",
        "[addr]",
    ],
    difi: [
        interceptor.interceptFunRetInt,
        "intercept the return value and replace it with the specified integer",
        "[addr] [num]",
    ],
    "dif-1": [
        interceptor.interceptFunRet_1,
        "intercept the return value and replace it with -1",
        "[addr]",
    ],
    e: [config.evalConfig, "configure the agent with these eval vars"],
    "e*": [config.evalConfigR2, "display eval config vars in r2 format"],
    "e/": [config.evalConfigSearch, "eval config search (?)"],
    fD: [lookup.lookupDebugInfo, "lookup debug information"],
    fd: [lookup.lookupAddress, "describe flag name at current address"],
    "fd.": [
        lookup.lookupAddress,
        "same as fd but using current offset instead of taking it as argument",
    ],
    "fd*": lookup.lookupAddressR2,
    fdj: lookup.lookupAddressJson,
    i: [info.dumpInfo, "show information about the target process"],
    "i*": [
        info.dumpInfoR2,
        "use .:i* to import r2frida target process info into r2",
    ],
    ij: [info.dumpInfoJson, "json version of :i"],
    ih: [info.listHeaders, "Show binary headers"],
    ihj: [info.listHeadersJson, "Show binary headers"],
    "ih*": [info.listHeadersR2, "Show binary headers"],
    ie: [info.listEntrypoint, "show entrypoint of binary in current offset"],
    ieq: info.listEntrypointQuiet,
    "ie*": info.listEntrypointR2,
    ies: [
        info.listEntrypointSymbols,
        "List the potential entrypoints of the binary (Darwin only)",
    ],
    iej: info.listEntrypointJson,
    ii: [info.listImports, "list imports"],
    "ii*": info.listImportsR2,
    iij: info.listImportsJson,
    il: [info.listModules, "list libraries"],
    "il.": [info.listModulesHere, "list libraries at current offset"],
    "il*": info.listModulesR2,
    ilq: info.listModulesQuiet,
    ilj: info.listModulesJson,
    ia: [
        info.listAllHelp,
        "show help for `all` subcommands which operate over all loaded modules",
    ],
    iAs: [info.listAllSymbols, "list symbols of all loaded modules (SLOW)"],
    iAsj: info.listAllSymbolsJson,
    "iAs*": info.listAllSymbolsR2,
    iAn: [classes.listAllClassesNatives, "list all native classes (ANDROID)"],
    is: [info.listSymbols, "list symbols"],
    "is.": [lookup.lookupSymbolHere, "lookup symbol name at current address"],
    isj: info.listSymbolsJson,
    "is*": info.listSymbolsR2,
    iSS: [info.listSegments, "list current bin segments"],
    "iSS.": [info.listSegmentsHere, "show segment name at current address"],
    "iSS*": info.listSegmentsR2,
    iSSj: info.listSegmentsJson,
    iS: [info.listSections, "list current bin sections"],
    "iS.": [info.listSectionsHere, "show section name at current address"],
    "iS*": info.listSectionsR2,
    iSj: info.listSectionsJson,
    ias: [
        lookup.lookupSymbol,
        "resolve symbol name in given address",
        "[addr]",
    ],
    "ias*": lookup.lookupSymbolR2,
    iasj: lookup.lookupSymbolJson,
    isa: [lookup.lookupSymbol, "same as `ias` (addr2name)", "[addr]"],
    "isa*": lookup.lookupSymbolR2,
    isaj: lookup.lookupSymbolJson,
    // many symbols
    isam: [
        lookup.lookupSymbolMany,
        "resolve multiple symbol names from many addresses",
        "[addr ...]",
    ],
    isamj: lookup.lookupSymbolManyJson,
    "isam*": lookup.lookupSymbolManyR2,
    iE: [info.listExports, "list exports at current binary"],
    "iE.": [
        lookup.lookupSymbolHere,
        "show symbol name at current address (see `:is.`)",
    ],
    iEj: info.listExportsJson,
    "iE*": info.listExportsR2,
    iaE: [
        lookup.lookupExport,
        "lookup implementation address for given export name",
    ],
    iaEj: lookup.lookupExportJson,
    "iaE*": lookup.lookupExportR2,
    iEa: [lookup.lookupExport, "lookup export"],
    "iEa*": lookup.lookupExportR2,
    iEaj: lookup.lookupExportJson,
    // maybe dupped
    iAE: [info.listAllExports, "enumerate exports from all binaries"],
    iAEj: info.listAllExportsJson,
    "iAE*": info.listAllExportsR2,
    init: [
        initBasicInfoFromTarget,
        "print initialization commands to import basic r2frida info into r2",
    ],
    "init*": [initBasicInfoFromTarget, "same as init"],
    ic: [
        classes.listClasses,
        "list classes associated with the binary at current address",
    ],
    "ic.": classes.listClassesHere,
    "icj.": classes.listClassesHereJson,
    ich: [classes.listClassesHooks, "list class hooks"],
    icw: [classes.listClassesWhere, "list classes where"],
    icv: [classes.listClassVariables, "list class variables"],
    ics: [classes.listClassSuperMethods, "list super methods"],
    ica: [classes.listClassesAllMethods, "list all methods for all classes"],
    icn: [classes.listClassesNatives, "enumerate native classes"],
    icL: [
        classes.listClassesLoaders,
        "enumerate instantiated java class loaders",
    ],
    icl: [classes.listClassesLoaded, "list loaded classes"],
    iclj: classes.listClassesLoadedJson,
    "ic*": classes.listClassesR2,
    icj: classes.listClassesJson,
    icm: [classes.listClassMethods, "list class methods", "[classname]"],
    icmj: classes.listClassMethodsJson,
    ip: [classes.listProtocols, "list objc protocols"],
    ipj: [classes.listProtocolsJson, "list objc protocols defined in json"],
    iz: [info.listStrings, "find strings in current binary and print them"],
    izj: [info.listStringsJson, "print strings in json format"],
    // unix compat
    pwd: [fs.getCwd, "print working directory inside the target process"],
    ls: [fs.fsList, "list files in current directory as seen by the target"],
    // required for m-io
    md: [
        fs.fsList,
        "list files in current directory (alias for `ls` for FS/IO)",
    ],
    mg: [fs.fsGet, "used by the FS/IO integration to get remote file"],
    m: [fs.fsOpen, "used by the FS/IO integration to open remote files"],
    pd: [disasm.disasmCode, "disassemble code using only frida apis"],
    px: [utils.Hexdump, "print memory contents in hexdump style"],
    r: [
        r2.cmd,
        "run an r2 command inside the agent (requires dlopen r_core, creates new instance)",
        "[cmd]",
    ],
    s: [
        r2.seek,
        "seek, change the current offset reference inside the agent",
        "[addr]",
    ],
    t: [swift.swiftTypes, "list swift types"],
    "t*": swift.swiftTypesR2,
    x: [utils.Hexdump, "alias for `:px`"],
};

async function initBasicInfoFromTarget(args: string[]): Promise<string> {
    if (java.JavaAvailable) {
        return `e dbg.backend = io
e anal.autoname=true
e cmd.fcn.new=aan
.:i*
s r2f.modulebase
.:dmm*
.:dm*
.:il*
m /r2f io 0
?q entry0-0 2> /dev/null
?? s entry0`;
    }
    return `e dbg.backend = io
e anal.autoname=true
e cmd.fcn.new=aan
.:i*
s r2f.modulebase
.:is*
.:ie*
.:dmm*
.:dm*
.:il*
m /r2f io 0
?q entry0-0 2> /dev/null
?? s entry0`;
}

if (Process.platform === "darwin") {
    darwin.initFoundation();
}
const requestHandlers = {
    safeio: () => {
        config.set("io.safe", true);
    },
    unsafeio: () => {
        config.set("io.safe", false);
    },
    read: io.read,
    write: io.write,
    state: state,
    perform: perform,
    evaluate: evaluate,
};

function state(params: any, data: any) {
    r2frida.offset = params.offset;
    breakpoints.setSuspended(params.suspended);
    return [{}, null];
}

function isPromise(value: any): boolean {
    return value !== null && typeof value === "object" &&
        typeof value.then === "function";
}

function getHelpMessage(prefix: string): string {
    return Object.keys(commandHandlers).sort()
        .filter((k) => {
            return !prefix || k.startsWith(prefix);
        })
        .filter((k) => {
            const firstChar = k.substring(0, 1);
            const lastChar = k.substring(k.length - 1);
            if (firstChar === "." && lastChar === ".") {
                return true;
            }
            switch (lastChar) {
                case "?":
                case "j":
                case ".":
                case "q":
                case "*":
                    return false;
            }
            return true;
        })
        .filter((k) => {
            const fcn = (commandHandlers as any)[k];
            return (typeof fcn === "object");
        })
        .sort()
        .map((k) => {
            const fcn = (commandHandlers as any)[k];
            if (typeof fcn === "object") {
                const desc = fcn[1];
                const args = fcn[2] || "";
                const haveJson = (commandHandlers as any)[k + "j"];
                const haveR2 = (commandHandlers as any)[k + "*"];
                const haveDot = (commandHandlers as any)[k + "."];
                let mods = "";
                if (haveDot || haveJson || haveR2) {
                    mods = "[" + (haveJson ? "j" : "") + (haveR2 ? "*" : "") +
                        (haveDot ? "." : "") + "]";
                }
                const cmd = k + mods + " " + args;
                // show subcommands if any (check for 'j' and '*')
                return ":" + utils.padString(cmd, 20) + desc;
            }
            return ":" + k;
        }).join("\n");
}

function perform(params: any) {
    let { command } = params;
    if (command.startsWith("!")) {
        command = "! " + command.substr(1);
    }
    if (command.startsWith("{")) {
        return r2pipe2(command);
    }
    const tokens = command.split(/ /).map((c: any) => c.trim()).filter((
        x: any,
    ) => x);
    const [name, ...args] = tokens;
    if (typeof name === "undefined") {
        const value = getHelpMessage("");
        return [{
            value: stringify(value),
        }, null];
    }
    const cmdHandler = (commandHandlers as any)[name];
    if (name === "help" || name === "?") {
        const value = getHelpMessage(args[0]);
        return [{
            value: stringify(value),
        }, null];
    }
    if (name.length > 0 && name.endsWith("?") && !cmdHandler) {
        const prefix = name.substring(0, name.length - 1);
        const value = getHelpMessage(prefix);
        return [{
            value: stringify(value),
        }, null];
    }
    const userHandler = r2frida.commandHandler(name);
    const handler = userHandler !== undefined
        ? userHandler
        : (typeof cmdHandler === "object")
        ? cmdHandler[0]
        : cmdHandler;
    if (handler === undefined) {
        throw new Error("Unhandled command: " + name);
    }
    if (isPromise(handler)) {
        throw new Error("The handler can't be a promise");
    }
    const value = handler(args);
    if (isPromise(value)) {
        return new Promise((resolve, reject) => {
            return value.then((output: any) => {
                resolve([{
                    value: stringify(output),
                }, null]);
            }).catch(reject);
        });
    }
    const nv = stringify(value);
    if (nv === "" || nv === "null" || nv === undefined || nv === null) {
        return [{}, null];
    }
    return [{ value: nv }, null];
}

function evaluate(params: any): Promise<any> {
    return new Promise((resolve) => {
        const { ccode } = params;
        let { code } = params;
        const isObjcMainLoopRunning = darwin.ObjCAvailable &&
            darwin.hasMainLoop();
        if (darwin.ObjCAvailable && isObjcMainLoopRunning) {
            ObjC.schedule(ObjC.mainQueue, performEval);
        } else {
            performEval();
        }
        function performEval() {
            let result;
            try {
                if (ccode) {
                    code = `
          var m = new CModule(` + "`" + ccode + "`" + `);
          const main = new NativeFunction(m.main, 'int', []);
          main();
          `;
                }
                // const rawResult = (1, eval)(code); // eslint-disable-line
                const rawResult = eval(code);
                // global._ = rawResult;
                result = rawResult; // 'undefined';
            } catch (e: any) {
                result = e.message + "\n" + eval(JSON.stringify(e.stack));
            }
            resolve([{
                value: result,
            }, null]);
        }
    });
}

Script.setGlobalAccessHandler({
    enumerate() {
        return [];
    },
    get(property) {
        return undefined;
    },
});

function fridaVersion(): string {
    return Frida.version;
}

function fridaVersionJson(): any {
    return { version: Frida.version };
}

function uiAlert(args: string[]): string | undefined {
    if (java.JavaAvailable) {
        return android.uiAlert(args);
    }
    if (darwin.ObjCAvailable) {
        return darwin.uiAlert(args);
    }
    return "Error: ui-alert is not implemented for this platform";
}

function echo(args: string[]) {
    console.log(args.join(" "));
    return null;
}

function onStanza(stanza: any, data: any) {
    const handler = (requestHandlers as any)[stanza.type];
    if (handler !== undefined) {
        try {
            const value = handler(stanza.payload, data);
            if (value === undefined) {
                send(utils.wrapStanza("reply", {}), []);
            } else if (value instanceof Promise) {
                // handle async stuff in here
                value
                    .then(([replyStanza, replyBytes]) => {
                        send(
                            utils.wrapStanza("reply", replyStanza),
                            replyBytes,
                        );
                    })
                    .catch((e) => {
                        send(
                            utils.wrapStanza("reply", {
                                error: e.message,
                            }),
                            [],
                        );
                    });
            } else {
                const [replyStanza, replyBytes] = value;
                send(utils.wrapStanza("reply", replyStanza), replyBytes);
            }
        } catch (e: any) {
            send(utils.wrapStanza("reply", { error: e.message }), []);
        }
    } else if (stanza.type === "bp") {
        console.error("Breakpoint handler");
    } else if (stanza.type === "cmd") {
        r2.onCmdResp(stanza.payload);
    } else {
        console.error("Unhandled stanza: " + stanza.type);
    }
    recv(onStanza);
}

function initializePuts(): PutsFunction | null {
    const putsAddress = utils.getGlobalExportByName("puts");
    if (putsAddress === null) {
        return null;
    }
    const putsFunction = new NativeFunction(putsAddress, "pointer", [
        "pointer",
    ]);
    return function (s: string) {
        if (putsFunction !== null) {
            const a = Memory.allocUtf8String(s);
            putsFunction(a);
        } else {
            console.error(s);
        }
    };
}

function stringify(value: any | null) {
    if (value === null) {
        return null;
    }
    if (typeof value === "undefined") {
        return "undefined";
    }
    if (typeof value === "string") {
        return value;
    }
    return JSON.stringify(value);
}

r2frida.hostCmd = r2.hostCmd;
r2frida.hostCmdj = r2.hostCmdj;
r2frida.hostCmds = r2.hostCmds;
r2frida.logs = log.logs;
r2frida.log = log.traceLog;
r2frida.emit = log.traceEmit;
r2frida.module = "";
r2frida.puts = initializePuts();
// r2frida.r2pipe = global.r2pipe;
r2frida.cmd = (cmd: string) => {
    const res: any = perform({ command: cmd });
    return res[0].value;
};
global.r2frida = r2frida;
global.dump = function (x: any) {
    console.log(JSON.stringify(x, null, 2));
};

declare let _setUnhandledExceptionCallback: any;
_setUnhandledExceptionCallback((error: Error) => {
    const message = {
        type: "error",
        error: "" + error,
        message: "" + error,
        description: "" + error,
        stack: "",
        fileName: "",
        lineNumber: 0,
        columnNumber: 0,
    };

    if (error instanceof Error) {
        const stack = error.stack;
        if (stack !== undefined) {
            message.stack = stack;
        }

        const fileName = (error as any).fileName;
        if (fileName !== undefined) {
            message.fileName = fileName;
        }

        const lineNumber = (error as any).lineNumber;
        if (lineNumber !== undefined) {
            message.lineNumber = lineNumber;
        }
        const columnNumber = (error as any).columnNumber;
        if (columnNumber !== undefined) {
            message.columnNumber = columnNumber;
        }
    }

    send(utils.wrapStanza("reply", message), []);
});

recv(onStanza);
