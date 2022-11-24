import expr from "../expr.js";
import log from "../../log.js";
import { getModuleByAddress } from "../info/lookup.js";
import config from "../../config.js";
import debug from "./index.js";
import darwin from "../darwin/index.js";
import swift from "../darwin/swift.js";
import java from "../java/index.js";
import utils from "../utils.js";
import { fromByteArray } from "base64-js";
'use strict';
const traceListeners = [];
const tracehooks = {};
function trace(args) {
    if (args.length === 0) {
        return _traceList();
    }
    return traceJson(args);
}
function traceFormat(args) {
    if (args.length === 0) {
        return _traceList();
    }
    let address, format;
    const name = args[0];
    if (args.length === 2) {
        address = '' + utils.getPtr(name);
        format = args[1];
    }
    else if (args.length === 1) {
        address = '' + utils.getPtr(name);
        format = '';
    }
    else {
        address = global.r2frida.offset;
        format = args[0];
    }
    if (haveTraceAt(address)) {
        return 'There\'s already a trace in here';
    }
    const traceOnEnter = format.indexOf('^') !== -1;
    const traceBacktrace = format.indexOf('+') !== -1;
    const useCmd = config.getString('hook.usecmd');
    const currentModule = getModuleByAddress(address);
    const listener = Interceptor.attach(ptr(address), {
        myArgs: [],
        myBacktrace: [],
        keepArgs: [],
        onEnter: function (args) {
            traceListener.hits++;
            if (!traceOnEnter) {
                this.keepArgs = _cloneArgs(args, format);
            }
            else {
                const fa = _formatArgs(args, format);
                this.myArgs = fa.args;
                this.myDumps = fa.dumps;
            }
            if (traceBacktrace) {
                this.myBacktrace = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
            }
            if (traceOnEnter) {
                const traceMessage = {
                    source: 'dtf',
                    name: name,
                    address: address,
                    timestamp: new Date(),
                    values: this.myArgs
                };
                if (config.getBoolean('hook.backtrace')) {
                    traceMessage.backtrace = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
                }
                if (config.getString('hook.output') === 'json') {
                    log.traceEmit(traceMessage);
                }
                else {
                    let msg = `[dtf onEnter][${traceMessage.timestamp}] ${name}@${address} - args: ${this.myArgs.join(', ')}`;
                    if (config.getBoolean('hook.backtrace')) {
                        msg += ` backtrace: ${traceMessage.backtrace.toString()}`;
                    }
                    for (let i = 0; i < this.myDumps.length; i++)
                        msg += `\ndump:${i + 1}\n${this.myDumps[i]}`;
                    log.traceEmit(msg);
                }
                if (useCmd.length > 0) {
                    console.log('[r2cmd]' + useCmd);
                }
            }
        },
        onLeave: function (retval) {
            if (!traceOnEnter) {
                const fmtArgs = _formatArgs(this.keepArgs, format);
                const fmtRet = _formatRetval(retval, format);
                this.myArgs = fmtArgs.args;
                this.myDumps = fmtArgs.dumps;
                const traceMessage = {
                    source: 'dtf',
                    name: name,
                    address: address,
                    timestamp: new Date(),
                    values: this.myArgs,
                    retval: fmtRet
                };
                if (config.getBoolean('hook.backtrace')) {
                    traceMessage.backtrace = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
                }
                if (config.getString('hook.output') === 'json') {
                    log.traceEmit(traceMessage);
                }
                else {
                    let msg = `[dtf onLeave][${traceMessage.timestamp}] ${name}@${address} - args: ${this.myArgs.join(', ')}. Retval: ${fmtRet}`;
                    if (config.getBoolean('hook.backtrace')) {
                        msg += ` backtrace: ${traceMessage.backtrace.toString()}`;
                    }
                    for (let i = 0; i < this.myDumps.length; i++)
                        msg += `\ndump:${i + 1}\n${this.myDumps[i]}`;
                    log.traceEmit(msg);
                }
                if (useCmd.length > 0) {
                    console.log('[r2cmd]' + useCmd);
                }
            }
        }
    });
    const traceListener = {
        source: 'dtf',
        hits: 0,
        at: ptr(address),
        name: name,
        moduleName: currentModule ? currentModule.name : '',
        format: format,
        listener: listener
    };
    traceListeners.push(traceListener);
    return true;
}
function traceHook(args) {
    if (args.length === 0) {
        return JSON.stringify(tracehooks, null, 2);
    }
    const arg = args[0];
    if (arg !== undefined) {
        _tracehookSet(arg, args.slice(1).join(' '));
    }
    return '';
}
function traceHere() {
    const args = [global.r2frida.offset];
    args.forEach(address => {
        const at = DebugSymbol.fromAddress(ptr(address)) || '' + ptr(address);
        const listener = Interceptor.attach(ptr(address), function () {
            const bt = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
            const at = debug.nameFromAddress(address);
            console.log('Trace here probe hit at ' + address + '::' + at + '\n\t' + bt.join('\n\t'));
        });
        traceListeners.push({
            at: at,
            listener: listener
        });
    });
    return true;
}
function traceJson(args) {
    if (args.length === 0) {
        return _traceListJson();
    }
    if (args[0].startsWith('java:')) {
        traceReal(args[0]);
        return;
    }
    return new Promise(function (resolve, reject) {
        (function pull() {
            const arg = args.pop();
            if (arg === undefined) {
                return resolve('');
            }
            const narg = utils.getPtr(arg);
            if (narg) {
                traceReal(arg, narg);
                pull();
            }
            else {
                expr.numEval(arg).then(function (at) {
                    console.error(traceReal(arg, at));
                    pull();
                }).catch(reject);
            }
        })();
    });
}
function traceQuiet(args) {
    return traceListeners.map(({ address, hits, moduleName, name }) => [address, hits, moduleName + ':' + name].join(' ')).join('\n') + '\n';
}
function traceR2(args) {
    return traceListeners.map(_ => `dt+ ${_.at} ${_.hits}`).join('\n') + '\n';
}
function clearTrace(args) {
    let index;
    if (args.length === 0) {
        return '';
    }
    try {
        index = parseInt(args[0], 10);
    }
    catch {
        return 'Integer argument is required.';
    }
    if (index < 0) {
        return 'Index should be equal or greater to 0.';
    }
    for (let i = 0; i < traceListeners.length; i++) {
        const tl = traceListeners[i];
        if (i === index) {
            tl.listener.detach();
            traceListeners.splice(i, 1);
            break;
        }
    }
    return '';
}
function clearAllTrace(args) {
    traceListeners.splice(0).forEach(lo => lo.listener ? lo.listener.detach() : null);
    return '';
}
function traceRegs(args) {
    if (args.length < 1) {
        return 'Usage: dtr [name|address] [reg ...]';
    }
    const address = utils.getPtr(args[0]);
    if (haveTraceAt(address)) {
        return 'There\'s already a trace in here';
    }
    const rest = args.slice(1);
    const currentModule = getModuleByAddress(address);
    const listener = Interceptor.attach(address, traceFunction);
    function traceFunction(_) {
        traceListener.hits++;
        const regState = {};
        rest.forEach((r) => {
            let regName = r;
            let regValue;
            if (r.indexOf('=') !== -1) {
                const kv = r.split('=');
                this.context[kv[0]] = ptr(kv[1]); // set register value
                regName = kv[0];
                regValue = kv[1];
            }
            else {
                try {
                    const rv = ptr(this.context[r]);
                    regValue = rv;
                    let tail = Memory.readCString(rv);
                    if (tail) {
                        tail = ' (' + tail + ')';
                        regValue += tail;
                    }
                }
                catch (e) {
                    // do nothing
                }
            }
            regState[regName] = regValue;
        });
        const traceMessage = {
            source: 'dtr',
            address: address,
            timestamp: new Date(),
            values: regState
        };
        if (config.getBoolean('hook.backtrace')) {
            traceMessage.backtrace = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
        }
        if (config.getString('hook.output') === 'json') {
            log.traceEmit(traceMessage);
        }
        else {
            let msg = `[dtr][${traceMessage.timestamp}] ${address} - registers: ${JSON.stringify(regState)}`;
            if (config.getBoolean('hook.backtrace')) {
                msg += ` backtrace: ${traceMessage.backtrace.toString()}`;
            }
            log.traceEmit(msg);
        }
    }
    const traceListener = {
        source: 'dtr',
        hits: 0,
        at: address,
        moduleName: currentModule ? currentModule.name : 'unknown',
        name: args[0],
        listener: listener,
        args: rest
    };
    traceListeners.push(traceListener);
    return '';
}
function traceReal(name, addressString) {
    if (arguments.length === 0) {
        return _traceList();
    }
    if (name.startsWith('swift:')) {
        const km = name.substring(6);
        const dot = km.lastIndexOf('.');
        if (dot === -1) {
            return 'Invalid syntax for swift uri. Use "swift:KLASS.METHOD"';
        }
        const klass = km.substring(0, dot);
        const methd = km.substring(dot + 1);
        return swift.traceSwift(klass, methd);
    }
    if (name.startsWith('java:')) {
        const javaName = name.substring(5);
        if (java.javaUse(javaName)) {
            console.error('Tracing class constructors');
            java.traceJavaConstructors(javaName);
        }
        else {
            const dot = javaName.lastIndexOf('.');
            if (dot !== -1) {
                const klass = javaName.substring(0, dot);
                const methd = javaName.substring(dot + 1);
                java.traceJava(klass, methd);
            }
            else {
                console.log('Invalid java method name. Use :dt java:package.class.method');
            }
        }
        return;
    }
    const address = ptr(addressString);
    if (haveTraceAt(address)) {
        return 'There\'s already a trace in here';
    }
    const currentModule = getModuleByAddress(address);
    const listener = Interceptor.attach(address, function (args) {
        const values = tracehook(address, args);
        const traceMessage = {
            source: 'dt',
            address: address,
            timestamp: new Date(),
            values: values
        };
        traceListener.hits++;
        if (config.getString('hook.output') === 'json') {
            log.traceEmit(traceMessage);
        }
        else {
            log.traceEmit(`[dt][${traceMessage.timestamp}] ${address} - args: ${JSON.stringify(values)}`);
        }
    });
    const traceListener = {
        source: 'dt',
        at: address,
        hits: 0,
        name: name,
        moduleName: currentModule ? currentModule.name : 'unknown',
        args: '',
        listener: listener
    };
    traceListeners.push(traceListener);
    return '';
}
// \dth printf 0,1 .. kind of dtf
function tracehook(address, args) {
    const at = debug.nameFromAddress(address);
    const th = tracehooks[at];
    const fmtarg = [];
    if (th && th.format) {
        for (const fmt of th.format.split(' ')) {
            const [k, v] = fmt.split(':');
            switch (k) {
                case 'i':
                    // console.log('int', args[v]);
                    fmtarg.push(+args[v]);
                    break;
                case 's':
                    {
                        const [a, l] = v.split(',');
                        const addr = ptr(args[a]);
                        const size = +args[l];
                        // const buf = Memory.readByteArray(addr, size);
                        // console.log('buf', utils.arrayBufferToHex(buf));
                        // console.log('string', Memory.readCString(addr, size));
                        fmtarg.push(Memory.readCString(addr, size));
                    }
                    break;
                case 'z':
                    // console.log('string', Memory.readCString(args[+v]));
                    fmtarg.push(Memory.readCString(ptr(args[+v])));
                    break;
                case 'v':
                    {
                        const [a, l] = v.split(',');
                        const addr = ptr(args[a]);
                        const buf = Memory.readByteArray(addr, +args[l]);
                        fmtarg.push(utils.arrayBufferToHex(buf));
                    }
                    break;
            }
        }
    }
    return fmtarg;
}
function traceLogDump() {
    return log.logs.map(_tracelogToString).join('\n') + '\n';
}
function traceLogDumpR2() {
    let res = '';
    for (const l of log.logs) {
        const s = '' + _traceNameFromAddress(l.address) + ': ';
        const input = JSON.stringify(l);
        const binput = Uint8Array.from(input.split('').map((x) => { return x.charCodeAt(0); }));
        const bytes = Uint8Array.from(binput);
        const data = fromByteArray(bytes);
        res += "T base64:" + data + "\n";
        if (l.script) {
            res += l.script;
        }
    }
    return res;
}
function traceLogDumpQuiet() {
    return log.logs.map(({ address, timestamp }) => [address, timestamp, _traceCountFromAddress(address), _traceNameFromAddress(address)].join(' '))
        .join('\n') + '\n';
}
function traceLogDumpJson() {
    return JSON.stringify(log.logs);
}
function traceLogClear(args) {
    // TODO: clear one trace instead of all
    console.error('ARGS', JSON.stringify(args));
    return traceLogClearAll();
}
function traceLogClearAll() {
    log.logs.splice(0);
    return '';
}
function haveTraceAt(address) {
    try {
        for (const trace of traceListeners) {
            if (trace.at.compare(address) === 0) {
                return true;
            }
        }
    }
    catch (e) {
        console.error(e);
    }
    return false;
}
function _cloneArgs(args, fmt) {
    const a = [];
    let j = 0;
    for (let i = 0; i < fmt.length; i++, j++) {
        const arg = args[j];
        switch (fmt[i]) {
            case '+':
            case '^':
                j--;
                break;
            default:
                a.push(arg);
                break;
        }
    }
    return a;
}
function _formatRetval(retval, fmt) {
    if (retval !== undefined && !retval.isNull()) {
        const retToken = fmt.indexOf('%');
        if (retToken !== -1 && fmt[retToken + 1] !== undefined) {
            try {
                return _format(retval, fmt[retToken + 1]);
            }
            catch (e) { }
        }
        return retval;
    }
}
function _formatArgs(args, fmt) {
    const fmtArgs = [];
    const dumps = [];
    let arg;
    let j = 0;
    for (let i = 0; i < fmt.length; i++, j++) {
        try {
            arg = args[j];
        }
        catch (err) {
            console.error('invalid format', i);
        }
        if (fmt[i] === '+' || fmt[i] === '^') {
            j--;
        }
        else if (fmt[i] === '%') {
            break;
        }
        else if (fmt[i] === 'Z') {
            fmtArgs.push(`${JSON.stringify(_readUntrustedUtf8(arg, +args[j + 1]))}`);
        }
        else if (fmt[i] === 'h') {
            // hexdump pointer target, default length 128
            // customize length with h<length>, f.e. h16 to dump 16 bytes
            let dumpLen = 128;
            const optionalNumStr = fmt.slice(i + 1).match(/^[0-9]*/)[0];
            if (optionalNumStr.length > 0) {
                i += optionalNumStr.length;
                dumpLen = +optionalNumStr;
            }
            fmtArgs.push(`dump:${dumps.length} (len=${dumpLen})`);
            dumps.push(_hexdumpUntrusted(arg, dumpLen));
        }
        else if (fmt[i] === 'H') {
            // hexdump pointer target, default length 128
            // use length from other funtion arg with H<arg number>, f.e. H0 to dump '+args[0]' bytes
            let dumpLen = 128;
            const optionalNumStr = fmt.slice(i + 1).match(/^[0-9]*/)[0];
            if (optionalNumStr.length > 0) {
                i += optionalNumStr.length;
                const posLenArg = +optionalNumStr;
                if (posLenArg !== j) {
                    // only adjust dump length, if the length param isn't the dump address itself
                    dumpLen = +args[posLenArg];
                }
            }
            // limit dumpLen, to avoid oversized dumps, caused by  accidentally parsing pointer agrs as length
            // set length limit to 64K for now
            const lenLimit = 0x10000;
            dumpLen = dumpLen > lenLimit ? lenLimit : dumpLen;
            fmtArgs.push(`dump:${dumps.length} (len=${dumpLen})`);
            dumps.push(_hexdumpUntrusted(arg, dumpLen));
        }
        else {
            fmtArgs.push(_format(arg, fmt[i]));
        }
    }
    return { args: fmtArgs, dumps: dumps };
}
function _format(addr, fmt) {
    let result;
    switch (fmt) {
        case 'x': {
            result = `${ptr(addr)}`;
            break;
        }
        case 'c':
            result = `'${addr}'`;
            break;
        case 'i':
            result = `${+addr}`;
            break;
        case 'z': // *s
            result = JSON.stringify(_readUntrustedUtf8(addr));
            break;
        case 'w': // *s
            result = JSON.stringify(_readUntrustedUtf16(addr));
            break;
        case 'a': // *s
            result = JSON.stringify(_readUntrustedAnsi(addr));
            break;
        case 'S': // **s
            result = JSON.stringify(_readUntrustedUtf8(Memory.readPointer(addr)));
            break;
        case 'o':
        case 'O':
            if (ObjC.available) {
                if (!addr.isNull()) {
                    if (darwin.isObjC(addr)) {
                        const o = new ObjC.Object(addr);
                        if (o.$className === 'Foundation.__NSSwiftData') {
                            result = `${o.$className}: "${ObjC.classes.NSString.alloc().initWithData_encoding_(o, 4).toString()}"`;
                        }
                        else {
                            result = `${o.$className}: "${o.toString()}"`;
                        }
                    }
                    else {
                        const str = Memory.readCString(addr);
                        if (str.length > 2) {
                            result = `${str}`;
                        }
                        else {
                            result = `${addr}`;
                        }
                    }
                }
                else {
                    result = 'nil';
                }
            }
            else {
                result = `${addr}`;
            }
            break;
        default:
            result = `${addr}`;
            break;
    }
    return result;
}
function _tracehookSet(name, format, callback) {
    if (name === null) {
        console.error('Name was not resolved');
        return false;
    }
    tracehooks[name] = {
        format: format,
        callback: callback
    };
    return true;
}
function _traceList() {
    let count = 0;
    return traceListeners.map((t) => {
        return [count++, t.hits, t.at, t.source, t.moduleName, t.name, t.args].join('\t');
    }).join('\n') + '\n';
}
function _traceListJson() {
    return traceListeners.map(_ => JSON.stringify(_)).join('\n') + '\n';
}
function _traceListenerFromAddress(address) {
    const results = traceListeners.filter((tl) => '' + address === '' + tl.at);
    return (results.length > 0) ? results[0] : undefined;
}
function _traceCountFromAddress(address) {
    const tl = _traceListenerFromAddress(address);
    return tl ? tl.hits : 0;
}
function _traceNameFromAddress(address) {
    const tl = _traceListenerFromAddress(address);
    return tl ? tl.moduleName + ':' + tl.name : '';
}
function _hexdumpUntrusted(addr, len) {
    try {
        if (typeof len === 'number')
            return hexdump(addr, { length: len });
        else
            return hexdump(addr);
    }
    catch (e) {
        return `hexdump at ${addr} failed: ${e}`;
    }
}
function _tracelogToString(l) {
    const line = [l.source, l.name || l.address, _objectToString(l.values)].join('\t');
    const bt = (!l.backtrace)
        ? ''
        : l.backtrace.map((b) => {
            return ['', b.address, b.moduleName, b.name].join('\t');
        }).join('\n') + '\n';
    return line + bt;
}
function _objectToString(o) {
    // console.error(JSON.stringify(o));
    const r = Object.keys(o).map((k) => {
        try {
            const p = ptr(o[k]);
            if (darwin.isObjC(p)) {
                const o = new ObjC.Object(p);
                return k + ': ' + o.toString();
            }
            const str = Memory.readCString(p);
            if (str.length > 2) {
                return k + ': "' + str + '"';
            }
        }
        catch (e) {
        }
        return k + ': ' + o[k];
    }).join(' ');
    return '(' + r + ')';
}
function _readUntrustedUtf8(address, length) {
    try {
        if (typeof length === 'number') {
            return Memory.readUtf8String(ptr(address), length);
        }
        return Memory.readUtf8String(ptr(address));
    }
    catch (e) {
        if (e.message !== 'invalid UTF-8') {
            // TODO: just use this, doo not mess with utf8 imho
            return Memory.readCString(ptr(address));
        }
        return '(invalid utf8)';
    }
}
function _readUntrustedUtf16(address, length) {
    try {
        if (typeof length === 'number') {
            return Memory.readUtf16String(ptr(address), length);
        }
        return Memory.readUtf16String(ptr(address));
    }
    catch (e) {
        if (e.message !== 'invalid UTF-16') {
            // TODO: just use this, doo not mess with utf8 imho
            return Memory.readCString(ptr(address));
        }
        return '(invalid utf16)';
    }
}
function _readUntrustedAnsi(address, length) {
    try {
        if (typeof length === 'number') {
            return Memory.readAnsiString(ptr(address), length);
        }
        return Memory.readAnsiString(ptr(address));
    }
    catch (e) {
        if (e.message !== 'invalid Ansi') {
            // TODO: just use this, doo not mess with utf8 imho
            return Memory.readCString(ptr(address));
        }
        return '(invalid Ansi)';
    }
}
export { trace };
export { traceFormat };
export { traceHook };
export { traceHere };
export { traceJson };
export { traceQuiet };
export { traceR2 };
export { clearTrace };
export { clearAllTrace };
export { traceRegs };
export { traceLogDump };
export { traceLogDumpR2 };
export { traceLogDumpQuiet };
export { traceLogDumpJson };
export { traceLogClear };
export { traceLogClearAll };
export default {
    trace,
    traceFormat,
    traceHook,
    traceHere,
    traceJson,
    traceQuiet,
    traceR2,
    clearTrace,
    clearAllTrace,
    traceRegs,
    traceLogDump,
    traceLogDumpR2,
    traceLogDumpQuiet,
    traceLogDumpJson,
    traceLogClear,
    traceLogClearAll
};
