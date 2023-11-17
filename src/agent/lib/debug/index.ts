import config from '../../config.js';
import r2 from '../r2.js';
import sys from '../sys.js';
import { autoType, getPtr, padPointer, byteArrayToHex } from '../utils.js';

const newBreakpoints = new Map();
let suspended = false;

const regProfileAliasForArm64 = `
=PC pc
=SP sp
=BP x29
=A0 x0
=A1 x1
=A2 x2
=A3 x3
=ZF zf
=SF nf
=OF vf
=CF cf
=SN x8
`;

const regProfileAliasForArm = `
=PC r15
=LR r14
=SP sp
=BP fp
=A0 r0
=A1 r1
=A2 r2
=A3 r3
=ZF zf
=SF nf
=OF vf
=CF cf
=SN r7
`;

const regProfileAliasForX64 = `
=PC rip
=SP rsp
=BP rbp
=A0 rdi
=A1 rsi
=A2 rdx
=A3 rcx
=A4 r8
=A5 r9
=SN rax
`;

const regProfileAliasForX86 = `
=PC eip
=SP esp
=BP ebp
=A0 eax
=A1 ebx
=A2 ecx
=A3 edx
=A4 esi
=A5 edi
=SN eax
`;

export function isSuspended() : boolean {
    return suspended;
}

export function setSuspended(v: boolean): void {
    suspended = v;
}

/* breakpoint handler */
Process.setExceptionHandler(({ address }) => {
    const bp = newBreakpoints.get(address.toString());
    if (!bp) {
        return false;
    }
    const index = bp.patches.findIndex((p: any) => p.address.equals(address));
    if (index === 0) {
        send({ name: 'breakpoint-event', stanza: { cmd: bp.cmd } });
        let state = 'stopped';
        if (config.getBoolean('hook.verbose')) {
            console.log(`Breakpoint ${address} hit`);
        }
        do {
            const op = recv('breakpoint-action', ({ action }) => {
                switch (action) {
                    case 'register-change':
                        console.log('TODO1');
                        break;
                    case 'resume':
                        state = 'running';
                        if (config.getBoolean('hook.verbose')) {
                            console.log('Continue thread(s).');
                        }
                        break;
                    default:
                        console.log('TODO2');
                        break;
                }
            });
            op.wait();
        } while (state === 'stopped');
    }
    const afterBp = newBreakpoints.get(address.toString());
    if (afterBp) {
        for (const p of bp.patches) {
            p.toggle();
        }
    }
    return true;
});

export class CodePatch {
    insn: any;
    _newData: any;
    _originalData: any;
    _applied: boolean;
    constructor(address: NativePointer) {
        const insn = Instruction.parse(address);
        this.address = address;
        this.insn = insn;
        const insnSize = insn.size;
        this._newData = breakpointInstruction();
        this._originalData = address.readByteArray(insnSize);
        this._applied = false;
    }

    toggle() {
        this._apply(this._applied ? this._originalData : this._newData);
        this._applied = !this._applied;
    }
    enable() {
        if (!this._applied) {
            this.toggle();
        }
    }

    disable() {
        if (this._applied) {
            this.toggle();
        }
    }
    address: any;
    _apply(data: any) {
        Memory.patchCode(this.address, data.byteLength, code => {
            code.writeByteArray(data);
        });
    }
}

export function breakpointInstruction() {
    if (Process.arch === 'arm64') {
        return new Uint8Array([0x60, 0x00, 0x20, 0xd4]).buffer;
    }
    return new Uint8Array([0xcc]).buffer;
}

export function breakpointNative(args: string[]) {
    if (args.length === 0) {
        _breakpointList([]);
    } else if (args[0].startsWith('-')) {
        const addr = args[0].substring(1);
        breakpointUnset([addr]);
    } else {
        _breakpointSet(args);
    }
}

export function breakpointJson() {
    const json: any = {};
    for (const [address, bp] of newBreakpoints.entries()) {
        if (bp.patches[0].address.equals(ptr(address))) {
            const k = '' + bp.patches[0].address;
            json[k] = {};
            json[k].enabled = true;
            if (bp.cmd) {
                json[k].cmd = bp.cmd;
            }
        }
    }
    return JSON.stringify(json);
}

export function breakpointNativeCommand(args: string[]) {
    if (args.length >= 2) {
        const address = args[0];
        const command = args.slice(1).join(' ');
        for (const [bpaddr, bp] of newBreakpoints.entries()) {
            if (bp.patches[0].address.equals(ptr(bpaddr))) {
                if (bpaddr === address) {
                    bp.cmd = command;
                    break;
                }
            }
        }
    } else {
        console.error('Usage: dbc [address-of-breakpoint] [r2-command-to-run-when-hit]');
    }
}

export function breakpointUnset(args: string[]) {
    const addr = getPtr(args[0]).toString();
    const bp = newBreakpoints.get(addr);
    for (const p of bp.patches) {
        p.disable();
        newBreakpoints.delete(p.address.toString());
    }
}

export function breakpointContinue(args: string[]) {
    if (suspended) {
        suspended = false;
        return r2.hostCmd(':dc');
    }
    return 'Continue thread(s).';
}

export function breakpointContinueUntil(args: string[]) {
    breakpointNative(args);
    breakpointContinue([]);
    breakpointNative(['-' + args[0]]);
}

export function sendSignal(args: string[]) {
    const argsLength = args.length;
    console.error('WARNING: Frida hangs when signal is sent. But at least the process doesnt continue');
    if (argsLength === 1) {
        const sig = +args[0];
        sys._kill!(Process.id, sig);
    } else if (argsLength === 2) {
        const [pid, sig] = args;
        sys._kill!(+pid, +sig);
    } else {
        return 'Usage: :dk ([pid]) [sig]';
    }
    return '';
}

function _breakpointList(args: string[]) {
    for (const [address, bp] of newBreakpoints.entries()) {
        if (bp.patches[0].address.equals(ptr(address))) {
            console.log(address);
        }
    }
}

function _breakpointSet(args: string[]) {
    const ptrAddr = getPtr(args[0]);
    const p1 = new CodePatch(ptrAddr) as any;
    const p2 = new CodePatch(p1.insn.next);
    const bp = {
        patches: [p1, p2]
    };
    newBreakpoints.set(p1.address.toString(), bp);
    newBreakpoints.set(p2.address.toString(), bp);
    p1.toggle();
}

export function dxCall(args: string[]) {
    if (args.length === 0) {
        return `
    Usage: dxc [funcptr] [arg0 arg1..]
    For example:
    :dxc write 1 "hello\\n" 6
    :dxc read 0 \`?v rsp\` 10
    `;
    }
    const address = (args[0].substring(0, 2) === '0x')
        ? ptr(args[0])
        : Module.getExportByName(null, args[0]);
    const [nfArgs, nfArgsData] = autoType(args.slice(1));
    const fun = new NativeFunction(address, 'pointer', nfArgs as any);
    /* eslint prefer-spread: 0 */
    return fun.apply(null, nfArgsData as any); // makes typescript happy
    // return fun.apply(...nfArgsData); // makes eslint happy
}

export function dxSyscall(args: string[]) {
    if (args.length === 0) {
        return 'Usage dxs [syscallname] [args ...]';
    }
    const syscallNumber = '' + _resolveSyscallNumber(args[0]);
    return dxCall(['syscall', syscallNumber, ...args.slice(1)]);
}

function _resolveSyscallNumber(name: string): number | string {
    const ios = Process.arch === 'arm64';
    switch (name) {
        case 'read':
            return ios ? 3 : 0x2000003;
        case 'write':
            return ios ? 4 : 0x2000004;
        case 'exit':
            return ios ? 1 : 0x2000001;
    }
    return '' + name;
}

export function listThreads() {
    return Process.enumerateThreads().map((thread) => {
        const threadName = _getThreadName(thread.id);
        return [thread.id, threadName].join(' ');
    }).join('\n') + '\n';
}

export function listThreadsJson() {
    return Process.enumerateThreads()
        .map(thread => thread.id);
}

export function dumpRegisters(args: string[]) {
    return _getThreads(args[0])
        .map(thread => {
            const { id, state, context } = thread;
            const heading = `tid ${id} ${state}`;
            const names = Object.keys(JSON.parse(JSON.stringify(context)));
            names.sort(_compareRegisterNames);
            const values = names
                .map((name, index) => _alignRight(name, 3) + ' : ' + padPointer((context as any)[name]))
                .map(_indent);
            return heading + '\n' + values.join('');
        })
        .join('\n\n') + '\n';
}

export function dumpRegistersJson(args: string[]) {
    return _getThreads(args[0]);
}

function _getThreads(threadid: string) {
    const tid = threadid !== undefined ? parseInt(threadid, 10) : threadid;
    return Process.enumerateThreads()
        .filter(thread => tid === undefined || thread.id === tid);
}

export function dumpRegistersEsil(args: string[]) {
    const threads = Process.enumerateThreads();
    const [tid] = args;
    const context = tid ? threads.filter(th => th.id === +tid) : threads[0].context;
    if (!context) {
        return '';
    }
    const names = Object.keys(JSON.parse(JSON.stringify(context)));
    names.sort(_compareRegisterNames);
    const values = names
        .map((name, index) => {
            if (name === 'pc' || name === 'sp') {
                return '';
            }
            const value = '' + ((context as any)[name] || 0);
            if (value.indexOf('object') !== -1) {
                return '';
            }
            return `${value},${name},:=`;
        });
    return values.join(',');
}

export function dumpRegistersR2(args: string[]) {
    const threads = Process.enumerateThreads();
    const [tid] = args;
    const context = tid ? threads.filter(th => th.id === +tid) : threads[0].context;
    if (!context) {
        return '';
    }
    const names = Object.keys(JSON.parse(JSON.stringify(context)));
    names.sort(_compareRegisterNames);
    const values = names
        .map((name, index) => {
            if (name === 'pc' || name === 'sp') {
                return '';
            }
            const value = '' + ((context as any)[name] || 0);
            if (value.indexOf('object') !== -1) {
                return '';
            }
            return `ar ${name} = ${value}\n`;
        });
    return values.join('');
}

export function dumpRegistersRecursively(args: string[]) {
    const [tid] = args;
    Process.enumerateThreads()
        .filter(thread => !tid || !+tid || +tid === thread.id)
        .forEach(thread => {
            const { id, state, context } = thread;
            const res = ['# thread ' + id + ' ' + state];
            for (const reg of Object.keys(context)) {
                try {
                    const data = _regcursive(reg, (context as any)[reg]);
                    res.push(reg + ': ' + data);
                } catch (e) {
                    res.push(reg);
                }
            }
            console.log(res.join('\n'));
        });
    return ''; // nothing to see here
}

export function dumpRegisterProfile(args: string[]) {
    const threads = Process.enumerateThreads();
    const context = threads[0].context;
    const names = Object.keys(JSON.parse(JSON.stringify(context)))
        .filter(_ => _ !== 'pc' && _ !== 'sp');
    names.sort(_compareRegisterNames);
    let off = 0;
    const inc = Process.pointerSize;
    let profile = _regProfileAliasFor(Process.arch);
    for (const reg of names) {
        profile += `gpr\t${reg}\t${inc}\t${off}\t0\n`;
        off += inc;
    }
    return profile;
}

export function dumpRegisterArena(args: string[]) {
    const threads = Process.enumerateThreads();
    if (threads.length < 1) {
        return "";
    }
    let tidx = +args[0];
    if (!tidx) {
        tidx = 0;
    }
    if (tidx < 0 || tidx >= threads.length) {
        return "";
    }
    const context: any = threads[tidx].context;
    const names = Object.keys(JSON.parse(JSON.stringify(context)))
        .filter(_ => _ !== 'pc' && _ !== 'sp');
    names.sort(_compareRegisterNames);
    let offset = 0;
    const regSize = Process.pointerSize;
    if (regSize !== 4 && regSize !== 8) {
        console.error("Invalid register size");
        return;
    }
    const buf = [];
    for (const reg of names) {
        const r = context[reg];
        if (typeof r.and !== 'function') {
            continue;
        }
        for (let i = 0; i < regSize; i++) {
            const idx = i * 8;
            buf.push(r.shr(idx).and(0xff));
        }
        offset += regSize;
    }
    return byteArrayToHex(buf);
}

export function nameFromAddress(address: NativePointer) {
    const at = DebugSymbol.fromAddress(address);
    if (at) {
        return at.name;
    }
    const module = Process.findModuleByAddress(address);
    if (module === null) {
        return null;
    }
    const imports = module.enumerateImports();
    for (const imp of imports) {
        if (imp.address !== undefined && imp.address.equals(address)) {
            return imp.name;
        }
    }
    const exports = module.enumerateExports();
    for (const exp of exports) {
        if (exp.address.equals(address)) {
            return exp.name;
        }
    }
    return address.toString();
}

function _getThreadName(tid: number) {
    let canGetThreadName = false;
    let pthreadGetnameNp: any | null = null;
    let pthreadFromMachThreadNp: any | null = null;
    try {
        const addr = Module.getExportByName(null, 'pthread_getname_np');
        const addr2 = Module.getExportByName(null, 'pthread_from_mach_thread_np');
        pthreadGetnameNp = new NativeFunction(addr, 'int', ['pointer', 'pointer', 'int']);
        pthreadFromMachThreadNp = new NativeFunction(addr2, 'pointer', ['uint']);
        canGetThreadName = true;
    } catch (e) {
        // do nothing
    }
    if (!canGetThreadName) {
        return '';
    }
    const buffer = Memory.alloc(4096);
    const p = pthreadFromMachThreadNp(tid);
    pthreadGetnameNp(p, buffer, 4096);
    return buffer.readCString();
}

function _compareRegisterNames(lhs: any, rhs: any) {
    const lhsIndex = _parseRegisterIndex(lhs);
    const rhsIndex = _parseRegisterIndex(rhs);
    const lhsHasIndex = lhsIndex !== null;
    const rhsHasIndex = rhsIndex !== null;
    if (lhsHasIndex && rhsHasIndex) {
        return lhsIndex - rhsIndex;
    }
    if (lhsHasIndex === rhsHasIndex) {
        const lhsLength = lhs.length;
        const rhsLength = rhs.length;
        if (lhsLength === rhsLength) {
            return lhs.localeCompare(rhs);
        }
        if (lhsLength > rhsLength) {
            return 1;
        }
        return -1;
    }
    if (lhsHasIndex) {
        return 1;
    }
    return -1;
}

function _parseRegisterIndex(name: string) {
    const length = name.length;
    for (let index = 1; index < length; index++) {
        const value = parseInt(name.substring(index));
        if (!isNaN(value)) {
            return value;
        }
    }
    return null;
}

function _regProfileAliasFor(arch: string): string {
    switch (arch) {
        case 'arm64':
            return regProfileAliasForArm64;
        case 'arm':
            return regProfileAliasForArm;
        case 'ia64':
        case 'x64':
            return regProfileAliasForX64;
        case 'ia32':
        case 'x86':
            return regProfileAliasForX86;
    }
    return '';
}

function _regcursive(regname: string, pregvalue: NativePointer) {
    const regvalue = pregvalue.toString();
    const data = [regvalue];
    try {
        const str = ptr(regvalue).readCString(32);
        if (str && str.length > 3) {
            const printableString = str.replace(/[^\x20-\x7E]/g, '');
            data.push("'" + printableString + "'");
        }
        const p = ptr(regvalue).readPointer();
        data.push('=>');
        data.push(_regcursive(regname, p));
    } catch (e) {
    }
    if (+regvalue === 0) {
        data.push('NULL');
    } else if (+regvalue === 0xffffffff) {
        data.push("-1");
    } else if (+regvalue > ' '.charCodeAt(0) && +regvalue < 127) {
        data.push('\'' + String.fromCharCode(+regvalue) + '\'');
    }
    try {
        // XXX regvalue must be a NativePointer not a string
        const module = Process.findModuleByAddress(pregvalue);
        if (module) {
            data.push(module.name);
        }
    } catch (e) {
    }
    try {
        const name = nameFromAddress(pregvalue);
        if (name) {
            data.push(name);
        }
    } catch (e) {
    }
    return data.join(' ');
}

function _indent(message: any, index: number) {
    if (index === 0) {
        return message;
    }
    if ((index % 3) === 0) {
        return '\n' + message;
    }
    return '\t' + message;
}

function _alignRight(text: string, width: number) {
    let result = text;
    while (result.length < width) {
        result = ' ' + result;
    }
    return result;
}
