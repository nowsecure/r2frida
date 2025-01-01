import config from '../../config.js';
import { getPtr } from '../utils.js';
import r2 from '../r2.js';

const breakpoints = new Map<string, BreakpointData>();
let suspended = false;
export let currentThreadContext: CpuContext | null = null;

initBreakpoints();

/**
 * Initializes the breakpoints by setting up an exception handler.
 * The handler checks if the exception is caused by a breakpoint and handles it accordingly.
 * It sends a 'breakpoint-event' message when a breakpoint is hit and waits for a 'breakpoint-action' message to determine the next action.
 */
export function initBreakpoints(): void {
    /* breakpoint handler */
    Process.setExceptionHandler(({ address, context, type }) => {
        const bp = breakpoints.get(address.toString());
        if (!bp) {
            return false;
        }
        let hasBreakpointHit = false;
        if (bp instanceof SoftwareBreakpointData) {
            hasBreakpointHit = bp.patches.findIndex((p: any) => p.address.equals(address)) === 0;
        } else {
            hasBreakpointHit = bp && Process.getCurrentThreadId() === bp.thread.id && ['breakpoint', 'single-step'].includes(type);
        }
        if (hasBreakpointHit && bp.enabled) {
            send({ name: 'breakpoint-event', stanza: { cmd: bp.cmd } });
            let state = 'stopped';
            currentThreadContext = context;
            if (config.getBoolean('hook.verbose')) {
                console.log(`Breakpoint at ${address} hit`);
            }
            do {
                const op = recv('breakpoint-action', ({ action }) => {
                    switch (action) {
                        case 'register-change':
                            console.log('TODO1');
                            break;
                        case 'resume':
                            state = 'running';
                            currentThreadContext = null;
                            if (bp instanceof HardwareBreakpointData) {
                                bp.unsetBreakpoint();
                            }
                            if (config.getBoolean('hook.verbose')) {
                                console.log('Continue thread(s).');
                            }
                            break;
                        default:
                            console.log('TODO: exceptionHandler: ' + action);
                            break;
                    }
                });
                op.wait();
            } while (state === 'stopped');
        }
        const afterBp = breakpoints.get(address.toString());
        if (afterBp) {
            afterBp.toggle();
        }
        return true;
    });
}

/**
 * Sets a breakpoint based on the provided arguments.
 *
 * If no arguments are provided, it logs the current list of breakpoints.
 * If the first argument starts with a '-', it unsets the breakpoint at the specified address.
 * Otherwise, it sets a breakpoint at the specified address and logs a confirmation message.
 *
 * @param {string[]} args - The first argument is the address as string.
 */
export function setBreakpoint(args: string[]) : void {
    if (args.length === 0) {
        console.log(_breakpointList([]));
    } else if (args[0].startsWith('-')) {
        const addr = args[0].substring(1);
        unsetBreakpoint([addr]);
    } else {
        if(_breakpointSet(args)) {
            console.log(`Breakpoint at ${args[0]} set`);
        };
    }
}

/**
 * Sets a breakpoint command for a given address.
 *
 * This function expects two arguments: the address of the breakpoint and the command to run when the breakpoint is hit.
 *
 * @param {string[]} args - The arguments array containing the address of the breakpoint and the command to run.
 */
export function setBreakpointCommand(args: string[]): void {
    if (args.length < 2) {
        console.error('Usage: dbc [address-of-breakpoint] [r2-command-to-run-when-hit]');
        return;
    }
    const address = getPtr(args[0]);
    if (!breakpoints.has(address.toString())) {
        if(_breakpointSet(args)) {
            console.log(`Breakpoint at ${args[0]} set`);
        };
    }
    const command = args.slice(1).join(' ');
    const bp = breakpoints.get(address.toString())
    if (bp && bp.address.equals(address)) {
                bp.cmd = command;
    }
}

/**
 * Unsets a breakpoint based on the provided arguments.
 *
 * If no arguments are provided, it logs the current list of breakpoints.
 * Otherwise, it attempts to unset the breakpoint at the provided address and logs the result.
 *
 * @param {string[]} args - The arguments for unsetting the breakpoint. 
 */
export function unsetBreakpoint(args: string[]): void {
    if (args.length === 0) {
        console.log(_breakpointList([]));
    } else if (args[0].startsWith('-')) {
        const addr = args[0].substring(1);
        unsetBreakpoint([addr]);
    } else {
        if(_breakpointUnset(args)) {
            console.log(`Breakpoint at ${args[0]} unset`);
        };
    }
}

/**
 * Unsets all breakpoints.
 *
 * @param args - This parameter is currently not used.
 */
export function breakpointUnsetAll(_: string[]) {
    for (const [address, _] of breakpoints.entries()) {
        unsetBreakpoint([address]);
    }
}

/**
 * Continues execution of the program if it is currently suspended.
 *
 * @param args - An array of strings representing the arguments passed to the function.
 * @returns If the program was suspended, it sends the ':dc' command to continue execution.
 */
export function breakpointContinue(args: string[]): Promise<string> {
    if (suspended) {
        suspended = false;
        return r2.hostCmd(':dc');
    }
    return Promise.resolve('Continue thread(s).');
}

/**
 * Sets a breakpoint and continues execution until the breakpoint is hit.
 * 
 * @param args - An array of strings representing the address for the breakpoint.
 */
export function setBreakpointContinueUntil(args: string[]): void {
    if (args.length === 0) {
        console.log(_breakpointList([]));
    } else if (args[0].startsWith('-')) {
        const addr = args[0].substring(1);
        unsetBreakpoint([addr]);
    } else {
        if (_breakpointSet(args)) {
            breakpointContinue([]);
            unsetBreakpoint(args);
        }
    }
}

/**
 * Converts the current breakpoints into a JSON string representation.
 *
 * @returns {string} A JSON string representation of the current breakpoints.
 */
export function breakpointJson(): string {
    const result: any = {};
    for (const [address, bp] of breakpoints.entries()) {
        if (bp instanceof SoftwareBreakpointData) {
            if (bp.patches[0].address.equals(ptr(address))) {
                const key = bp.patches[0].address.toString();
                result[key] = {};
                result[key].type = 'sw';
                result[key].id = bp.id;
                result[key].enabled = true;
                if (bp.cmd) {
                    result[key].cmd = bp.cmd;
                }
            }
        } else {
            const key = bp.address.toString();
            result[key] = {};
            result[key].type = 'hw';
            result[key].id = bp.id;
            result[key].enabled = true;
            if (bp.cmd) {
                result[key].cmd = bp.cmd;
            }
        }
    }
    return JSON.stringify(result);
}

/**
 * Toggles a breakpoint at the specified address.
 *
 * @param args - The pointer address from the provided address string.
 * 
 * If a breakpoint does not exist at the specified address, it logs a message to the console.
 * Otherwise, it switches the state of the breakpoint.
 */
export function toggleBreakpoint(args: string[]): void {
    const address = args[0];
    const ptrAddr = getPtr(address);
    if (!breakpoints.has(ptrAddr.toString())) {
        console.log(`Breakpoint at ${ptrAddr.toString()} does not exists`);
    }
    _breakpointSwitch(breakpoints.get(ptrAddr.toString()) as BreakpointData);
}

/**
 * Generates a formatted list of breakpoints.
 *
 * @param {string[]} args - Currently unused.
 * @returns {string} A formatted string representing the list of breakpoints.
 *
 * The output format includes:
 * - Type of breakpoint (software or hardware)
 * - Address of the breakpoint
 * - Whether the breakpoint is enabled
 * - Command associated with the breakpoint
 *
 */
function _breakpointList(_: string[]) : string {
    const bps = [] as string[];
    if (breakpoints.size === 0) {
        return "No breakpoints set";
    }
    for (const [address, bp] of breakpoints.entries()) {
        if (bp instanceof SoftwareBreakpointData) {
            if (bp.patches[0].address.equals(ptr(address))) {
                bps.push(["(sw)", address, bp.enabled.toString(), bp.cmd].join(' '));
            }
        } else {
            bps.push(["(hw)", address, bp.enabled.toString(), bp.cmd].join(' '));
        }
    }
    return bps.join('\n');
}

/**
 * Sets a breakpoint at the specified address.
 *
 * @param {string[]} args - An array containing the address where the breakpoint should be set.
 * @returns {boolean} - Returns true if the breakpoint was successfully set, false otherwise.
 *
 * The function supports setting both hardware and software breakpoints based on the configuration.
 * If the address starts with "java:", it logs a message indicating that breakpoints only work on native code and returns false.
 * If a breakpoint already exists at the specified address, it switches the existing breakpoint and returns false.
 * Otherwise, it sets a new breakpoint at the specified address.
 *
 * Hardware breakpoints are set if the configuration option "dbg.hwbp" is enabled.
 * Software breakpoints are set by creating code patches at the specified address.
 */
function _breakpointSet(args: string[]) : boolean {
    const address = args[0];
    if (address.startsWith("java:")) {
        console.log("Breakpoints only work on native code");
        return false;
    }
    const ptrAddr = getPtr(address);
    if (breakpoints.has(ptrAddr.toString())) {
        console.log(`Breakpoint at ${ptrAddr.toString()} already exists`);
        return false;
    }
    const id = breakpoints.size;
    const thread = Process.enumerateThreads()[0];
    if (config.getBoolean("dbg.hwbp")) {
        const bp = new HardwareBreakpointData(id, thread, ptrAddr, "");
        bp.setBreakpoint();
        thread.setHardwareBreakpoint(bp.id, ptrAddr);
        breakpoints.set(bp.address.toString(), bp);
    } else {
        const p1 = new CodePatch(ptrAddr) as any;
        const p2 = new CodePatch(p1.insn.next);
        const bp = new SoftwareBreakpointData (id, thread, ptrAddr, "", [p1, p2]);
        breakpoints.set(p1.address.toString(), bp);
        breakpoints.set(p2.address.toString(), bp);
        p1.toggle();
    }
    return true;
}

/**
 * Toggles the enabled state of a given breakpoint.
 *
 * @param bp - The breakpoint data object to be toggled. If the breakpoint is currently enabled, it will be disabled, and vice versa.
 */
function _breakpointSwitch(bp: BreakpointData): void {
    if (!bp) {
        return;
    }
    bp.enabled? bp.disable() : bp.enable();
}

/**
 * Unsets a breakpoint at the specified address.
 *
 * @param {string[]} args - An array containing the address of the breakpoint to unset.
 * @returns {boolean} - Returns `true` if the breakpoint was successfully unset, `false` otherwise.
 *
 * If the breakpoint is a software breakpoint, it disables all patches associated with it
 * and deletes the breakpoint from the `breakpoints` map.
 *
 * If the breakpoint is a hardware breakpoint, it unsets the breakpoint and deletes it from
 * the `breakpoints` map.
 */
function _breakpointUnset(args: string[]): boolean {
    const addr = getPtr(args[0]).toString();
    const bp = breakpoints.get(addr);
    if (!bp) {
        console.log(`Breakpoint at ${addr} does not exist`);
        return false;
    }
    if (bp instanceof SoftwareBreakpointData) {
        for (const p of bp.patches) {
            p.disable();
            breakpoints.delete(p.address.toString());
        }
    } else if (bp instanceof HardwareBreakpointData) {
        bp.unsetBreakpoint();
        breakpoints.delete(bp.address.toString());
    } else {
        return false
    }
    return true;
}

/**
 * Checks if the current execution is suspended.
 *
 * @returns {boolean} `true` if the execution is suspended, otherwise `false`.
 */
export function isSuspended() : boolean {
    return suspended;
}

/**
 * Sets the suspended state of the debugger.
 *
 * @param v - A boolean value indicating whether the debugger should be suspended (true) or not (false).
 */
export function setSuspended(v: boolean): void {
    suspended = v;
}

/**
 * Generates a platform-specific Software breakpoint instruction.
 *
 *
 * @returns {ArrayBufferLike} An ArrayBuffer containing the breakpoint instruction.
 *
 * - For ARM64 architecture, it returns a 4-byte buffer with the instruction `0x60, 0x00, 0x20, 0xd4`.
 * - For other architectures, it returns a 1-byte buffer with the instruction `0xcc`.
 */
export function breakpointInstruction(): ArrayBufferLike {
    if (Process.arch === 'arm64') {
        return new Uint8Array([0x60, 0x00, 0x20, 0xd4]).buffer;
    }
    return new Uint8Array([0xcc]).buffer;
}

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
    address: NativePointer;
    _apply(data: any) {
        Memory.patchCode(this.address, data.byteLength, code => {
            code.writeByteArray(data);
        });
    }
}

class BreakpointData {
    id: number;
    address: NativePointer;
    cmd: string;
    enabled: boolean;
    thread: ThreadDetails;

    constructor(id: number, thread: ThreadDetails,address: NativePointer, cmd = "", enabled = true) {
        this.id = id;
        this.address = address;
        this.cmd = cmd;
        this.enabled = enabled;
        this.thread = thread;
    }

    enable(): void {
        console.log(`Enable Breakpoint at ${this.address.toString()}`);
        this.enabled = true;
        this.setBreakpoint();
    }

    disable(): void {
        console.log(`Disable Breakpoint at ${this.address.toString()}`);
        this.enabled = false;
        this.unsetBreakpoint();
    }

    toggle(): void {
        console.log("Not implemented");
    }

    setBreakpoint(): void {
        console.log("Not implemented");
    }

    unsetBreakpoint(): void {
        console.log("Not implemented");
    }
}

class HardwareBreakpointData extends BreakpointData {
    _applied: boolean;

    constructor(id: number, thread: ThreadDetails,address: NativePointer, cmd = "", enabled = true) {
        super(id, thread, address, cmd, enabled);
        this._applied = false;
    }

    setBreakpoint(): void {
        this.thread.setHardwareBreakpoint(this.id, this.address);
        this._applied = true;
    }

    unsetBreakpoint(): void {
        this.thread.unsetHardwareBreakpoint(this.id);
        this._applied = false;
    }

    toggle(): void {
        setTimeout(()=> {
            this._applied ? this.unsetBreakpoint() : this.setBreakpoint();
        }, 100);
    }
}

class SoftwareBreakpointData extends BreakpointData {
    patches: CodePatch[];

    constructor(id: number, thread: ThreadDetails, address: NativePointer, cmd = "", patches: CodePatch[], enabled = true) {
        super(id, thread, address, cmd, enabled);
        this.patches = patches;
    }

    setBreakpoint(): void {
        for (const p of this.patches) {
            p.enable();
        }
    }

    unsetBreakpoint(): void {
        for (const p of this.patches) {
            p.disable();
        }
    }

    toggle(): void {
        for (const p of this.patches) {
            p.toggle();
        }
    }
}
