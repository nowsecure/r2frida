import config from "../../config.js";
import { getPtr } from "../utils.js";
import r2 from "../r2.js";

const breakpoints = new Map<string, BreakpointData>();
let suspended = false;
export let currentThreadContext: CpuContext | null = null;

initExceptionHandler();

/**
 * Initializes the breakpoints and watchpoints by setting up an exception handler.
 * The handler checks if the exception is caused by a breakpoint/watchpoint and handles it accordingly.
 */
export function initExceptionHandler(): void {
    Process.setExceptionHandler(({ address, context, type }) => {
        let bp = breakpoints.get(address.toString());
        let addressHit = null;
        if (!bp && isWatchpointEnabled()) {
            const inst = Instruction.parse(address);
            if ("operands" in inst) {
                for (const op of inst.operands) {
                    if (op.type === "mem" && op.value.base !== undefined) {
                        const registerHit = op.value.base as keyof CpuContext;
                        addressHit = context[registerHit].add(op.value.disp);
                        bp = breakpoints.get(addressHit.toString());
                    }
                }
            }
        }
        if (!bp) {
            return false;
        }
        let hasBreakpointHit = false;
        if (bp instanceof SoftwareBreakpointData) {
            hasBreakpointHit = bp.patches.findIndex((p: any) =>
                p.address.equals(address)
            ) === 0;
        } else if (
            bp instanceof HardwareBreakpointData || bp instanceof WatchpointData
        ) {
            hasBreakpointHit = Process.getCurrentThreadId() === bp.thread.id &&
                ["breakpoint", "single-step"].includes(type);
        } else {
            console.log("TODO: exceptionHandler: " + bp);
        }
        if (hasBreakpointHit) {
            send({ name: "breakpoint-event", stanza: { cmd: bp.cmd } });
            let state = "stopped";
            currentThreadContext = context;
            if (config.getBoolean("hook.verbose")) {
                if (bp instanceof WatchpointData && addressHit) {
                    console.log(
                        `Watchpoint at ${addressHit} hit by instruction ${address}`,
                    );
                } else {
                    console.log(`Breakpoint at ${address} hit`);
                }
            }
            do {
                const op = recv("breakpoint-action", ({ action }) => {
                    switch (action) {
                        case "register-change":
                            console.log("TODO1");
                            break;
                        case "resume":
                            state = "running";
                            currentThreadContext = null;
                            if (bp instanceof HardwareBreakpointData) {
                                bp.unsetBreakpoint();
                            }
                            if (bp instanceof WatchpointData) {
                                bp.unsetWatchpoint();
                            }
                            if (config.getBoolean("hook.verbose")) {
                                console.log("Continue thread(s).");
                            }
                            break;
                        default:
                            console.log("TODO: exceptionHandler: " + action);
                            break;
                    }
                });
                op.wait();
            } while (state === "stopped");
        }
        let afterBp = null;
        if (bp instanceof WatchpointData && addressHit) {
            afterBp = breakpoints.get(addressHit.toString());
        } else {
            afterBp = breakpoints.get(address.toString());
        }
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
export function setBreakpoint(args: string[]): void {
    if (args.length === 0) {
        console.log(_breakpointList([]));
    } else if (args[0].startsWith("-")) {
        const addr = args[0].substring(1);
        unsetBreakpoint([addr]);
    } else {
        if (_breakpointSet(args)) {
            console.log(`Breakpoint at ${args[0]} set`);
        }
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
        console.error(
            "Usage: dbc [address-of-breakpoint] [r2-command-to-run-when-hit]",
        );
        return;
    }
    const address = getPtr(args[0]);
    let bp = breakpoints.get(address.toString());
    if (
        !(bp instanceof HardwareBreakpointData) &&
        !(bp instanceof SoftwareBreakpointData)
    ) {
        if (_breakpointSet(args)) {
            console.log(`Breakpoint at ${args[0]} set`);
        }
    }
    const command = args.slice(1).join(" ");
    bp = breakpoints.get(address.toString());
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
    } else if (args[0].startsWith("-")) {
        const addr = args[0].substring(1);
        unsetBreakpoint([addr]);
    } else {
        if (_breakpointUnset(args)) {
            console.log(`Breakpoint at ${args[0]} unset`);
        }
    }
}

/**
 * Unsets all breakpoints.
 *
 * @param args - This parameter is currently not used.
 */
export function breakpointUnsetAll(_: string[]): void {
    for (const [address, bp] of breakpoints.entries()) {
        if (
            bp instanceof HardwareBreakpointData ||
            bp instanceof SoftwareBreakpointData
        ) {
            unsetBreakpoint([address]);
        }
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
        return r2.hostCmd(":dc");
    }
    return Promise.resolve("Continue thread(s).");
}

/**
 * Sets a breakpoint and continues execution until the breakpoint is hit.
 *
 * @param args - An array of strings representing the address for the breakpoint.
 */
export function setBreakpointContinueUntil(args: string[]): void {
    if (args.length === 0) {
        console.log(_breakpointList([]));
    } else if (args[0].startsWith("-")) {
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
                result[key].type = "sw";
                result[key].id = bp.id;
                result[key].enabled = true;
                if (bp.cmd) {
                    result[key].cmd = bp.cmd;
                }
            }
        } else if (bp instanceof HardwareBreakpointData) {
            const key = bp.address.toString();
            result[key] = {};
            result[key].type = "hw";
            result[key].id = bp.id;
            result[key].enabled = true;
            if (bp.cmd) {
                result[key].cmd = bp.cmd;
            }
        } else {
            continue;
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
    const bp = breakpoints.get(address.toString());
    if (
        !(bp instanceof HardwareBreakpointData) &&
        !(bp instanceof SoftwareBreakpointData)
    ) {
        console.log(`Breakpoint at ${ptrAddr.toString()} does not exists`);
        return;
    }
    _breakpointSwitch(breakpoints.get(ptrAddr.toString()) as BreakpointData);
}

/**
 * Sets  a watchpoint based on the provided arguments.
 *
 * @param {string[]} args - The address for setting a watchpoint.
 *   - If empty, lists all current watchpoints.
 *   - Otherwise, sets a watchpoint at the specified address.
 */
export function setWatchpoint(args: string[]): void {
    if (args.length === 0) {
        console.log(_watchpointList([]));
    } else if (args[0].startsWith("-")) {
        const addr = args[0].substring(1);
        unsetWatchpoint([addr]);
    } else {
        if (_watchpointSet(args)) {
            console.log(`Watchpoint at ${args[0]} set`);
        }
    }
}

/**
 * Unsets a watchpoint based on the provided arguments.
 *
 * @param {string[]} args - The address for setting a watchpoint.
 *   - If empty, lists all current watchpoints.
 *   - Otherwise, unsets a watchpoint at the specified address.
 */
export function unsetWatchpoint(args: string[]): void {
    if (args.length === 0) {
        console.log(_watchpointList([]));
    } else if (args[0].startsWith("-")) {
        const addr = args[0].substring(1);
        unsetWatchpoint([addr]);
    } else {
        if (_watchpointUnset(args)) {
            console.log(`Watchpoint at ${args[0]} unset`);
        }
    }
}

/**
 * Converts the current watchtpoints into a JSON string representation.
 *
 * @returns {string} A JSON string representation of the current watchpoints.
 */
export function watchpointJson(): string {
    const result: any = {};
    for (const [_, wp] of breakpoints.entries()) {
        if (wp instanceof WatchpointData) {
            const key = wp.address.toString();
            result[key] = {};
            result[key].type = "wp";
            result[key].id = wp.id;
            result[key].size = wp.size;
            result[key].condition = wp.condition;
            result[key].enabled = true;
            if (wp.cmd) {
                result[key].cmd = wp.cmd;
            }
        }
    }
    return JSON.stringify(result);
}

/**
 * Unsets all watchpoints.
 *
 * @param args - This parameter is currently not used.
 */
export function watchpointUnsetAll(_: string[]): void {
    for (const [address, wp] of breakpoints.entries()) {
        if (wp instanceof WatchpointData) {
            unsetWatchpoint([address]);
        }
    }
}

/**
 * Sets a watchpoint command for a given address.
 *
 * This function expects two arguments: the address of the breakpoint and the command to run when the breakpoint is hit.
 *
 * @param {string[]} args - The arguments array containing the address of the breakpoint and the command to run.
 */
export function setWatchpointCommand(args: string[]): void {
    if (args.length < 2) {
        console.error(
            "Usage: dbwc [address-of-watchpoint] [r2-command-to-run-when-hit]",
        );
        return;
    }
    const address = getPtr(args[0]);
    const wp = breakpoints.get(address.toString());
    if (!(wp instanceof WatchpointData)) {
        console.log(`Watchpoint at ${args[0]} does not exist`);
        return;
    }
    const command = args.slice(1).join(" ");
    if (wp.address.equals(address)) {
        wp.cmd = command;
    }
}

/**
 * Toggles a watchpoint at the specified address.
 *
 * @param args - The pointer address from the provided address string.
 *
 * If a watchpoint does not exist at the specified address, it logs a message to the console.
 * Otherwise, it switches the state of the watchpoint.
 */
export function toggleWatchpoint(args: string[]): void {
    const address = args[0];
    const ptrAddr = getPtr(address);
    const wp = breakpoints.get(address.toString());
    if (!(wp instanceof WatchpointData)) {
        console.log(`Watchpoint at ${ptrAddr.toString()} does not exists`);
        return;
    }
    _watchpointSwitch(breakpoints.get(ptrAddr.toString()) as WatchpointData);
}

function _watchpointsSize(): number {
    let result = 0;
    for (const [_, wp] of breakpoints.entries()) {
        if (wp instanceof WatchpointData) {
            result++;
        }
    }
    return result;
}

function _breakpointsSize(): number {
    let result = 0;
    for (const [_, wp] of breakpoints.entries()) {
        if (
            wp instanceof HardwareBreakpointData ||
            wp instanceof SoftwareBreakpointData
        ) {
            result++;
        }
    }
    return result;
}

/**
 * Sets a watchpoint on a specified memory address.
 *
 * @param {string[]} args - An array of arguments where:
 *   - args[0]: The memory address to set the watchpoint on. If the address starts with "java:", the function will return false as watchpoints only work on native code.
 *   - args[1]: The size of the watchpoint. Must be a valid integer.
 *   - args[2]: The condition for the watchpoint. Must be one of 'r' (read), 'w' (write), or 'rw' (read/write).
 * @returns {boolean} - Returns true if the watchpoint was successfully set, otherwise false.
 */
function _watchpointSet(args: string[]): boolean {
    const address = args[0];
    if (address.startsWith("java:")) {
        console.log("Watchpoints only work on native code");
        return false;
    }
    const size = parseInt(args[1], 10);
    if (isNaN(size)) {
        console.log("Invalid size");
        return false;
    }
    const condition = args[2] as HardwareWatchpointCondition;
    switch (condition) {
        case "r":
        case "w":
            break;
        default:
            console.log("Invalid condition");
            return false;
    }
    const ptrAddr = getPtr(address);
    if (breakpoints.get(address.toString()) instanceof WatchpointData) {
        console.log(`Watchpoint at ${ptrAddr.toString()} already exists`);
        return false;
    }
    const id = _watchpointsSize();
    const thread = _currentThread();
    const wp = new WatchpointData(id, thread, ptrAddr, size, condition);
    wp.setWatchpoint();
    breakpoints.set(wp.address.toString(), wp);
    return true;
}

/**
 * Unsets a watchpoint at the specified address.
 *
 * @param {string[]} args - An array containing the address of the watchpoint to unset.
 * @returns {boolean} - Returns `true` if the watchpoint was successfully unset, `false` otherwise.
 *
 * This function retrieves the address from the provided arguments, checks if a watchpoint exists at that address,
 * and if it does, unsets the watchpoint and removes it from the watchpoints map.
 */
function _watchpointUnset(args: string[]): boolean {
    const addr = getPtr(args[0]).toString();
    const wp = breakpoints.get(addr);
    if (!(wp instanceof WatchpointData)) {
        console.log(`Watchpoint at ${addr} does not exist`);
        return false;
    }
    wp.unsetWatchpoint();
    breakpoints.delete(wp.address.toString());
    return true;
}

/**
 * Generates a list of watchpoints in a formatted string.
 *
 * @returns A string representing the list of watchpoints.
 */
function _watchpointList(_: string[]): string {
    const wps = [] as string[];
    if (_watchpointsSize() === 0) {
        return "No watchpoints set";
    }
    for (const [address, wp] of breakpoints.entries()) {
        if (wp instanceof WatchpointData) {
            wps.push(
                ["(wp)", address, wp.enabled.toString(), wp.cmd].join(" "),
            );
        }
    }
    return wps.join("\n");
}

/**
 * Toggles the enabled state of a given watchpoint.
 *
 * @param wp - The watchpoint data object to be toggled.
 *             If the watchpoint is currently enabled, it will be disabled, and vice versa.
 */
function _watchpointSwitch(wp: WatchpointData): void {
    if (!wp) {
        return;
    }
    if (wp.enabled) {
        wp.disable();
    } else {
        wp.enable();
    }
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
 */
function _breakpointList(_: string[]): string {
    const bps = [] as string[];
    if (_breakpointsSize() === 0) {
        return "No breakpoints set";
    }
    for (const [address, bp] of breakpoints.entries()) {
        if (bp instanceof SoftwareBreakpointData) {
            if (bp.patches[0].address.equals(ptr(address))) {
                bps.push(
                    ["(sw)", address, bp.enabled.toString(), bp.cmd].join(" "),
                );
            }
        } else if (bp instanceof HardwareBreakpointData) {
            bps.push(
                ["(hw)", address, bp.enabled.toString(), bp.cmd].join(" "),
            );
        } else {
            continue;
        }
    }
    return bps.join("\n");
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
function _breakpointSet(args: string[]): boolean {
    const address = args[0];
    if (address.startsWith("java:")) {
        console.log("Breakpoints only work on native code");
        return false;
    }
    const ptrAddr = getPtr(address);
    if (ptrAddr.equals(ptr("0"))) {
        console.error("Invalid pointer");
        return false;
    }
    const bp = breakpoints.get(address.toString());
    if (
        (bp instanceof HardwareBreakpointData) ||
        (bp instanceof SoftwareBreakpointData)
    ) {
        console.error(`Breakpoint at ${ptrAddr.toString()} already exists`);
        return false;
    }
    const id = _breakpointsSize();
    const thread = _currentThread();
    if (config.getBoolean("dbg.hwbp")) {
        const bp = new HardwareBreakpointData(id, thread, ptrAddr, "");
        bp.setBreakpoint();
        breakpoints.set(bp.address.toString(), bp);
    } else {
        const p1 = new CodePatch(ptrAddr) as any;
        const p2 = new CodePatch(p1.insn.next);
        const bp = new SoftwareBreakpointData(id, thread, ptrAddr, "", [
            p1,
            p2,
        ]);
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
    if (bp.enabled) {
        bp.disable();
    } else {
        bp.enable();
    }
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
    if (
        !(bp instanceof HardwareBreakpointData) &&
        !(bp instanceof SoftwareBreakpointData)
    ) {
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
        return false;
    }
    return true;
}

function _currentThread(): ThreadDetails {
    const threads = Process.enumerateThreads();
    if (threads.length === 0) {
        throw new Error(
            "No threads available, you may want to resume the process. See :dc and :dpt",
        );
    }
    return threads[0];
}

function isWatchpointEnabled(): boolean {
    for (const [_, wp] of breakpoints.entries()) {
        if (wp instanceof WatchpointData && wp.enabled) {
            return true;
        }
    }
    return false;
}

/**
 * Checks if the current execution is suspended.
 *
 * @returns {boolean} `true` if the execution is suspended, otherwise `false`.
 */
export function isSuspended(): boolean {
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
 * @returns {ArrayBufferLike} An ArrayBuffer containing the breakpoint instruction.
 *
 * - For ARM64 architecture, it returns a 4-byte buffer with the instruction `0x60, 0x00, 0x20, 0xd4`.
 * - For other architectures, it returns a 1-byte buffer with the instruction `0xcc`.
 */
export function _breakpointInstruction(): ArrayBufferLike {
    if (Process.arch === "arm64") {
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
        this._newData = _breakpointInstruction();
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
        Memory.patchCode(this.address, data.byteLength, (code) => {
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

    constructor(
        id: number,
        thread: ThreadDetails,
        address: NativePointer,
        cmd = "",
        enabled = true,
    ) {
        this.id = id;
        this.address = address;
        this.cmd = cmd;
        this.enabled = enabled;
        this.thread = thread;
    }

    enable(): void {
        console.log("Not implemented");
    }

    disable(): void {
        console.log("Not implemented");
    }

    toggle(): void {
        console.log("Not implemented");
    }

    // setBreakpoint(): void {
    //     console.log("Not implemented");
    // }

    // unsetBreakpoint(): void {
    //     console.log("Not implemented");
    // }
}

class WatchpointData extends BreakpointData {
    size: number;
    condition: HardwareWatchpointCondition;
    _applied: boolean;

    constructor(
        id: number,
        thread: ThreadDetails,
        address: NativePointer,
        size: number,
        condition: HardwareWatchpointCondition,
        cmd = "",
        enabled = true,
    ) {
        super(id, thread, address, cmd, enabled);
        this.size = size;
        this.condition = condition;
        this._applied = false;
    }

    enable(): void {
        console.log(`Enable Watchpoint at ${this.address.toString()}`);
        this.enabled = true;
        this.setWatchpoint();
    }

    disable(): void {
        console.log(`Disable Watchpoint at ${this.address.toString()}`);
        this.enabled = false;
        this.unsetWatchpoint();
    }

    setWatchpoint(): void {
        this.thread.setHardwareWatchpoint(
            this.id,
            this.address,
            this.size,
            this.condition,
        );
        this._applied = true;
    }

    unsetWatchpoint(): void {
        this.thread.unsetHardwareWatchpoint(this.id);
        this._applied = false;
    }

    toggle(): void {
        setTimeout(() => {
            if (this._applied) {
                this.unsetWatchpoint();
            } else {
                this.setWatchpoint();
            }
        }, 100);
    }
}

type HardwareWatchpointCondition = "r" | "w" | "rw";

class HardwareBreakpointData extends BreakpointData {
    _applied: boolean;

    constructor(
        id: number,
        thread: ThreadDetails,
        address: NativePointer,
        cmd = "",
        enabled = true,
    ) {
        super(id, thread, address, cmd, enabled);
        this._applied = false;
    }

    enable(): void {
        console.log(`Enable Hardware Breakpoint at ${this.address.toString()}`);
        this.enabled = true;
        this.setBreakpoint();
    }

    disable(): void {
        console.log(
            `Disable Hardware Breakpoint at ${this.address.toString()}`,
        );
        this.enabled = false;
        this.unsetBreakpoint();
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
        setTimeout(() => {
            if (this._applied) {
                this.unsetBreakpoint();
            } else {
                this.setBreakpoint();
            }
        }, 100);
    }
}

class SoftwareBreakpointData extends BreakpointData {
    patches: CodePatch[];

    constructor(
        id: number,
        thread: ThreadDetails,
        address: NativePointer,
        cmd = "",
        patches: CodePatch[],
        enabled = true,
    ) {
        super(id, thread, address, cmd, enabled);
        this.patches = patches;
    }

    enable(): void {
        console.log(`Enable Software Breakpoint at ${this.address.toString()}`);
        this.enabled = true;
        this.setBreakpoint();
    }

    disable(): void {
        console.log(
            `Disable Software Breakpoint at ${this.address.toString()}`,
        );
        this.enabled = false;
        this.unsetBreakpoint();
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
