import config from "../../config.js";
import { getPtr } from "../utils.js";
import r2 from "../r2.js";
import {
    type BreakpointKind,
    type BreakpointRecord,
    type WatchpointCondition,
    type WatchpointRecord,
    type WatchpointSpec,
    breakpointJsonObject,
    buildBreakpointHitStanza,
    operandAccess,
    parseWatchpointSpec,
    renderBreakpointR2,
    renderWatchpointR2,
    watchpointJsonObject,
} from "./breakpoint-model.js";

const breakpoints = new Map<string, BreakpointData>();
let suspended = false;
export let currentThreadContext: CpuContext | null = null;

// Hardware breakpoints and watchpoints share the same physical debug
// registers, so their ids come from a single pool reclaimed on removal.
let nextHwId = 0;
const freeHwIds: number[] = [];
const _allocHwId = (): number => freeHwIds.pop() ?? nextHwId++;
const _freeHwId = (id: number): void => {
    if (id >= 0) {
        freeHwIds.push(id);
    }
};

initExceptionHandler();

/**
 * Initializes the breakpoints and watchpoints by setting up an exception handler.
 * The handler checks if the exception is caused by a breakpoint/watchpoint and handles it accordingly.
 */
export function initExceptionHandler(): void {
    Process.setExceptionHandler(({ address, context, type }) => {
        let bp = breakpoints.get(address.toString());
        let addressHit: NativePointer | null = null;
        let operandHit: any = null;
        if (!bp && isWatchpointEnabled()) {
            const inst = Instruction.parse(address);
            if ("operands" in inst) {
                for (const op of inst.operands) {
                    if (op.type === "mem") {
                        addressHit = _memoryOperandAddress(op, context);
                        if (addressHit !== null) {
                            const wp = _watchpointForAddress(addressHit);
                            if (wp !== null) {
                                bp = wp;
                                operandHit = op;
                                break;
                            }
                        }
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
            send({
                name: "breakpoint-event",
                stanza: _breakpointHitStanza(
                    bp,
                    address,
                    addressHit,
                    operandHit,
                    type,
                ),
            });
            let state = "stopped";
            currentThreadContext = context;
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
            if (bp.temporary) {
                bp.removeAfterStep = true;
            }
        }
        // sw breakpoints need the post-hit single-step to restore the patch
        if (
            bp.removeAfterStep &&
            (!hasBreakpointHit || !(bp instanceof SoftwareBreakpointData))
        ) {
            _breakpointRemove(bp);
            return true;
        }
        const afterBp = bp instanceof WatchpointData
            ? bp
            : breakpoints.get(address.toString());
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
    _setBreakpointCommand(args);
}

export function setBreakpointCommandContinue(args: string[]): void {
    _setBreakpointCommand(args, true);
}

function _setBreakpointCommand(args: string[], continueAfterHit = false): void {
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
        bp.continueAfterHit = continueAfterHit;
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
    for (const bp of _uniqueBreakpoints(_isNativeBreakpoint)) {
        _breakpointRemove(bp);
    }
}

export function breakpointEnable(args: string[]): void {
    _setBreakpointEnabled(args, true);
}

export function breakpointDisable(args: string[]): void {
    _setBreakpointEnabled(args, false);
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
export function setBreakpointContinueUntil(
    args: string[],
): Promise<string> | void {
    if (args.length === 0) {
        console.log(_breakpointList([]));
    } else if (args[0].startsWith("-")) {
        unsetBreakpoint([args[0].substring(1)]);
    } else if (_breakpointSet(args, true)) {
        return breakpointContinue([]);
    }
}

/**
 * Converts the current breakpoints into a JSON string representation.
 *
 * @returns {string} A JSON string representation of the current breakpoints.
 */
export function breakpointJson(): string {
    return JSON.stringify(breakpointJsonObject(_breakpointRecords()));
}

export function breakpointR2(_: string[]): string {
    return renderBreakpointR2(_breakpointRecords());
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
    const bp = breakpoints.get(ptrAddr.toString());
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
    return JSON.stringify(watchpointJsonObject(_watchpointRecords()));
}

export function watchpointR2(_: string[]): string {
    return renderWatchpointR2(_watchpointRecords());
}

/**
 * Unsets all watchpoints.
 *
 * @param args - This parameter is currently not used.
 */
export function watchpointUnsetAll(_: string[]): void {
    for (const wp of _uniqueBreakpoints(_isWatchpoint)) {
        _breakpointRemove(wp);
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
    _setWatchpointCommand(args);
}

export function setWatchpointCommandContinue(args: string[]): void {
    _setWatchpointCommand(args, true);
}

function _setWatchpointCommand(args: string[], continueAfterHit = false): void {
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
        wp.continueAfterHit = continueAfterHit;
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
    const wp = breakpoints.get(ptrAddr.toString());
    if (!(wp instanceof WatchpointData)) {
        console.log(`Watchpoint at ${ptrAddr.toString()} does not exists`);
        return;
    }
    _watchpointSwitch(breakpoints.get(ptrAddr.toString()) as WatchpointData);
}

export function watchpointEnable(args: string[]): void {
    _setWatchpointEnabled(args, true);
}

export function watchpointDisable(args: string[]): void {
    _setWatchpointEnabled(args, false);
}

function _watchpointsSize(): number {
    return _uniqueBreakpoints(_isWatchpoint).length;
}

function _breakpointsSize(): number {
    return _uniqueBreakpoints(_isNativeBreakpoint).length;
}

function _breakpointRecords(): BreakpointRecord[] {
    return _uniqueBreakpoints(_isNativeBreakpoint).map((bp) => ({
        type: bp instanceof HardwareBreakpointData ? "hw" : "sw",
        id: bp.id,
        address: bp.address.toString(),
        enabled: bp.enabled,
        cmd: bp.cmd,
        continueAfterHit: bp.continueAfterHit,
        temporary: bp.temporary,
    }));
}

function _watchpointRecords(): WatchpointRecord[] {
    return _uniqueBreakpoints(_isWatchpoint).map((wp) => ({
        type: "wp",
        id: wp.id,
        address: wp.address.toString(),
        size: wp.size,
        condition: wp.condition as any,
        enabled: wp.enabled,
        cmd: wp.cmd,
        continueAfterHit: wp.continueAfterHit,
        temporary: wp.temporary,
    }));
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
    const spec = _parseWatchpointSpec(args);
    if (spec === null) {
        return false;
    }
    const { address, size, condition } = spec;
    if (address.startsWith("java:")) {
        console.log("Watchpoints only work on native code");
        return false;
    }
    const ptrAddr = getPtr(address);
    if (breakpoints.get(ptrAddr.toString()) instanceof WatchpointData) {
        console.log(`Watchpoint at ${ptrAddr.toString()} already exists`);
        return false;
    }
    const id = _allocHwId();
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
    _breakpointRemove(wp);
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
    for (const wp of _uniqueBreakpoints(_isWatchpoint)) {
        wps.push(
            [
                "(wp)",
                wp.address.toString(),
                wp.size.toString(),
                wp.condition,
                wp.enabled.toString(),
                wp.cmd,
            ].join(" "),
        );
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
    for (const bp of _uniqueBreakpoints(_isNativeBreakpoint)) {
        if (bp instanceof SoftwareBreakpointData) {
            bps.push(
                ["(sw)", bp.address.toString(), bp.enabled.toString(), bp.cmd]
                    .join(" "),
            );
        } else if (bp instanceof HardwareBreakpointData) {
            bps.push(
                ["(hw)", bp.address.toString(), bp.enabled.toString(), bp.cmd]
                    .join(" "),
            );
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
function _breakpointSet(args: string[], temporary = false): boolean {
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
    const bp = breakpoints.get(ptrAddr.toString());
    if (
        (bp instanceof HardwareBreakpointData) ||
        (bp instanceof SoftwareBreakpointData)
    ) {
        console.error(`Breakpoint at ${ptrAddr.toString()} already exists`);
        return false;
    }
    const thread = _currentThread();
    if (config.getBoolean("dbg.hwbp")) {
        const bp = new HardwareBreakpointData(
            _allocHwId(),
            thread,
            ptrAddr,
            "",
            true,
            temporary,
        );
        bp.setBreakpoint();
        breakpoints.set(bp.address.toString(), bp);
    } else {
        const p1 = new CodePatch(ptrAddr) as any;
        const p2 = new CodePatch(p1.insn.next);
        const bp = new SoftwareBreakpointData(-1, thread, ptrAddr, "", [
            p1,
            p2,
        ], true, temporary);
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
    _breakpointRemove(bp);
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
    for (const wp of _uniqueBreakpoints(_isWatchpoint)) {
        if (wp.enabled) {
            return true;
        }
    }
    return false;
}

function _setBreakpointEnabled(args: string[], enabled: boolean): void {
    if (args.length === 0) {
        console.error(`Usage: db${enabled ? "e" : "d"} [addr]`);
        return;
    }
    const addr = getPtr(args[0]).toString();
    const bp = breakpoints.get(addr);
    if (
        !(bp instanceof HardwareBreakpointData) &&
        !(bp instanceof SoftwareBreakpointData)
    ) {
        console.log(`Breakpoint at ${addr} does not exist`);
        return;
    }
    _setBreakpointDataEnabled(bp, enabled);
}

function _setWatchpointEnabled(args: string[], enabled: boolean): void {
    if (args.length === 0) {
        console.error(`Usage: dbw${enabled ? "e" : "d"} [addr]`);
        return;
    }
    const addr = getPtr(args[0]).toString();
    const wp = breakpoints.get(addr);
    if (!(wp instanceof WatchpointData)) {
        console.log(`Watchpoint at ${addr} does not exist`);
        return;
    }
    _setBreakpointDataEnabled(wp, enabled);
}

function _setBreakpointDataEnabled(
    bp: BreakpointData,
    enabled: boolean,
): void {
    if (bp.enabled === enabled) {
        return;
    }
    if (enabled) {
        bp.enable();
    } else {
        bp.disable();
    }
}

function _parseWatchpointSpec(args: string[]): WatchpointSpec | null {
    const parsed = parseWatchpointSpec(
        args,
        Number(config.getNumber("dbg.wpsize")),
    );
    if (!parsed.ok) {
        console.log(parsed.message);
        return null;
    }
    return parsed.spec;
}

function _isNativeBreakpoint(
    bp: BreakpointData,
): bp is HardwareBreakpointData | SoftwareBreakpointData {
    return bp instanceof HardwareBreakpointData ||
        bp instanceof SoftwareBreakpointData;
}

function _isWatchpoint(bp: BreakpointData): bp is WatchpointData {
    return bp instanceof WatchpointData;
}

function _watchpointForAddress(address: NativePointer): WatchpointData | null {
    for (const wp of _uniqueBreakpoints(_isWatchpoint)) {
        if (!wp.enabled) {
            continue;
        }
        const start = wp.address;
        const end = wp.address.add(wp.size);
        if (address.compare(start) >= 0 && address.compare(end) < 0) {
            return wp;
        }
    }
    return null;
}

function _memoryOperandAddress(
    operand: any,
    context: any,
): NativePointer | null {
    const v = operand.value;
    let result = 0n;
    let haveRegister = false;
    if (v?.base !== undefined && context[v.base] !== undefined) {
        result += BigInt(context[v.base].toString());
        haveRegister = true;
    }
    if (v?.index !== undefined && context[v.index] !== undefined) {
        result += BigInt(context[v.index].toString()) * BigInt(v.scale ?? 1);
        haveRegister = true;
    }
    if (!haveRegister) {
        return null;
    }
    return ptr("0x" + (result + BigInt(v.disp ?? 0)).toString(16));
}

function _breakpointHitStanza(
    bp: BreakpointData,
    instruction: NativePointer,
    hitAddress: NativePointer | null,
    operand: any,
    exceptionType: string,
): any {
    return buildBreakpointHitStanza({
        cmd: bp.cmd,
        globalCommand: config.getString("cmd.bps"),
        continueAfterHit: bp.continueAfterHit,
        kind: _breakpointKind(bp),
        id: bp.id,
        address: bp.address.toString(),
        instruction: instruction.toString(),
        threadId: Process.getCurrentThreadId(),
        exception: exceptionType,
        includeMessage: config.getBoolean("cmd.hitinfo") ||
            config.getBoolean("hook.verbose"),
        hit: hitAddress !== null ? hitAddress.toString() : undefined,
        size: bp instanceof WatchpointData ? bp.size : undefined,
        condition: bp instanceof WatchpointData
            ? bp.condition as any
            : undefined,
        access: operandAccess(operand),
    });
}

function _breakpointKind(bp: BreakpointData): BreakpointKind {
    if (bp instanceof WatchpointData) {
        return "wp";
    }
    if (bp instanceof HardwareBreakpointData) {
        return "hw";
    }
    return "sw";
}

function _uniqueBreakpoints<T extends BreakpointData>(
    predicate: (bp: BreakpointData) => bp is T,
): T[] {
    const seen = new Set<BreakpointData>();
    const result: T[] = [];
    for (const bp of breakpoints.values()) {
        if (seen.has(bp) || !predicate(bp)) {
            continue;
        }
        seen.add(bp);
        result.push(bp);
    }
    return result;
}

function _breakpointRemove(bp: BreakpointData): void {
    if (bp instanceof SoftwareBreakpointData) {
        for (const p of bp.patches) {
            p.disable();
            breakpoints.delete(p.address.toString());
        }
        return;
    }
    if (bp instanceof HardwareBreakpointData && bp._applied) {
        bp.unsetBreakpoint();
    } else if (bp instanceof WatchpointData && bp._applied) {
        bp.unsetWatchpoint();
    }
    breakpoints.delete(bp.address.toString());
    _freeHwId(bp.id);
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
    temporary: boolean;
    removeAfterStep: boolean;
    continueAfterHit: boolean;

    constructor(
        id: number,
        thread: ThreadDetails,
        address: NativePointer,
        cmd = "",
        enabled = true,
        temporary = false,
        continueAfterHit = false,
    ) {
        this.id = id;
        this.address = address;
        this.cmd = cmd;
        this.enabled = enabled;
        this.thread = thread;
        this.temporary = temporary;
        this.removeAfterStep = false;
        this.continueAfterHit = continueAfterHit;
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
    condition: WatchpointCondition;
    _applied: boolean;

    constructor(
        id: number,
        thread: ThreadDetails,
        address: NativePointer,
        size: number,
        condition: WatchpointCondition,
        cmd = "",
        enabled = true,
        temporary = false,
        continueAfterHit = false,
    ) {
        super(id, thread, address, cmd, enabled, temporary, continueAfterHit);
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

class HardwareBreakpointData extends BreakpointData {
    _applied: boolean;

    constructor(
        id: number,
        thread: ThreadDetails,
        address: NativePointer,
        cmd = "",
        enabled = true,
        temporary = false,
        continueAfterHit = false,
    ) {
        super(id, thread, address, cmd, enabled, temporary, continueAfterHit);
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
        temporary = false,
        continueAfterHit = false,
    ) {
        super(id, thread, address, cmd, enabled, temporary, continueAfterHit);
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
