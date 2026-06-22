import config from "../../config.js";
import { getPtr } from "../utils.js";
import r2 from "../r2.js";
import {
    breakpointJsonObject,
    parseWatchpointSpec,
    renderBreakpointR2,
    renderWatchpointR2,
    type WatchpointCondition,
    watchpointJsonObject,
    type WatchpointSpec,
} from "./breakpoint-model.js";

// One map holds every breakpoint kind (sw/hw/wp). Software breakpoints are
// registered under both of their patch addresses, hardware ones and watchpoints
// under their single address.
const breakpoints = new Map<string, Breakpoint>();
let suspended = false;
const stoppedContexts = new Map<number, CpuContext>();
export let currentThreadContext: CpuContext | null = null;

function _refreshCurrentThreadContext(): void {
    let last: CpuContext | null = null;
    for (const ctx of stoppedContexts.values()) {
        last = ctx;
    }
    currentThreadContext = last;
}

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

function _isX86(): boolean {
    return Process.arch === "ia32" || Process.arch === "x64";
}

type BpHit = { address: NativePointer; bp: Breakpoint };

// x86 reports INT3 traps one byte past the applied 0xcc patch; rewind onto it.
function _x86SoftwareBreakpointHit(
    address: NativePointer,
    context: CpuContext,
    type: string,
    bp: Breakpoint | undefined,
): BpHit | null {
    if (!_isX86() || type !== "breakpoint" || (bp && bp.kind !== "sw")) {
        return null;
    }
    const hitAddress = address.sub(1);
    const candidate = breakpoints.get(hitAddress.toString());
    if (!candidate || candidate.kind !== "sw") {
        return null;
    }
    const patch = candidate.patches.find((p) => p.address.equals(hitAddress));
    if (!patch?._applied) {
        return null;
    }
    context.pc = hitAddress;
    return { address: hitAddress, bp: candidate };
}

initExceptionHandler();

export function initExceptionHandler(): void {
    Process.setExceptionHandler(({ address, context, type }) => {
        let hitAddress = address;
        let bp = breakpoints.get(hitAddress.toString());
        const x86Hit = _x86SoftwareBreakpointHit(address, context, type, bp);
        if (x86Hit !== null) {
            hitAddress = x86Hit.address;
            bp = x86Hit.bp;
        }
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
        if (bp.kind === "sw") {
            hasBreakpointHit =
                bp.patches.findIndex((p) => p.address.equals(hitAddress)) === 0;
        } else {
            hasBreakpointHit = bp.appliesToThread(Process.getCurrentThreadId()) &&
                ["breakpoint", "single-step"].includes(type);
        }
        if (hasBreakpointHit) {
            send({
                name: "breakpoint-event",
                stanza: _breakpointHitStanza(
                    bp,
                    hitAddress,
                    addressHit,
                    operandHit,
                    type,
                ),
            });
            let state = "stopped";
            const stoppedTid = Process.getCurrentThreadId();
            stoppedContexts.set(stoppedTid, context);
            currentThreadContext = context;
            do {
                const op = recv("breakpoint-action-" + stoppedTid, ({ action }) => {
                    switch (action) {
                        case "register-change":
                            console.log("TODO1");
                            break;
                        case "resume":
                            state = "running";
                            stoppedContexts.delete(stoppedTid);
                            _refreshCurrentThreadContext();
                            if (bp.kind !== "sw") {
                                bp.unsetBreakpoint();
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
        if (bp.removeAfterStep && (!hasBreakpointHit || bp.kind !== "sw")) {
            _breakpointRemove(bp);
            return true;
        }
        const afterBp = bp.kind === "wp"
            ? bp
            : breakpoints.get(hitAddress.toString());
        if (afterBp) {
            afterBp.toggle();
        }
        return true;
    });
}

// === command surface ========================================================
// db / dbw and friends are thin wrappers over the shared helpers below.

export function setBreakpoint(args: string[]): string | void {
    return _listSetOrUnset(args, "bp");
}

export function setWatchpoint(args: string[]): string | void {
    return _listSetOrUnset(args, "wp");
}

export function unsetBreakpoint(args: string[]): string | void {
    return _listSetOrUnset(["-" + (args[0] ?? "")], "bp");
}

export function unsetWatchpoint(args: string[]): string | void {
    return _listSetOrUnset(["-" + (args[0] ?? "")], "wp");
}

export function setBreakpointCommand(args: string[]): string | void {
    return _setCommand(args, "bp", false);
}

export function setBreakpointCommandContinue(args: string[]): string | void {
    return _setCommand(args, "bp", true);
}

export function setWatchpointCommand(args: string[]): string | void {
    return _setCommand(args, "wp", false);
}

export function setWatchpointCommandContinue(args: string[]): string | void {
    return _setCommand(args, "wp", true);
}

export function breakpointEnable(args: string[]): string | void {
    return _setEnabled(args, "bp", true);
}

export function breakpointDisable(args: string[]): string | void {
    return _setEnabled(args, "bp", false);
}

export function watchpointEnable(args: string[]): string | void {
    return _setEnabled(args, "wp", true);
}

export function watchpointDisable(args: string[]): string | void {
    return _setEnabled(args, "wp", false);
}

export function toggleBreakpoint(args: string[]): string | void {
    return _toggleEnabled(args, "bp");
}

export function toggleWatchpoint(args: string[]): string | void {
    return _toggleEnabled(args, "wp");
}

export function breakpointUnsetAll(_: string[]): void {
    for (const bp of _unique(_isNativeBreakpoint)) {
        _breakpointRemove(bp);
    }
}

export function watchpointUnsetAll(_: string[]): void {
    for (const wp of _unique(_isWatchpoint)) {
        _breakpointRemove(wp);
    }
}

export function breakpointJson(): string {
    return JSON.stringify(breakpointJsonObject(_unique(_isNativeBreakpoint)));
}

export function watchpointJson(): string {
    return JSON.stringify(watchpointJsonObject(_unique(_isWatchpoint)));
}

export function breakpointR2(_: string[]): string {
    return renderBreakpointR2(_unique(_isNativeBreakpoint));
}

export function watchpointR2(_: string[]): string {
    return renderWatchpointR2(_unique(_isWatchpoint));
}

/**
 * Continues execution of the program if it is currently suspended.
 */
export function breakpointContinue(_args: string[]): Promise<string> {
    if (suspended) {
        suspended = false;
        return r2.hostCmd(":dc");
    }
    return Promise.resolve("Continue thread(s).");
}

/**
 * Sets a temporary breakpoint and continues execution until it is hit.
 */
export function setBreakpointContinueUntil(
    args: string[],
): Promise<string> | string | void {
    if (args.length === 0) {
        return _breakpointList();
    } else if (args[0].startsWith("-")) {
        return unsetBreakpoint([args[0].substring(1)]);
    }
    const result = _breakpointSet(args, true, !suspended);
    if (result === true) {
        return breakpointContinue([]);
    }
    if (typeof result === "string") {
        return result;
    }
}

export function isSuspended(): boolean {
    return suspended;
}

export function setSuspended(v: boolean): void {
    suspended = v;
}

// === shared command helpers =================================================

type BpClass = "bp" | "wp";

function _lookup(args: string[], cls: BpClass): Breakpoint | string {
    const addr = getPtr(args[0]).toString();
    const bp = breakpoints.get(addr);
    return bp && (cls === "wp" ? bp.kind === "wp" : bp.kind !== "wp")
        ? bp
        : `${cls === "wp" ? "Watchpoint" : "Breakpoint"} at ${addr} does not exist`;
}

function _listSetOrUnset(args: string[], cls: BpClass): string | void {
    const isWp = cls === "wp";
    const noun = isWp ? "Watchpoint" : "Breakpoint";
    if (args.length === 0) {
        return isWp ? _watchpointList() : _breakpointList();
    }
    if (args[0].startsWith("-")) {
        const result = _breakpointUnset(args[0].substring(1), cls);
        return result === true ? `${noun} at ${args[0].substring(1)} unset` : result;
    }
    const result = isWp ? _watchpointSet(args) : _breakpointSet(args);
    return result === true ? `${noun} at ${args[0]} set` : (result || undefined);
}

function _setCommand(
    args: string[],
    cls: BpClass,
    continueAfterHit: boolean,
): string | void {
    const isWp = cls === "wp";
    if (args.length < 2) {
        return isWp
            ? "Usage: dbwc [address-of-watchpoint] [r2-command-to-run-when-hit]"
            : "Usage: dbc [address-of-breakpoint] [r2-command-to-run-when-hit]";
    }
    const address = getPtr(args[0]);
    let bp = breakpoints.get(address.toString());
    let message: string | undefined;
    if (isWp) {
        if (!bp || bp.kind !== "wp") {
            return `Watchpoint at ${args[0]} does not exist`;
        }
    } else if (!bp || bp.kind === "wp") {
        const result = _breakpointSet(args);
        if (result === true) {
            message = `Breakpoint at ${args[0]} set`;
        } else if (typeof result === "string") {
            return result;
        }
        bp = breakpoints.get(address.toString());
    }
    if (bp && bp.address.equals(address)) {
        bp.cmd = args.slice(1).join(" ");
        bp.continueAfterHit = continueAfterHit;
    }
    return message;
}

function _setEnabled(
    args: string[],
    cls: BpClass,
    enabled: boolean,
): string | void {
    const isWp = cls === "wp";
    if (args.length === 0) {
        const verb = enabled ? "e" : "d";
        return isWp ? `Usage: dbw${verb} [addr]` : `Usage: db${verb} [addr]`;
    }
    const bp = _lookup(args, cls);
    if (typeof bp !== "string" && bp.enabled !== enabled) {
        return enabled ? bp.enable() : bp.disable();
    }
    return typeof bp === "string" ? bp : undefined;
}

function _toggleEnabled(args: string[], cls: BpClass): string | void {
    const bp = _lookup(args, cls);
    return typeof bp === "string" ? bp : bp.enabled ? bp.disable() : bp.enable();
}

// === internal breakpoint/watchpoint logic ===================================

function _breakpointList(): string {
    const bps = _unique(_isNativeBreakpoint).map((bp) =>
        [`(${bp.kind})`, bp.address.toString(), bp.enabled.toString(), bp.cmd]
            .join(" ")
    );
    return bps.length ? bps.join("\n") : "No breakpoints set";
}

function _watchpointList(): string {
    const wps = _unique(_isWatchpoint).map((wp) =>
        [
            "(wp)",
            wp.address.toString(),
            wp.size.toString(),
            wp.condition,
            wp.enabled.toString(),
            wp.cmd,
        ].join(" ")
    );
    return wps.length ? wps.join("\n") : "No watchpoints set";
}

function _breakpointSet(
    args: string[],
    temporary = false,
    continueAfterHit = false,
): true | string {
    const address = args[0];
    if (address.startsWith("java:")) {
        return "Breakpoints only work on native code";
    }
    const ptrAddr = getPtr(address);
    if (ptrAddr.equals(ptr("0"))) {
        return "Invalid pointer";
    }
    const existing = breakpoints.get(ptrAddr.toString());
    if (existing && existing.kind !== "wp") {
        return `Breakpoint at ${ptrAddr.toString()} already exists`;
    }
    const threads = _targetThreads();
    if (config.getBoolean("dbg.hwbp")) {
        const bp = new Breakpoint("hw", _allocHwId(), threads, ptrAddr, {
            temporary,
            continueAfterHit,
        });
        bp.setBreakpoint();
        breakpoints.set(bp.address.toString(), bp);
        return true;
    }
    const p1 = new CodePatch(ptrAddr);
    const p2 = new CodePatch((p1.insn as any).next);
    // refuse to patch a location already occupied by another sw breakpoint's
    // patch, which would capture a live 0xcc as its "original" bytes
    if (breakpoints.has(p2.address.toString())) {
        return `Breakpoint at ${p2.address.toString()} already exists`;
    }
    const bp = new Breakpoint("sw", -1, threads, ptrAddr, {
        temporary,
        continueAfterHit,
        patches: [p1, p2],
    });
    breakpoints.set(p1.address.toString(), bp);
    breakpoints.set(p2.address.toString(), bp);
    p1.toggle();
    return true;
}

function _watchpointSet(args: string[]): true | string {
    if (args[0]?.startsWith("java:")) {
        return "Watchpoints only work on native code";
    }
    const spec = _parseWatchpointSpec(args);
    if (typeof spec === "string") {
        return spec;
    }
    const { address, size, condition } = spec;
    const ptrAddr = getPtr(address);
    if (breakpoints.get(ptrAddr.toString())?.kind === "wp") {
        return `Watchpoint at ${ptrAddr.toString()} already exists`;
    }
    const wp = new Breakpoint("wp", _allocHwId(), _targetThreads(), ptrAddr, {
        size,
        condition,
    });
    wp.setBreakpoint();
    breakpoints.set(wp.address.toString(), wp);
    return true;
}

function _breakpointUnset(addrArg: string, cls: BpClass): true | string {
    const bp = _lookup([addrArg], cls);
    if (typeof bp === "string") {
        return bp;
    }
    _breakpointRemove(bp);
    return true;
}

// The thread(s) a hardware breakpoint/watchpoint is armed on. Defaults to every
// thread so a breakpoint fires regardless of which thread runs the code; set
// dbg.bpthread to a thread id to scope it to a single thread.
function _targetThreads(): ThreadDetails[] {
    const threads = Process.enumerateThreads();
    if (threads.length === 0) {
        throw new Error(
            "No threads available, you may want to resume the process. See :dc and :dpt",
        );
    }
    const tid = config.getNumber("dbg.bpthread");
    if (tid > 0) {
        const only = threads.find((t) => t.id === tid);
        if (only) {
            return [only];
        }
    }
    return threads;
}

function isWatchpointEnabled(): boolean {
    return _unique(_isWatchpoint).some((wp) => wp.enabled);
}

function _parseWatchpointSpec(args: string[]): WatchpointSpec | string {
    const parsed = parseWatchpointSpec(
        args,
        config.getNumber("dbg.wpsize"),
    );
    return parsed.ok ? parsed.spec : parsed.message;
}

function _isNativeBreakpoint(bp: Breakpoint): boolean {
    return bp.kind === "sw" || bp.kind === "hw";
}

function _isWatchpoint(bp: Breakpoint): boolean {
    return bp.kind === "wp";
}

function _watchpointForAddress(address: NativePointer): Breakpoint | null {
    for (const wp of _unique(_isWatchpoint)) {
        if (!wp.enabled) {
            continue;
        }
        const end = wp.address.add(wp.size);
        if (address.compare(wp.address) >= 0 && address.compare(end) < 0) {
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
    bp: Breakpoint,
    instruction: NativePointer,
    hitAddress: NativePointer | null,
    operand: any,
    exceptionType: string,
): any {
    const address = bp.address.toString();
    const instructionAddress = instruction.toString();
    const threadId = Process.getCurrentThreadId();
    const stanza: any = {
        cmd: [bp.cmd, config.getString("cmd.bps")].filter(Boolean).join(";"),
        continue: bp.continueAfterHit,
        kind: bp.kind,
        id: bp.id,
        address,
        instruction: instructionAddress,
        threadId,
        exception: exceptionType,
    };
    if (bp.kind === "wp") {
        stanza.hit = hitAddress !== null ? hitAddress.toString() : address;
        stanza.size = bp.size;
        stanza.condition = bp.condition;
        const access = operand && (operand.access || operand.value?.access);
        if (["r", "w", "rw"].indexOf(access) !== -1) {
            stanza.access = access;
        }
    }
    if (config.getBoolean("cmd.hitinfo") || config.getBoolean("hook.verbose")) {
        if (bp.kind === "wp") {
            const access = stanza.access ? ` ${stanza.access}` : "";
            stanza.message = `Watchpoint ${address}${access} hit at ${stanza.hit} ` +
                `by ${instructionAddress} thread ${threadId}`;
        } else {
            stanza.message = `Breakpoint ${address} hit at ${instructionAddress} ` +
                `thread ${threadId}`;
        }
    }
    return stanza;
}

function _unique(predicate: (bp: Breakpoint) => boolean): Breakpoint[] {
    const seen = new Set<Breakpoint>();
    const result: Breakpoint[] = [];
    for (const bp of breakpoints.values()) {
        if (seen.has(bp) || !predicate(bp)) {
            continue;
        }
        seen.add(bp);
        result.push(bp);
    }
    return result;
}

function _breakpointRemove(bp: Breakpoint): void {
    if (bp.kind === "sw") {
        for (const p of bp.patches) {
            p.disable();
            breakpoints.delete(p.address.toString());
        }
        return;
    }
    if (bp.applied) {
        bp.unsetBreakpoint();
    }
    breakpoints.delete(bp.address.toString());
    _freeHwId(bp.id);
}

/**
 * Platform-specific software breakpoint instruction (BRK on arm64, INT3 else).
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
    address: NativePointer;
    constructor(address: NativePointer) {
        const insn = Instruction.parse(address);
        this.address = address;
        this.insn = insn;
        this._newData = _breakpointInstruction();
        this._originalData = address.readByteArray(insn.size);
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

    _apply(data: any) {
        Memory.patchCode(this.address, data.byteLength, (code) => {
            code.writeByteArray(data);
        });
    }
}

type BpKind = "sw" | "hw" | "wp";

// Unified breakpoint/watchpoint. Software ones are backed by two CodePatches
// (the breakpoint + its step-over trampoline); hardware ones and watchpoints
// are backed by per-thread debug registers (id is the register slot).
class Breakpoint {
    kind: BpKind;
    id: number;
    address: NativePointer;
    threads: ThreadDetails[];
    cmd: string;
    enabled: boolean;
    temporary: boolean;
    removeAfterStep: boolean;
    continueAfterHit: boolean;
    applied: boolean;
    patches: CodePatch[];
    size: number;
    condition: WatchpointCondition;

    constructor(
        kind: BpKind,
        id: number,
        threads: ThreadDetails[],
        address: NativePointer,
        opts: {
            cmd?: string;
            enabled?: boolean;
            temporary?: boolean;
            continueAfterHit?: boolean;
            patches?: CodePatch[];
            size?: number;
            condition?: WatchpointCondition;
        } = {},
    ) {
        this.kind = kind;
        this.id = id;
        this.threads = threads;
        this.address = address;
        this.cmd = opts.cmd ?? "";
        this.enabled = opts.enabled ?? true;
        this.temporary = opts.temporary ?? false;
        this.removeAfterStep = false;
        this.continueAfterHit = opts.continueAfterHit ?? false;
        this.applied = false;
        this.patches = opts.patches ?? [];
        this.size = opts.size ?? 0;
        this.condition = opts.condition ?? "rw";
    }

    get _label(): string {
        switch (this.kind) {
            case "wp":
                return "Watchpoint";
            case "hw":
                return "Hardware Breakpoint";
            default:
                return "Software Breakpoint";
        }
    }

    appliesToThread(tid: number): boolean {
        return this.threads.some((t) => t.id === tid);
    }

    setBreakpoint(): void {
        if (this.kind === "sw") {
            for (const p of this.patches) {
                p.enable();
            }
            return;
        }
        for (const t of this.threads) {
            if (this.kind === "wp") {
                t.setHardwareWatchpoint(
                    this.id,
                    this.address,
                    this.size,
                    this.condition,
                );
            } else {
                t.setHardwareBreakpoint(this.id, this.address);
            }
        }
        this.applied = true;
    }

    unsetBreakpoint(): void {
        if (this.kind === "sw") {
            for (const p of this.patches) {
                p.disable();
            }
            return;
        }
        for (const t of this.threads) {
            if (this.kind === "wp") {
                t.unsetHardwareWatchpoint(this.id);
            } else {
                t.unsetHardwareBreakpoint(this.id);
            }
        }
        this.applied = false;
    }

    enable(): string {
        this.enabled = true;
        this.setBreakpoint();
        return `Enable ${this._label} at ${this.address.toString()}`;
    }

    disable(): string {
        this.enabled = false;
        this.unsetBreakpoint();
        return `Disable ${this._label} at ${this.address.toString()}`;
    }

    toggle(): void {
        if (this.kind === "sw") {
            for (const p of this.patches) {
                p.toggle();
            }
            return;
        }
        // Defer re-arming the debug register so execution can step past the
        // faulting instruction first; bail if the bp was removed meanwhile so a
        // freed register id is never reprogrammed.
        const self = this;
        setTimeout(() => {
            if (breakpoints.get(self.address.toString()) !== self) {
                return;
            }
            if (self.applied) {
                self.unsetBreakpoint();
            } else {
                self.setBreakpoint();
            }
        }, 100);
    }
}
