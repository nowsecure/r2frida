export type BreakpointKind = "sw" | "hw" | "wp";
export type WatchpointCondition = "r" | "w" | "rw";
export type WatchpointAccess = WatchpointCondition;

export type WatchpointSpec = {
    address: string;
    size: number;
    condition: WatchpointCondition;
};

export type ParseWatchpointSpecResult =
    | { ok: true; spec: WatchpointSpec }
    | { ok: false; message: string };

export type BreakpointRecord = {
    type: "sw" | "hw";
    id: number;
    address: string;
    enabled: boolean;
    cmd: string;
    continueAfterHit: boolean;
    temporary: boolean;
};

export type WatchpointRecord = {
    type: "wp";
    id: number;
    address: string;
    size: number;
    condition: WatchpointCondition;
    enabled: boolean;
    cmd: string;
    continueAfterHit: boolean;
    temporary: boolean;
};

export type BreakpointHitInput = {
    kind: BreakpointKind;
    id: number;
    address: string;
    instruction: string;
    threadId: number;
    exception: string;
    cmd: string;
    globalCommand: string;
    continueAfterHit: boolean;
    includeMessage: boolean;
    hit?: string;
    size?: number;
    condition?: WatchpointCondition;
    access?: WatchpointAccess | null;
};

export type BreakpointHitStanza = {
    cmd: string;
    continue: boolean;
    kind: BreakpointKind;
    id: number;
    address: string;
    instruction: string;
    threadId: number;
    exception: string;
    hit?: string;
    size?: number;
    condition?: WatchpointCondition;
    access?: WatchpointAccess;
    message?: string;
};

export type MemoryOperand = {
    value?: {
        base?: string;
        index?: string;
        scale?: number;
        disp?: number;
    };
};

export type RegisterValues = Record<string, string | number | bigint>;

export function parseWatchpointSpec(
    args: string[],
    defaultSize: number,
): ParseWatchpointSpecResult {
    if (args.length < 2) {
        return {
            ok: false,
            message: "Usage: dbw [addr] ([size]) [r|w|rw]",
        };
    }
    const address = args[0];
    let size = defaultSize;
    let conditionArg = args[1];
    if (args.length > 2) {
        size = Number(args[1]);
        conditionArg = args[2];
    }
    if (!Number.isInteger(size) || !isWatchpointSize(size)) {
        return { ok: false, message: "Invalid size" };
    }
    const condition = normalizeWatchpointCondition(conditionArg);
    if (condition === null) {
        return { ok: false, message: "Invalid condition" };
    }
    return { ok: true, spec: { address, size, condition } };
}

export function isWatchpointSize(size: number): boolean {
    return [1, 2, 4, 8].indexOf(size) !== -1;
}

export function normalizeWatchpointCondition(
    condition: string | undefined,
): WatchpointCondition | null {
    switch (condition) {
        case "r":
        case "w":
        case "rw":
            return condition;
        case "wr":
            return "rw";
        default:
            return null;
    }
}

export function renderBreakpointR2(records: BreakpointRecord[]): string {
    const lines = [];
    for (const bp of records) {
        lines.push(`:db ${bp.address}`);
        if (!bp.enabled) {
            lines.push(`:dbd ${bp.address}`);
        }
        if (bp.cmd) {
            lines.push(`:${bp.continueAfterHit ? "dbC" : "dbc"} ` +
                `${bp.address} ${bp.cmd}`);
        }
    }
    return lines.join("\n");
}

export function renderWatchpointR2(records: WatchpointRecord[]): string {
    const lines = [];
    for (const wp of records) {
        lines.push(`:dbw ${wp.address} ${wp.size} ${wp.condition}`);
        if (!wp.enabled) {
            lines.push(`:dbwd ${wp.address}`);
        }
        if (wp.cmd) {
            lines.push(`:${wp.continueAfterHit ? "dbwC" : "dbwc"} ` +
                `${wp.address} ${wp.cmd}`);
        }
    }
    return lines.join("\n");
}

export function breakpointJsonObject(
    records: BreakpointRecord[],
): Record<string, any> {
    const result: Record<string, any> = {};
    for (const bp of records) {
        result[bp.address] = {
            type: bp.type,
            id: bp.id,
            enabled: bp.enabled,
            continue: bp.continueAfterHit,
            temporary: bp.temporary,
        };
        if (bp.cmd) {
            result[bp.address].cmd = bp.cmd;
        }
    }
    return result;
}

export function watchpointJsonObject(
    records: WatchpointRecord[],
): Record<string, any> {
    const result: Record<string, any> = {};
    for (const wp of records) {
        result[wp.address] = {
            type: "wp",
            id: wp.id,
            size: wp.size,
            condition: wp.condition,
            enabled: wp.enabled,
            continue: wp.continueAfterHit,
            temporary: wp.temporary,
        };
        if (wp.cmd) {
            result[wp.address].cmd = wp.cmd;
        }
    }
    return result;
}

export function buildBreakpointHitStanza(
    input: BreakpointHitInput,
): BreakpointHitStanza {
    const stanza: BreakpointHitStanza = {
        cmd: composeBreakpointHitCommand(input.cmd, input.globalCommand),
        continue: input.continueAfterHit,
        kind: input.kind,
        id: input.id,
        address: input.address,
        instruction: input.instruction,
        threadId: input.threadId,
        exception: input.exception,
    };
    if (input.kind === "wp") {
        stanza.hit = input.hit ?? input.address;
        stanza.size = input.size;
        stanza.condition = input.condition;
        if (input.access !== null && input.access !== undefined) {
            stanza.access = input.access;
        }
    }
    if (input.includeMessage) {
        stanza.message = breakpointHitMessage(stanza);
    }
    return stanza;
}

export function composeBreakpointHitCommand(
    breakpointCommand: string,
    globalCommand: string,
): string {
    const commands = [];
    if (breakpointCommand) {
        commands.push(breakpointCommand);
    }
    if (globalCommand) {
        commands.push(globalCommand);
    }
    return commands.join(";");
}

export function breakpointHitMessage(stanza: BreakpointHitStanza): string {
    if (stanza.kind === "wp") {
        const access = stanza.access ? ` ${stanza.access}` : "";
        return `Watchpoint ${stanza.address}${access} hit at ${stanza.hit} ` +
            `by ${stanza.instruction} thread ${stanza.threadId}`;
    }
    return `Breakpoint ${stanza.address} hit at ${stanza.instruction} ` +
        `thread ${stanza.threadId}`;
}

export function operandAccess(operand: any): WatchpointAccess | null {
    const access = operand && (operand.access || operand.value?.access);
    switch (access) {
        case "read":
        case "r":
            return "r";
        case "write":
        case "w":
            return "w";
        case "read-write":
        case "rw":
            return "rw";
        default:
            return null;
    }
}

export function memoryOperandAddress(
    operand: MemoryOperand,
    registers: RegisterValues,
): string | null {
    const value = operand.value;
    if (value === undefined) {
        return null;
    }
    let result = 0n;
    let haveRegister = false;
    if (value.base !== undefined && registers[value.base] !== undefined) {
        result += registerToBigInt(registers[value.base]);
        haveRegister = true;
    }
    if (value.index !== undefined && registers[value.index] !== undefined) {
        const index = registerToBigInt(registers[value.index]);
        const scale = typeof value.scale === "number" ? BigInt(value.scale) : 1n;
        result += index * scale;
        haveRegister = true;
    }
    if (!haveRegister) {
        return null;
    }
    const disp = typeof value.disp === "number" ? BigInt(value.disp) : 0n;
    return toHex(result + disp);
}

export function watchpointContains(
    watchpointAddress: string,
    size: number,
    address: string,
): boolean {
    const start = pointerToBigInt(watchpointAddress);
    const hit = pointerToBigInt(address);
    if (start === null || hit === null) {
        return false;
    }
    const end = start + BigInt(size);
    return hit >= start && hit < end;
}

export function pointerToBigInt(value: string): bigint | null {
    try {
        return BigInt(value);
    } catch (_) {
        return null;
    }
}

function registerToBigInt(value: string | number | bigint): bigint {
    if (typeof value === "bigint") {
        return value;
    }
    if (typeof value === "number") {
        return BigInt(value);
    }
    return BigInt(value);
}

function toHex(value: bigint): string {
    if (value < 0) {
        return `-0x${(-value).toString(16)}`;
    }
    return `0x${value.toString(16)}`;
}
