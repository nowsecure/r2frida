export type WatchpointCondition = "r" | "w" | "rw";

export type WatchpointSpec = {
    address: string;
    size: number;
    condition: WatchpointCondition;
};

export type ParseWatchpointSpecResult =
    | { ok: true; spec: WatchpointSpec }
    | { ok: false; message: string };

export type BreakpointView = {
    kind: "sw" | "hw" | "wp";
    id: number;
    address: { toString(): string };
    enabled: boolean;
    cmd: string;
    continueAfterHit: boolean;
    temporary: boolean;
    size: number;
    condition: WatchpointCondition;
};

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
    if (!Number.isInteger(size) || [1, 2, 4, 8].indexOf(size) === -1) {
        return { ok: false, message: "Invalid size" };
    }
    const condition = normalizeWatchpointCondition(conditionArg);
    if (condition === null) {
        return { ok: false, message: "Invalid condition" };
    }
    return { ok: true, spec: { address, size, condition } };
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

export function renderBreakpointR2(bps: BreakpointView[]): string {
    const lines = [];
    for (const bp of bps) {
        // set dbg.hwbp so replay recreates the same sw/hw breakpoint type
        lines.push(`:e dbg.hwbp=${bp.kind === "hw"}`, `:db ${bp.address}`);
        if (!bp.enabled) {
            lines.push(`:dbd ${bp.address}`);
        }
        if (bp.cmd) {
            lines.push(
                `:${bp.continueAfterHit ? "dbC" : "dbc"} ` +
                    `${bp.address} ${bp.cmd}`,
            );
        }
    }
    return lines.join("\n");
}

export function renderWatchpointR2(wps: BreakpointView[]): string {
    const lines = [];
    for (const wp of wps) {
        lines.push(`:dbw ${wp.address} ${wp.size} ${wp.condition}`);
        if (!wp.enabled) {
            lines.push(`:dbwd ${wp.address}`);
        }
        if (wp.cmd) {
            lines.push(
                `:${wp.continueAfterHit ? "dbwC" : "dbwc"} ` +
                    `${wp.address} ${wp.cmd}`,
            );
        }
    }
    return lines.join("\n");
}

export function breakpointJsonObject(
    bps: BreakpointView[],
): Record<string, any> {
    const result: Record<string, any> = {};
    for (const bp of bps) {
        result[bp.address.toString()] = {
            type: bp.kind === "hw" ? "hw" : "sw",
            id: bp.id,
            enabled: bp.enabled,
            continue: bp.continueAfterHit,
            temporary: bp.temporary,
            ...(bp.cmd ? { cmd: bp.cmd } : {}),
        };
    }
    return result;
}

export function watchpointJsonObject(
    wps: BreakpointView[],
): Record<string, any> {
    const result: Record<string, any> = {};
    for (const wp of wps) {
        result[wp.address.toString()] = {
            type: "wp",
            id: wp.id,
            size: wp.size,
            condition: wp.condition,
            enabled: wp.enabled,
            continue: wp.continueAfterHit,
            temporary: wp.temporary,
            ...(wp.cmd ? { cmd: wp.cmd } : {}),
        };
    }
    return result;
}

export function operandAccess(operand: any): WatchpointCondition | null {
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
