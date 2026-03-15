import config, { getSystraceCfgGen } from "./config.js";
import log from "./log.js";

const systracePending = new Set<string>();
const systraceEnterState = new Map<string, { name: string; args: string[] }>();
let seenSystraceCfgGen = -1;
let systraceFilterValue = "";
let systraceFilterMatcher: RegExp | string = "";

const systraceBufferArgNames = ["buf", "ubuf", "buffer"];
const systraceBufferLengthArgNames = [
    "count",
    "len",
    "size",
    "nbytes",
    "buflen",
    "length",
];
const systraceBufferPreviewMax = 256;

function getSystraceKey(params: any): string {
    return `${params.pid}:${params.tid}`;
}

function parseSystraceArgs(values: string[]): Map<string, string> {
    const parsed = new Map<string, string>();
    for (const value of values) {
        const eq = value.indexOf("=");
        if (eq === -1) {
            continue;
        }
        parsed.set(value.slice(0, eq), value.slice(eq + 1));
    }
    return parsed;
}

function parseSystraceInteger(value: string | undefined): number | null {
    if (value === undefined || value.length === 0 || value === "NULL") {
        return null;
    }
    const radix = value.startsWith("0x") ? 16 : 10;
    const parsed = Number.parseInt(value, radix);
    return Number.isFinite(parsed) ? parsed : null;
}

function isSystraceWriteLike(name: string): boolean {
    return name.startsWith("write") || name.startsWith("send");
}

function isSystraceReadLike(name: string): boolean {
    return name.startsWith("read") || name.startsWith("recv");
}

function formatSystraceBufferValue(
    pointerText: string,
    size: number,
): string | null {
    if (size <= 0 || pointerText === "NULL") {
        return null;
    }
    const previewSize = Math.min(size, systraceBufferPreviewMax);
    try {
        const data = ptr(pointerText).readByteArray(previewSize);
        if (data === null) {
            return null;
        }
        const bytes = new Uint8Array(data);
        const suffix = size > previewSize ? `...(${size} bytes)` : "";
        return `${pointerText} ${
            JSON.stringify(new TextDecoder().decode(bytes))
        }${suffix}`;
    } catch (_error) {
        return null;
    }
}

function findSystraceBufferArg(
    parsed: Map<string, string>,
): [string, string] | null {
    for (const name of systraceBufferArgNames) {
        const value = parsed.get(name);
        if (value !== undefined && value.startsWith("0x")) {
            return [name, value];
        }
    }
    return null;
}

function findSystraceBufferLength(parsed: Map<string, string>): number | null {
    for (const name of systraceBufferLengthArgNames) {
        const value = parseSystraceInteger(parsed.get(name));
        if (value !== null) {
            return value;
        }
    }
    return null;
}

function renderSystraceEnterArgs(name: string, values: string[]): string[] {
    if (!isSystraceWriteLike(name)) {
        return values;
    }
    const parsed = parseSystraceArgs(values);
    const bufferArg = findSystraceBufferArg(parsed);
    if (bufferArg === null) {
        return values;
    }
    const bufferLength = findSystraceBufferLength(parsed);
    if (bufferLength === null || bufferLength <= 0) {
        return values;
    }
    const [bufferName, pointerText] = bufferArg;
    const rendered = formatSystraceBufferValue(pointerText, bufferLength);
    if (rendered === null) {
        return values;
    }
    return values.map((value) =>
        value.startsWith(`${bufferName}=`) ? `${bufferName}=${rendered}` : value
    );
}

function renderSystraceExitArgs(
    name: string,
    enterArgs: string[],
    values: string[],
    retval: string,
): string[] {
    if (!isSystraceReadLike(name)) {
        return values;
    }
    const parsed = parseSystraceArgs(enterArgs);
    const bufferArg = findSystraceBufferArg(parsed);
    if (bufferArg === null) {
        return values;
    }
    const requestedLength = findSystraceBufferLength(parsed);
    const actualLength = parseSystraceInteger(retval);
    if (actualLength === null || actualLength <= 0) {
        return values;
    }
    const [bufferName, pointerText] = bufferArg;
    const previewLength = (requestedLength !== null)
        ? Math.min(requestedLength, actualLength)
        : actualLength;
    const rendered = formatSystraceBufferValue(pointerText, previewLength);
    if (
        rendered === null ||
        values.some((value) => value.startsWith(`${bufferName}=`))
    ) {
        return values;
    }
    return [...values, `${bufferName}=${rendered}`];
}

function prepareSystraceParams(params: any): any {
    const key = getSystraceKey(params);
    if (params.phase === "enter") {
        const values: string[] = params.args || [];
        systraceEnterState.set(key, {
            name: params.name,
            args: [...values],
        });
        const rendered = renderSystraceEnterArgs(params.name, values);
        return rendered === values ? params : { ...params, args: rendered };
    }
    const state = systraceEnterState.get(key);
    systraceEnterState.delete(key);
    if (state === undefined || state.name !== params.name) {
        return params;
    }
    const values: string[] = params.outArgs || [];
    const rendered = renderSystraceExitArgs(
        params.name,
        state.args,
        values,
        String(params.retval ?? ""),
    );
    return rendered === values ? params : { ...params, outArgs: rendered };
}

function getSystraceFilterMatcher(): RegExp | string {
    const curCfgGen = getSystraceCfgGen();
    if (curCfgGen !== seenSystraceCfgGen) {
        systracePending.clear();
        systraceEnterState.clear();
        seenSystraceCfgGen = curCfgGen;
    }
    const filter = config.getString("systrace.filter");
    if (filter === systraceFilterValue) {
        return systraceFilterMatcher;
    }
    systraceFilterValue = filter;
    if (!filter.startsWith("/")) {
        systraceFilterMatcher = filter;
        return systraceFilterMatcher;
    }
    const body = (filter.length > 1 && filter.endsWith("/"))
        ? filter.substring(1, filter.length - 1)
        : filter.substring(1);
    systraceFilterMatcher = new RegExp(body);
    return systraceFilterMatcher;
}

function systraceMatchesFilter(filter: RegExp | string, text: string): boolean {
    return (filter instanceof RegExp)
        ? filter.test(text)
        : text.includes(filter);
}

function systraceShouldLog(params: any): boolean {
    const filter = getSystraceFilterMatcher();
    if (filter === "") {
        return true;
    }
    const key = getSystraceKey(params);
    const isEnter = params.phase === "enter";
    const values: string[] = isEnter
        ? (params.args || [])
        : (params.outArgs || []);
    const text = values.length > 0
        ? values.join(", ")
        : String(params.retval ?? "");
    if (isEnter) {
        const matched = systraceMatchesFilter(filter, text);
        if (matched) {
            systracePending.add(key);
        } else {
            systracePending.delete(key);
        }
        return matched;
    }
    return systracePending.delete(key) || systraceMatchesFilter(filter, text);
}

export function systraceLog(params: any) {
    params = prepareSystraceParams(params);
    if (!systraceShouldLog(params)) {
        return [{}, null];
    }
    const isEnter = params.phase === "enter";
    const values: string[] = isEnter
        ? (params.args || [])
        : (params.outArgs || []);
    const traceMessage: any = {
        source: "systrace",
        phase: params.phase,
        name: params.name,
        nr: params.nr,
        pid: params.pid,
        tid: params.tid,
        abi: params.abi,
        timestamp: new Date(),
    };
    if (params.timeNs !== undefined) {
        traceMessage.timeNs = params.timeNs;
    }
    if (isEnter) {
        traceMessage.values = values;
    } else {
        traceMessage.retval = params.retval;
        traceMessage.outValues = values;
        traceMessage.failed = params.failed === true;
    }
    if (config.getString("hook.output") === "json") {
        log.traceEmit(JSON.stringify(traceMessage));
    } else {
        const useTimestamp = config.getBoolean("hook.time");
        const tss = useTimestamp ? `[${traceMessage.timestamp}]` : "";
        const where = `pid=${params.pid} tid=${params.tid} abi=${params.abi}`;
        if (isEnter) {
            log.traceEmit(
                `[systrace enter]${tss} ${params.name}#${params.nr} ${where} - args: ${
                    values.join(", ")
                }`,
            );
        } else {
            const failed = params.failed === true ? " failed" : "";
            let msg =
                `[systrace exit]${tss} ${params.name}#${params.nr} ${where} - ret: ${params.retval}${failed}`;
            if (values.length > 0) {
                msg += ` out: ${values.join(", ")}`;
            }
            log.traceEmit(msg);
        }
    }
    return [{}, null];
}
