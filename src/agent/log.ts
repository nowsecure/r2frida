import config from "./config.js";
import { wrapStanza } from "./lib/utils.js";
import r2frida from "./plugin.js";

export const logs: any[] = [];

export function traceEmit(msg: string) {
    const fileLog = config.getString("file.log");
    if (fileLog.length > 0) {
        send(wrapStanza("log-file", {
            filename: fileLog,
            message: msg,
        }));
    } else {
        traceLog(msg);
    }
    if (config.getBoolean("hook.logs")) {
        logs.push(msg);
    }
    r2frida.logs = logs;
}

function objtrim(msg: any, field: string): string {
    try {
        const obj = JSON.parse(msg);
        delete obj[field];
        msg = JSON.stringify(obj);
    } catch (e) {
        try {
            delete msg[field];
        } catch (e2) {
        }
    }
    return msg;
}

export function traceLog(msg: any | string) {
    if (!config.getBoolean("hook.time")) {
        msg = objtrim(msg, "ts");
    }
    if (!config.getBoolean("hook.backtrace")) {
        msg = objtrim(msg, "backtrace");
    }
    msg = objtrim(msg, "scope");
    msg = objtrim(msg, "type");
    if (config.getBoolean("hook.verbose")) {
        send(wrapStanza("log", {
            message: msg,
        }));
    }
}

export default {
    logs,
    traceEmit,
    traceLog,
};
