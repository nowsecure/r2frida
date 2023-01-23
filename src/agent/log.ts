import config from './config.js';
import { wrapStanza } from './lib/utils.js';
import r2frida from './plugin.js';

export const logs: any[] = [];

export function traceEmit(msg: string) {
    const fileLog = config.getString('file.log');
    if (fileLog.length > 0) {
        send(wrapStanza('log-file', {
            filename: fileLog,
            message: msg
        }));
    } else {
        traceLog(msg);
    }
    if (config.getBoolean('hook.logs')) {
        logs.push(msg);
    }
    r2frida.logs = logs;
}

export function traceLog(msg: string) {
    if (config.getBoolean('hook.verbose')) {
        send(wrapStanza('log', {
            message: msg
        }));
    }
}

export default {
    logs,
    traceEmit,
    traceLog
};
