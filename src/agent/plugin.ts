const commandHandlers: any[any] = {};

function pluginRegister(name: string, ch: any) {
    if (name in commandHandlers) {
        console.log('Cannot register the same handler twice');
        return false;
    }
    commandHandlers[name] = ch;
    return true;
}

function pluginUnregister(name: string) {
    if (name in commandHandlers) {
        delete commandHandlers[name];
        return true;
    }
    return false;
}

function commandHandler(name: string) {
    for (const key of Object.keys(commandHandlers)) {
        const ch: any = commandHandlers[key];
        if (typeof ch === 'function') {
            const handler = ch(name);
            if (handler !== undefined) {
                return handler;
            }
        }
    }
    return undefined;
}

function pluginList() {
    return Object.keys(commandHandlers).join('\n');
}
export type PutsFunction = (s: string) => void;

// import packageJson from "./package.json" assert { type: "json" };
export interface R2FridaPlugin {
    version: string,
    safeio: boolean,
    commandHandler: any,
    pluginRegister: any,
    pluginUnregister: any,
    pluginList: any,
    hookedRead: any,
    hookedWrite: any,
    hookedRanges: any,
    hookedScan: any,
    offset: string,
    logs: string[],
    hostCmd: any,
    hostCmdj: any,
    log: any,
    emit: any,
    module: string,
    puts: PutsFunction | null,
}

/*
r2frida.hostCmd = r2.hostCmd;
r2frida.hostCmdj = r2.hostCmdj;
r2frida.logs = log.logs;
r2frida.log = log.traceLog;
r2frida.emit = log.traceEmit;
r2frida.safeio = NeedsSafeIo;
r2frida.module = '';
r2frida.puts = initializePuts();
*/

export const r2frida: R2FridaPlugin = {
    version: "5.8.2",
    safeio: false,
    commandHandler: commandHandler,
    pluginRegister: pluginRegister,
    pluginUnregister: pluginUnregister,
    pluginList: pluginList,
    // io hook plugin API //
    hookedRead: null,
    hookedWrite: null,
    hookedRanges: null,
    hookedScan: null,
    offset: "",
    logs: [],
    hostCmd: undefined,
    hostCmdj: undefined,
    log: undefined,
    emit: undefined,
    module: "",
    puts: null 
};

// dont do this global, we can export and use the r2frida object
export default r2frida;
