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
}

const r2frida: R2FridaPlugin = {
    version: "5.7.9", // packageJson.version,
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
};

declare let global: any;

global.r2frida = r2frida;

export default r2frida;
