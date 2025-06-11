/* author  Sergi Alvarez i Capilla <pancake@nowsecure.com> */

import { r2frida } from "./plugin.js";

 
let _r_core_new: any | null = null;
let _r_core_cmd_str: any | null = null;
let _r_core_free: any | null = null;
// const _free = new NativeFunction(Module.findExportByName(null, 'free'), 'void', ['pointer']);
// const _dlopen = new NativeFunction(Module.findExportByName(null, 'dlopen'), 'pointer', ['pointer', 'int']);

function sym(name: string, ret: any, arg: any) {
    return new NativeFunction(Module.findGlobalExportByName(name)!, ret, arg);
}

function r2nakedSymbols() {
    _r_core_new = sym("r_core_new", "pointer", []);
    _r_core_cmd_str = sym("r_core_cmd_str", "pointer", ["pointer", "pointer"]);
    _r_core_free = sym("r_core_free", "void", ["pointer"]);
}

 
export class R2PipeFridaNative {
    r2: any;
    constructor() {
        if (_r_core_new === null) {
            r2nakedSymbols();
            if (_r_core_new === null) {
                throw new Error("Cannot find libr_core symbols");
            }
        }
        this.r2 = _r_core_new();
    }
    cmd(cmd: string) {
        return _r_core_cmd_str(this.r2, Memory.allocUtf8String(cmd)).toString();
    }
    quit() {
        _r_core_free(this.r2);
    }
}
export class R2PipeFridaHost {
    constructor() {
    }
    log(args: string) {
        console.log(args);
    }
    cmd(cmd: string) {
        return r2frida.hostCmd(cmd);
    }
    quit() {
        // do nothing
    }
}

export class R2PipeFridaAgent {
    constructor() {
    }
    log(args: string) {
        console.log(args);
    }
    cmd(cmd: string) {
        return r2frida.cmd(cmd);
    }
    quit() {
        // do nothing
    }
}

export const r2pipe: any = {
    open: (type: string): any => {
        if (type === "r2frida") {
            return new R2PipeFridaAgent();
        }
        if (type === "native") {
            return new R2PipeFridaNative();
        }
        return new R2PipeFridaHost();
    },
};

/* example */
/*
const r2 = new R2PipeFrida();
console.log(r2.cmd("?V"));
r2.quit();
*/
