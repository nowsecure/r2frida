/* author  Sergi Alvarez i Capilla <pancake@nowsecure.com> */

/* eslint-disable camelcase */
let _r_core_new : any | null = null;
let _r_core_cmd_str : any | null = null;
let _r_core_free : any | null = null;
// const _free = new NativeFunction(Module.findExportByName(null, 'free'), 'void', ['pointer']);
// const _dlopen = new NativeFunction(Module.findExportByName(null, 'dlopen'), 'pointer', ['pointer', 'int']);

function sym(name: string, ret: any, arg: any) {
    return new NativeFunction(Module.findExportByName(null, name)!, ret, arg);
}

// eslint-disable-next-line
function R2PipeFrida() {
    function r2nakedSymbols() {
        _r_core_new = sym('r_core_new', 'pointer', []);
        _r_core_cmd_str = sym('r_core_cmd_str', 'pointer', ['pointer', 'pointer']);
        _r_core_free = sym('r_core_free', 'void', ['pointer']);
    }
    if (_r_core_new === null) {
        r2nakedSymbols();
        if (_r_core_new === null) {
            throw new Error('Cannot find libr_core symbols');
        }
    }
    const r2 = _r_core_new();
    return {
        cmd: function (cmd: string) {
            return _r_core_cmd_str(r2, Memory.allocUtf8String(cmd)).toString();
        },
        quit: function () {
            _r_core_free(r2);
        }
    };
}

/* example */
/*
const r2 = new R2PipeFrida();
console.log(r2.cmd("?V"));
r2.quit();
*/
