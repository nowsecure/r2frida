/* author  Sergi Alvarez i Capilla <pancake@nowsecure.com> */
'use strict';

/* eslint-disable camelcase */
let _r_core_new = null;
let _r_core_cmd_str = null;
let _r_core_free = null;
// const _free = new NativeFunction(Module.findExportByName(null, 'free'), 'void', ['pointer']);
// const _dlopen = new NativeFunction(Module.findExportByName(null, 'dlopen'), 'pointer', ['pointer', 'int']);

function sym (name, ret, arg) {
  return new NativeFunction(Module.findExportByName(null, name), ret, arg);
}

// eslint-disable-next-line
function R2PipeFrida () {
  function r2nakedSymbols () {
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
  let r2 = _r_core_new();
  return {
    cmd: function (cmd) {
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
