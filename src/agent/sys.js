'use strict';

let _getenv = 0;
let _setenv = 0;
let _getpid = 0;
let _getuid = 0;
let _dup2 = 0;
let _readlink = 0;
let _fstat = 0;
let _close = 0;
let _kill = 0;

if (Process.platform === 'windows') {
  _getenv = sym('getenv', 'pointer', ['pointer']);
  _setenv = sym('SetEnvironmentVariableA', 'int', ['pointer', 'pointer']);
  _getpid = sym('_getpid', 'int', []);
  _getuid = getWindowsUserNameA;
  _dup2 = sym('_dup2', 'int', ['int', 'int']);
  _fstat = sym('_fstat', 'int', ['int', 'pointer']);
  _close = sym('_close', 'int', ['int']);
  _kill = sym('TerminateProcess', 'int', ['int', 'int']);
} else {
  _getenv = sym('getenv', 'pointer', ['pointer']);
  _setenv = sym('setenv', 'int', ['pointer', 'pointer', 'int']);
  _getpid = sym('getpid', 'int', []);
  _getuid = sym('getuid', 'int', []);
  _dup2 = sym('dup2', 'int', ['int', 'int']);
  _readlink = sym('readlink', 'int', ['pointer', 'pointer', 'int']);
  _fstat = Module.findExportByName(null, 'fstat') ? sym('fstat', 'int', ['int', 'pointer']) : sym('__fxstat', 'int', ['int', 'pointer']);
  _close = sym('close', 'int', ['int']);
  _kill = sym('kill', 'int', ['int', 'int']);
}

function sym (name, ret, arg) {
  try {
    return new NativeFunction(Module.getExportByName(null, name), ret, arg);
  } catch (e) {
    console.error(name, ':', e);
  }
}

function symf (name, ret, arg) {
  try {
    return new SystemFunction(Module.getExportByName(null, name), ret, arg);
  } catch (e) {
    // console.error('Warning', name, ':', e);
  }
}

function getWindowsUserNameA () {
  const _GetUserNameA = sym('GetUserNameA', 'int', ['pointer', 'pointer']);
  const PATH_MAX = 4096;
  const buf = Memory.allocUtf8String('A'.repeat(PATH_MAX));
  const charOut = Memory.allocUtf8String('A'.repeat(PATH_MAX));
  const res = _GetUserNameA(buf, charOut);
  if (res) {
    return Memory.readCString(buf);
  }
  return '';
}

function getPidJson () {
  return JSON.stringify({ pid: getPid() });
}

function getPid () {
  return _getpid();
}

module.exports = {
  sym,
  symf,
  _getenv,
  _setenv,
  _getpid,
  _getuid,
  _dup2,
  _readlink,
  _fstat,
  _close,
  _kill,
  getPid,
  getPidJson
};
