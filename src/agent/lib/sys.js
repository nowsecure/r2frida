import fs from './fs.js';
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

function getOrSetEnv (args) {
  if (args.length === 0) {
    return getEnv().join('\n') + '\n';
  }
  const { key, value } = getOrSetEnvJson(args);
  return key + '=' + value;
}

function getOrSetEnvJson (args) {
  if (args.length === 0) {
    return getEnvJson();
  }
  const kv = args.join('');
  const eq = kv.indexOf('=');
  if (eq !== -1) {
    const k = kv.substring(0, eq);
    const v = kv.substring(eq + 1);
    setenv(k, v, true);
    return {
      key: k,
      value: v
    };
  } else {
    return {
      key: kv,
      value: getenv(kv)
    };
  }
}

function getEnv () {
  const result = [];
  let envp = Memory.readPointer(Module.findExportByName(null, 'environ'));
  let env;
  while (!envp.isNull() && !(env = envp.readPointer()).isNull()) {
    result.push(env.readCString());
    envp = envp.add(Process.pointerSize);
  }
  return result;
}

function getEnvJson () {
  return getEnv().map(kv => {
    const eq = kv.indexOf('=');
    return {
      key: kv.substring(0, eq),
      value: kv.substring(eq + 1)
    };
  });
}

function dlopen (args) {
  const path = fs.transformVirtualPath(args[0]);
  if (fs.exist(path)) {
    return Module.load(path);
  }
  return Module.load(args[0]);
}

function getenv (name) {
  return Memory.readUtf8String(_getenv(Memory.allocUtf8String(name)));
}

function setenv (name, value, overwrite) {
  return _setenv(Memory.allocUtf8String(name), Memory.allocUtf8String(value), overwrite ? 1 : 0);
}

function changeSelinuxContext (args) {
  if (Process.platform !== 'linux') {
    console.error('This is only available on Android/Linux');
    return '';
  }
  const _setfilecon = symf('setfilecon', 'int', ['pointer', 'pointer']);
  if (_setfilecon === null) {
    return 'Error: cannot find setfilecon symbol';
  }
  // TODO This doesnt run yet because permissions
  // TODO If it runs as root, then file might be checked
  const file = args[0];
  const con = Memory.allocUtf8String('u:object_r:frida_file:s0');
  const path = Memory.allocUtf8String(file);
  const rv = _setfilecon(path, con);
  return JSON.stringify({ ret: rv.value, errno: rv.errno });
}

export { sym };
export { symf };
export { _getpid };
export { _getuid };
export { _dup2 };
export { _readlink };
export { _fstat };
export { _close };
export { _kill };
export { getPid };
export { getPidJson };
export { getOrSetEnv };
export { getOrSetEnvJson };
export { dlopen };
export { changeSelinuxContext };
export default {
  sym,
  symf,
  _getpid,
  _getuid,
  _dup2,
  _readlink,
  _fstat,
  _close,
  _kill,
  getPid,
  getPidJson,
  getOrSetEnv,
  getOrSetEnvJson,
  dlopen,
  changeSelinuxContext
};
