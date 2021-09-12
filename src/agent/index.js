/* eslint-disable comma-dangle */
'use strict';
// TODO : implement tracelog eval var and dump trace info into this file
// this cant be done from the agent-side

const { stalkFunction, stalkEverything } = require('./stalker');
const fs = require('./fs');
const path = require('path');
const config = require('./config');
const io = require('./io');
const isObjC = require('./isobjc');
const strings = require('./strings');
const utils = require('./utils');

// registered as a plugin
require('../../ext/swift-frida/examples/r2swida/index.js');

let Gcwd = '/';

/* ObjC.available is buggy on non-objc apps, so override this */
const SwiftAvailable = Process.platform === 'darwin' && Swift && Swift.available;
const ObjCAvailable = (Process.platform === 'darwin') && ObjC && ObjC.available && ObjC.classes && typeof ObjC.classes.NSString !== 'undefined';
const NeedsSafeIo = (Process.platform === 'linux' && Process.arch === 'arm' && Process.pointerSize === 4);
const JavaAvailable = Java && Java.available;

/* globals */
const pointerSize = Process.pointerSize;

let suspended = false;
const tracehooks = {};
let logs = [];
let traces = {};
let breakpoints = {};

const allocPool = {};
const pendingCmds = {};
const pendingCmdSends = [];
let sendingCommand = false;
const specialChars = '`${}~|;#@&<> ()';

function numEval (expr) {
  return new Promise((resolve, reject) => {
    const symbol = DebugSymbol.fromName(expr);
    if (symbol && symbol.name) {
      return resolve(symbol.address);
    }
    hostCmd('?v ' + expr).then(_ => resolve(_.trim())).catch(reject);
  });
}

function javaUse (name) {
  const initialLoader = Java.classFactory.loader;
  let res = null;
  javaPerform(function () {
    for (const kl of Java.enumerateClassLoadersSync()) {
      try {
        Java.classFactory.loader = kl;
        res = Java.use(name);
        break;
      } catch (e) {
        // do nothing
      }
    }
  });
  Java.classFactory.loader = initialLoader;
  return res;
}

function evalNum (args) {
  return new Promise((resolve, reject) => {
    numEval(args.join(' ')).then(res => {
      resolve(res);
    });
  });
}

function javaTraceExample () {
  javaPerform(function () {
    const System = Java.use('java.lang.System');
    System.loadLibrary.implementation = function (library) {
      try {
        traceEmit('System.loadLibrary ' + library);
        const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
        return loaded;
      } catch (e) {
        console.error(e);
      }
    };
  });
}

const commandHandlers = {
  E: evalNum,
  '?e': echo,
  '?E': uiAlert,
  '/': search,
  '/i': searchInstances,
  '/ij': searchInstancesJson,
  '/j': searchJson,
  '/x': searchHex,
  '/xj': searchHexJson,
  '/w': searchWide,
  '/wj': searchWideJson,
  '/v1': searchValueImpl(1),
  '/v2': searchValueImpl(2),
  '/v4': searchValueImpl(4),
  '/v8': searchValueImpl(8),
  '/v1j': searchValueImplJson(1),
  '/v2j': searchValueImplJson(2),
  '/v4j': searchValueImplJson(4),
  '/v8j': searchValueImplJson(8),
  '?V': fridaVersion,
  // '.': // this is implemented in C
  i: dumpInfo,
  'i*': dumpInfoR2,
  ij: dumpInfoJson,
  e: evalConfig,
  'e*': evalConfigR2,
  'e/': evalConfigSearch,
  db: breakpoint,
  dbj: breakpointJson,
  'db-': breakpointUnset,
  dc: breakpointContinue,
  dcu: breakpointContinueUntil,
  dk: sendSignal,

  s: radareSeek,
  r: radareCommand,

  ie: listEntrypoint,
  ieq: listEntrypointQuiet,
  'ie*': listEntrypointR2,
  iej: listEntrypointJson,
  afs: analFunctionSignature,
  ii: listImports,
  'ii*': listImportsR2,
  iij: listImportsJson,
  il: listModules,
  'il.': listModulesHere,
  'il*': listModulesR2,
  ilq: listModulesQuiet,
  ilj: listModulesJson,

  ia: listAllHelp,

  iAs: listAllSymbols, // SLOW
  iAsj: listAllSymbolsJson,
  'iAs*': listAllSymbolsR2,
  iAn: listAllClassesNatives,

  is: listSymbols,
  'is.': lookupSymbolHere,
  isj: listSymbolsJson,
  'is*': listSymbolsR2,

  ias: lookupSymbol,
  'ias*': lookupSymbolR2,
  iasj: lookupSymbolJson,
  isa: lookupSymbol,
  'isa*': lookupSymbolR2,
  isaj: lookupSymbolJson,
  // many symbols
  isam: lookupSymbolMany,
  isamj: lookupSymbolManyJson,
  'isam*': lookupSymbolManyR2,

  iE: listExports,
  'iE.': lookupSymbolHere,
  iEj: listExportsJson,
  'iE*': listExportsR2,
  iaE: lookupExport,
  iaEj: lookupExportJson,
  'iaE*': lookupExportR2,

  iEa: lookupExport,
  'iEa*': lookupExportR2,
  iEaj: lookupExportJson,

  // maybe dupped
  iAE: listAllExports,
  iAEj: listAllExportsJson,
  'iAE*': listAllExportsR2,

  init: initBasicInfoFromTarget,

  fD: lookupDebugInfo,
  fd: lookupAddress,
  'fd.': lookupAddress,
  'fd*': lookupAddressR2,
  fdj: lookupAddressJson,
  ic: listClasses,
  ich: listClassesHooks,
  icw: listClassesWhere,
  icv: listClassVariables,
  ics: listClassSuperMethods,
  ica: listClassesAllMethods,
  icn: listClassesNatives,
  icL: listClassesLoaders,
  icl: listClassesLoaded,
  iclj: listClassesLoadedJson,
  'ic*': listClassesR2,
  icj: listClassesJson,
  icm: listClassMethods,
  icmj: listClassMethodsJson,
  ip: listProtocols,
  ipj: listProtocolsJson,
  iz: listStrings,
  izj: listStringsJson,
  dd: listFileDescriptors,
  ddj: listFileDescriptorsJson,
  'dd-': closeFileDescriptors,
  dm: listMemoryRanges,
  'dm*': listMemoryRangesR2,
  dmj: listMemoryRangesJson,
  dmp: changeMemoryProtection,
  'dm.': listMemoryRangesHere,
  dmm: listMemoryMaps,
  'dmm*': listMemoryMapsR2,
  'dmm.': listMemoryMapsHere, // alias for 'dm.'
  dmh: listMallocRanges,
  'dmh*': listMallocRangesR2,
  dmhj: listMallocRangesJson,
  dmhm: listMallocMaps,
  dma: allocSize,
  dmas: allocString,
  dmad: allocDup,
  dmal: listAllocs,
  'dma-': removeAlloc,
  dp: getPid,
  dxc: dxCall,
  dxo: dxObjc,
  dxs: dxSyscall,
  dpj: getPidJson,
  dpt: listThreads,
  dptj: listThreadsJson,
  dr: dumpRegisters,
  'dr*': dumpRegistersR2,
  drr: dumpRegistersRecursively,
  drp: dumpRegisterProfile,
  dr8: dumpRegisterArena,
  drj: dumpRegistersJson,
  env: getOrSetEnv,
  envj: getOrSetEnvJson,
  dl: dlopen,
  dlf: loadFrameworkBundle,
  'dlf-': unloadFrameworkBundle,
  dtf: traceFormat,
  dth: traceHook,
  t: types,
  't*': typesR2,
  dt: trace,
  dtj: traceJson,
  dtq: traceQuiet,
  'dt*': traceR2,
  'dt.': traceHere,
  'dt-': clearTrace,
  'dt-*': clearAllTrace,
  dtr: traceRegs,
  dtl: traceLogDump,
  'dtl*': traceLogDumpR2,
  dtlq: traceLogDumpQuiet,
  dtlj: traceLogDumpJson,
  'dtl-': traceLogClear,
  'dtl-*': traceLogClearAll,
  dts: stalkTraceEverything,
  'dts?': stalkTraceEverythingHelp,
  dtsj: stalkTraceEverythingJson,
  'dts*': stalkTraceEverythingR2,
  dtsf: stalkTraceFunction,
  dtsfj: stalkTraceFunctionJson,
  'dtsf*': stalkTraceFunctionR2,
  di: interceptHelp,
  dif: interceptHelp,
  // intercept ret after calling function
  dis: interceptRetString,
  di0: interceptRet0,
  di1: interceptRet1,
  dii: interceptRetInt,
  'di-1': interceptRet_1,
  // intercept ret and dont call the function
  difs: interceptFunRetString,
  dif0: interceptFunRet0,
  dif1: interceptFunRet1,
  difi: interceptFunRetInt,
  'dif-1': interceptFunRet_1,
  // unix compat
  pwd: getCwd,
  cd: chDir,
  cat: fsCat,
  ls: fsList,
  // required for m-io
  md: fsList,
  mg: fsGet,
  m: fsOpen,
  pd: disasmCode,
  px: printHexdump,
  x: printHexdump,
  eval: evalCode,
  chcon: changeSelinuxContext,
};

async function initBasicInfoFromTarget (args) {
  const str = `
e dbg.backend = io
e anal.autoname=true
e cmd.fcn.new=aan
.:ie*
.:dmm*
.:il*
m /r2f io 0
s entry0
 `;
  return str;
}

function nameFromAddress (address) {
  const at = DebugSymbol.fromAddress(ptr(address));
  if (at) {
    return at.name;
  }
  const module = Process.findModuleByAddress(address);
  if (module === null) {
    return null;
  }
  const imports = Module.enumerateImports(module.name);
  for (const imp of imports) {
    if (imp.address.equals(address)) {
      return imp.name;
    }
  }
  const exports = Module.enumerateExports(module.name);
  for (const exp of exports) {
    if (exp.address.equals(address)) {
      return exp.name;
    }
  }
  return address.toString();
}

function allocSize (args) {
  const size = +args[0];
  if (size > 0) {
    const a = Memory.alloc(size);
    return _addAlloc(a);
  }
  return 0;
}

function allocString (args) {
  const theString = args.join(' ');
  if (theString.length > 0) {
    const a = Memory.allocUtf8String(theString);
    return _addAlloc(a);
  }
  throw new Error('Usage: dmas [string]');
}

function allocDup (args) {
  if (args.length < 2) {
    throw new Error('Missing argument');
  }
  const addr = +args[0];
  const size = +args[1];
  if (addr > 0 && size > 0) {
    const a = Memory.dup(ptr(addr), size);
    return _addAlloc(a);
  }
  return 0;
}

function removeAlloc (args) {
  if (args.length === 0) {
    _clearAllocs();
  } else {
    for (const addr of args) {
      _delAlloc(addr);
    }
  }
  return '';
}

function listAllocs (args) {
  return Object.values(allocPool)
    .sort()
    .map((x) => {
      const bytes = Memory.readByteArray(x, 60);
      const printables = _filterPrintable(bytes);
      return `${x}\t"${printables}"`;
    })
    .join('\n') + '\n';
}

function _delAlloc (addr) {
  delete allocPool[addr];
}

function _clearAllocs () {
  Object.keys(allocPool)
    .forEach(addr => delete allocPool[addr]);
}

function _addAlloc (allocPtr) {
  const key = allocPtr.toString();
  if (!allocPtr.isNull()) {
    allocPool[key] = allocPtr;
  }
  return key;
}

function resolveSyscallNumber (name) {
  const ios = Process.arch === 'arm64';
  switch (name) {
    case 'read':
      return ios ? 3 : 0x2000003;
    case 'write':
      return ios ? 4 : 0x2000004;
    case 'exit':
      return ios ? 1 : 0x2000001;
  }
  return '' + name;
}

function dxSyscall (args) {
  if (args.length === 0) {
    return 'Usage dxs [syscallname] [args ...]';
  }
  const syscallNumber = '' + resolveSyscallNumber(args[0]);
  return dxCall(['syscall', syscallNumber, ...args.slice(1)]);
}

function autoType (args) {
  const nfArgs = [];
  const nfArgsData = [];
  // push arguments
  for (let i = 0; i < args.length; i++) {
    if (args[i].substring(0, 2) === '0x') {
      nfArgs.push('pointer');
      nfArgsData.push(ptr(args[i]));
    } else if (args[i][0] === '"') {
      // string.. join args
      nfArgs.push('pointer');
      const str = args[i].substring(1, args[i].length - 1);
      const buf = Memory.allocUtf8String(str.replace(/\\n/g, '\n'));
      nfArgsData.push(buf);
    } else if (args[i].endsWith('f')) {
      nfArgs.push('float');
      nfArgsData.push(0.0 + args[i]);
    } else if (args[i].endsWith('F')) {
      nfArgs.push('double');
      nfArgsData.push(0.0 + args[i]);
    } else if (+args[i] > 0 || args[i] === '0') {
      nfArgs.push('int');
      nfArgsData.push(+args[i]);
    } else {
      nfArgs.push('pointer');
      const address = Module.getExportByName(null, args[i]);
      nfArgsData.push(address);
    }
  }
  return [nfArgs, nfArgsData];
}

function dxObjc (args) {
  if (!ObjCAvailable) {
    return 'dxo requires the objc runtime to be available to work.';
  }
  if (args.length === 0) {
    return 'Usage: dxo [klassname|instancepointer] [methodname] [args...]';
  }
  if (args.length === 1) {
    return listClasses(args);
  }
  // Usage: "dxo instance-pointer [arg0 arg1]"
  let instancePointer = null;
  if (args[0].startsWith('0x')) {
    instancePointer = new ObjC.Object(ptr(args[0]));
  } else {
    const klassName = args[0];
    if (!ObjC.classes[klassName]) {
      return 'Cannot find objc class ' + klassName;
    }
    const instances = ObjC.chooseSync(ObjC.classes[klassName]);
    if (!instances) {
      return 'Cannot find any instance for klass ' + klassName;
    }
    instancePointer = instances[0];
  }
  const methodName = args[1];
  const [v, t] = autoType(args.slice(2));
  try {
    ObjC.schedule(ObjC.mainQueue, function () {
      if (instancePointer.hasOwnProperty(methodName)) {
        instancePointer[methodName](...t);
      } else {
        console.error('unknown method ' + methodName + ' for objc instance at ' + padPointer(ptr(instancePointer)));
      }
    });
  } catch (e) {
    console.error(e);
  }
  return '';
}

function dxCall (args) {
  if (args.length === 0) {
    return `
Usage: dxc [funcptr] [arg0 arg1..]
For example:
 :dxc write 1 "hello\\n" 6
 :dxc read 0 \`?v rsp\` 10
`;
  }
  const address = (args[0].substring(0, 2) === '0x')
    ? ptr(args[0])
    : Module.getExportByName(null, args[0]);
  const [nfArgs, nfArgsData] = autoType(args.slice(1));
  const fun = new NativeFunction(address, 'pointer', nfArgs);
  if (nfArgs.length === 0) {
    return fun();
  }
  return fun(...nfArgsData);
}

function evalCode (args) {
  const code = args.join(' ');
  const result = eval(code); // eslint-disable-line
  return (result !== undefined) ? result : '';
}

function printHexdump (lenstr) {
  const len = +lenstr || 32;
  try {
    return hexdump(ptr(r2frida.offset), len) || '';
  } catch (e) {
    return 'Cannot read memory.';
  }
}

function disasmCode (lenstr) {
  const len = +lenstr || 32;
  return disasm(r2frida.offset, len);
}

function disasm (addr, len, initialOldName) {
  len = len || 32;
  if (typeof addr === 'string') {
    try {
      addr = Module.findExportByName(null, addr);
      if (!addr) {
        throw new Error();
      }
    } catch (e) {
      addr = ptr(r2frida.offset);
    }
  }
  let oldName = initialOldName !== undefined ? initialOldName : null;
  let lastAt = null;
  let disco = '';
  for (let i = 0; i < len; i++) {
    const [op, next] = _tolerantInstructionParse(addr);
    const vaddr = padPointer(addr);
    if (op === null) {
      disco += `${vaddr}\tinvalid\n`;
      addr = next;
      continue;
    }
    const ds = DebugSymbol.fromAddress(addr);
    let dsName = (ds.name === null || ds.name.indexOf('0x') === 0) ? '' : ds.name;
    let moduleName = ds.moduleName;
    if (!ds.moduleName) {
      moduleName = '';
    }
    if (!dsName) {
      dsName = '';
    }
    if ((moduleName || dsName) && dsName !== oldName) {
      disco += ';;; ' + (moduleName || dsName) + '\n';
      oldName = dsName;
    }
    let comment = '';
    const id = op.opStr.indexOf('#0x');
    if (id !== -1) {
      try {
        const at = op.opStr.substring(id + 1).split(' ')[0].split(',')[0].split(']')[0];
        if (op.opStr.indexOf(']') !== -1) {
          try {
            const p = Memory.readPointer(ptr(lastAt).add(at));
            const str = Memory.readCString(p);
            // console.log(';  str:', str);
            disco += ';  str:' + str + '\n';
          } catch (e) {
            const p2 = Memory.readPointer(ptr(at));
            const str2 = Memory.readCString(p2);
            // console.log(';  str2:', str2);
            disco += ';  str2:' + str2 + '\n';
            console.log(e);
          }
        }
        lastAt = at;
        const di = DebugSymbol.fromAddress(ptr(at));
        if (di.name !== null) {
          comment = '\t; ' + (di.moduleName || '') + ' ' + di.name;
        } else {
          const op2 = Instruction.parse(ptr(at));
          const id2 = op2.opStr.indexOf('#0x');
          const at2 = op2.opStr.substring(id2 + 1).split(' ')[0].split(',')[0].split(']')[0];
          const di2 = DebugSymbol.fromAddress(ptr(at2));
          if (di2.name !== null) {
            comment = '\t; -> ' + (di2.moduleName || '') + ' ' + di2.name;
          }
        }
      } catch (e) {
        // console.log(e);
      }
    }
    // console.log([op.address, op.mnemonic, op.opStr, comment].join('\t'));
    disco += [padPointer(op.address), op.mnemonic, op.opStr, comment].join('\t') + '\n';
    if (op.size < 1) {
      // break; // continue after invalid
      op.size = 1;
    }
    addr = addr.add(op.size);
  }
  return disco;
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
  _fstat = Module.findExportByName(null, 'fstat')
    ? sym('fstat', 'int', ['int', 'pointer'])
    : sym('__fxstat', 'int', ['int', 'pointer']);
  _close = sym('close', 'int', ['int']);
  _kill = sym('kill', 'int', ['int', 'int']);
}

/* This is only available on Android/Linux */
const _setfilecon = symf('setfilecon', 'int', ['pointer', 'pointer']);

if (Process.platform === 'darwin') {
  // required for early instrumentation
  try {
    Module.load('/System/Library/Frameworks/Foundation.framework/Foundation');
  } catch (e) {
    // ignored
  }
}

const traceListeners = [];

async function dumpInfo () {
  const padding = (x) => ''.padStart(20 - x, ' ');
  const properties = await dumpInfoJson();
  return Object.keys(properties)
    .map(k => k + padding(k.length) + properties[k])
    .join('\n');
}

async function dumpInfoR2 () {
  const properties = await dumpInfoJson();
  const jnienv = properties.jniEnv !== undefined ? properties.jniEnv : '';
  return [
    'e asm.arch=' + properties.arch,
    'e asm.bits=' + properties.bits,
    'e asm.os=' + properties.os,
  ].join('\n') + jnienv;
}

function getR2Arch (arch) {
  switch (arch) {
    case 'ia32':
    case 'x64':
      return 'x86';
    case 'arm64':
      return 'arm';
  }
  return arch;
}

function breakpointUnset (args) {
  if (args.length === 1) {
    /*
    if (args[0] === '*') {
      for (let k of Object.keys(breakpoints)) {
        const bp = breakpoints[k];
        Interceptor.revert(ptr(bp.address));
      }
      breakpoints = {};
      return 'All breakpoints removed';
    }
*/
    const symbol = Module.findExportByName(null, args[0]);
    const arg0 = args[0];
    const addr = arg0 === '*' ? ptr(0) : (symbol !== null) ? symbol : ptr(arg0);
    const newbps = [];
    let found = false;
    for (const k of Object.keys(breakpoints)) {
      const bp = breakpoints[k];
      console.log(bp.address, addr, JSON.stringify(bp));
      if (arg0 === '*' || '' + bp.address === '' + addr) {
        found = true;
        console.log('Breakpoint reverted', JSON.stringify(bp));
        breakpoints[k].continue = true;
        // continue execution
        // send continue action here
        bp.handler.detach();
      } else {
        newbps.push(bp);
      }
    }
    if (!found) {
      console.error('Cannot found any breakpoint matching');
    }
    // // NOPE
    // if (arg0 === '*') {
    //   Interceptor.detachAll();
    // }
    breakpoints = {};
    for (const bp of newbps) {
      breakpoints[bp.address] = bp;
    }
    Interceptor.flush();
    return '';
  }
  return 'Usage: db- [addr|*]';
}

function breakpointExist (addr) {
  const bp = breakpoints['' + addr];
  return bp && !bp.continue;
}

let _r2 = null;
let _r_core_new = null;
let _r_core_cmd_str = null;
let _r_core_free = null;
let _free = null;

function radareCommandInit () {
  if (_r2) {
    return true;
  }
  if (!_r_core_new) {
    _r_core_new = sym('r_core_new', 'pointer', []);
    if (!_r_core_new) {
      console.error('ERROR: Cannot find r_core_new. Do :dl /tmp/libr.dylib');
      return false;
    }
    _r_core_cmd_str = sym('r_core_cmd_str', 'pointer', ['pointer', 'pointer']);
    _r_core_free = sym('r_core_free', 'void', ['pointer']);
    _free = sym('free', 'void', ['pointer']);
    _r2 = _r_core_new();
  }
  return true;
}

function radareCommandString (cmd) {
  if (_r2) {
    const aCmd = Memory.allocUtf8String(cmd);
    const ptr = _r_core_cmd_str(_r2, aCmd);
    const str = Memory.readCString(ptr);
    _free(ptr);
    return str;
  }
  console.error('Warning: not calling back r2');
  return '';
}

function radareSeek (args) {
  const addr = getPtr('' + args);
  const cmdstr = 's ' + (addr || '' + args);
  return cmdstr;
  // XXX hangs
  // return hostCmd(cmdstr);
}

function radareCommand (args) {
  const cmd = args.join(' ');
  if (cmd.length === 0) {
    return 'Usage: :r [cmd]';
  }
  if (radareCommandInit()) {
    return radareCommandString(cmd);
  }
  return ':dl /tmp/libr.dylib';
}

function sendSignal (args) {
  const argsLength = args.length;
  console.error('WARNING: Frida hangs when signal is sent. But at least the process doesnt continue');
  if (argsLength === 1) {
    const sig = +args[0];
    _kill(_getpid(), sig);
  } else if (argsLength === 2) {
    const [pid, sig] = args;
    _kill(+pid, +sig);
  } else {
    return 'Usage: :dk ([pid]) [sig]';
  }
  return '';
}

function breakpointContinueUntil (args) {
  return new Promise((resolve, reject) => {
    numEval(args[0]).then(num => {
      setBreakpoint(num);
      const shouldPromise = breakpointContinue();
      if (typeof shouldPromise === 'object') {
        shouldPromise.then(resolve).catch(reject);
      } else {
        resolve(shouldPromise);
      }
    }).catch(reject);
  });
}

function breakpointContinue (args) {
  if (suspended) {
    suspended = false;
    return hostCmd(':dc');
  }
  let count = 0;
  for (const k of Object.keys(breakpoints)) {
    const bp = breakpoints[k];
    if (bp && bp.stopped) {
      count++;
      bp.continue = true;
    }
  }
  for (const thread of Process.enumerateThreads()) {
    // console.error('send ', thread.id);
    send(wrapStanza('action-' + thread.id, { action: 'continue' }));
  }
  return 'Continue ' + count + ' thread(s).';
}

function breakpointJson (args) {
  if (args.length === 0) {
    return JSON.stringify(breakpoints, null, '  ');
  }
  return new Promise((resolve, reject) => {
    numEval(args[0]).then(num => {
      setBreakpoint(num);
      resolve(JSON.stringify(breakpoints, null, '  '));
    }).catch(e => {
      console.error(e);
      reject(e);
    });
  });
}

function breakpoint (args) {
  if (args.length === 0) {
    return Object.keys(breakpoints).map((bpat) => {
      const bp = breakpoints[bpat];
      const stop = bp.stopped ? 'stop' : 'nostop';
      const cont = bp.continue ? 'cont' : 'nocont';
      return [bp.address, bp.moduleName, bp.name, stop, cont].join('\t');
    }).join('\n');
  }
  return new Promise((resolve, reject) => {
    numEval(args[0]).then(num => {
      resolve(setBreakpoint(args[0], num));
    }).catch(e => {
      console.error(e);
      reject(e);
    });
  });
}

function setBreakpoint (name, address) {
  const symbol = Module.findExportByName(null, name);
  const addr = (symbol !== null) ? symbol : ptr(address);
  if (breakpointExist(addr)) {
    return 'Cant set a breakpoint twice';
  }
  const addrString = '' + addr;
  const currentModule = Process.findModuleByAddress(address);
  const bp = {
    name: name,
    moduleName: currentModule ? currentModule.name : '',
    stopped: false,
    address: address,
    continue: false,
    handler: Interceptor.attach(addr, function () {
      if (breakpoints[addrString]) {
        breakpoints[addrString].stopped = true;
        if (config.getBoolean('hook.backtrace')) {
          console.log(addr);
          const bt = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
          console.log(bt.join('\n\t'));
        }
      }
      /*
      while (breakpointExist(addr)) {
        Thread.sleep(1);
      }
      */

      const tid = this.threadId;
      send({ type: 'breakpoint-hit', name: addrString, tid: tid });
      let state = 'stopped';
      do {
        const op = recv((stanza, data) => {
          if (stanza.payload.command === 'dc') {
            state = 'hit';
            for (const bp in breakpoints) {
              breakpoints[bp].continue = true;
            }
          } else {
            onceStanza = true;
            onStanza(stanza, data);
          }
        });
        op.wait();
      } while (state === 'stopped');

      if (breakpoints[addrString]) {
        breakpoints[addrString].stopped = false;
        breakpoints[addrString].continue = false;
      }
    })
  };
  breakpoints[addrString] = bp;
}

function getCwd () {
  let _getcwd = 0;
  if (Process.platform === 'windows') {
    _getcwd = sym('_getcwd', 'pointer', ['pointer', 'int']);
  } else {
    _getcwd = sym('getcwd', 'pointer', ['pointer', 'int']);
  }

  if (_getcwd) {
    const PATH_MAX = 4096;
    const buf = Memory.alloc(PATH_MAX);
    if (!buf.isNull()) {
      const ptr = _getcwd(buf, PATH_MAX);
      const str = Memory.readCString(ptr);
      Gcwd = str;
      return str;
    }
  }
  return '';
}

function chDir (args) {
  const _chdir = sym('chdir', 'int', ['pointer']);
  if (_chdir && args) {
    const arg = Memory.allocUtf8String(args[0]);
    _chdir(arg);
    getCwd(); // update Gcwd
  }
  return '';
}

function waitForJava () {
  javaPerform(function () {
    const ActivityThread = Java.use('android.app.ActivityThread');
    const app = ActivityThread.currentApplication();
    const ctx = app.getApplicationContext();
    console.log('Done: ' + ctx);
  });
}

async function dumpInfoJson () {
  const res = {
    arch: getR2Arch(Process.arch),
    bits: pointerSize * 8,
    os: Process.platform,
    pid: getPid(),
    uid: _getuid(),
    objc: ObjCAvailable,
    runtime: Script.runtime,
    swift: SwiftAvailable,
    java: JavaAvailable,
    mainLoop: hasMainLoop(),
    pageSize: Process.pageSize,
    pointerSize: Process.pointerSize,
    codeSigningPolicy: Process.codeSigningPolicy,
    isDebuggerAttached: Process.isDebuggerAttached(),
    cwd: getCwd(),
  };

  if (ObjCAvailable && !suspended) {
    try {
      const mb = (ObjC && ObjC.classes && ObjC.classes.NSBundle) ? ObjC.classes.NSBundle.mainBundle() : '';
      const id = mb ? mb.infoDictionary() : '';
      function get (k) {
        const v = id ? id.objectForKey_(k) : '';
        return v ? v.toString() : '';
      }
      const NSHomeDirectory = new NativeFunction(
        Module.getExportByName(null, 'NSHomeDirectory'),
        'pointer', []);
      const NSTemporaryDirectory = new NativeFunction(
        Module.getExportByName(null, 'NSTemporaryDirectory'),
        'pointer', []);
      res.bundle = get('CFBundleIdentifier');
      res.exename = get('CFBundleExecutable');
      res.appname = get('CFBundleDisplayName');
      res.appversion = get('CFBundleShortVersionString');
      res.appnumversion = get('CFBundleNumericVersion');
      res.homedir = (new ObjC.Object(NSHomeDirectory()).toString());
      res.tmpdir = (new ObjC.Object(NSTemporaryDirectory()).toString());
      res.bundledir = ObjC.classes.NSBundle.mainBundle().bundleURL().path();
      // res.appdata = ObjC.classes.NSBundle.mainBundle().bundleURL().path();
      res.minOS = get('MinimumOSVersion');
    } catch (e) {
      console.error(e);
    }
  }
  if (JavaAvailable) {
    await performOnJavaVM(() => {
      const ActivityThread = Java.use('android.app.ActivityThread');
      const app = ActivityThread.currentApplication();
      if (app !== null) {
        const ctx = app.getApplicationContext();
        if (ctx !== null) {
          try {
            res.dataDir = ctx.getDataDir().getAbsolutePath();
          } catch (e) {
            // not available below API 24 (<Android7)
          }
          res.codeCacheDir = ctx.getCodeCacheDir().getAbsolutePath();
          res.extCacheDir = ctx.getExternalCacheDir().getAbsolutePath();
          res.obbDir = ctx.getObbDir().getAbsolutePath();
          res.filesDir = ctx.getFilesDir().getAbsolutePath();
          res.noBackupDir = ctx.getNoBackupFilesDir().getAbsolutePath();
          res.codePath = ctx.getPackageCodePath();
          res.packageName = ctx.getPackageName();
        }

        try {
          function getContext () {
            return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext().getContentResolver();
          }

          res.androidId = Java.use('android.provider.Settings$Secure').getString(getContext(), 'android_id');
        } catch (ignoredError) {
        }
      }
      res.cacheDir = Java.classFactory.cacheDir;
      const jniEnv = ptr(Java.vm.getEnv());
      if (jniEnv) {
        res.jniEnv = jniEnv.toString();
      }
    });
  }

  return res;
}

function listModules () {
  return Process.enumerateModules()
    .map(m => padPointer(m.base) + ' ' + m.name)
    .join('\n');
}

function listModulesQuiet () {
  return Process.enumerateModules().map(m => m.name).join('\n');
}

function listModulesR2 () {
  return Process.enumerateModules()
    .map(m => 'f lib.' + utils.flagify(m.name) + ' = ' + padPointer(m.base))
    .join('\n');
}

function listModulesJson () {
  return Process.enumerateModules();
}

function listModulesHere () {
  const here = ptr(r2frida.offset);
  return Process.enumerateModules()
    .filter(m => here.compare(m.base) >= 0 && here.compare(m.base.add(m.size)) < 0)
    .map(m => padPointer(m.base) + ' ' + m.name)
    .join('\n');
}

function listExports (args) {
  return listExportsJson(args)
    .map(({ type, name, address }) => {
      return [address, type[0], name].join(' ');
    })
    .join('\n');
}

function listExportsR2 (args) {
  return listExportsJson(args)
    .map(({ type, name, address }) => {
      return ['f', 'sym.' + type.substring(0, 3) + '.' + name, '=', address].join(' ');
    })
    .join('\n');
}

function listAllExportsJson (args) {
  const modules = (args.length === 0) ? Process.enumerateModules().map(m => m.path) : [args.join(' ')];
  return modules.reduce((result, moduleName) => {
    return result.concat(Module.enumerateExports(moduleName));
  }, []);
}

function listAllExports (args) {
  return listAllExportsJson(args)
    .map(({ type, name, address }) => {
      return [address, type[0], name].join(' ');
    })
    .join('\n');
}

function listAllExportsR2 (args) {
  return listAllExportsJson(args)
    .map(({ type, name, address }) => {
      return ['f', 'sym.' + type.substring(0, 3) + '.' + name, '=', address].join(' ');
    })
    .join('\n');
}

function listAllSymbolsJson (args) {
  const argName = args[0];
  const modules = Process.enumerateModules().map(m => m.path);
  let res = [];
  for (const module of modules) {
    const symbols = Module.enumerateSymbols(module)
      .filter((r) => r.address.compare(ptr('0')) > 0 && r.name);
    if (argName) {
      res.push(...symbols.filter((s) => s.name.indexOf(argName) !== -1));
    } else {
      res.push(...symbols);
    }
    if (res.length > 100000) {
      res.forEach((r) => {
        console.error([r.address, r.moduleName, r.name].join(' '));
      });
      res = [];
    }
  }
  return res;
}

function listAllHelp (args) {
  return 'See :ia? for more information. Those commands may take a while to run.';
}

function listAllSymbols (args) {
  return listAllSymbolsJson(args)
    .map(({ type, name, address }) => {
      return [address, type[0], name].join(' ');
    })
    .join('\n');
}

function listAllSymbolsR2 (args) {
  return listAllSymbolsJson(args)
    .map(({ type, name, address }) => {
      return ['f', 'sym.' + type.substring(0, 3) + '.' + name, '=', address].join(' ');
    })
    .join('\n');
}

function listExportsJson (args) {
  const currentModule = (args.length > 0)
    ? Process.getModuleByName(args[0])
    : getModuleByAddress(ptr(r2frida.offset));
  return Module.enumerateExports(currentModule.name);
}

function getModuleByAddress (addr) {
  const m = config.getString('symbols.module');
  if (m !== '') {
    return Process.getModuleByName(m);
  }
  try {
    return Process.getModuleByAddress(addr);
  } catch (e) {
    return Process.getModuleByAddress(ptr(r2frida.offset));
  }
}

function listSymbols (args) {
  return listSymbolsJson(args)
    .map(({ type, name, address }) => {
      return [address, type[0], name].join(' ');
    })
    .join('\n');
}

function listSymbolsR2 (args) {
  return listSymbolsJson(args)
    .filter(({ address }) => !address.isNull())
    .map(({ type, name, address }) => {
      return ['f', 'sym.' + type.substring(0, 3) + '.' + sanitizeString(name), '=', address].join(' ');
    })
    .join('\n');
}

function sanitizeString (str) {
  return str.split('').map(c => specialChars.indexOf(c) === -1 ? c : '_').join('');
}

function listSymbolsJson (args) {
  const currentModule = (args.length > 0)
    ? Process.getModuleByName(args[0])
    : getModuleByAddress(r2frida.offset);
  const symbols = Module.enumerateSymbols(currentModule.name);
  return symbols.map(sym => {
    if (config.getBoolean('symbols.unredact') && sym.name.indexOf('redacted') !== -1) {
      const dbgSym = DebugSymbol.fromAddress(sym.address);
      if (dbgSym !== null) {
        sym.name = dbgSym.name;
      }
    }
    return sym;
  });
}

function lookupDebugInfo (args) {
  const o = DebugSymbol.fromAddress(ptr('' + args));
  console.log(o);
}

function lookupAddress (args) {
  if (args.length === 0) {
    args = [ptr(r2frida.offset)];
  }
  return lookupAddressJson(args)
    .map(({ type, name, address }) => [type, name, address].join(' '))
    .join('\n');
}

function lookupAddressR2 (args) {
  return lookupAddressJson(args)
    .map(({ type, name, address }) =>
      ['f', 'sym.' + name, '=', address].join(' '))
    .join('\n');
}

function lookupAddressJson (args) {
  const exportAddress = ptr(args[0]);
  const result = [];
  const modules = Process.enumerateModules().map(m => m.path);
  return modules.reduce((result, moduleName) => {
    return result.concat(Module.enumerateExports(moduleName));
  }, [])
    .reduce((type, obj) => {
      if (ptr(obj.address).compare(exportAddress) === 0) {
        result.push({
          type: obj.type,
          name: obj.name,
          address: obj.address
        });
      }
      return result;
    }, []);
}

function lookupSymbolHere (args) {
  return lookupAddress([ptr(r2frida.offset)]);
}

function lookupExport (args) {
  return lookupExportJson(args)
  // .map(({library, name, address}) => [library, name, address].join(' '))
    .map(({ address }) => '' + address)
    .join('\n');
}

function lookupExportR2 (args) {
  return lookupExportJson(args)
    .map(({ name, address }) =>
      ['f', 'sym.' + name, '=', address].join(' '))
    .join('\n');
}

function lookupExportJson (args) {
  if (args.length === 2) {
    const [moduleName, exportName] = args;
    const address = Module.findExportByName(moduleName, exportName);
    if (address === null) {
      return [];
    }
    const m = getModuleByAddress(address);
    return [{
      library: m.name,
      name: exportName,
      address: address
    }];
  } else {
    const exportName = args[0];
    let prevAddress = null;
    return Process.enumerateModules()
      .reduce((result, m) => {
        const address = Module.findExportByName(m.path, exportName);
        if (address !== null && (prevAddress === null || address.compare(prevAddress))) {
          result.push({
            library: m.name,
            name: exportName,
            address: address
          });
          prevAddress = address;
        }
        return result;
      }, []);
  }
}

// lookup symbols

function lookupSymbol (args) {
  return lookupSymbolJson(args)
  // .map(({library, name, address}) => [library, name, address].join(' '))
    .map(({ address }) => '' + address)
    .join('\n');
}

function lookupSymbolR2 (args) {
  return lookupSymbolJson(args)
    .map(({ name, address }) =>
      ['f', 'sym.' + name, '=', address].join(' '))
    .join('\n');
}

function lookupSymbolManyJson (args) {
  const res = [];
  for (const arg of args) {
    res.push({ name: arg, address: lookupSymbol([arg]) });
  }
  return res;
}

function lookupSymbolMany (args) {
  return lookupSymbolManyJson(args).map(({ address }) => address).join('\n');
}

function lookupSymbolManyR2 (args) {
  return lookupSymbolManyJson(args)
    .map(({ name, address }) =>
      ['f', 'sym.' + name, '=', address].join(' '))
    .join('\n');
}

function lookupSymbolJson (args) {
  if (args.length === 0) {
    return [];
  }
  if (args.length === 2) {
    let [moduleName, symbolName] = args;
    try {
      const m = Process.getModuleByName(moduleName);
      // unused, this needs to be rewritten
    } catch (e) {
      const res = Process.enumerateModules().filter(function (x) {
        return x.name.indexOf(moduleName) !== -1;
      });
      if (res.length !== 1) {
        return [];
      }
      moduleName = res[0].name;
    }
    let address = 0;
    Module.enumerateSymbols(moduleName).filter(function (s) {
      if (s.name === symbolName) {
        address = s.address;
      }
    });
    return [{
      library: moduleName,
      name: symbolName,
      address: address
    }];
  } else {
    const [symbolName] = args;
    const res = getPtr(symbolName);
    const mod = getModuleAt(res);
    if (res) {
      return [{
        library: mod ? mod.name : 'unknown',
        name: symbolName,
        address: res
      }];
    }
    const fcns = DebugSymbol.findFunctionsNamed(symbolName);
    if (fcns) {
      return fcns.map((f) => { return { name: symbolName, address: f }; });
    }
    return [];

    /*
    var at = DebugSymbol.fromName(symbolName);
    if (at.name) {
      return [{
        library: at.moduleName,
        name: symbolName,
        address: at.address
      }];
    }
*/
  }
}

function listEntrypointJson (args) {
  function isEntrypoint (s) {
    if (s.type === 'section') {
      switch (s.name) {
        case '_start':
        case 'start':
        case 'main':
          return true;
      }
    }
    return false;
  }
  if (Process.platform === 'linux') {
    const at = DebugSymbol.fromName('main');
    if (at) {
      return [at];
    }
  }
  const firstModule = Process.enumerateModules()[0];
  return Module.enumerateSymbols(firstModule.name)
    .filter((symbol) => {
      return isEntrypoint(symbol);
    }).map((symbol) => {
      symbol.moduleName = getModuleByAddress(symbol.address).name;
      return symbol;
    });
}

function listEntrypointR2 (args) {
  let n = 0;
  return listEntrypointJson()
    .map((entry) => {
      return 'f entry' + (n++) + ' = ' + entry.address;
    }).join('\n');
}

function listEntrypointQuiet (args) {
  return listEntrypointJson()
    .map((entry) => {
      return entry.address;
    }).join('\n');
}

function listEntrypoint (args) {
  const n = 0;
  return listEntrypointJson()
    .map((entry) => {
      return entry.address + ' ' + entry.name + '  # ' + entry.moduleName;
    }).join('\n');
}

function analFunctionSignature (args) {
  if (!ObjCAvailable) {
    return 'Error: afs is only implemented for ObjC methods.';
  }
  if (args.length === 0) {
    return 'Usage: afs [class] [method]';
  }
  if (args.length === 1) {
    return listClasses(args);
  }
  if (args.length > 1) {
    const klassName = args[0];
    const methodName = args[1].replace(/:/g, '_');
    const klass = ObjC.classes[klassName];
    if (!klass) {
      // try to resolve from DebugSymbol
      const at = klassName.startsWith('0x')
        ? DebugSymbol.fromAddress(ptr(klassName))
        : DebugSymbol.fromName(klassName);
      if (at) {
        return JSON.stringify(at);
      }
      return 'Cannot find class named ' + klassName;
    }
    // const instance = ObjC.chooseSync(ObjC.classes[klassName])[0];
    const instance = ObjC.chooseSync(klass)[0];
    if (!instance) {
      return 'Cannot find any instance for ' + klassName;
    }
    const method = instance[methodName];
    if (!method) {
      return 'Cannot find method ' + methodName + ' for class ' + klassName;
    }
    return method.returnType + ' (' + method.argumentTypes.join(', ') + ');';
  }
  return 'Usage: afs [klassName] [methodName]';
}

function listImports (args) {
  return listImportsJson(args)
    .map(({ type, name, module, address }) => [address, type ? type[0] : ' ', name, module].join(' '))
    .join('\n');
}

function listImportsR2 (args) {
  const seen = new Set();
  return listImportsJson(args).map((x) => {
    const flags = [];
    if (!seen.has(x.address)) {
      seen.add(x.address);
      flags.push('f sym.imp.' + utils.flagify(x.name) + ` = ${x.address}`);
    }
    if (x.slot !== undefined) {
      const fn = utils.flagify(`f reloc.${x.targetModuleName}.${x.name}_${x.index}`);
      flags.push(`f ${fn} = ${x.slot}`);
    }
    return flags.join('\n');
  }).join('\n');
}

function listImportsJson (args) {
  const alen = args.length;
  let result = [];
  let moduleName = null;
  if (alen === 2) {
    moduleName = args[0];
    const importName = args[1];
    const imports = Module.enumerateImports(moduleName);
    if (imports !== null) {
      result = imports.filter((x, i) => {
        x.index = i;
        return x.name === importName;
      });
    }
  } else if (alen === 1) {
    moduleName = args[0];
    result = Module.enumerateImports(moduleName) || [];
  } else {
    const currentModule = getModuleByAddress(r2frida.offset);
    if (currentModule) {
      result = Module.enumerateImports(currentModule.name) || [];
    }
  }
  result.forEach((x, i) => {
    if (x.index === undefined) {
      x.index = i;
    }
    x.targetModuleName = moduleName;
  });
  return result;
}

function listClassesLoadedJson (args) {
  if (JavaAvailable) {
    return listClasses(args);
  }
  if (ObjCAvailable) {
    return JSON.stringify(ObjC.enumerateLoadedClassesSync());
  }
}

function listClassesLoaders (args) {
  if (!JavaAvailable) {
    return 'Error: icL is only available on Android targets.';
  }
  let res = '';
  javaPerform(function () {
    function s2o (s) {
      let indent = 0;
      let res = '';
      for (const ch of s.toString()) {
        switch (ch) {
          case '[':
            indent++;
            res += '[\n' + Array(indent + 1).join(' ');
            break;
          case ']':
            indent--;
            res += ']\n' + Array(indent + 1).join(' ');
            break;
          case ',':
            res += ',\n' + Array(indent + 1).join(' ');
            break;
          default:
            res += ch;
            break;
        }
      }
      return res;
    }
    const c = Java.enumerateClassLoadersSync();
    for (const cl in c) {
      const cs = s2o(c[cl].toString());
      res += cs;
    }
  });
  return res;
}

function listClassesLoaded (args) {
  if (JavaAvailable) {
    return listClasses(args);
  }
  if (ObjCAvailable) {
    const results = ObjC.enumerateLoadedClassesSync();
    const loadedClasses = [];
    for (const module of Object.keys(results)) {
      loadedClasses.push(...results[module]);
    }
    return loadedClasses.join('\n');
  }
  return [];
}

// only for java
function listAllClassesNatives (args) {
  return listClassesNatives(['.']);
}

function listClassesNatives (args) {
  const natives = [];
  const vkn = args[0] || 'com';
  javaPerform(function () {
    const klasses = listClassesJson([]);
    for (let kn of klasses) {
      kn = kn.toString();
      // if (kn.indexOf('android') !== -1) { continue; }
      if (kn.indexOf(vkn) === -1) {
        continue;
      }
      try {
        const handle = javaUse(kn);
        const klass = handle.class;
        const klassNatives = klass.getMethods().map(_ => _.toString()).filter(_ => _.indexOf('static native') !== -1);
        if (klassNatives.length > 0) {
          const kns = klassNatives.map((n) => {
            const p = n.indexOf('(');
            let sn = '';
            if (p !== -1) {
              const s = n.substring(0, p);
              const w = s.split(' ');
              sn = w[w.length - 1];
              return sn;
            }
            return n; // { name: sn, fullname: n };
          });
          console.error(kns.join('\n'));
          for (const tkn of kns) {
            if (natives.indexOf(tkn) === -1) {
              natives.push(tkn);
            }
          }
        }
      } catch (ignoreError) {
      }
    }
  });
  return natives;
}

function listClassesAllMethods (args) {
  return listClassesJson(args, 'all').join('\n');
}

function listClassSuperMethods (args) {
  return listClassesJson(args, 'super').join('\n');
}

function listClassVariables (args) {
  return listClassesJson(args, 'ivars').join('\n');
}

function listClassesHooks (args, mode) {
  let out = '';
  if (args.length === 0) {
    return 'Usage: :ich [kw]';
  }
  const moduleNames = {};
  const result = listClassesJson([]);
  if (ObjCAvailable) {
    const klasses = ObjC.classes;
    for (const k of result) {
      moduleNames[k] = ObjC.classes[k].$moduleName;
    }
  }
  for (const k of result) {
    const modName = moduleNames[k];
    if (k.indexOf(args[0]) !== -1 || (modName && modName.indexOf(args[0]) !== -1)) {
      const ins = searchInstancesJson([k]);
      const inss = ins.map((x) => { return x.address; }).join(' ');
      const a = 'OOO';
      const klass = ObjC.classes[k];
      if (klass) {
        for (const m of klass.$ownMethods) {
          // TODO: use instance.argumentTypes to generate the 'OOO'
          out += ':dtf objc:' + k + '.' + m + ' ' + a + '\n';
        }
      }
    }
  }
  return out;
}

function listClassesWhere (args, mode) {
  let out = '';
  if (args.length === 0) {
    const moduleNames = {};
    const result = listClassesJson([]);
    if (ObjCAvailable) {
      const klasses = ObjC.classes;
      for (const k of result) {
        moduleNames[k] = klasses[k].$moduleName;
      }
    }
    for (const klass of result) {
      const modName = moduleNames[klass];
      out += [modName, klass].join(' ') + '\n';
    }
    return out;
  } else {
    const moduleNames = {};
    const result = listClassesJson([]);
    if (ObjCAvailable) {
      const klasses = ObjC.classes;
      for (const k of result) {
        moduleNames[k] = ObjC.classes[k].$moduleName;
      }
    }
    for (const k of result) {
      const modName = moduleNames[k];
      if (modName && modName.indexOf(args[0]) != -1) {
        const ins = searchInstancesJson([k]);
        const inss = ins.map((x) => { return x.address; }).join(' ');
        out += k + ' # ' + inss + '\n';
        if (mode === 'ivars') {
          for (const a of ins) {
            out += 'instance ' + padPointer(a.address) + '\n';
            const i = new ObjC.Object(ptr(a.address));
            out += (JSON.stringify(i.$ivars)) + '\n';
          }
        }
      }
    }
    return out;
  }
}

function listClasses (args) {
  const result = listClassesJson(args);
  if (result instanceof Array) {
    return result.join('\n');
  }
  return Object.keys(result)
    .map(methodName => {
      const address = result[methodName];
      return [padPointer(address), methodName].join(' ');
    })
    .join('\n');
}

function classGlob (k, v) {
  if (!k || !v) {
    return true;
  }
  return k.indexOf(v.replace(/\*/g, '')) !== -1;
}

function listClassesR2 (args) {
  const className = args[0];
  if (args.length === 0 || args[0].indexOf('*') !== -1) {
    let methods = '';
    if (ObjCAvailable) {
      for (const cn of Object.keys(ObjC.classes)) {
        if (classGlob(cn, args[0])) {
          methods += listClassesR2([cn]);
        }
      }
    }
    return methods;
  }
  const result = listClassesJson(args);
  return Object.keys(result)
    .map(methodName => {
      const address = result[methodName];
      return ['f', flagName(methodName), '=', padPointer(address)].join(' ');
    })
    .join('\n') + '\n';

  function flagName (m) {
    return 'sym.objc.' +
      (className + '.' + m)
        .replace(':', '')
        .replace(' ', '')
        .replace('-', '')
        .replace('+', '');
  }
}

/* this ugly sync mehtod with while+settimeout is needed because
  returning a promise is not properly handled yet and makes r2
  lose track of the output of the command so you cant grep on it */
function listJavaClassesJsonSync (args) {
  if (args.length === 1) {
    let methods;
    /* list methods */
    javaPerform(function () {
      const obj = javaUse(args[0]);
      methods = Object.getOwnPropertyNames(Object.getPrototypeOf(obj));
      // methods = Object.keys(obj).map(x => x + ':' + obj[x] );
    });
    // eslint-disable-next-line
    while (methods === undefined) {
      /* wait here */
      setTimeout(null, 0);
    }
    return methods;
  }
  let classes;
  javaPerform(function () {
    try {
      classes = Java.enumerateLoadedClassesSync();
    } catch (e) {
      classes = null;
    }
  });
  return classes;
}

// eslint-disable-next-line
function listJavaClassesJson (args, classMethodsOnly) {
  let res = [];
  if (args.length === 1) {
    javaPerform(function () {
      try {
        const arg = args[0];
        const handle = javaUse(arg);
        if (handle === null || !handle.class) {
          throw new Error('Cannot find a classloader for this class');
        }
        const klass = handle.class;
        try {
          if (classMethodsOnly) {
            klass.getMethods().filter(x => x.toString().indexOf(arg) !== -1).map(_ => res.push(_.toString()));
          } else {
            klass.getMethods().map(_ => res.push(_.toString()));
          }
          klass.getFields().map(_ => res.push(_.toString()));
          try {
            klass.getConstructors().map(_ => res.push(_.toString()));
          } catch (ignore) {
          }
        } catch (e) {
          console.error(e.message);
          console.error(Object.keys(klass), JSON.stringify(klass), klass);
        }
      } catch (e) {
        console.error(e.message);
      }
    });
  } else {
    javaPerform(function () {
      try {
        res = Java.enumerateLoadedClassesSync();
      } catch (e) {
        console.error(e);
      }
    });
  }
  return res;
}

function listClassMethods (args) {
  return listClassesJson(args, 'methods').join('\n');
}

function listClassMethodsJson (args) {
  return listClassesJson(args, 'methods');
}

function listClassesJson (args, mode) {
  if (JavaAvailable) {
    return listJavaClassesJson(args, mode === 'methods');
  }
  if (!ObjCAvailable) {
    return [];
  }
  if (args.length === 0) {
    return Object.keys(ObjC.classes);
  }
  const klassName = args[0];
  const klass = ObjC.classes[klassName];
  if (klass === undefined) {
    throw new Error('Class ' + klassName + ' not found');
  }
  let out = '';
  if (mode === 'ivars') {
    const ins = searchInstancesJson([klassName]);
    out += klassName + ': ';
    for (const i of ins) {
      out += 'instance ' + padPointer(ptr(i.address)) + ': ';
      const ii = new ObjC.Object(ptr(i.address));
      out += JSON.stringify(ii.$ivars, null, '  ');
    }
    return [out];
  }
  const methods =
(mode === 'methods')
  ? klass.$ownMethods
  : (mode === 'super')
      ? klass.$super.$ownMethods
      : (mode === 'all')
          ? klass.$methods
          : klass.$ownMethods;
  const getImpl = ObjC.api.method_getImplementation;
  try {
    return methods
      .reduce((result, methodName) => {
        try {
          result[methodName] = getImpl(klass[methodName].handle);
        } catch (_) {
          console.error('warning: unsupported method \'' + methodName + '\' in ' + klassName);
        }
        return result;
      }, {});
  } catch (e) {
    return methods;
  }
}

function listProtocols (args) {
  return listProtocolsJson(args)
    .join('\n');
}

function closeFileDescriptors (args) {
  if (args.length === 0) {
    return 'Please, provide a file descriptor';
  }
  return _close(+args[0]);
}

function listFileDescriptors (args) {
  return listFileDescriptorsJson(args).map(([fd, name]) => {
    return fd + ' ' + name;
  }).join('\n');
}

function listFileDescriptorsJson (args) {
  const PATH_MAX = 4096;
  function getFdName (fd) {
    if (_readlink && Process.platform === 'linux') {
      const fdPath = path.join('proc', '' + getPid(), 'fd', '' + fd);
      const buffer = Memory.alloc(PATH_MAX);
      const source = Memory.alloc(PATH_MAX);
      source.writeUtf8String(fdPath);
      buffer.writeUtf8String('');
      if (_readlink(source, buffer, PATH_MAX) !== -1) {
        return buffer.readUtf8String();
      }
      return undefined;
    }
    try {
      // TODO: port this to iOS
      const F_GETPATH = 50; // on macOS
      const buffer = Memory.alloc(PATH_MAX);
      const addr = Module.getExportByName(null, 'fcntl');
      const fcntl = new NativeFunction(addr, 'int', ['int', 'int', 'pointer']);
      fcntl(fd, F_GETPATH, buffer);
      return buffer.readCString();
    } catch (e) {
      return '';
    }
  }
  if (args.length === 0) {
    const statBuf = Memory.alloc(128);
    const fds = [];
    for (let i = 0; i < 1024; i++) {
      if (_fstat(i, statBuf) === 0) {
        fds.push(i);
      }
    }
    return fds.map((fd) => {
      return [fd, getFdName(fd)];
    });
  } else {
    const rc = _dup2(+args[0], +args[1]);
    return rc;
  }
}

function listStringsJson (args) {
  if (!args || args.length !== 1) {
    args = [r2frida.offset];
  }
  const base = ptr(args[0]);
  const currentRange = Process.findRangeByAddress(base);
  if (currentRange) {
    const options = { base: base }; // filter for urls?
    const length = Math.min(currentRange.size, 1024 * 1024 * 128);
    const block = 1024 * 1024; // 512KB
    if (length !== currentRange.size) {
      const curSize = currentRange.size / (1024 * 1024);
      console.error('Warning: this range is too big (' + curSize + 'MB), truncated to ' + length / (1024 * 1024) + 'MB');
    }
    try {
      const res = [];
      console.log('Reading ' + (length / (1024 * 1024)) + 'MB ...');
      for (let i = 0; i < length; i += block) {
        const addr = currentRange.base.add(i);
        const bytes = addr.readCString(block);
        const blockResults = strings(bytes.split('').map(_ => _.charCodeAt(0)), options);
        res.push(...blockResults);
      }
      return res;
    } catch (e) {
      console.log(e.message);
    }
  }
  throw new Error('Memory not mapped here');
}

function listStrings (args) {
  if (!args || args.length !== 1) {
    args = [ptr(r2frida.offset)];
  }
  const base = ptr(args[0]);
  return listStringsJson(args).map(({ base, text }) => padPointer(base) + `  "${text}"`).join('\n');
}

function listProtocolsJson (args) {
  if (!ObjCAvailable) {
    return [];
  }
  if (args.length === 0) {
    return Object.keys(ObjC.protocols);
  } else {
    const protocol = ObjC.protocols[args[0]];
    if (protocol === undefined) {
      throw new Error('Protocol not found');
    }
    return Object.keys(protocol.methods);
  }
}

function listMallocMaps (args) {
  const heaps = squashRanges(listMallocRangesJson(args));
  function inRange (x) {
    for (const heap of heaps) {
      if (x.base.compare(heap.base) >= 0 &&
      x.base.add(x.size).compare(heap.base.add(heap.size))) {
        return true;
      }
    }
    return false;
  }
  return squashRanges(listMemoryRangesJson())
    .filter(inRange)
    .map(({ base, size, protection, file }) =>
      [
        padPointer(base),
        '-',
        padPointer(base.add(size)),
        protection,
      ]
        .concat((file !== undefined) ? [file.path] : [])
        .join(' ')
    )
    .join('\n') + '\n';
}

function listMallocRangesJson (args) {
  return Process.enumerateMallocRanges();
}

function listMallocRangesR2 (args) {
  const chunks = listMallocRangesJson(args)
    .map(_ => 'f chunk.' + _.base + ' ' + _.size + ' ' + _.base).join('\n');
  return chunks + squashRanges(listMallocRangesJson(args))
    .map(_ => 'f heap.' + _.base + ' ' + _.size + ' ' + _.base).join('\n');
}

function listMallocRanges (args) {
  return squashRanges(listMallocRangesJson(args))
    .map(_ => '' + _.base + ' - ' + _.base.add(_.size) + '  (' + _.size + ')').join('\n') + '\n';
}

function listMemoryMapsHere (args) {
  if (args.length !== 1) {
    args = [ptr(r2frida.offset)];
  }
  const addr = ptr(args[0]);
  return squashRanges(listMemoryRangesJson())
    .filter(({ base, size }) => addr.compare(base) >= 0 && addr.compare(base.add(size)) < 0)
    .map(({ base, size, protection, file }) => {
      return [
        padPointer(base),
        '-',
        padPointer(base.add(size)),
        protection,
        file.path
      ].join(' ');
    })
    .join('\n') + '\n';
}

function listMemoryRangesHere (args) {
  if (args.length !== 1) {
    args = [ptr(r2frida.offset)];
  }
  const addr = ptr(args[0]);
  return listMemoryRangesJson()
    .filter(({ base, size }) => addr.compare(base) >= 0 && addr.compare(base.add(size)) < 0)
    .map(({ base, size, protection, file }) =>
      [
        padPointer(base),
        '-',
        padPointer(base.add(size)),
        protection,
      ]
        .concat((file !== undefined) ? [file.path] : [])
        .join(' ')
    )
    .join('\n') + '\n';
}

function rwxstr (x) {
  let str = '';
  str += (x & 1) ? 'r' : '-';
  str += (x & 2) ? 'w' : '-';
  str += (x & 4) ? 'x' : '-';
  return str;
}

function rwxint (x) {
  const ops = ['---', '--x', '-w-', '-wx', 'r--', 'r-x', 'rw-', 'rwx'];
  return ops.indexOf([x]);
}

function squashRanges (ranges) {
  const res = [];
  let begin = ptr(0);
  let end = ptr(0);
  let lastPerm = 0;
  let lastFile = '';
  for (const r of ranges) {
    lastPerm |= rwxint(r.protection);
    // console.log("-", r.base, range.base.add(range.size));
    if (r.base.equals(end)) {
      // enlarge segment
      end = end.add(r.size);
      // console.log("enlarge", begin, end);
    } else {
      if (begin.equals(ptr(0))) {
        begin = r.base;
        end = begin.add(r.size);
        // console.log("  set", begin, end);
      } else {
        // console.log("  append", begin, end);
        res.push({
          base: begin,
          size: end.sub(begin),
          protection: rwxstr(lastPerm),
          file: lastFile
        });
        end = ptr(0);
        begin = ptr(0);
        lastPerm = 0;
        lastFile = '';
      }
    }
    if (r.file) {
      lastFile = r.file;
    }
  }
  if (!begin.equals(ptr(0))) {
    res.push({ base: begin, size: end.sub(begin), protection: rwxstr(lastPerm), file: lastFile });
  }
  return res;
}

function listMemoryMapsR2 () {
  function filterFile (file) {
    return file.replace(/\//g, '_').replace(/-/g, '_');
  }
  return squashRanges(listMemoryRangesJson())
    .filter(_ => _.file)
    .map(({ base, size, protection, file }) =>
      [
        'f',
        'dmm.' + filterFile(file.path),
        '=',
        padPointer(base),
      ]
        .join(' ')
    )
    .join('\n') + '\n';
}

function listMemoryMaps () {
  return squashRanges(listMemoryRangesJson())
    .filter(_ => _.file)
    .map(({ base, size, protection, file }) =>
      [
        padPointer(base),
        '-',
        padPointer(base.add(size)),
        protection,
      ]
        .concat((file !== undefined) ? [file.path] : [])
        .join(' ')
    )
    .join('\n') + '\n';
}

function listMemoryRangesR2 () {
  return listMemoryRangesJson()
    .map(({ base, size, protection, file }) =>
      [
        'f', 'map.' + padPointer(base),
        '=', base,
        // padPointer(base.add(size)),
        '#',
        protection,
      ]
        .concat((file !== undefined) ? [file.path] : [])
        .join(' ')
    )
    .join('\n') + '\n';
}

function listMemoryRanges () {
  return listMemoryRangesJson()
    .map(({ base, size, protection, file }) =>
      [
        padPointer(base),
        '-',
        padPointer(base.add(size)),
        protection,
      ]
        .concat((file !== undefined) ? [file.path] : [])
        .join(' ')
    )
    .join('\n') + '\n';
}

function listMemoryRangesJson () {
  return _getMemoryRanges('---');
}

function _getMemoryRanges (protection) {
  if (r2frida.hookedRanges !== null) {
    return r2frida.hookedRanges(protection);
  }
  return Process.enumerateRangesSync({
    protection,
    coalesce: false
  });
}

async function changeMemoryProtection (args) {
  const [addr, size, protection] = args;
  if (args.length !== 3 || protection.length > 3) {
    return 'Usage: :dmp [address] [size] [rwx]';
  }
  const address = getPtr(addr);
  const mapsize = await numEval(size);
  Memory.protect(address, ptr(mapsize).toInt32(), protection);
  return '';
}

function getPidJson () {
  return JSON.stringify({ pid: getPid() });
}

function getPid () {
  return _getpid();
}

function listThreads () {
  let canGetThreadName = false;
  try {
    const addr = Module.getExportByName(null, 'pthread_getname_np');
    var pthreadGetnameNp = new NativeFunction(addr, 'int', ['pointer', 'pointer', 'int']);
    const addr2 = Module.getExportByName(null, 'pthread_from_mach_thread_np');
    var pthreadFromMachThreadNp = new NativeFunction(addr2, 'pointer', ['uint']);
    canGetThreadName = true;
  } catch (e) {
    // do nothing
  }

  function getThreadName (tid) {
    if (!canGetThreadName) {
      return '';
    }
    const buffer = Memory.alloc(4096);
    const p = pthreadFromMachThreadNp(tid);
    pthreadGetnameNp(p, buffer, 4096);
    return buffer.readCString();
  }

  return Process.enumerateThreads().map((thread) => {
    const threadName = getThreadName(thread.id);
    return [thread.id, threadName].join(' ');
  }).join('\n') + '\n';
}

function listThreadsJson () {
  return Process.enumerateThreads()
    .map(thread => thread.id);
}

function regProfileAliasFor (arch) {
  switch (arch) {
    case 'arm64':
      return `=PC pc
=SP sp
=BP x29
=A0 x0
=A1 x1
=A2 x2
=A3 x3
=ZF zf
=SF nf
=OF vf
=CF cf
=SN x8
`;
    case 'arm':
      return `=PC r15
=LR r14
=SP sp
=BP fp
=A0 r0
=A1 r1
=A2 r2
=A3 r3
=ZF zf
=SF nf
=OF vf
=CF cf
=SN r7
`;
    case 'ia64':
    case 'x64':
      return `=PC rip
=SP rsp
=BP rbp
=A0 rdi
=A1 rsi
=A2 rdx
=A3 rcx
=A4 r8
=A5 r9
=SN rax
`;
    case 'ia32':
    case 'x86':
      return `=PC eip
=SP esp
=BP ebp
=A0 eax
=A1 ebx
=A2 ecx
=A3 edx
=A4 esi
=A5 edi
=SN eax
`;
  }
  return '';
}

function dumpRegisterProfile (args) {
  const threads = Process.enumerateThreads();
  const context = threads[0].context;
  const names = Object.keys(JSON.parse(JSON.stringify(context)))
    .filter(_ => _ !== 'pc' && _ !== 'sp');
  names.sort(compareRegisterNames);
  let off = 0;
  const inc = Process.pointerSize;
  let profile = regProfileAliasFor(Process.arch);
  for (const reg of names) {
    profile += `gpr\t${reg}\t${inc}\t${off}\t0\n`;
    off += inc;
  }
  return profile;
}

function dumpRegisterArena (args) {
  const threads = Process.enumerateThreads();
  let [tidx] = args;
  if (!tidx) {
    tidx = 0;
  }
  if (tidx < 0 || tidx >= threads.length) {
    return '';
  }
  const context = threads[tidx].context;
  const names = Object.keys(JSON.parse(JSON.stringify(context)))
    .filter(_ => _ !== 'pc' && _ !== 'sp');
  names.sort(compareRegisterNames);
  let off = 0;
  const inc = Process.pointerSize;
  const buf = Buffer.alloc(inc * names.length);
  for (const reg of names) {
    const r = context[reg];
    const b = [r.and(0xff),
      r.shr(8).and(0xff),
      r.shr(16).and(0xff),
      r.shr(24).and(0xff),
      r.shr(32).and(0xff),
      r.shr(40).and(0xff),
      r.shr(48).and(0xff),
      r.shr(56).and(0xff)];
    for (let i = 0; i < inc; i++) {
      buf.writeUInt8(b[i], off + i);
    }
    off += inc;
  }
  return buf.toString('hex');
}

function regcursive (regname, regvalue) {
  const data = [regvalue];
  try {
    const str = Memory.readCString(regvalue, 32);
    if (str && str.length > 3) {
      const printableString = str.replace(/[^\x20-\x7E]/g, '');
      data.push('\'' + printableString + '\'');
    }
    const ptr = regvalue.readPointer();
    data.push('=>');
    data.push(regcursive(regname, ptr));
  } catch (e) {
  }
  if (regvalue === 0) {
    data.push('NULL');
  } else if (regvalue === 0xffffffff) {
    data.push(-1);
  } else if (regvalue > ' ' && regvalue < 127) {
    data.push('\'' + String.fromCharCode(regvalue) + '\'');
  }
  try {
    const module = Process.findModuleByAddress(regvalue);
    if (module) {
      data.push(module.name);
    }
  } catch (e) {
  }
  try {
    const name = nameFromAddress(regvalue);
    if (name) {
      data.push(name);
    }
  } catch (e) {
  }
  return data.join(' ');
}

function dumpRegistersRecursively (args) {
  const [tid] = args;
  Process.enumerateThreads()
    .filter(thread => !tid || tid === thread.id)
    .map(thread => {
      const { id, state, context } = thread;
      const res = ['# thread ' + id + ' ' + state];
      for (const reg of Object.keys(context)) {
        try {
          const data = regcursive(reg, context[reg]);
          res.push(reg + ': ' + data);
        } catch (e) {
          res.push(reg);
        }
      }
      console.log(res.join('\n'));
    });
  return ''; // nothing to see here
}

function dumpRegistersR2 (args) {
  const threads = Process.enumerateThreads();
  const [tid] = args;
  const context = tid ? threads.filter(th => th.id === tid) : threads[0].context;
  if (!context) {
    return '';
  }
  const names = Object.keys(JSON.parse(JSON.stringify(context)));
  names.sort(compareRegisterNames);
  const values = names
    .map((name, index) => {
      if (name === 'pc' || name === 'sp') return '';
      const value = context[name] || 0;
      return `ar ${name} = ${value}\n`;
    });
  return values.join('');
}

function dumpRegisters (args) {
  const [tid] = args;
  return Process.enumerateThreads()
    .filter(thread => !tid || thread.id === tid)
    .map(thread => {
      const { id, state, context } = thread;
      const heading = `tid ${id} ${state}`;
      const names = Object.keys(JSON.parse(JSON.stringify(context)));
      names.sort(compareRegisterNames);
      const values = names
        .map((name, index) => alignRight(name, 3) + ' : ' + padPointer(context[name]))
        .map(indent);
      return heading + '\n' + values.join('');
    })
    .join('\n\n') + '\n';
}

function dumpRegistersJson () {
  return Process.enumerateThreads();
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

function loadFrameworkBundle (args) {
  if (!ObjCAvailable) {
    console.log('dlf: This command requires the objc runtime');
    return false;
  }
  const path = args[0];
  const app_path = ObjC.classes.NSBundle.mainBundle().bundlePath();
  const full_path = app_path.stringByAppendingPathComponent_(path);
  const bundle = ObjC.classes.NSBundle.bundleWithPath_(full_path);
  if (bundle.isLoaded()) {
    console.log('Bundle already loaded');
    return false;
  }
  return bundle.load();
}

function unloadFrameworkBundle (args) {
  if (!ObjCAvailable) {
    console.log('dlf: This command requires the objc runtime');
    return false;
  }
  const path = args[0];
  const app_path = ObjC.classes.NSBundle.mainBundle().bundlePath();
  const full_path = app_path.stringByAppendingPathComponent_(path);
  const bundle = ObjC.classes.NSBundle.bundleWithPath_(full_path);
  if (!bundle.isLoaded()) {
    console.log('Bundle already unloaded');
    return false;
  }
  return bundle.unload();
}

function changeSelinuxContext (args) {
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

function formatArgs (args, fmt) {
  const a = [];
  const dumps = [];
  let arg; let j = 0;
  for (let i = 0; i < fmt.length; i++, j++) {
    try {
      arg = args[j];
    } catch (err) {
      console.error('invalid format', i);
    }
    switch (fmt[i]) {
      case '+':
      case '^':
        j--;
        break;
      case 'h': {
        // hexdump pointer target, default length 128
        // customize length with h<length>, f.e. h16 to dump 16 bytes
        let dumpLen = 128;
        const optionalNumStr = fmt.slice(i + 1).match(/^[0-9]*/)[0];
        if (optionalNumStr.length > 0) {
          i += optionalNumStr.length;
          dumpLen = +optionalNumStr;
        }
        dumps.push(_hexdumpUntrusted(arg, dumpLen));
        a.push(`dump:${dumps.length} (len=${dumpLen})`);
      }
        break;
      case 'H': {
        // hexdump pointer target, default length 128
        // use length from other funtion arg with H<arg number>, f.e. H0 to dump '+args[0]' bytes
        let dumpLen = 128;
        const optionalNumStr = fmt.slice(i + 1).match(/^[0-9]*/)[0];
        if (optionalNumStr.length > 0) {
          i += optionalNumStr.length;
          const posLenArg = +optionalNumStr;
          if (posLenArg !== j) {
            // only adjust dump length, if the length param isn't the dump address itself
            dumpLen = +args[posLenArg];
          }
        }
        // limit dumpLen, to avoid oversized dumps, caused by  accidentally parsing pointer agrs as length
        // set length limit to 64K for now
        const lenLimit = 0x10000;
        dumpLen = dumpLen > lenLimit ? lenLimit : dumpLen;
        dumps.push(_hexdumpUntrusted(arg, dumpLen));
        a.push(`dump:${dumps.length} (len=${dumpLen})`);
      }
        break;
      case 'x':
        a.push('' + ptr(arg));
        break;
      case 'c':
        a.push("'" + arg + "'");
        break;
      case 'i':
        a.push(+arg);
        break;
      case 'z': // *s
        const s = _readUntrustedUtf8(arg);
        a.push(JSON.stringify(s));
        break;
      case 'Z': // *s[i]
        const len = +args[j + 1];
        const str = _readUntrustedUtf8(arg, len);
        a.push(JSON.stringify(str));
        break;
      case 'S': // **s
        const sss = _readUntrustedUtf8(Memory.readPointer(arg));
        a.push(JSON.stringify(sss));
        break;
      case 'o':
      case 'O':
        if (ObjC.available) {
          if (!arg.isNull()) {
            if (isObjC(arg)) {
              const o = new ObjC.Object(arg);
              a.push(`${o.$className}: "${o.toString()}"`);
            } else {
              const str = Memory.readCString(arg);
              if (str.length > 2) {
                a.push(str);
              } else {
                a.push('' + arg);
              }
            }
          } else {
            a.push('nil');
          }
        } else {
          a.push(arg);
        }
        break;
      default:
        a.push(arg);
        break;
    }
  }
  return { args: a, dumps: dumps };
}

function cloneArgs (args, fmt) {
  const a = [];
  let j = 0;
  for (let i = 0; i < fmt.length; i++, j++) {
    const arg = args[j];
    switch (fmt[i]) {
      case '+':
      case '^':
        j--;
        break;
      default:
        a.push(arg);
        break;
    }
  }
  return a;
}

function _hexdumpUntrusted (addr, len) {
  try {
    if (typeof len === 'number') return hexdump(addr, { length: len });
    else return hexdump(addr);
  } catch (e) {
    return `hexdump at ${addr} failed: ${e}`;
  }
}

function _readUntrustedUtf8 (address, length) {
  try {
    if (typeof length === 'number') {
      return Memory.readUtf8String(ptr(address), length);
    }
    return Memory.readUtf8String(ptr(address));
  } catch (e) {
    if (e.message !== 'invalid UTF-8') {
      // TODO: just use this, doo not mess with utf8 imho
      return Memory.readCString(ptr(address));
    }
    return '(invalid utf8)';
  }
}

function traceList () {
  let count = 0;
  return traceListeners.map((t) => {
    return [count++, t.hits, t.at, t.source, t.moduleName, t.name, t.args].join('\t');
  }).join('\n') + '\n';
}

function traceListJson () {
  return traceListeners.map(_ => JSON.stringify(_)).join('\n') + '\n';
}

function getPtr (p) {
  if (typeof p === 'string') {
    p = p.trim();
  }
  if (!p || p === '$$') {
    return ptr(global.r2frida.offset);
  }
  if (p.startsWith('swift:')) {
    if (!SwiftAvailable) {
      return ptr(0);
    }
    // swift:CLASSNAME.method
    const km = p.substring(6).split('.');
    if (km.length !== 2) {
      return ptr(0);
    }
    const klass = km[0];
    const method = km[1];
    if (!Swift.classes[klass]) {
      console.error('Missing class ' + klass);
      return;
    }
    const klassDefinition = Swift.classes[klass];
    let targetAddress = ptr(0);
    for (const kd of klassDefinition.$methods) {
      if (method === kd.name) {
        targetAddress = kd.address;
      }
    }
    return p;
  }
  if (p.startsWith('java:')) {
    return p;
  }
  if (p.startsWith('objc:')) {
    const hatSign = p.indexOf('^') !== -1;
    if (hatSign !== -1) {
      p = p.replace('^', '');
    }
    const endsWith = p.endsWith('$');
    if (endsWith) {
      p = p.substring(0, p.length - 1);
    }
    p = p.substring(5);
    let dot = p.indexOf('.');
    if (dot === -1) {
      dot = p.indexOf(':');
      if (dot === -1) {
        throw new Error('r2frida\'s ObjC class syntax is: objc:CLASSNAME.METHOD');
      }
    }
    const kv0 = p.substring(0, dot);
    const kv1 = p.substring(dot + 1);
    const klass = ObjC.classes[kv0];
    if (klass === undefined) {
      throw new Error('Class ' + kv0 + ' not found');
    }
    let found = null;
    let firstFail = false;
    let oldMethodName = null;
    for (const methodName of klass.$ownMethods) {
      const method = klass[methodName];
      if (methodName.indexOf(kv1) !== -1) {
        if (hatSign && !methodName.substring(2).startsWith(kv1)) {
          continue;
        }
        if (endsWith && !methodName.endsWith(kv1)) {
          continue;
        }
        if (found) {
          if (!firstFail) {
            console.error(found.implementation, oldMethodName);
            firstFail = true;
          }
          console.error(method.implementation, methodName);
        }
        found = method;
        oldMethodName = methodName;
      }
    }
    if (firstFail) {
      return ptr(0);
    }
    return found ? found.implementation : ptr(0);
  }
  try {
    if (p.substring(0, 2) === '0x') {
      return ptr(p);
    }
  } catch (e) {
    // console.error(e);
  }
  // return DebugSymbol.fromAddress(ptr_p) || '' + ptr_p;
  return Module.findExportByName(null, p);
}

function traceHook (args) {
  if (args.length === 0) {
    return JSON.stringify(tracehooks, null, 2);
  }
  const arg = args[0];
  if (arg !== undefined) {
    tracehookSet(arg, args.slice(1).join(' '));
  }
  return '';
}

function traceFormat (args) {
  if (args.length === 0) {
    return traceList();
  }
  let address, format;
  const name = args[0];
  if (args.length === 2) {
    address = '' + getPtr(name);
    format = args[1];
  } else if (args.length === 1) {
    address = '' + getPtr(name);
    format = '';
  } else {
    address = global.r2frida.offset;
    format = args[0];
  }
  if (haveTraceAt(address)) {
    return 'There\'s already a trace in here';
  }
  const traceOnEnter = format.indexOf('^') !== -1;
  const traceBacktrace = format.indexOf('+') !== -1;
  const useCmd = config.getString('hook.usecmd');

  const currentModule = getModuleByAddress(address);
  const listener = Interceptor.attach(ptr(address), {
    myArgs: [],
    myBacktrace: [],
    keepArgs: [],
    onEnter: function (args) {
      traceListener.hits++;
      if (!traceOnEnter) {
        this.keepArgs = cloneArgs(args, format);
      } else {
        const fa = formatArgs(args, format);
        this.myArgs = fa.args;
        this.myDumps = fa.dumps;
      }
      if (traceBacktrace) {
        this.myBacktrace = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
      }
      if (traceOnEnter) {
        const traceMessage = {
          source: 'dtf',
          name: name,
          address: address,
          timestamp: new Date(),
          values: this.myArgs,
        };
        if (config.getBoolean('hook.backtrace')) {
          traceMessage.backtrace = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
        }
        if (config.getString('hook.output') === 'json') {
          traceEmit(traceMessage);
        } else {
          let msg = `[dtf onEnter][${traceMessage.timestamp}] ${name}@${address} - args: ${this.myArgs.join(', ')}`;
          if (config.getBoolean('hook.backtrace')) {
            msg += ` backtrace: ${traceMessage.backtrace.toString()}`;
          }
          for (let i = 0; i < this.myDumps.length; i++) msg += `\ndump:${i + 1}\n${this.myDumps[i]}`;
          traceEmit(msg);
        }
        if (useCmd.length > 0) {
          console.log('[r2cmd]' + useCmd);
        }
      }
    },
    onLeave: function (retval) {
      if (!traceOnEnter) {
        const fa = formatArgs(this.keepArgs, format);
        this.myArgs = fa.args;
        this.myDumps = fa.dumps;

        const traceMessage = {
          source: 'dtf',
          name: name,
          address: address,
          timestamp: new Date(),
          values: this.myArgs,
          retval
        };
        if (config.getBoolean('hook.backtrace')) {
          traceMessage.backtrace = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
        }
        if (config.getString('hook.output') === 'json') {
          traceEmit(traceMessage);
        } else {
          let msg = `[dtf onLeave][${traceMessage.timestamp}] ${name}@${address} - args: ${this.myArgs.join(', ')}. Retval: ${retval.toString()}`;
          if (config.getBoolean('hook.backtrace')) {
            msg += ` backtrace: ${traceMessage.backtrace.toString()}`;
          }
          for (let i = 0; i < this.myDumps.length; i++) msg += `\ndump:${i + 1}\n${this.myDumps[i]}`;
          traceEmit(msg);
        }
        if (useCmd.length > 0) {
          console.log('[r2cmd]' + useCmd);
        }
      }
    }
  });
  const traceListener = {
    source: 'dtf',
    hits: 0,
    at: ptr(address),
    name: name,
    moduleName: currentModule ? currentModule.name : '',
    format: format,
    listener: listener
  };
  traceListeners.push(traceListener);
  return true;
}

function traceListenerFromAddress (address) {
  const results = traceListeners.filter((tl) => '' + address === '' + tl.at);
  return (results.length > 0) ? results[0] : undefined;
}

function traceCountFromAddress (address) {
  const tl = traceListenerFromAddress(address);
  return tl ? tl.hits : 0;
}

function traceNameFromAddress (address) {
  const tl = traceListenerFromAddress(address);
  return tl ? tl.moduleName + ':' + tl.name : '';
}

function traceLogDumpQuiet () {
  return logs.map(({ address, timestamp }) =>
    [address, timestamp, traceCountFromAddress(address), traceNameFromAddress(address)].join(' '))
    .join('\n') + '\n';
}

function traceLogDumpJson () {
  return JSON.stringify(logs);
}

function traceLogDumpR2 () {
  let res = '';
  for (const l of logs) {
    if (l.script) {
      res += l.script;
    }
  }
  return res;
}

function objectToString (o) {
  // console.error(JSON.stringify(o));
  const r = Object.keys(o).map((k) => {
    try {
      const p = ptr(o[k]);
      if (isObjC(p)) {
        const o = new ObjC.Object(p);
        return k + ': ' + o.toString();
      }
      const str = Memory.readCString(p);
      if (str.length > 2) {
        return k + ': "' + str + '"';
      }
    } catch (e) {
    }
    return k + ': ' + o[k];
  }).join(' ');
  return '(' + r + ')';
}

function tracelogToString (l) {
  const line = [l.source, l.name || l.address, objectToString(l.values)].join('\t');
  const bt = (!l.backtrace)
    ? ''
    : l.backtrace.map((b) => {
      return ['', b.address, b.moduleName, b.name].join('\t');
    }).join('\n') + '\n';
  return line + bt;
}

function traceLogDump () {
  return logs.map(tracelogToString).join('\n') + '\n';
}

function traceLogClear (args) {
  // TODO: clear one trace instead of all
  console.error('ARGS', JSON.stringify(args));
  return traceLogClearAll();
}

function traceLogClearAll () {
  logs = [];
  traces = {};
  return '';
}

function traceEmit (msg) {
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
  global.r2frida.logs = logs;
}

function traceLog (msg) {
  if (config.getBoolean('hook.verbose')) {
    send(wrapStanza('log', {
      message: msg
    }));
  }
}

function haveTraceAt (address) {
  try {
    for (const trace of traceListeners) {
      if (trace.at.compare(address) === 0) {
        return true;
      }
    }
  } catch (e) {
    console.error(e);
  }
  return false;
}

function traceRegs (args) {
  if (args.length < 1) {
    return 'Usage: dtr [name|address] [reg ...]';
  }
  const address = getPtr(args[0]);
  if (haveTraceAt(address)) {
    return 'There\'s already a trace in here';
  }
  const rest = args.slice(1);
  const currentModule = getModuleByAddress(address);
  const listener = Interceptor.attach(address, traceFunction);
  function traceFunction (_) {
    traceListener.hits++;
    const regState = {};
    rest.forEach((r) => {
      let regName = r;
      let regValue;
      if (r.indexOf('=') !== -1) {
        const kv = r.split('=');
        this.context[kv[0]] = ptr(kv[1]); // set register value
        regName = kv[0];
        regValue = kv[1];
      } else {
        try {
          const rv = ptr(this.context[r]);
          regValue = rv;
          let tail = Memory.readCString(rv);
          if (tail) {
            tail = ' (' + tail + ')';
            regValue += tail;
          }
        } catch (e) {
          // do nothing
        }
      }
      regState[regName] = regValue;
    });
    const traceMessage = {
      source: 'dtr',
      address: address,
      timestamp: new Date(),
      values: regState,
    };
    if (config.getBoolean('hook.backtrace')) {
      traceMessage.backtrace = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
    }
    if (config.getString('hook.output') === 'json') {
      traceEmit(traceMessage);
    } else {
      let msg = `[dtr][${traceMessage.timestamp}] ${address} - registers: ${JSON.stringify(regState)}`;
      if (config.getBoolean('hook.backtrace')) {
        msg += ` backtrace: ${traceMessage.backtrace.toString()}`;
      }
      traceEmit(msg);
    }
  }
  const traceListener = {
    source: 'dtr',
    hits: 0,
    at: address,
    moduleName: currentModule ? currentModule.name : 'unknown',
    name: args[0],
    listener: listener,
    args: rest
  };
  traceListeners.push(traceListener);
  return '';
}

function traceHere () {
  const args = [r2frida.offset];
  args.forEach(address => {
    const at = DebugSymbol.fromAddress(ptr(address)) || '' + ptr(address);
    const listener = Interceptor.attach(ptr(address), function () {
      const bt = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
      const at = nameFromAddress(address);
      console.log('Trace here probe hit at ' + address + '::' + at + '\n\t' + bt.join('\n\t'));
    });
    traceListeners.push({
      at: at,
      listener: listener
    });
  });
  return true;
}

function traceR2 (args) {
  return traceListeners.map(_ => `dt+ ${_.at} ${_.hits}`).join('\n') + '\n';
}

function dumpJavaArguments (args) {
  let res = '';
  try {
    for (const a of args) {
      try {
        res += a.toString() + ' ';
      } catch (ee) {
      }
    }
  } catch (e) {
  }
  return res;
}

function traceJavaConstructors (className) {
  javaPerform(function () {
    const foo = Java.use(className).$init.overloads;
    foo.forEach((over) => {
      over.implementation = function () {
        console.log('dt', className, '(', dumpJavaArguments(arguments), ')');
        if (config.getBoolean('hook.backtrace')) {
          const Throwable = Java.use('java.lang.Throwable');
          const bt = Throwable.$new().getStackTrace().map(_ => _.toString()).join('\n- ') + '\n';
          console.log('-', bt);
        }
        return over.apply(this, arguments);
      };
    });
  });
}

function traceSwift (klass, method) {
  if (!SwiftAvailable) {
    return;
  }
  const targetAddress = getPtr('swift:' + klass + '.' + method);
  if (ptr(0).equals(targetAddress)) {
    console.error('Missing method ' + method + ' in class ' + klass);
    return;
  }

  const callback = function (args) {
    const msg = ['[SWIFT]', klass, method, JSON.stringify(args)];
    traceEmit(msg.join(' '));
  };
  Swift.Interceptor.Attach(target, callback);
}

function traceJava (klass, method) {
  javaPerform(function () {
    const Throwable = Java.use('java.lang.Throwable');
    const k = javaUse(klass);
    k[method].implementation = function (args) {
      const res = this[method]();
      const bt = config.getBoolean('hook.backtrace')
        ? Throwable.$new().getStackTrace().map(_ => _.toString())
        : [];
      const traceMessage = {
        source: 'dt',
        klass: klass,
        method: method,
        backtrace: bt,
        timestamp: new Date(),
        result: res,
        values: args
      };
      if (config.getString('hook.output') === 'json') {
        traceEmit(traceMessage);
      } else {
        let msg = `[JAVA TRACE][${traceMessage.timestamp}] ${klass}:${method} - args: ${JSON.stringify(args)}. Return value: ${res.toString()}`;
        if (config.getBoolean('hook.backtrace')) {
          msg += ` backtrace: \n${traceMessage.backtrace.toString().split(',').join('\nat ')}\n`;
        }
        traceEmit(msg);
      }
      return res;
    };
  });
}

function traceQuiet (args) {
  return traceListeners.map(({ address, hits, moduleName, name }) => [address, hits, moduleName + ':' + name].join(' ')).join('\n') + '\n';
}

function traceJson (args) {
  if (args.length === 0) {
    return traceListJson();
  }
  if (args[0].startsWith('java:')) {
    traceReal(args[0]);
    return;
  }
  return new Promise(function (resolve, reject) {
    (function pull () {
      const arg = args.pop();
      if (arg === undefined) {
        return resolve('');
      }
      const narg = getPtr(arg);
      if (narg) {
        traceReal(arg, narg);
        pull();
      } else {
        numEval(arg).then(function (at) {
          console.error(traceReal(arg, at));
          pull();
        }).catch(reject);
      }
    })();
  });
}

function typesR2 (args) {
  let res = '';
  if (SwiftAvailable) {
    switch (args.length) {
      case 0:
        for (const mod in Swift.modules) {
          res += mod + '\n';
        }
        break;
      case 1:
        try {
          const target = args[0];
          const module = (Swift && Swift.modules) ? Swift.modules[target] : null;
          if (!module) {
            throw new Error('No module named like this.');
          }
          let m = module.enums;
          if (m) {
            for (const e of Object.keys(m)) {
              res += 'td enum ' + e + ' {';
              const fields = [];
              if (m[e].$fields) {
                for (const f of m[e].$fields) {
                  fields.push(f.name);
                }
              }
              res += fields.join(', ');
              res += '}\n';
            }
          }
          m = Swift.modules[target].classes;
          if (m) {
            for (const e of Object.keys(m)) {
              if (m[e].$methods) {
                for (const f of m[e].$methods) {
                  const name = f.type + '_' + (f.name ? f.name : f.address);
                  res += 'f swift.' + target + '.' + e + '.' + name + ' = ' + f.address + '\n';
                }
              }
            }
          }
          m = Swift.modules[target].structs;
          if (m) {
            for (const e of Object.keys(m)) {
              res += '"td struct ' + target + '.' + e + ' {';
              if (m[e].$fields) {
                for (const f of m[e].$fields) {
                  res += 'int ' + f.name + ';';
                  // res += '  ' + f.name + ' ' + f.typeName + '\n';
                }
              }
              res += '}"\n';
            }
          }
        } catch (e) {
          res += e;
        }
        break;
    }
  }
  return res;
}

function types (args) {
  let res = '';
  if (SwiftAvailable) {
    switch (args.length) {
      case 0:
        for (const mod in Swift.modules) {
          res += mod + '\n';
        }
        break;
      case 1:
        try {
          const target = args[0];
          const module = (Swift && Swift.modules) ? Swift.modules[target] : null;
          if (!module) {
            throw new Error('No module named like this.');
          }
          res += 'module ' + target + '\n\n';
          let m = module.enums;
          if (m) {
            for (const e of Object.keys(m)) {
              if (e.$conformances) {
                res += '// conforms to ' + (m[e].$conformances.join(', ')) + '\n';
              }
              res += 'enum ' + e + ' {\n';
              if (m[e].$fields) {
                for (const f of m[e].$fields) {
                  res += '  ' + f.name + ',\n';
                }
              }
              res += '}\n';
            }
            res += '\n';
          }
          m = Swift.modules[target].classes;
          if (m) {
            for (const e of Object.keys(m)) {
              res += 'class ' + e + ' {\n';
              if (m[e].$fields) {
                for (const f of m[e].$fields) {
                  res += '  ' + f.name + ' ' + f.typeName + '\n';
                }
              }
              if (m[e].$methods) {
                for (const f of m[e].$methods) {
                  const name = f.type + (f.name ? f.name : f.address);
                  res += '  fn ' + name + '() // ' + f.address + '\n';
                }
              }
              res += '}\n';
            }
            res += '\n';
          }
          m = Swift.modules[target].structs;
          if (m) {
            for (const e of Object.keys(m)) {
              if (e.$conformances) {
                res += '// conforms to ' + (m[e].$conformances.join(', ')) + '\n';
              }
              res += 'struct ' + e + ' {\n';
              if (m[e].$fields) {
                for (const f of m[e].$fields) {
                  res += '  ' + f.name + ' ' + f.typeName + '\n';
                }
              }
              res += '}\n';
            }
            res += '\n';
          }
          m = module.protocols;
          if (m) {
            for (const e of Object.keys(m)) {
              if (m[e].isClassOnly) {
                res += 'class ';
              }
              res += 'protocol ' + e + ' (requires: ' + m[e].numRequirements + ')\n';
            }
            res += '\n';
          }
        } catch (e) {
          res += e;
        }
        break;
    }
  }
  return res;
}

function trace (args) {
  if (args.length === 0) {
    return traceList();
  }
  return traceJson(args);
}

function tracehookSet (name, format, callback) {
  if (name === null) {
    console.error('Name was not resolved');
    return false;
  }
  tracehooks[name] = {
    format: format,
    callback: callback
  };
  return true;
}

function arrayBufferToHex (arrayBuffer) {
  if (typeof arrayBuffer !== 'object' || arrayBuffer === null || typeof arrayBuffer.byteLength !== 'number') {
    throw new TypeError('Expected input to be an ArrayBuffer');
  }

  const view = new Uint8Array(arrayBuffer);
  let result = '';
  let value;

  for (let i = 0; i < view.length; i++) {
    value = view[i].toString(16);
    result += (value.length === 1 ? '0' + value : value);
  }

  return result;
}

// \dth printf 0,1 .. kind of dtf
function tracehook (address, args) {
  const at = nameFromAddress(address);
  const th = tracehooks[at];
  const fmtarg = [];
  if (th && th.format) {
    for (const fmt of th.format.split(' ')) {
      const [k, v] = fmt.split(':');
      switch (k) {
        case 'i':
        // console.log('int', args[v]);
          fmtarg.push(+args[v]);
          break;
        case 's':
          {
            const [a, l] = v.split(',');
            const addr = ptr(args[a]);
            const size = +args[l];
            // const buf = Memory.readByteArray(addr, size);
            // console.log('buf', arrayBufferToHex(buf));
            // console.log('string', Memory.readCString(addr, size));
            fmtarg.push(Memory.readCString(addr, size));
          }
          break;
        case 'z':
        // console.log('string', Memory.readCString(args[+v]));
          fmtarg.push(Memory.readCString(ptr(args[+v])));
          break;
        case 'v':
          {
            const [a, l] = v.split(',');
            const addr = ptr(args[a]);
            const buf = Memory.readByteArray(addr, +args[l]);
            fmtarg.push(arrayBufferToHex(buf));
          }
          break;
      }
    }
  }
  return fmtarg;
}

function traceReal (name, addressString) {
  if (arguments.length === 0) {
    return traceList();
  }
  if (name.startsWith('swift:')) {
    const km = name.substring(6);
    const dot = km.lastIndexOf('.');
    if (dot === -1) {
      return 'Invalid syntax for swift uri. Use "swift:KLASS.METHOD"';
    }
    const klass = km.substring(0, dot);
    const methd = km.substring(dot + 1);
    return traceSwift(klass, methd);
  }
  if (name.startsWith('java:')) {
    const javaName = name.substring(5);
    if (javaUse(javaName)) {
      console.error('Tracing class constructors');
      traceJavaConstructors(javaName);
    } else {
      const dot = javaName.lastIndexOf('.');
      if (dot !== -1) {
        const klass = javaName.substring(0, dot);
        const methd = javaName.substring(dot + 1);
        traceJava(klass, methd);
      } else {
        console.log('Invalid java method name. Use :dt java:package.class.method');
      }
    }
    return;
  }
  const address = ptr(addressString);
  if (haveTraceAt(address)) {
    return 'There\'s already a trace in here';
  }
  const currentModule = getModuleByAddress(address);
  const listener = Interceptor.attach(address, function (args) {
    const values = tracehook(address, args);
    const traceMessage = {
      source: 'dt',
      address: address,
      timestamp: new Date(),
      values: values,
    };
    traceListener.hits++;
    if (config.getString('hook.output') === 'json') {
      traceEmit(traceMessage);
    } else {
      traceEmit(`[dt][${traceMessage.timestamp}] ${address} - args: ${JSON.stringify(values)}`);
    }
  });
  const traceListener = {
    source: 'dt',
    at: address,
    hits: 0,
    name: name,
    moduleName: currentModule ? currentModule.name : 'unknown',
    args: '',
    listener: listener
  };
  traceListeners.push(traceListener);
  return '';
}

function clearAllTrace (args) {
  traceListeners.splice(0).forEach(lo => lo.listener ? lo.listener.detach() : null);
  return '';
}

function clearTrace (args) {
  if (args.length > 0 && +args[0] > 0) {
    const res = [];
    const nth = +args[0];
    for (let i = 0; i < traceListeners.length; i++) {
      const tl = traceListeners[i];
      if (i === nth) {
        tl.listener.detach();
      } else {
        res.push(tl);
      }
    }
  }
  return '';
}

function interceptHelp (args) {
  return 'Usage: di[f][0,1,-1,s] [addr] : intercept function [without] method calling and replace return value\n';
  'dif0 0x808080  # when program calls this address, dont run the function and return 0\n';
}

function interceptFunRetJava (klass, method, value) {
  javaPerform(function () {
    const System = javaUse(klass);
    System[method].implementation = function (library) {
      const timestamp = new Date();
      if (config.getString('hook.output') === 'json') {
        traceEmit({
          source: 'java',
          class: klass,
          method,
          returnValue: value,
          timestamp
        });
      } else {
        traceEmit(`[JAVA TRACE][${timestamp}] Intercept return for ${klass}:${method} with ${value}`);
      }
      switch (value) {
        case 0: return false;
        case 1: return true;
        case -1: return -1; // TODO should throw an error?
      }
      return value;
    };
  });
}

function interceptRetJava (className, methodName, value) {
  javaPerform(function () {
    const targetClass = javaUse(className);
    targetClass[methodName].overload().implementation = function () {
      const timestamp = new Date();
      if (config.getString('hook.output') === 'json') {
        traceEmit({
          source: 'java',
          class: className,
          methodName,
          returnValue: value,
          timestamp
        });
      } else {
        traceEmit(`[JAVA TRACE][${timestamp}] Intercept return for ${className}:${methodName} with ${value}`);
      }
      console.log(methodName);
      this[methodName]();
      switch (value) {
        case 0: return false;
        case 1: return true;
        case -1: return -1; // TODO should throw an error?
      }
      return value;
    };
  });
}

function parseTargetJavaExpression (target) {
  let klass = target.substring('java:'.length);
  const lastDot = klass.lastIndexOf('.');
  if (lastDot !== -1) {
    const method = klass.substring(lastDot + 1);
    klass = klass.substring(0, lastDot);
    return [klass, method];
  }
  throw new Error('Error: Wrong java method syntax');
}

/* Intercept function call and modify the return value after calling the original function code */
function interceptRet (target, value) {
  if (target.startsWith('java:')) {
    try {
      const java_target = parseTargetJavaExpression(target, value);
      return interceptRetJava(java_target[0], java_target[1], value);
    } catch(e) {
      return e.message
    }
  }
  const p = getPtr(target);
  Interceptor.attach(p, {
    onLeave (retval) {
      retval.replace(ptr(value));
    }
  });
}

function interceptRet0 (args) {
  const target = args[0];
  return interceptRet(target, 0);
}

function interceptRetString (args) {
  const target = args[0];
  return interceptRet(target, args[1]);
}

function interceptRetInt (args) {
  const target = args[0];
  return interceptRet(target, args[1]);
}

function interceptRet1 (args) {
  const target = args[0];
  return interceptRet(target, 1);
}

function interceptRet_1 (args) { // eslint-disable-line
  const target = args[0];
  return interceptRet(target, -1);
}

/* Intercept function calls and modify return value without calling the original function code */
function interceptFunRet (target, value) {
  if (target.startsWith('java:')) {
    const java_target = parseTargetJavaExpression(target, value);
    return interceptFunRetJava(java_target[0], java_target[1], value);
  }
  const p = getPtr(target);
  const useCmd = config.getString('hook.usecmd');
  Interceptor.replace(p, new NativeCallback(function () {
    if (useCmd.length > 0) {
      console.log('[r2cmd]' + useCmd);
    }
    return ptr(value);
  }, 'pointer', ['pointer']));
}

function interceptFunRet0 (args) {
  const target = args[0];
  return interceptFunRet(target, 0);
}

function interceptFunRetString (args) {
  const target = args[0];
  return interceptFunRet(target, args[1]);
}

function interceptFunRetInt (args) {
  const target = args[0];
  return interceptFunRet(target, args[1]);
}

function interceptFunRet1 (args) {
  const target = args[0];
  return interceptFunRet(target, 1);
}

function interceptFunRet_1 (args) { // eslint-disable-line
  const target = args[0];
  return interceptFunRet(target, -1);
}

function getenv (name) {
  return Memory.readUtf8String(_getenv(Memory.allocUtf8String(name)));
}

function setenv (name, value, overwrite) {
  return _setenv(Memory.allocUtf8String(name), Memory.allocUtf8String(value), overwrite ? 1 : 0);
}

function getWindowsUserNameA () {
  const _GetUserNameA = sym('GetUserNameA', 'int', ['pointer', 'pointer']);
  const PATH_MAX = 4096;
  const buf = Memory.allocUtf8String('A'.repeat(PATH_MAX));
  const char_out = Memory.allocUtf8String('A'.repeat(PATH_MAX));
  const res = _GetUserNameA(buf, char_out);
  if (res) {
    return Memory.readCString(buf);
  }
  return '';
}

function stalkTraceFunction (args) {
  return _stalkTraceSomething(_stalkFunctionAndGetEvents, args);
}

function stalkTraceFunctionR2 (args) {
  return _stalkTraceSomethingR2(_stalkFunctionAndGetEvents, args);
}

function stalkTraceFunctionJson (args) {
  return _stalkTraceSomethingJson(_stalkFunctionAndGetEvents, args);
}

function stalkTraceEverything (args) {
  if (args.length === 0) {
    return 'Warnnig: dts is experimental and slow\nUsage: dts [symbol]';
  }
  return _stalkTraceSomething(_stalkEverythingAndGetEvents, args);
}

function stalkTraceEverythingR2 (args) {
  if (args.length === 0) {
    return 'Warnnig: dts is experimental and slow\nUsage: dts* [symbol]';
  }
  return _stalkTraceSomethingR2(_stalkEverythingAndGetEvents, args);
}

function stalkTraceEverythingJson (args) {
  if (args.length === 0) {
    return 'Warnnig: dts is experimental and slow\nUsage: dtsj [symbol]';
  }
  return _stalkTraceSomethingJson(_stalkEverythingAndGetEvents, args);
}

function _stalkTraceSomething (getEvents, args) {
  return getEvents(args, (isBlock, events) => {
    let previousSymbolName;
    const result = [];
    const threads = Object.keys(events);

    for (const threadId of threads) {
      result.push(`; --- thread ${threadId} --- ;`);
      if (isBlock) {
        result.push(..._mapBlockEvents(events[threadId], (address) => {
          const pd = disasmOne(address, previousSymbolName);
          previousSymbolName = getSymbolName(address);
          return pd;
        }, (begin, end) => {
          previousSymbolName = null;
          return '';
        }));
      } else {
        result.push(...events[threadId].map((event) => {
          const address = event[0];
          const target = event[1];
          const pd = disasmOne(address, previousSymbolName, target);
          previousSymbolName = getSymbolName(address);
          return pd;
        }));
      }
    }
    return result.join('\n') + '\n';
  });

  function disasmOne (address, previousSymbolName, target) {
    let pd = disasm(address, 1, previousSymbolName);
    if (pd.endsWith('\n')) {
      pd = pd.slice(0, -1);
    }
    if (target) {
      pd += ` ; ${target} ${getSymbolName(target)}`;
    }
    return pd;
  }
}

function _stalkTraceSomethingR2 (getEvents, args) {
  return getEvents(args, (isBlock, events) => {
    const result = [];
    const threads = Object.keys(events);

    for (const threadId of threads) {
      if (isBlock) {
        result.push(..._mapBlockEvents(events[threadId], (address) => {
          return `dt+ ${address} 1`;
        }));
      } else {
        result.push(...events[threadId].map((event) => {
          const commands = [];

          const location = event[0];
          commands.push(`dt+ ${location} 1`);

          const target = event[1];
          if (target) {
            commands.push(`CC ${target} ${getSymbolName(target)} @ ${location}`);
          }
          return commands.join('\n') + '\n';
        }));
      }
    }

    return result.join('\n') + '\n';
  });
}

function _stalkTraceSomethingJson (getEvents, args) {
  return getEvents(args, (isBlock, events) => {
    const result = {
      event: config.get('stalker.event'),
      threads: events
    };

    return result;
  });
}

function _stalkFunctionAndGetEvents (args, eventsHandler) {
  _requireFridaVersion(10, 3, 13);

  const at = getPtr(args[0]);
  const conf = {
    event: config.get('stalker.event'),
    timeout: config.get('stalker.timeout'),
    stalkin: config.get('stalker.in')
  };
  const isBlock = conf.event === 'block' || conf.event === 'compile';

  const operation = stalkFunction(conf, at)
    .then((events) => {
      return eventsHandler(isBlock, events);
    });

  breakpointContinue([]);
  return operation;
}

function _stalkEverythingAndGetEvents (args, eventsHandler) {
  _requireFridaVersion(10, 3, 13);

  const timeout = (args.length > 0) ? +args[0] : null;
  const conf = {
    event: config.get('stalker.event'),
    timeout: config.get('stalker.timeout'),
    stalkin: config.get('stalker.in')
  };
  const isBlock = conf.event === 'block' || conf.event === 'compile';

  const operation = stalkEverything(conf, timeout)
    .then((events) => {
      return eventsHandler(isBlock, events);
    });

  breakpointContinue([]);
  return operation;
}

function getSymbolName (address) {
  const ds = DebugSymbol.fromAddress(address);
  return (ds.name === null || ds.name.indexOf('0x') === 0) ? '' : ds.name;
}

function _requireFridaVersion (major, minor, patch) {
  const required = [major, minor, patch];
  const actual = Frida.version.split('.');
  for (let i = 0; i < actual.length; i++) {
    if (actual[i] > required[i]) {
      return;
    }
    if (actual[i] < required[i]) {
      throw new Error(`Frida v${major}.${minor}.${patch} or higher required for this (you have v${Frida.version}).`);
    }
  }
}

function _mapBlockEvents (events, onInstruction, onBlock) {
  const result = [];

  events.forEach(([begin, end]) => {
    if (typeof onBlock === 'function') {
      result.push(onBlock(begin, end));
    }
    let cursor = begin;
    while (cursor < end) {
      const [instr, next] = _tolerantInstructionParse(cursor);
      if (instr !== null) {
        result.push(onInstruction(cursor));
      }
      cursor = next;
    }
  });

  return result;
}

function _tolerantInstructionParse (address) {
  let instr = null;
  let cursor = address;
  try {
    instr = Instruction.parse(cursor);
    cursor = instr.next;
  } catch (e) {
    if (e.message !== 'invalid instruction' &&
        e.message !== `access violation accessing ${cursor}`) {
      throw e;
    }
    if (e.message.indexOf('access violation') !== -1) {
      // cannot access the memory
    } else {
      // console.log(`warning: error parsing instruction at ${cursor}`);
    }
    // skip invalid instructions
    switch (Process.arch) {
      case 'arm64':
        cursor = cursor.add(4);
        break;
      case 'arm':
        cursor = cursor.add(2);
        break;
      default:
        cursor = cursor.add(1);
        break;
    }
  }

  return [instr, cursor];
}

function compareRegisterNames (lhs, rhs) {
  const lhsIndex = parseRegisterIndex(lhs);
  const rhsIndex = parseRegisterIndex(rhs);

  const lhsHasIndex = lhsIndex !== null;
  const rhsHasIndex = rhsIndex !== null;

  if (lhsHasIndex && rhsHasIndex) {
    return lhsIndex - rhsIndex;
  }
  if (lhsHasIndex === rhsHasIndex) {
    const lhsLength = lhs.length;
    const rhsLength = rhs.length;
    if (lhsLength === rhsLength) {
      return lhs.localeCompare(rhs);
    }
    if (lhsLength > rhsLength) {
      return 1;
    }
    return -1;
  }
  if (lhsHasIndex) {
    return 1;
  }
  return -1;
}

function parseRegisterIndex (name) {
  const length = name.length;
  for (let index = 1; index < length; index++) {
    const value = parseInt(name.substr(index));
    if (!isNaN(value)) {
      return value;
    }
  }
  return null;
}

function indent (message, index) {
  if (index === 0) {
    return message;
  }
  if ((index % 3) === 0) {
    return '\n' + message;
  }
  return '\t' + message;
}

function alignRight (text, width) {
  let result = text;
  while (result.length < width) {
    result = ' ' + result;
  }
  return result;
}

function padPointer (value) {
  let result = value.toString(16);
  const paddedLength = 2 * pointerSize;
  while (result.length < paddedLength) {
    result = '0' + result;
  }
  return '0x' + result;
}

const requestHandlers = {
  safeio: () => { r2frida.safeio = true; },
  read: io.read,
  write: io.write,
  state: state,
  perform: perform,
  evaluate: evaluate,
};

function state (params, data) {
  r2frida.offset = params.offset;
  suspended = params.suspended;
  return [{}, null];
}

function isPromise (value) {
  return value !== null && typeof value === 'object' && typeof value.then === 'function';
}

function stalkTraceEverythingHelp () {
  return `Usage: dts[j*] [symbol|address] - Trace given symbol using the Frida Stalker
dtsf[*j] [sym|addr]        Trace address or symbol using the stalker
dts[*j] seconds            Trace all threads for given seconds using the stalker
`;
}

function getHelpMessage (prefix) {
  return Object.keys(commandHandlers).sort()
    .filter((k) => {
      return !prefix || k.startsWith(prefix);
    })
    .map((k) => {
      const desc = commandHandlers[k].name
        .replace(/(?:^|\.?)([A-Z])/g, function (x, y) {
          return ' ' + y.toLowerCase();
        }).replace(/^_/, '');
      return ' ' + k + '\t' + desc;
    }).join('\n') + '\n';
}

function perform (params) {
  const { command } = params;

  const tokens = command.split(/ /).map((c) => c.trim()).filter((x) => x);
  const [name, ...args] = tokens;
  if (typeof name === 'undefined') {
    const value = getHelpMessage('');
    return [{
      value: normalizeValue(value)
    }, null];
  }
  if (name.length > 0 && name.endsWith('?') && !commandHandlers[name]) {
    const prefix = name.substring(0, name.length - 1);
    const value = getHelpMessage(prefix);
    return [{
      value: normalizeValue(value)
    }, null];
  }
  const userHandler = global.r2frida.commandHandler(name);
  const handler = userHandler !== undefined
    ? userHandler
    : commandHandlers[name];
  if (handler === undefined) {
    throw new Error('Unhandled command: ' + name);
  }

  if (isPromise(handler)) {
    throw new Error("The handler can't be a promise");
  }
  const value = handler(args);
  if (isPromise(value)) {
    return new Promise((resolve, reject) => {
      return value.then(output => {
        resolve([{
          value: normalizeValue(output)
        }, null]);
      }).catch(reject);
    });
  }
  const nv = normalizeValue(value);
  if (nv === '' || nv === 'null' || nv === undefined || nv === null) {
    return [{}, null];
  }
  return [{ value: nv }, null];
}

function normalizeValue (value) {
  if (typeof value === null || typeof value === undefined) {
    return null;
  }
  if (typeof value === 'undefined') {
    return 'undefined';
  }
  if (typeof value === 'string') {
    return value;
  }
  return JSON.stringify(value);
}

function evaluate (params) {
  return new Promise(resolve => {
    let { code, ccode } = params;
    const isObjcMainLoopRunning = ObjCAvailable && hasMainLoop();

    if (ObjCAvailable && isObjcMainLoopRunning && !suspended) {
      ObjC.schedule(ObjC.mainQueue, performEval);
    } else {
      performEval();
    }

    function performEval () {
      let result;
      try {
        if (ccode) {
          code = `
var m = new CModule(` + '`' + ccode + '`' + `);
const main = new NativeFunction(m.main, 'int', []);
main();
`;
        }
        const rawResult = (1, eval)(code); // eslint-disable-line
        global._ = rawResult;
        result = rawResult; // 'undefined';
      } catch (e) {
        result = 'throw new ' + e.name + '("' + e.message + '")';
      }

      resolve([{
        value: result
      }, null]);
    }
  });
}

function hasMainLoop () {
  const getMainPtr = Module.findExportByName(null, 'CFRunLoopGetMain');
  if (getMainPtr === null) {
    return false;
  }

  const copyCurrentModePtr = Module.findExportByName(null, 'CFRunLoopCopyCurrentMode');
  if (copyCurrentModePtr === null) {
    return false;
  }

  const getMain = new NativeFunction(getMainPtr, 'pointer', []);
  const copyCurrentMode = new NativeFunction(copyCurrentModePtr, 'pointer', ['pointer']);

  const main = getMain();
  if (main.isNull()) {
    return false;
  }

  const mode = copyCurrentMode(main);
  const hasLoop = !mode.isNull();

  if (hasLoop) {
    new ObjC.Object(mode).release();
  }

  return hasLoop;
}

Script.setGlobalAccessHandler({
  enumerate () {
    return [];
  },
  get (property) {
    return undefined;
  }
});

function fridaVersion () {
  return { version: Frida.version };
}

function uiAlertAndroid (args) {
  if (args.length < 2) {
    return 'Usage: ?E title message';
  }
  const title = args[0];
  const message = args.slice(1).join(' ');
  Java.perform(function () {
    const System = Java.use('java.lang.System');
    const ActivityThread = Java.use('android.app.ActivityThread');
    const AlertDialogBuilder = Java.use('android.app.AlertDialog$Builder');
    const DialogInterfaceOnClickListener = Java.use('android.content.DialogInterface$OnClickListener');

    Java.use('android.app.Activity').onCreate.overload('android.os.Bundle').implementation = function (savedInstanceState) {
      const currentActivity = this;

      // Get Main Activity
      const application = ActivityThread.currentApplication();
      const launcherIntent = application.getPackageManager().getLaunchIntentForPackage(application.getPackageName());
      const launchActivityInfo = launcherIntent.resolveActivityInfo(application.getPackageManager(), 0);

      // Alert Will Only Execute On Main Package Activity Creation
      if (launchActivityInfo.name.value === this.getComponentName().getClassName()) {
        const alert = AlertDialogBuilder.$new(this);
        alert.setMessage(title + message); // "What you want to do now?");

        /*
            alert.setPositiveButton("Dismiss", Java.registerClass({
                name: 'il.co.realgame.OnClickListenerPositive',
                implements: [DialogInterfaceOnClickListener],
                methods: {
                    getName: function() {
                        return 'OnClickListenerPositive';
                    },
                    onClick: function(dialog, which) {
                        // Dismiss
                        dialog.dismiss();
                    }
                }
            }).$new());

            alert.setNegativeButton("Force Close!", Java.registerClass({
                name: 'il.co.realgame.OnClickListenerNegative',
                implements: [DialogInterfaceOnClickListener],
                methods: {
                    getName: function() {
                        return 'OnClickListenerNegative';
                    },
                    onClick: function(dialog, which) {
                        // Close Application
                        currentActivity.finish();
                        System.exit(0);
                    }
                }
            }).$new());

*/
        // Create Alert
        alert.create().show();
      }
      return this.onCreate.overload('android.os.Bundle').call(this, savedInstanceState);
    };
  });
}

function uiAlert (args) {
  if (JavaAvailable) {
    return uiAlertAndroid(args);
  }
  if (!ObjCAvailable) {
    return 'Error: ui-alert is not implemented for this platform';
  }
  if (args.length < 2) {
    return 'Usage: ?E title message';
  }
  const title = args[0];
  const message = args.slice(1).join(' ');
  ObjC.schedule(ObjC.mainQueue, function () {
    const UIAlertView = ObjC.classes.UIAlertView; /* iOS 7 */
    const view = UIAlertView.alloc().initWithTitle_message_delegate_cancelButtonTitle_otherButtonTitles_(
      title,
      message,
      NULL,
      'OK',
      NULL);
    view.show();
    view.release();
  });
}

function search (args) {
  return searchJson(args).then(hits => {
    return _readableHits(hits);
  });
}

function echo (args) {
  console.log(args.join(' '));
  return null;
}

function searchJson (args) {
  const pattern = _toHexPairs(args.join(' '));
  return _searchPatternJson(pattern).then(hits => {
    hits.forEach(hit => {
      try {
        const bytes = io.read({
          offset: hit.address,
          count: 60
        })[1];
        hit.content = _filterPrintable(bytes);
      } catch (e) {
      }
    });
    return hits.filter(hit => hit.content !== undefined);
  });
}

function searchInstancesJson (args) {
  const className = args.join('');
  if (ObjCAvailable) {
    const results = JSON.parse(JSON.stringify(ObjC.chooseSync(ObjC.classes[className])));
    return results.map(function (res) {
      return { address: res.handle, content: className };
    });
  } else {
    Java.performNow(function () {
      const results = Java.choose(Java.classes[className]);
      return results.map(function (res) {
        return { address: res, content: className };
      });
    });
  }
}

function searchInstances (args) {
  return _readableHits(searchInstancesJson(args));
}

function searchHex (args) {
  return searchHexJson(args).then(hits => {
    return _readableHits(hits);
  });
}

function searchHexJson (args) {
  const pattern = _normHexPairs(args.join(''));
  return _searchPatternJson(pattern).then(hits => {
    hits.forEach(hit => {
      const bytes = Memory.readByteArray(hit.address, hit.size);
      hit.content = _byteArrayToHex(bytes);
    });
    return hits;
  });
}

function searchWide (args) {
  return searchWideJson(args).then(hits => {
    return _readableHits(hits);
  });
}

function searchWideJson (args) {
  const pattern = _toWidePairs(args.join(' '));
  return searchHexJson([pattern]);
}

function searchValueImpl (width) {
  return function (args) {
    return searchValueJson(args, width).then(hits => {
      return _readableHits(hits);
    });
  };
}

function searchValueImplJson (width) {
  return function (args) {
    return searchValueJson(args, width);
  };
}

function searchValueJson (args, width) {
  let value;
  try {
    value = uint64(args.join(''));
  } catch (e) {
    return new Promise((resolve, reject) => reject(e));
  }

  return hostCmdj('ej')
    .then((r2cfg) => {
      const bigEndian = r2cfg['cfg.bigendian'];
      const bytes = _renderEndian(value, bigEndian, width);
      return searchHexJson([_toHexPairs(bytes)]);
    });
}

function evalConfigSearch (args) {
  const currentRange = Process.getRangeByAddress(ptr(r2frida.offset));
  const from = currentRange.base;
  const to = from.add(currentRange.size);
  return `e search.in=raw
e search.from=${from}
e search.to=${to}
e anal.in=raw
e anal.from=${from}
e anal.to=${to}`;
}

function evalConfigR2 (args) {
  return config.asR2Script();
}

function evalConfig (args) {
  // list
  if (args.length === 0) {
    return config.asR2Script();
  }
  const argstr = args.join(' ');
  const kv = argstr.split(/=/);
  const [k, v] = kv;
  if (kv.length === 2) {
    if (config.get(k) !== undefined) {
      // help
      if (v === '?') {
        return config.helpFor(kv[0]);
      }
      // set (and flatten case for variables except file.log)
      /*
      if (kv[0] !== 'file.log' && typeof kv[1] === 'string') {
        config.set(kv[0], kv[1].toLowerCase());
      } else {
        config.set(kv[0], kv[1]);
      }
*/
      config.set(kv[0], kv[1]);
    } else {
      console.error('unknown variable');
    }
    return '';
  }
  // get
  return config.getString(argstr);
}

function _renderEndian (value, bigEndian, width) {
  const bytes = [];
  for (let i = 0; i !== width; i++) {
    if (bigEndian) {
      bytes.push(value.shr((width - i - 1) * 8).and(0xff).toNumber());
    } else {
      bytes.push(value.shr(i * 8).and(0xff).toNumber());
    }
  }
  return bytes;
}

function _byteArrayToHex (arr) {
  const u8arr = new Uint8Array(arr);
  const hexs = [];
  for (let i = 0; i !== u8arr.length; i += 1) {
    const h = u8arr[i].toString(16);
    hexs.push((h.length === 2) ? h : `0${h}`);
  }
  return hexs.join('');
}

const minPrintable = ' '.charCodeAt(0);
const maxPrintable = '~'.charCodeAt(0);

function _filterPrintable (arr) {
  const u8arr = new Uint8Array(arr);
  const printable = [];
  for (let i = 0; i !== u8arr.length; i += 1) {
    const c = u8arr[i];
    if (c === 0) {
      break;
    }
    if (c >= minPrintable && c <= maxPrintable) {
      printable.push(String.fromCharCode(c));
    }
  }
  return printable.join('');
}

function _readableHits (hits) {
  const output = hits.map(hit => {
    if (typeof hit.flag === 'string') {
      return `${hexPtr(hit.address)} ${hit.flag} ${hit.content}`;
    }
    return `${hexPtr(hit.address)} ${hit.content}`;
  });
  return output.join('\n') + '\n';
}

function hexPtr (p) {
  if (p instanceof UInt64) {
    return `0x${p.toString(16)}`;
  }
  return p.toString();
}

function _searchPatternJson (pattern) {
  return hostCmdj('ej')
    .then(r2cfg => {
      const flags = r2cfg['search.flags'];
      const prefix = r2cfg['search.prefix'] || 'hit';
      const count = r2cfg['search.count'] || 0;
      const kwidx = r2cfg['search.kwidx'] || 0;

      const ranges = _getRanges(r2cfg['search.from'], r2cfg['search.to']);
      const nBytes = pattern.split(' ').length;

      qlog(`Searching ${nBytes} bytes: ${pattern}`);

      let results = [];
      const commands = [];
      let idx = 0;
      for (const range of ranges) {
        if (range.size === 0) {
          continue;
        }

        const rangeStr = `[${padPointer(range.address)}-${padPointer(range.address.add(range.size))}]`;
        qlog(`Searching ${nBytes} bytes in ${rangeStr}`);
        try {
          const partial = _scanForPattern(range.address, range.size, pattern);

          partial.forEach((hit) => {
            if (flags) {
              hit.flag = `${prefix}${kwidx}_${idx + count}`;
              commands.push('fs+searches');
              commands.push(`f ${hit.flag} ${hit.size} ${hexPtr(hit.address)}`);
              commands.push('fs-');
            }
            idx += 1;
          });

          results = results.concat(partial);
        } catch (e) {
          console.error('Oops', e);
        }
      }

      qlog(`hits: ${results.length}`);

      commands.push(`e search.kwidx=${kwidx + 1}`);

      return hostCmds(commands).then(() => {
        return results;
      });
    });

  function qlog (message) {
    if (!config.getBoolean('search.quiet')) {
      console.log(message);
    }
  }
}

function _scanForPattern (address, size, pattern) {
  if (r2frida.hookedScan !== null) {
    return r2frida.hookedScan(address, size, pattern);
  }
  return Memory.scanSync(address, size, pattern);
}

function _configParseSearchIn () {
  const res = {
    current: false,
    perm: 'r--',
    path: null,
    heap: false
  };

  const c = config.getString('search.in');
  const cSplit = c.split(':');
  const [scope, param] = cSplit;

  if (scope === 'current') {
    res.current = true;
  }
  if (scope === 'heap') {
    res.heap = true;
  }
  if (scope === 'perm') {
    res.perm = param;
  }
  if (scope === 'path') {
    cSplit.shift();
    res.path = cSplit.join('');
  }

  return res;
}

function _getRanges (fromNum, toNum) {
  const searchIn = _configParseSearchIn();

  if (searchIn.heap) {
    return Process.enumerateMallocRanges()
      .map(_ => {
        return {
          address: _.base,
          size: _.size
        };
      });
  }
  const ranges = _getMemoryRanges(searchIn.perm).filter(range => {
    const start = range.base;
    const end = start.add(range.size);
    const offPtr = ptr(r2frida.offset);
    if (searchIn.current) {
      return offPtr.compare(start) >= 0 && offPtr.compare(end) < 0;
    }
    if (searchIn.path !== null) {
      if (range.file !== undefined) {
        return range.file.path.indexOf(searchIn.path) >= 0;
      }
      return false;
    }
    return true;
  });

  if (ranges.length === 0) {
    return [];
  }

  const first = ranges[0];
  const last = ranges[ranges.length - 1];

  const from = (fromNum === -1) ? first.base : ptr(fromNum);
  const to = (toNum === -1) ? last.base.add(last.size) : ptr(toNum);

  return ranges.filter(range => {
    return range.base.compare(to) <= 0 && range.base.add(range.size).compare(from) >= 0;
  }).map(range => {
    const start = _ptrMax(range.base, from);
    const end = _ptrMin(range.base.add(range.size), to);
    return {
      address: start,
      size: uint64(end.sub(start).toString()).toNumber()
    };
  });
}

function _ptrMax (a, b) {
  return a.compare(b) > 0 ? a : b;
}

function _ptrMin (a, b) {
  return a.compare(b) < 0 ? a : b;
}

function _toHexPairs (raw) {
  const isString = typeof raw === 'string';
  const pairs = [];
  for (let i = 0; i !== raw.length; i += 1) {
    const code = (isString ? raw.charCodeAt(i) : raw[i]) & 0xff;
    const h = code.toString(16);
    pairs.push((h.length === 2) ? h : `0${h}`);
  }
  return pairs.join(' ');
}

function _toWidePairs (raw) {
  const pairs = [];
  for (let i = 0; i !== raw.length; i += 1) {
    const code = raw.charCodeAt(i) & 0xff;
    const h = code.toString(16);
    pairs.push((h.length === 2) ? h : `0${h}`);
    pairs.push('00');
  }
  return pairs.join(' ');
}

function _normHexPairs (raw) {
  const norm = raw.replace(/ /g, '');
  if (_isHex(norm)) {
    return _toPairs(norm.replace(/\./g, '?'));
  }
  throw new Error('Invalid hex string');
}

function _toPairs (hex) {
  if ((hex.length % 2) !== 0) {
    throw new Error('Odd-length string');
  }

  const pairs = [];
  for (let i = 0; i !== hex.length; i += 2) {
    pairs.push(hex.substr(i, 2));
  }
  return pairs.join(' ').toLowerCase();
}

function _isHex (raw) {
  const hexSet = new Set(Array.from('abcdefABCDEF0123456789?.'));
  const inSet = new Set(Array.from(raw));
  for (const h of hexSet) {
    inSet.delete(h);
  }
  return inSet.size === 0;
}

function fsList (args) {
  return fs.ls(args[0] || Gcwd);
}

function fsGet (args) {
  return fs.cat(args[0] || '', '*', args[1] || 0, args[2] || null);
}

function fsCat (args) {
  return fs.cat(args[0] || '');
}

function fsOpen (args) {
  return fs.open(args[0] || Gcwd);
}

function javaPerform (fn) {
  if (config.getBoolean('java.wait')) {
    return Java.perform(fn);
  }
  return Java.performNow(fn);
}

function performOnJavaVM (fn) {
  return new Promise((resolve, reject) => {
    javaPerform(function () {
      try {
        const result = fn();
        resolve(result);
      } catch (e) {
        reject(e);
      }
    });
  });
}

function getModuleAt (addr) {
  if (addr === null) {
    return null;
  }
  const modules = Process.enumerateModules()
    .filter((m) => {
      const a = m.base;
      const b = m.base.add(m.size);
      return addr.compare(a) >= 0 && addr.compare(b) < 0;
    });
  return modules.length > 0 ? modules[0] : null;
}

let onceStanza = false;
function onStanza (stanza, data) {
  const handler = requestHandlers[stanza.type];
  if (handler !== undefined) {
    try {
      const value = handler(stanza.payload, data);
      if (value instanceof Promise) {
        // handle async stuff in here
        value
          .then(([replyStanza, replyBytes]) => {
            send(wrapStanza('reply', replyStanza), replyBytes);
          })
          .catch(e => {
            send(wrapStanza('reply', {
              error: e.message
            }));
          });
      } else {
        const [replyStanza, replyBytes] = value;
        send(wrapStanza('reply', replyStanza), replyBytes);
      }
    } catch (e) {
      send(wrapStanza('reply', {
        error: e.message
      }));
    }
  } else if (stanza.type === 'bp') {
    console.error('Breakpoint handler');
  } else if (stanza.type === 'cmd') {
    onCmdResp(stanza.payload);
  } else {
    console.error('Unhandled stanza: ' + stanza.type);
  }
  if (!onceStanza) {
    recv(onStanza);
  }
}

let cmdSerial = 0;

function hostCmds (commands) {
  let i = 0;
  function sendOne () {
    if (i < commands.length) {
      return hostCmd(commands[i]).then(() => {
        i += 1;
        return sendOne();
      });
    } else {
      return Promise.resolve();
    }
  }
  return sendOne();
}

function hostCmdj (cmd) {
  return hostCmd(cmd)
    .then(output => {
      return JSON.parse(output);
    });
}

function hostCmd (cmd) {
  return new Promise((resolve) => {
    const serial = cmdSerial;
    cmdSerial++;
    pendingCmds[serial] = resolve;
    sendCommand(cmd, serial);
  });
}

global.r2frida.hostCmd = hostCmd;
global.r2frida.hostCmdj = hostCmdj;
global.r2frida.logs = logs;
global.r2frida.log = traceLog;
global.r2frida.emit = traceEmit;
global.r2frida.safeio = NeedsSafeIo;
global.r2frida.module = '';

function sendCommand (cmd, serial) {
  function sendIt () {
    sendingCommand = true;
    send(wrapStanza('cmd', {
      cmd: cmd,
      serial: serial
    }));
  }

  if (sendingCommand) {
    pendingCmdSends.push(sendIt);
  } else {
    sendIt();
  }
}

function onCmdResp (params) {
  const { serial, output } = params;

  sendingCommand = false;

  if (serial in pendingCmds) {
    const onFinish = pendingCmds[serial];
    delete pendingCmds[serial];
    process.nextTick(() => onFinish(output));
  } else {
    throw new Error('Command response out of sync');
  }

  process.nextTick(() => {
    if (!sendingCommand) {
      const nextSend = pendingCmdSends.shift();
      if (nextSend !== undefined) {
        nextSend();
      }
    }
  });

  return [{}, null];
}

function wrapStanza (name, stanza) {
  return {
    name: name,
    stanza: stanza
  };
}

recv(onStanza);
