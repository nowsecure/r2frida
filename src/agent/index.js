/* eslint-disable comma-dangle */
'use strict';

const { stalkFunction, stalkEverything } = require('./debug/stalker');
const android = require('./java/android');
const classes = require('./info/classes');
const config = require('./config');
const darwin = require('./darwin/index');
const debug = require('./debug');
const fs = require('./fs');
const info = require('./info/index');
const io = require('./io');
const java = require('./java/index');
const log = require('./log');
const lookup = require('./lookup');
const memory = require('./memory');
const r2 = require('./r2');
const search = require('./search');
const sys = require('./sys');
const swift = require('./darwin/swift');
const utils = require('./utils');

// r2->io->frida->r2pipe->r2
let _r2 = null;
let _r_core_new = null; // eslint-disable-line camelcase
let _r_core_cmd_str = null; // eslint-disable-line camelcase
let _r_core_free = null; // eslint-disable-line camelcase,no-unused-vars
let _free = null;

function initializePuts () {
  const putsAddress = Module.findExportByName(null, 'puts');
  const putsFunction = new NativeFunction(putsAddress, 'pointer', ['pointer']);

  return function (s) {
    if (putsFunction) {
      const a = Memory.allocUtf8String(s);
      putsFunction(a);
    } else {
      console.error(s);
    }
  };
}

let Gcwd = '/';

const NeedsSafeIo = isLinuxArm32 || isIOS15;
// const NeedsSafeIo = (Process.platform === 'linux' && Process.arch === 'arm' && Process.pointerSize === 4);
/*
const isLinuxArm32 = (Process.platform === 'linux' && Process.arch === 'arm' && Process.pointerSize === 4);
const isIOS15 = getIOSVersion().startsWith('15');
const NeedsSafeIo = isLinuxArm32 || isIOS15;

function getIOSVersion () {
  const processInfo = ObjC.classes.NSProcessInfo.processInfo();
  const versionString = processInfo.operatingSystemVersionString().UTF8String().toString();
  // E.g. "Version 13.5 (Build 17F75)"
  const version = versionString.split(' ')[1];
  // E.g. 13.5
  return version;
}
*/

function numEval (expr) {
  return new Promise((resolve, reject) => {
    const symbol = DebugSymbol.fromName(expr);
    if (symbol && symbol.name) {
      return resolve(symbol.address);
    }
    r2.hostCmd('?v ' + expr).then(_ => resolve(_.trim())).catch(reject);
  });
}

function evalNum (args) {
  return new Promise((resolve, reject) => {
    numEval(args.join(' ')).then(res => {
      resolve(res);
    });
  });
}

const commandHandlers = {
  E: evalNum,
  '?e': echo,
  '?E': uiAlert,
  '/': search.search,
  '/i': search.searchInstances,
  '/ij': search.searchInstancesJson,
  '/j': search.searchJson,
  '/x': search.searchHex,
  '/xj': search.searchHexJson,
  '/w': search.searchWide,
  '/wj': search.searchWideJson,
  '/v1': search.searchValueImpl(1),
  '/v2': search.searchValueImpl(2),
  '/v4': search.searchValueImpl(4),
  '/v8': search.searchValueImpl(8),
  '/v1j': search.searchValueImplJson(1),
  '/v2j': search.searchValueImplJson(2),
  '/v4j': search.searchValueImplJson(4),
  '/v8j': search.searchValueImplJson(8),
  '?V': fridaVersion,
  // '.': // this is implemented in C
  i: info.dumpInfo,
  'i*': info.dumpInfoR2,
  ij: info.dumpInfoJson,
  e: evalConfig,
  'e*': evalConfigR2,
  'e/': evalConfigSearch,
  db: debug.breakpointNative,
  dbj: debug.breakpointJson,
  dbc: debug.breakpointNativeCommand,
  'db-': debug.breakpointUnset,
  dc: debug.breakpointContinue,
  dcu: debug.breakpointContinueUntil,
  dk: debug.sendSignal,

  s: radareSeek,
  r: radareCommand,

  ie: info.listEntrypoint,
  ieq: info.listEntrypointQuiet,
  'ie*': info.listEntrypointR2,
  iej: info.listEntrypointJson,
  afs: analFunctionSignature,
  ii: info.listImports,
  'ii*': info.listImportsR2,
  iij: info.listImportsJson,
  il: info.listModules,
  'il.': info.listModulesHere,
  'il*': info.listModulesR2,
  ilq: info.listModulesQuiet,
  ilj: info.listModulesJson,

  ia: info.listAllHelp,

  iAs: info.listAllSymbols, // SLOW
  iAsj: info.listAllSymbolsJson,
  'iAs*': info.listAllSymbolsR2,
  iAn: classes.listAllClassesNatives,

  is: info.listSymbols,
  'is.': lookup.lookupSymbolHere,
  isj: info.listSymbolsJson,
  'is*': info.listSymbolsR2,

  iS: info.listSections,
  'iS.': info.listSectionsHere,
  'iS*': info.listSectionsR2,
  iSj: info.listSectionsJson,

  ias: lookup.lookupSymbol,
  'ias*': lookup.lookupSymbolR2,
  iasj: lookup.lookupSymbolJson,
  isa: lookup.lookupSymbol,
  'isa*': lookup.lookupSymbolR2,
  isaj: lookup.lookupSymbolJson,
  // many symbols
  isam: lookup.lookupSymbolMany,
  isamj: lookup.lookupSymbolManyJson,
  'isam*': lookup.lookupSymbolManyR2,

  iE: info.listExports,
  'iE.': lookup.lookupSymbolHere,
  iEj: info.listExportsJson,
  'iE*': info.listExportsR2,
  iaE: lookup.lookupExport,
  iaEj: lookup.lookupExportJson,
  'iaE*': lookup.lookupExportR2,

  iEa: lookup.lookupExport,
  'iEa*': lookup.lookupExportR2,
  iEaj: lookup.lookupExportJson,

  // maybe dupped
  iAE: info.listAllExports,
  iAEj: info.listAllExportsJson,
  'iAE*': info.listAllExportsR2,

  init: initBasicInfoFromTarget,

  fD: lookup.lookupDebugInfo,
  fd: lookup.lookupAddress,
  'fd.': lookup.lookupAddress,
  'fd*': lookup.lookupAddressR2,
  fdj: lookup.lookupAddressJson,
  ic: classes.listClasses,
  ich: classes.listClassesHooks,
  icw: classes.listClassesWhere,
  icv: classes.listClassVariables,
  ics: classes.listClassSuperMethods,
  ica: classes.listClassesAllMethods,
  icn: classes.listClassesNatives,
  icL: classes.listClassesLoaders,
  icl: classes.listClassesLoaded,
  iclj: classes.listClassesLoadedJson,
  'ic*': classes.listClassesR2,
  icj: classes.listClassesJson,
  icm: classes.listClassMethods,
  icmj: classes.listClassMethodsJson,
  ip: classes.listProtocols,
  ipj: classes.listProtocolsJson,
  iz: info.listStrings,
  izj: info.listStringsJson,
  dd: fs.listFileDescriptors,
  ddj: fs.listFileDescriptorsJson,
  'dd-': fs.closeFileDescriptors,
  dm: memory.listMemoryRanges,
  'dm*': memory.listMemoryRangesR2,
  dmj: memory.listMemoryRangesJson,
  dmp: memory.changeMemoryProtection,
  'dm.': memory.listMemoryRangesHere,
  dmm: memory.listMemoryMaps,
  'dmm*': memory.listMemoryMapsR2,
  'dmm.': memory.listMemoryMapsHere, // alias for 'dm.'
  dmh: memory.listMallocRanges,
  'dmh*': memory.listMallocRangesR2,
  dmhj: memory.listMallocRangesJson,
  dmhm: memory.listMallocMaps,
  dma: memory.allocSize,
  dmas: memory.allocString,
  dmaw: memory.allocWstring,
  dmad: memory.allocDup,
  dmal: memory.listAllocs,
  'dma-': memory.removeAlloc,
  dp: sys.getPid,
  dxc: debug.dxCall,
  dxo: darwin.dxObjc,
  dxs: debug.dxSyscall,
  dpj: sys.getPidJson,
  dpt: debug.listThreads,
  dptj: debug.listThreadsJson,
  dr: debug.dumpRegisters,
  'dr*': debug.dumpRegistersR2,
  drr: debug.dumpRegistersRecursively,
  drp: debug.dumpRegisterProfile,
  dr8: debug.dumpRegisterArena,
  drj: debug.dumpRegistersJson,
  env: sys.getOrSetEnv,
  envj: sys.getOrSetEnvJson,
  dl: sys.dlopen,
  dlf: darwin.loadFrameworkBundle,
  'dlf-': darwin.unloadFrameworkBundle,
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
  dif: interceptFunHelp,
  // intercept ret function and dont call the function
  dis: interceptRetString,
  di0: interceptRet0,
  di1: interceptRet1,
  dii: interceptRetInt,
  'di-1': interceptRet_1,
  div: interceptRetVoid,
  // intercept ret after calling the function
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
.:i*
s r2f.modulebase
.:is*
.:ie*
.:dmm*
.:il*
m /r2f io 0
s entry0 2> /dev/null
 `;
  return str;
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
  // return r2.hostCmd(cmdstr);
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
      globals.Gcwd = str;
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

function getModuleByAddress (addr) {
  const m = config.getString('symbols.module');
  if (m !== '') {
    return Process.getModuleByName(m);
  }
  try {
    return Process.getModuleByAddress(addr);
  } catch (e) {
    return Process.getModuleByAddress(ptr(global.r2frida.offset));
  }
}

function analFunctionSignature (args) {
  if (!darwin.ObjCAvailable) {
    return 'Error: afs is only implemented for ObjC methods.';
  }
  if (args.length === 0) {
    return 'Usage: afs [class] [method]';
  }
  if (args.length === 1) {
    return classes.listClasses(args);
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
      case 'w': // *s
        const sw = _readUntrustedUtf16(arg);
        a.push(JSON.stringify(sw));
        break;
      case 'a': // *s
        const sa = _readUntrustedAnsi(arg);
        a.push(JSON.stringify(sa));
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
            if (darwin.isObjC(arg)) {
              const o = new ObjC.Object(arg);
              if (o.$className === 'Foundation.__NSSwiftData') {
                a.push(`${o.$className}: "${ObjC.classes.NSString.alloc().initWithData_encoding_(o, 4).toString()}"`);
              } else {
                a.push(`${o.$className}: "${o.toString()}"`);
              }
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

function _readUntrustedUtf16 (address, length) {
  try {
    if (typeof length === 'number') {
      return Memory.readUtf16String(ptr(address), length);
    }
    return Memory.readUtf16String(ptr(address));
  } catch (e) {
    if (e.message !== 'invalid UTF-16') {
      // TODO: just use this, doo not mess with utf8 imho
      return Memory.readCString(ptr(address));
    }
    return '(invalid utf16)';
  }
}

function _readUntrustedAnsi (address, length) {
  try {
    if (typeof length === 'number') {
      return Memory.readAnsiString(ptr(address), length);
    }
    return Memory.readAnsiString(ptr(address));
  } catch (e) {
    if (e.message !== 'invalid Ansi') {
      // TODO: just use this, doo not mess with utf8 imho
      return Memory.readCString(ptr(address));
    }
    return '(invalid Ansi)';
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
          log.traceEmit(traceMessage);
        } else {
          let msg = `[dtf onEnter][${traceMessage.timestamp}] ${name}@${address} - args: ${this.myArgs.join(', ')}`;
          if (config.getBoolean('hook.backtrace')) {
            msg += ` backtrace: ${traceMessage.backtrace.toString()}`;
          }
          for (let i = 0; i < this.myDumps.length; i++) msg += `\ndump:${i + 1}\n${this.myDumps[i]}`;
          log.traceEmit(msg);
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
          log.traceEmit(traceMessage);
        } else {
          let msg = `[dtf onLeave][${traceMessage.timestamp}] ${name}@${address} - args: ${this.myArgs.join(', ')}. Retval: ${retval.toString()}`;
          if (config.getBoolean('hook.backtrace')) {
            msg += ` backtrace: ${traceMessage.backtrace.toString()}`;
          }
          for (let i = 0; i < this.myDumps.length; i++) msg += `\ndump:${i + 1}\n${this.myDumps[i]}`;
          log.traceEmit(msg);
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
  return log.logs.map(({ address, timestamp }) =>
    [address, timestamp, traceCountFromAddress(address), traceNameFromAddress(address)].join(' '))
    .join('\n') + '\n';
}

function traceLogDumpJson () {
  return JSON.stringify(log.logs);
}

function traceLogDumpR2 () {
  let res = '';
  for (const l of log.logs) {
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
      if (darwin.isObjC(p)) {
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
  return log.logs.map(tracelogToString).join('\n') + '\n';
}

function traceLogClear (args) {
  // TODO: clear one trace instead of all
  console.error('ARGS', JSON.stringify(args));
  return traceLogClearAll();
}

function traceLogClearAll () {
  log.logs = [];
  log.traces = {};
  return '';
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
      log.traceEmit(traceMessage);
    } else {
      let msg = `[dtr][${traceMessage.timestamp}] ${address} - registers: ${JSON.stringify(regState)}`;
      if (config.getBoolean('hook.backtrace')) {
        msg += ` backtrace: ${traceMessage.backtrace.toString()}`;
      }
      log.traceEmit(msg);
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
  if (!swift.SwiftAvailable()) {
    return;
  }
  const targetAddress = getPtr('swift:' + klass + '.' + method);
  if (ptr(0).equals(targetAddress)) {
    console.error('Missing method ' + method + ' in class ' + klass);
    return;
  }

  const callback = function (args) {
    const msg = ['[SWIFT]', klass, method, JSON.stringify(args)];
    log.traceEmit(msg.join(' '));
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
        log.traceEmit(traceMessage);
      } else {
        let msg = `[JAVA TRACE][${traceMessage.timestamp}] ${klass}:${method} - args: ${JSON.stringify(args)}. Return value: ${res.toString()}`;
        if (config.getBoolean('hook.backtrace')) {
          msg += ` backtrace: \n${traceMessage.backtrace.toString().split(',').join('\nat ')}\n`;
        }
        log.traceEmit(msg);
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
  if (swift.SwiftAvailable()) {
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
  if (swift.SwiftAvailable()) {
    return swiftTypes(args);
  }
  return '';
}

function swiftTypes (args) {
  if (!swift.SwiftAvailable()) {
    if (config.getBoolean('want.swift')) {
      console.error('See :e want.swift=true');
    }
    return '';
  }
  let res = '';
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
      log.traceEmit(traceMessage);
    } else {
      log.traceEmit(`[dt][${traceMessage.timestamp}] ${address} - args: ${JSON.stringify(values)}`);
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
  return 'Usage: di[0,1,-1,s,v] [addr] : intercepts function method and replace the return value.\n';
  'di0 0x808080  # when program calls this address, the original function is not called, then return value is replaced.\n';
  'div java:org.ex.class.method  # when program calls this address, the original function is not called and no value is returned.\n';
}

function interceptFunHelp (args) {
  return 'Usage: dif[0,1,-1,s] [addr] [str] [param_types]: intercepts function method, call it, and replace the return value.\n';
  'dif0 0x808080  # when program calls this address, the original function is called, then return value is replaced.\n';
  'dif0 java:com.example.MainActivity.method1 int,java.lang.String  # Only with JVM methods. You need to define param_types when overload a Java method.\n';
  'dis 0x808080 str  #.\n';
}

function interceptRetJava (klass, method, value) {
  javaPerform(function () {
    const targetClass = javaUse(klass);
    targetClass[method].implementation = function (library) {
      const timestamp = new Date();
      if (config.getString('hook.output') === 'json') {
        log.traceEmit({
          source: 'java',
          class: klass,
          method,
          returnValue: value,
          timestamp
        });
      } else {
        log.traceEmit(`[JAVA TRACE][${timestamp}] Intercept return for ${klass}:${method} with ${value}`);
      }
      switch (value) {
        case 0: return false;
        case 1: return true;
        case -1: return -1; // TODO should throw an error?
        case null: return;
      }
      return value;
    };
  });
}

function interceptFunRetJava (className, methodName, value, paramTypes) {
  javaPerform(function () {
    const targetClass = javaUse(className);
    targetClass[methodName].overload(paramTypes).implementation = function (args) {
      const timestamp = new Date();
      if (config.getString('hook.output') === 'json') {
        log.traceEmit({
          source: 'java',
          class: className,
          methodName,
          returnValue: value,
          timestamp
        });
      } else {
        log.traceEmit(`[JAVA TRACE][${timestamp}] Intercept return for ${className}:${methodName} with ${value}`);
      }
      this[methodName](args);
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

/* Intercepts function call and modify the return value without calling the original function code */
function interceptRet (target, value) {
  if (target.startsWith('java:')) {
    try {
      const java_target = parseTargetJavaExpression(target, value);
      return interceptRetJava(java_target[0], java_target[1], value);
    } catch (e) {
      return e.message;
    }
  }
  const funcPtr = getPtr(target);
  const useCmd = config.getString('hook.usecmd');
  Interceptor.replace(funcPtr, new NativeCallback(function () {
    if (useCmd.length > 0) {
      console.log('[r2cmd]' + useCmd);
    }
    return ptr(value);
  }, 'pointer', ['pointer']));
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

function interceptRetVoid (args) { // eslint-disable-line
  const target = args[0];
  return interceptRet(target, null);
}

/* Intercept function calls and modify return value after calling the original function code */
function interceptFunRet (target, value, paramTypes) {
  if (target.startsWith('java:')) {
    const javaTarget = parseTargetJavaExpression(target, value);
    return interceptFunRetJava(javaTarget[0], javaTarget[1], value, paramTypes);
  }
  const p = getPtr(target);
  Interceptor.attach(p, {
    onLeave (retval) {
      retval.replace(ptr(value));
    }
  });
}

function interceptFunRet0 (args) {
  const target = args[0];
  const paramTypes = args[1];
  return interceptFunRet(target, 0, paramTypes);
}

function interceptFunRetString (args) {
  const target = args[0];
  const paramTypes = args[2];
  return interceptFunRet(target, args[1], paramTypes);
}

function interceptFunRetInt (args) {
  const target = args[0];
  const paramTypes = args[2];
  return interceptFunRet(target, args[1], paramTypes);
}

function interceptFunRet1 (args) {
  const target = args[0];
  const paramTypes = args[1];
  return interceptFunRet(target, 1, paramTypes);
}

function interceptFunRet_1 (args) { // eslint-disable-line
  const target = args[0];
  const paramTypes = args[1];
  return interceptFunRet(target, -1, paramTypes);
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



const requestHandlers = {
  safeio: () => { global.r2frida.safeio = true; },
  unsafeio: () => { if (!NeedsSafeIo) { global.r2frida.safeio = false; } },
  read: io.read,
  write: io.write,
  state: state,
  perform: perform,
  evaluate: evaluate,
};

function state (params, data) {
  global.r2frida.offset = params.offset;
  debug.suspended = params.suspended;
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
    const isObjcMainLoopRunning = darwin.ObjCAvailable && darwin.hasMainLoop();

    if (darwin.ObjCAvailable && isObjcMainLoopRunning && !debug.suspended) {
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

function uiAlert (args) {
  if (java.JavaAvailable) {
    return android.uiAlert(args);
  }
  if (darwin.ObjCAvailable) {
    return darwin.uiAlert(args);
  }
  return 'Error: ui-alert is not implemented for this platform';
}

function echo (args) {
  console.log(args.join(' '));
  return null;
}

function evalConfigSearch (args) {
  const currentRange = Process.getRangeByAddress(ptr(r2frida.offset));
  const from = currentRange.base;
  const to = from.add(currentRange.size);
  return `e search.in=range
e search.from=${from}
e search.to=${to}
e anal.in=range
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

function fsList (args) {
  return fs.ls(args[0] || globals.Gcwd);
}

function fsGet (args) {
  return fs.cat(args[0] || '', '*', args[1] || 0, args[2] || null);
}

function fsCat (args) {
  return fs.cat(args[0] || '');
}

function fsOpen (args) {
  return fs.open(args[0] || globals.Gcwd);
}

function onStanza (stanza, data) {
  const handler = requestHandlers[stanza.type];
  if (handler !== undefined) {
    try {
      const value = handler(stanza.payload, data);
      if (value === undefined) {
        send(utils.wrapStanza('reply', {}), []);
      } else if (value instanceof Promise) {
        // handle async stuff in here
        value
          .then(([replyStanza, replyBytes]) => {
            send(utils.wrapStanza('reply', replyStanza), replyBytes);
          })
          .catch(e => {
            send(utils.wrapStanza('reply', {
              error: e.message
            }), []);
          });
      } else {
        const [replyStanza, replyBytes] = value;
        send(utils.wrapStanza('reply', replyStanza), replyBytes);
      }
    } catch (e) {
      send(utils.wrapStanza('reply', { error: e.message }), []);
    }
  } else if (stanza.type === 'bp') {
    console.error('Breakpoint handler');
  } else if (stanza.type === 'cmd') {
    r2.onCmdResp(stanza.payload);
  } else {
    console.error('Unhandled stanza: ' + stanza.type);
  }
  recv(onStanza);
}

global.r2frida.hostCmd = r2.hostCmd;
global.r2frida.hostCmdj = r2.hostCmdj;
global.r2frida.logs = log.logs;
global.r2frida.log = log.traceLog;
global.r2frida.emit = log.traceEmit;
global.r2frida.safeio = NeedsSafeIo;
global.r2frida.module = '';
global.r2frida.puts = initializePuts();

recv(onStanza);
