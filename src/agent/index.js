/* eslint-disable comma-dangle */
'use strict';

const { stalkFunction, stalkEverything } = require('./debug/stalker');
const android = require('./java/android');
const classes = require('./info/classes');
const config = require('./config');
const darwin = require('./darwin/index');
const debug = require('./debug');
const expr = require('./expr');
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
const trace = require('./debug/trace');
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

const commandHandlers = {
  E: expr.evalNum,
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
  e: config.evalConfig,
  'e*': config.evalConfigR2,
  'e/': config.evalConfigSearch,
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
  dtf: trace.traceFormat,
  dth: trace.traceHook,
  t: types,
  't*': typesR2,
  dt: trace.trace,
  dtj: trace.traceJson,
  dtq: trace.traceQuiet,
  'dt*': trace.traceR2,
  'dt.': trace.traceHere,
  'dt-': trace.clearTrace,
  'dt-*': trace.clearAllTrace,
  dtr: trace.traceRegs,
  dtl: trace.traceLogDump,
  'dtl*': trace.traceLogDumpR2,
  dtlq: trace.traceLogDumpQuiet,
  dtlj: trace.traceLogDumpJson,
  'dtl-': trace.traceLogClear,
  'dtl-*': trace.traceLogClearAll,
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
