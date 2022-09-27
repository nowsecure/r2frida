/* eslint-disable comma-dangle */
'use strict';

const android = require('./lib/java/android');
const classes = require('./lib/info/classes');
const config = require('./config');
const darwin = require('./lib/darwin');
const debug = require('./lib/debug');
const disasm = require('./lib/disasm');
const dump = require('./dump');
const expr = require('./expr');
const fs = require('./lib/fs');
const info = require('./lib/info');
const io = require('./io');
const interceptor = require('./lib/debug/interceptor');
const java = require('./lib/java');
const log = require('./log');
const lookup = require('./lib/info/lookup');
const memory = require('./lib/debug/memory');
const r2 = require('./lib/r2');
const search = require('./lib/search');
const stalker = require('./lib/debug/stalker');
const sys = require('./lib/sys');
const swift = require('./lib/darwin/swift');
const trace = require('./lib/debug/trace');
const utils = require('./lib/utils');

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
  dts: stalker.stalkTraceEverything,
  'dts?': stalker.stalkTraceEverythingHelp,
  dtsj: stalker.stalkTraceEverythingJson,
  'dts*': stalker.stalkTraceEverythingR2,
  dtsf: stalker.stalkTraceFunction,
  dtsfj: stalker.stalkTraceFunctionJson,
  'dtsf*': stalker.stalkTraceFunctionR2,
  di: interceptor.interceptHelp,
  dif: interceptor.interceptFunHelp,
  // intercept ret function and dont call the function
  dis: interceptor.interceptRetString,
  di0: interceptor.interceptRet0,
  di1: interceptor.interceptRet1,
  dii: interceptor.interceptRetInt,
  'di-1': interceptor.interceptRet_1,
  div: interceptor.interceptRetVoid,
  // intercept ret after calling the function
  difs: interceptor.interceptFunRetString,
  dif0: interceptor.interceptFunRet0,
  dif1: interceptor.interceptFunRet1,
  difi: interceptor.interceptFunRetInt,
  'dif-1': interceptor.interceptFunRet_1,
  // unix compat
  pwd: getCwd,
  cd: chDir,
  cat: fsCat,
  ls: fsList,
  // required for m-io
  md: fsList,
  mg: fsGet,
  m: fsOpen,
  pd: disasm.disasmCode,
  px: dump.Hexdump,
  x: dump.Hexdump,
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
