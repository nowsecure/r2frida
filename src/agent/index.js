/* eslint-disable comma-dangle */
'use strict';

const anal = require('./lib/anal');
const android = require('./lib/java/android');
const classes = require('./lib/info/classes');
const config = require('./config');
const darwin = require('./lib/darwin');
const debug = require('./lib/debug');
const disasm = require('./lib/disasm');
const dump = require('./lib/dump');
const expr = require('./lib/expr');
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

let Gcwd = '/';

const NeedsSafeIo = isLinuxArm32 || isIOS15;
// const NeedsSafeIo = (Process.platform === 'linux' && Process.arch === 'arm' && Process.pointerSize === 4);
/*
const isLinuxArm32 = (Process.platform === 'linux' && Process.arch === 'arm' && Process.pointerSize === 4);
const isIOS15 = darwin.getIOSVersion().startsWith('15');
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

  s: r2.radareSeek,
  r: r2.radareCommand,

  ie: info.listEntrypoint,
  ieq: info.listEntrypointQuiet,
  'ie*': info.listEntrypointR2,
  iej: info.listEntrypointJson,
  afs: anal.analFunctionSignature,
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
  t: swift.swiftTypes,
  't*': swift.swiftTypesR2,
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
  pwd: fs.getCwd,
  cd: fs.chDir,
  cat: fs.fsCat,
  ls: fs.fsList,
  // required for m-io
  md: fs.fsList,
  mg: fs.fsGet,
  m: fs.fsOpen,
  pd: disasm.disasmCode,
  px: dump.Hexdump,
  x: dump.Hexdump,
  eval: expr.evalCode,
  chcon: sys.changeSelinuxContext,
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

if (Process.platform === 'darwin') {
  darwin.initFoundation();
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
      value: _normalizeValue(value)
    }, null];
  }
  if (name.length > 0 && name.endsWith('?') && !commandHandlers[name]) {
    const prefix = name.substring(0, name.length - 1);
    const value = getHelpMessage(prefix);
    return [{
      value: _normalizeValue(value)
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
          value: _normalizeValue(output)
        }, null]);
      }).catch(reject);
    });
  }
  const nv = _normalizeValue(value);
  if (nv === '' || nv === 'null' || nv === undefined || nv === null) {
    return [{}, null];
  }
  return [{ value: nv }, null];
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

function _normalizeValue (value) {
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

global.r2frida.hostCmd = r2.hostCmd;
global.r2frida.hostCmdj = r2.hostCmdj;
global.r2frida.logs = log.logs;
global.r2frida.log = log.traceLog;
global.r2frida.emit = log.traceEmit;
global.r2frida.safeio = NeedsSafeIo;
global.r2frida.module = '';
global.r2frida.puts = initializePuts();

recv(onStanza);
