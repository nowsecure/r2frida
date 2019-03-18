/* eslint-disable comma-dangle */
'use strict';
// TODO : implement tracelog eval var and dump trace info into this file
// this cant be done from the agent-side

const r2frida = require('./plugin'); // eslint-disable-line
const {stalkFunction, stalkEverything} = require('./stalker');
const fs = require('./fs');

/* ObjC.available is buggy on non-objc apps, so override this */
const ObjCAvailable = ObjC && ObjC.available && ObjC.classes && typeof ObjC.classes.NSString !== 'undefined';
const JavaAvailable = Java && Java.available;

if (ObjCAvailable) {
  var mjolner = require('mjolner');
}

const pointerSize = Process.pointerSize;

var offset = '0';
var suspended = false;

function numEval (expr) {
  return new Promise((resolve, reject) => {
    var symbol = DebugSymbol.fromName(expr);
    if (symbol != 0) {
      return resolve(symbol.address);
    }
    hostCmd('?v ' + expr).then(_ => resolve(_.trim())).catch(reject);
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
  'E': evalNum,
  '/': search,
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
  'i': dumpInfo,
  'e': evalConfig,
  'i*': dumpInfoR2,
  'ij': dumpInfoJson,
  'db': breakpoint,
  'db-': breakpointUnset,
  'dbt': backtrace,
  'dc': breakpointContinue,
  'dcu': breakpointContinueUntil,
  'dk': sendSignal,
  'ii': listImports,
  'ii*': listImportsR2,
  'iij': listImportsJson,
  'il': listModules,
  'il.': listModulesHere,
  'il*': listModulesR2,
  'ilj': listModulesJson,

  'iE': listExports,
  'iE.': lookupSymbolHere,
  'iEj': listExportsJson,
  'iE*': listExportsR2,

  'is': listSymbols,
  'is.': lookupSymbolHere,
  'isj': listSymbolsJson,
  'is*': listSymbolsR2,

  'isa': lookupSymbol,
  'isa*': lookupSymbolR2,
  'isaj': lookupSymbolJson,

  'iEa': lookupExport,
  'iEa*': lookupExportR2,
  'iEaj': lookupExportJson,

  'fD': lookupDebugInfo,
  'fd': lookupAddress,
  'fd.': lookupAddress,
  'fd*': lookupAddressR2,
  'fdj': lookupAddressJson,
  'ic': listClasses,
  'ic*': listClassesR2,
  'icj': listClassesJson,
  'ip': listProtocols,
  'ipj': listProtocolsJson,
  'dd': listFileDescriptors,
  'dd-': closeFileDescriptors,
  'dm': listMemoryRanges,
  'dm*': listMemoryRangesR2,
  'dmj': listMemoryRangesJson,
  'dmp': changeMemoryProtection,
  'dm.': listMemoryRangesHere,
  'dmm': listMemoryMaps,
  'dmh': listMallocRanges,
  'dmh*': listMallocRangesR2,
  'dmhj': listMallocRangesJson,
  'dmhm': listMallocMaps,
  'dma': allocSize,
  'dmas': allocString,
  'dmad': allocDup,
  'dmal': listAllocs,
  'dma-': removeAlloc,
  'dp': getPid,
  'dxc': dxCall,
  'dx': dxHexpairs,
  'dpj': getPid,
  'dpt': listThreads,
  'dptj': listThreadsJson,
  'dr': dumpRegisters,
  'dr*': dumpRegistersR2,
  'drp': dumpRegisterProfile,
  'dr8': dumpRegisterArena,
  'drj': dumpRegistersJson,
  'env': getOrSetEnv,
  'envj': getOrSetEnvJson,
  'dl': dlopen,
  'dtf': traceFormat,
  'dth': traceHook,
  'dt': trace,
  'dtj': traceJson,
  'dt*': traceR2,
  'dt.': traceHere,
  'dt-': clearTrace,
  'dtr': traceRegs,
  'T': traceLogDump,
  'T-': traceLogClear,
  'T*': traceLog,
  'dtS': stalkTraceEverything,
  'dtSj': stalkTraceEverythingJson,
  'dtS*': stalkTraceEverythingR2,
  'dtSf': stalkTraceFunction,
  'dtSfj': stalkTraceFunctionJson,
  'dtSf*': stalkTraceFunctionR2,
  'di': interceptHelp,
  'di0': interceptRet0,
  'di1': interceptRet1,
  'di-1': interceptRet_1,
  'md': fsList,
  'mg': fsCat,
  'm': fsOpen,
  'pd': disasmCode,
  'px': printHexdump,
  'x': printHexdump,
  'eval': evalCode,
};

const RTLD_GLOBAL = 0x8;
const RTLD_LAZY = 0x1;
const allocPool = {};
const pendingCmds = {};
const pendingCmdSends = [];
let sendingCommand = false;

function nameFromAddress (address) {
  const at = DebugSymbol.fromAddress(ptr(address));
  if (at) {
    return at.name;
  }
  const module = Process.findModuleByAddress(address);
  if (module === null) {
    return null;
  }
  const imports = Module.enumerateImportsSync(module.name);
  for (let imp of imports) {
    if (imp.address.equals(address)) {
      return imp.name;
    }
  }
  const exports = Module.enumerateExportsSync(module.name);
  for (let exp of exports) {
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
    for (let addr of args) {
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
    .join('\n');
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

function dxCall (args) {
  const nfArgs = [];
  const nfArgsData = [];
  for (var i = 1; i < args.length; i++) {
    if (args[i].substring(0, 2) === '0x') {
      nfArgs.push('pointer');
      nfArgsData.push(ptr(args[i]));
    } else if (args[i][0] === '"') {
      // string.. join args
      nfArgs.push('pointer');
      const str = args[i].substring(1, args[i].length - 1);
      const buf = Memory.allocUtf8String(str);
      nfArgsData.push(buf);
      // TODO: fix memory leak ?
    } else if (+args[i] > 0) {
      nfArgs.push('int');
      nfArgsData.push(+args[i]);
    } else {
      nfArgs.push('pointer');
      const address = Module.findExportByName(null, args[i]);
      nfArgsData.push(ptr(address));
    }
  }
  let address;
  if (args[0].substring(0, 2) === '0x') {
    address = ptr(args[0]);
  } else {
    address = Module.findExportByName(null, args[0]);
  }

  const fun = new NativeFunction(address, 'pointer', nfArgs);
  return fun(...nfArgsData);
}

function dxHexpairs (args) {
  return 'TODO';
}

function evalCode (args) {
  const code = args.join(' ');
  const result = eval(code); // eslint-disable-line
  return (result !== undefined) ? result : '';
}

function printHexdump (lenstr) {
  const len = +lenstr || 20;
  return hexdump(ptr(offset), len) || '';
}

function disasmCode (lenstr) {
  const len = +lenstr || 20;
  return disasm(offset, len);
}

function disasm (addr, len, initialOldName) {
  len = len || 20;
  if (typeof addr === 'string') {
    try {
      addr = Module.findExportByName(null, addr);
      if (!addr) {
        throw new Error();
      }
    } catch (e) {
      addr = ptr(offset);
    }
  }
  addr = ptr('' + addr);
  let oldName = initialOldName !== undefined ? initialOldName : null;
  let lastAt = null;
  let disco = '';
  for (let i = 0; i < len; i++) {
    const [op, next] = _tolerantInstructionParse(addr);
    if (op === null) {
      disco += `${addr}\tinvalid`;
      addr = next;
      continue;
    }
    const ds = DebugSymbol.fromAddress(addr);
    const dsName = (ds.name === null || ds.name.indexOf('0x') === 0) ? '' : ds.name;
    if ((ds.moduleName !== null || dsName !== null) && dsName !== oldName) {
      disco += `;;; ${ds.moduleName} ${dsName}\n`;
      oldName = dsName;
    }
    var comment = '';
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
    disco += [op.address, op.mnemonic, op.opStr, comment].join('\t') + '\n';
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
    return new NativeFunction(Module.findExportByName(null, name), ret, arg);
  } catch (e) {
    console.error(name, ':', e);
  }
}

/* This is not available on Windows */
const _getenv = sym('getenv', 'pointer', ['pointer']);
const _setenv = sym('setenv', 'int', ['pointer', 'pointer', 'int']);
const _getpid = sym('getpid', 'int', []);
const _getuid = sym('getuid', 'int', []);
const _dlopen = sym('dlopen', 'pointer', ['pointer', 'int']);
const _dup2 = sym('dup2', 'int', ['int', 'int']);
const _fstat = Module.findExportByName(null, 'fstat')
  ? sym('fstat', 'int', ['int', 'pointer'])
  : sym('__fxstat', 'int', ['int', 'pointer']);
const _close = sym('close', 'int', ['int']);
const _kill = sym('kill', 'int', ['int', 'int']);

if (Process.platform === 'darwin') {
  // required for mjolner.register() to work on early instrumentation
  dlopen(['/System/Library/Frameworks/Foundation.framework/Foundation']);
}

const traceListeners = [];
const config = {
  'patch.code': true,
  'search.in': 'perm:r--',
  'search.quiet': false,
  'stalker.event': 'compile',
  'stalker.timeout': 5 * 60,
  'stalker.in': 'raw',
};

const configHelp = {
  'search.in': configHelpSearchIn,
  'stalker.event': configHelpStalkerEvent,
  'stalker.timeout': configHelpStalkerTimeout,
  'stalker.in': configHelpStalkerIn,
};

const configValidator = {
  'search.in': configValidateSearchIn,
  'stalker.event': configValidateStalkerEvent,
  'stalker.timeout': configValidateStalkerTimeout,
  'stalker.in': configValidateStalkerIn,
};

function configHelpSearchIn () {
  return `Specify which memory ranges to search in, possible values:

    perm:---        filter by permissions (default: 'perm:r--')
    current         search the range containing current offset
    heap            search inside the heap allocated regions
    path:pattern    search ranges mapping paths containing 'pattern'
  `;
}

function configValidateSearchIn (val) {
  if (val === 'heap') {
    return true;
  }
  const valSplit = val.split(':');
  const [scope, param] = valSplit;

  if (param === undefined) {
    if (scope === 'current') {
      return valSplit.length === 1;
    }
    return false;
  }
  if (scope === 'perm') {
    const paramSplit = param.split('');
    if (paramSplit.length !== 3 || valSplit.length > 2) {
      return false;
    }
    const [r, w, x] = paramSplit;
    return (r === 'r' || r === '-') &&
      (w === 'w' || w === '-') &&
      (x === 'x' || x === '-');
  }
  return scope === 'path';
}

function configHelpStalkerEvent () {
  return `Specify the event to use when stalking, possible values:

    call            trace calls
    ret             trace returns
    exec            trace every instruction
    block           trace basic block execution (every time)
    compile         trace basic blocks once (this is the default)
  `;
}

function configValidateStalkerEvent (val) {
  return ['call', 'ret', 'exec', 'block', 'compile'].indexOf(val) !== -1;
}

function configHelpStalkerTimeout () {
  return `Time after which the stalker gives up (in seconds). Defaults to 5 minutes,
 set to 0 to disable.`;
}

function configValidateStalkerTimeout (val) {
  return val >= 0;
}

function configHelpStalkerIn () {
  return `Restrict stalker results based on where the event has originated:

    raw             stalk everywhere (the default)
    app             stalk only in the app module
    modules         stalk in app module and all linked libraries
  `;
}

function configValidateStalkerIn (val) {
  return ['raw', 'app', 'modules'].indexOf(val) !== -1;
}

function evalConfig (args) {
  if (args.length === 0) {
    return Object.keys(config)
      .map(k => 'e ' + k + '=' + config[k])
      .join('\n');
  }
  const kv = args[0].split(/=/);
  if (kv.length === 2) {
    if (config[kv[0]] !== undefined) {
      if (kv[1] === '?') {
        if (configHelp[kv[0]] !== undefined) {
          return configHelp[kv[0]]();
        }
        console.error(`no help for ${kv[0]}`);
        return '';
      }
      if (configValidator[kv[0]] !== undefined) {
        if (!configValidator[kv[0]](kv[1])) {
          console.error(`Invalid value for ${kv[0]}`);
          return '';
        }
      }
      config[kv[0]] = kv[1];
    } else {
      console.error('unknown variable');
    }
    return '';
  }
  return config[args[0]];
}

function dumpInfo () {
  const properties = dumpInfoJson();
  return Object.keys(properties)
    .map(k => k + '  ' + properties[k])
    .join('\n');
}

function dumpInfoR2 () {
  const properties = dumpInfoJson();
  return [
    'e asm.arch=' + properties.arch,
    'e asm.bits=' + properties.bits,
    'e asm.os=' + properties.os
  ].join('\n');
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

var breakpoints = {};

function breakpointUnset (args) {
  if (args.length === 1) {
    if (args[0] === '*') {
      for (let k of Object.keys(breakpoints)) {
        const bp = breakpoints[k];
        Interceptor.revert(ptr(bp.address));
      }
      breakpoints = {};
      return 'All breakpoints removed';
    }
    const symbol = Module.findExportByName(null, args[0]);
    const addr = (symbol !== null) ? symbol : ptr(args[0]);
    const newbps = [];
    let found = false;
    for (let k of Object.keys(breakpoints)) {
      const bp = breakpoints[k];
      // eslint-disable-next-line
      if (args[0] === '*' || bp.address == addr) {
        found = true;
        console.log('Breakpoint reverted');
        Interceptor.revert(ptr(bp.address));
      } else {
        newbps.push(bp);
      }
    }
    if (!found) {
      console.error('Cannot found any breakpoint matching');
    }
    breakpoints = {};
    for (let bp of newbps) {
      breakpoints[bp.address] = bp;
    }
    return '';
  }
  return 'Usage: db- [addr|*]';
}

function breakpointExist (addr) {
  const bp = breakpoints['' + addr];
  return bp && !bp.continue;
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
    return 'Usage: \dk ([pid]) [sig]';
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
    return hostCmd('=!dc');
  }
  let count = 0;
  for (let k of Object.keys(breakpoints)) {
    const bp = breakpoints[k];
    if (bp && bp.stopped) {
      count++;
      bp.continue = true;
    }
  }
  return 'Continue ' + count + ' thread(s).';
}

function breakpoint (args) {
  if (args.length === 0) {
    return JSON.stringify(breakpoints, null, '  ');
  }
  return new Promise((res, rej) => {
    numEval(args[0]).then(num => {
      setBreakpoint(num);
      res(JSON.stringify(breakpoints, null, '  '));
    }).catch(e => {
      console.error(e);
      rej(e);
    });
  });
}

function setBreakpoint (address) {
  const symbol = Module.findExportByName(null, address);
  const addr = (symbol !== null) ? symbol : ptr(address);
  if (breakpointExist(addr)) {
    return 'Cant set a breakpoint twice';
  }
  const addrString = '' + addr;
  const bp = {
    name: address,
    stopped: false,
    address: addrString,
    continue: false,
    handler: Interceptor.attach(addr, function () {
      if (breakpoints[addrString]) {
        breakpoints[addrString].stopped = true;
        const showBacktrace = true;
        if (showBacktrace) {
          console.log(addr);
          const bt = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
          console.log(bt.join('\n\t'));
        }
      }
      while (breakpointExist(addr)) {
        Thread.sleep(1);
      }
      if (breakpoints[addrString]) {
        breakpoints[addrString].stopped = false;
        breakpoints[addrString].continue = false;
      }
    })
  };
  breakpoints[addrString] = bp;
}

function dumpInfoJson () {
  return {
    arch: getR2Arch(Process.arch),
    bits: pointerSize * 8,
    os: Process.platform,
    pid: getPid(),
    uid: _getuid(),
    objc: ObjCAvailable,
    runtime: Script.runtime,
    java: JavaAvailable,
    cylang: mjolner !== undefined,
  };
}

function listModules () {
  return Process.enumerateModulesSync()
    .map(m => padPointer(m.base) + ' ' + m.name)
    .join('\n');
}

function listModulesR2 () {
  return Process.enumerateModulesSync()
    .map(m => 'f lib.' + m.name + ' = ' + padPointer(m.base))
    .join('\n');
}

function listModulesJson () {
  return Process.enumerateModulesSync();
}

function listModulesHere () {
  const here = ptr(offset);

  return Process.enumerateModulesSync()
    .filter(m => here.compare(m.base) >= 0 && here.compare(m.base.add(m.size)) < 0)
    .map(m => padPointer(m.base) + ' ' + m.name)
    .join('\n');
}

function listExports (args) {
  return listExportsJson(args)
    .map(({type, name, address}) => {
      return [address, type[0], name].join(' ');
    })
    .join('\n');
}

function listExportsR2 (args) {
  return listExportsJson(args)
    .map(({type, name, address}) => {
      return ['f', 'sym.' + type.substring(0, 3) + '.' + name, '=', address].join(' ');
    })
    .join('\n');
}

function listExportsJson (args) {
  const modules = (args.length === 0) ? Process.enumerateModulesSync().map(m => m.path) : [args.join(' ')];
  return modules.reduce((result, moduleName) => {
    return result.concat(Module.enumerateExportsSync(moduleName));
  }, []);
}

function listSymbols (args) {
  return listSymbolsJson(args)
    .map(({type, name, address}) => {
      return [address, type[0], name].join(' ');
    })
    .join('\n');
}

function listSymbolsR2 (args) {
  return listSymbolsJson(args)
    .map(({type, name, address}) => {
      return ['f', 'sym.' + type.substring(0, 3) + '.' + name, '=', address].join(' ');
    })
    .join('\n');
}

function listSymbolsJson (args) {
  const modules = (args.length === 0) ? Process.enumerateModulesSync().map(m => m.path) : [args[0]];
  return modules.reduce((result, moduleName) => {
    return result.concat(Module.enumerateSymbolsSync(moduleName));
  }, []);
}

function lookupDebugInfo (args) {
  const o = DebugSymbol.fromAddress(ptr('' + args));
  console.log(o);
}

/* function lookupDebugInfoR2 (args) {
  const o = DebugSymbol.fromAddress(ptr('' + args));
  console.log(o);
} */

function lookupAddress (args) {
  if (args.length === 0) {
    args = [ptr(offset)];
  }
  return lookupAddressJson(args)
    .map(({type, name, address}) => [type, name, address].join(' '))
    .join('\n');
}

function lookupAddressR2 (args) {
  return lookupAddressJson(args)
    .map(({type, name, address}) =>
      ['f', 'sym.' + name, '=', address].join(' '))
    .join('\n');
}

function lookupAddressJson (args) {
  const exportAddress = ptr(args[0]);
  const result = [];
  const modules = Process.enumerateModulesSync().map(m => m.path);
  return modules.reduce((result, moduleName) => {
    return result.concat(Module.enumerateExportsSync(moduleName));
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
  return lookupAddress([ptr(offset)]);
}

function lookupExport (args) {
  return lookupExportJson(args)
  // .map(({library, name, address}) => [library, name, address].join(' '))
    .map(({address}) => '' + address)
    .join('\n');
}

function lookupExportR2 (args) {
  return lookupExportJson(args)
    .map(({name, address}) =>
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
    const m = Process.getModuleByAddress(address);
    return [{
      library: m.name,
      name: exportName,
      address: address
    }];
  } else {
    const exportName = args[0];
    let prevAddress = null;
    return Process.enumerateModulesSync()
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
    .map(({address}) => '' + address)
    .join('\n');
}

function lookupSymbolR2 (args) {
  return lookupSymbolJson(args)
    .map(({name, address}) =>
      ['f', 'sym.' + name, '=', address].join(' '))
    .join('\n');
}

function lookupSymbolJson (args) {
  if (args.length === 2) {
    let [moduleName, symbolName] = args;
    try {
      const m = Process.getModuleByName(moduleName);
    } catch (e) {
      const res = Process.enumerateModulesSync().filter(function (x) {
        return x.name.indexOf(moduleName) !== -1;
      });
      if (res.length !== 1) {
        return [];
      }
      moduleName = res[0].name;
    }
    return [{
      library: moduleName,
      name: symbolName,
      address: address
    }];
    let address = 0;
    Module.enumerateSymbolsSync(moduleName).filter(function (s) {
      if (s.name === symbolName) {
        address = s.address;
      }
    });
    if (address === 0) {
      return [];
    }
    return [{
      library: moduleName,
      name: symbolName,
      address: address
    }];
  } else {
    let [symbolName] = args;
    var at = DebugSymbol.fromName(symbolName);
    if (at) {
    return [{
      library: moduleName,
      name: symbolName,
      address: at.address
    }];
    }
    const modules = Process.enumerateModulesSync();
    let address = 0;
    let moduleName = '';
    for (let m of modules) {
      Module.enumerateSymbolsSync(m.name).filter(function (s) {
        if (s.name === symbolName) {
          moduleName = m.name;
          address = s.address;
        }
      });
      if (address === 0) {
        return [];
      }
    }
    return [{
      library: moduleName,
      name: symbolName,
      address: address
    }];
  }
}

function listImports (args) {
  return listImportsJson(args)
    .map(({type, name, module, address}) => [address, type ? type[0] : ' ', name, module].join(' '))
    .join('\n');
}

function listImportsR2 (args) {
  const seen = new Set();
  return listImportsJson(args).map((x) => {
    const flags = [];
    if (!seen.has(x.address)) {
      seen.add(x.address);
      flags.push(`f sym.imp.${x.name} = ${x.address}`);
    }
    if (x.slot !== undefined) {
      flags.push(`f reloc.${x.targetModuleName}.${x.name}_${x.index} = ${x.slot}`);
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
    const imports = Module.enumerateImportsSync(moduleName);
    if (imports !== null) {
      result = imports.filter((x, i) => {
        x.index = i;
        return x.name === importName;
      });
    }
  } else if (alen === 1) {
    moduleName = args[0];
    result = Module.enumerateImportsSync(moduleName) || [];
  } else {
    const modules = Process.enumerateModulesSync() || [];
    if (modules.length > 0) {
      moduleName = modules[0].name;
      result = Module.enumerateImportsSync(moduleName) || [];
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

function listClasses (args) {
  const result = listClassesJson(args);
  if (result instanceof Array) {
    return result.join('\n');
  } else {
    return Object.keys(result)
      .map(methodName => {
        const address = result[methodName];
        return [padPointer(address), methodName].join(' ');
      })
      .join('\n');
  }
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
    for (let cn of Object.keys(ObjC.classes)) {
      if (classGlob(cn, args[0])) {
        methods += listClassesR2([cn]);
      }
    }
    return methods;
  }
  const result = listClassesJson(args);
  if (result instanceof Array) {
    return result.join('\n');
  } else {
    return Object.keys(result)
      .map(methodName => {
        const address = result[methodName];
        return ['f', flagName(methodName), '=', padPointer(address)].join(' ');
      })
      .join('\n');
  }

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
    Java.perform(function () {
      const obj = Java.use(args[0]);
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
  /* list all classes */
  Java.perform(function () {
    try {
      classes = Java.enumerateLoadedClassesSync();
    } catch (e) {
      classes = null;
    }
  });
  // eslint-disable-next-line
  while (classes === undefined) {
    /* wait here */
    setTimeout(null, 0);
  }
  return classes;
}

// eslint-disable-next-line
function listJavaClassesJson (args) {
  return new Promise(function (resolve, reject) {
    if (args.length === 1) {
      /* list methods */
      Java.perform(function () {
        var obj = Java.use(args[0]);
        resolve(JSON.stringify(obj, null, '  '));
      });
      return;
    }
    /* list all classes */
    Java.perform(function () {
      try {
        resolve(Java.enumerateLoadedClassesSync().join('\n'));
      } catch (e) {
        reject(e);
      }
    });
  });
}

function listClassesJson (args) {
  if (JavaAvailable) {
    return listJavaClassesJsonSync(args);
    // return listJavaClassesJson(args);
  }
  if (args.length === 0) {
    return Object.keys(ObjC.classes);
  } else {
    const klass = ObjC.classes[args[0]];
    if (klass === undefined) {
      throw new Error('Class ' + args[0] + ' not found');
    }
    return klass.$ownMethods
      .reduce((result, methodName) => {
        try {
          result[methodName] = klass[methodName].implementation;
        } catch (_) {
          console.log('warning: unsupported method \'' + methodName + '\'');
        }
        return result;
      }, {});
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
  if (args.length === 0) {
    const statBuf = Memory.alloc(128);
    const fds = [];
    for (let i = 0; i < 1024; i++) {
      if (_fstat(i, statBuf) === 0) {
        fds.push(i);
      }
    }
    return fds;
  } else {
    const rc = _dup2(+args[0], +args[1]);
    return rc;
  }
}

function listProtocolsJson (args) {
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
    for (let heap of heaps) {
      if (x.base.compare(heap.base) >= 0 &&
      x.base.add(x.size).compare(heap.base.add(heap.size))) {
        return true;
      }
    }
    return false;
  }
  return squashRanges(listMemoryRangesJson())
    .filter(inRange)
    .map(({base, size, protection, file}) =>
      [
        padPointer(base),
        '-',
        padPointer(base.add(size)),
        protection,
      ]
        .concat((file !== undefined) ? [file.path] : [])
        .join(' ')
    )
    .join('\n');
}

function listMallocRangesJson (args) {
  return Process.enumerateMallocRangesSync();
}

function listMallocRangesR2 (args) {
  const chunks = listMallocRangesJson(args)
    .map(_ => 'f chunk.' + _.base + ' ' + _.size + ' ' + _.base).join('\n');
  return chunks + squashRanges(listMallocRangesJson(args))
    .map(_ => 'f heap.' + _.base + ' ' + _.size + ' ' + _.base).join('\n');
}

function listMallocRanges (args) {
  return squashRanges(listMallocRangesJson(args))
    .map(_ => '' + _.base + ' - ' + _.base.add(_.size) + '  (' + _.size + ')').join('\n');
}

function listMemoryRangesHere (args) {
  if (args.length !== 1) {
    args = [ ptr(offset) ];
  }
  const addr = +args[0];
  return listMemoryRangesJson()
    .filter(({base, size}) => (addr >= +base && addr < (+base + size)))
    .map(({base, size, protection, file}) =>
      [
        padPointer(base),
        '-',
        padPointer(base.add(size)),
        protection,
      ]
        .concat((file !== undefined) ? [file.path] : [])
        .join(' ')
    )
    .join('\n');
}

function rwxstr (x) {
  let str = '';
  str += (x & 1) ? 'r' : '-';
  str += (x & 2) ? 'w' : '-';
  str += (x & 4) ? 'x' : '-';
  return str;
}

function rwxint (x) {
  const ops = [ '---', '--x', '-w-', '-wx', 'r--', 'r-x', 'rw-', 'rwx' ];
  return ops.indexOf([x]);
}

function squashRanges (ranges) {
// console.log("SquashRanges");
  let res = [];
  let begin = ptr(0);
  let end = ptr(0);
  let lastPerm = 0;
  let lastFile = '';
  for (let r of ranges) {
    lastPerm |= rwxint(r.protection);
    if (r.file) {
      lastFile = r.file;
    }
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
        res.push({base: begin, size: end.sub(begin), protection: rwxstr(lastPerm), file: lastFile});
        end = ptr(0);
        begin = ptr(0);
        lastPerm = 0;
        lastFile = '';
      }
    }
  }
  if (!begin.equals(ptr(0))) {
    res.push({base: begin, size: end.sub(begin), protection: rwxstr(lastPerm), file: lastFile});
  }
  return res;
}

function listMemoryMaps () {
  return squashRanges(listMemoryRangesJson())
    .filter(_ => _.file)
    .map(({base, size, protection, file}) =>
      [
        padPointer(base),
        '-',
        padPointer(base.add(size)),
        protection,
      ]
        .concat((file !== undefined) ? [file.path] : [])
        .join(' ')
    )
    .join('\n');
}

function listMemoryRangesR2 () {
  return listMemoryRangesJson()
    .map(({base, size, protection, file}) =>
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
    .join('\n');
}

function listMemoryRanges () {
  return listMemoryRangesJson()
    .map(({base, size, protection, file}) =>
      [
        padPointer(base),
        '-',
        padPointer(base.add(size)),
        protection,
      ]
        .concat((file !== undefined) ? [file.path] : [])
        .join(' ')
    )
    .join('\n');
}

function listMemoryRangesJson () {
  return Process.enumerateRangesSync({
    protection: '---',
    coalesce: false
  });
}

function changeMemoryProtection (args) {
  const [address, size, protection] = args;

  Memory.protect(ptr(address), parseInt(size), protection);

  return true;
}

function getPid () {
  return _getpid();
}

function listThreads () {
  return Process.enumerateThreadsSync()
    .map(thread => thread.id)
    .join('\n');
}

function listThreadsJson () {
  return Process.enumerateThreadsSync()
    .map(thread => thread.id);
}

function regProfileAliasFor (arch) {
  switch (arch) {
    case 'arm64':
      return `=PC	pc
=SP	sp
=BP	x29
=A0	x0
=A1	x1
=A2	x2
=A3	x3
=ZF	zf
=SF	nf
=OF	vf
=CF	cf
=SN	x8
`;
      break;
    case 'arm':
      return `=PC	r15
=LR	r14
=SP	sp
=BP	fp
=A0	r0
=A1	r1
=A2	r2
=A3	r3
=ZF	zf
=SF	nf
=OF	vf
=CF	cf
=SN	r7
`;
      break;
    case 'x64':
      return `=PC	rip
=SP	rsp
=BP	rbp
=A0	rdi
=A1	rsi
=A2	rdx
=A3	rcx
=A4	r8
=A5	r9
=SN	rax
`;
      break;
    case 'x86':
      return `=PC	eip
=SP	esp
=BP	ebp
=A0	eax
=A1	ebx
=A2	ecx
=A3	edx
=A4	esi
=A5	edi
=SN	eax
`;
      break;
  }
}

function dumpRegisterProfile (args) {
  const threads = Process.enumerateThreadsSync();
  const thread = threads[0];
  const {id, state, context} = thread;
  const names = Object.keys(JSON.parse(JSON.stringify(context)))
    .filter(_ => _ !== 'pc' && _ !== 'sp');
  names.sort(compareRegisterNames);
  let off = 0;
  const inc = Process.pointerSize;
  let profile = regProfileAliasFor(Process.arch);
  for (let reg of names) {
    profile += `gpr\t${reg}\t${inc}\t${off}\t0\n`;
    off += inc;
  }
  return profile;
}

function dumpRegisterArena (args) {
  const threads = Process.enumerateThreadsSync();
  let [tidx] = args;
  if (!tidx) {
    tidx = 0;
  }
  if (tidx < 0 || tidx >= threads.length) {
    return '';
  }
  const thread = threads[tidx];
  const {id, state, context} = thread;
  const names = Object.keys(JSON.parse(JSON.stringify(context)))
    .filter(_ => _ !== 'pc' && _ !== 'sp');
  names.sort(compareRegisterNames);
  let off = 0;
  const inc = Process.pointerSize;
  let buf = Buffer.alloc(inc * names.length);
  for (let reg of names) {
    const r = context[reg];
    let b = [r.and(0xff),
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

function dumpRegistersR2 (args) {
  const threads = Process.enumerateThreadsSync();
  let [tidx] = args;
  if (!tidx) {
    tidx = 0;
  }
  if (tidx < 0 || tidx >= threads.length) {
    return '';
  }
  const thread = threads[tidx];
  const {id, state, context} = thread;
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

function dumpRegisters () {
  return Process.enumerateThreadsSync()
    .map(thread => {
      const {id, state, context} = thread;
      const heading = `tid ${id} ${state}`;
      const names = Object.keys(JSON.parse(JSON.stringify(context)));
      names.sort(compareRegisterNames);
      const values = names
        .map((name, index) => alignRight(name, 3) + ' : ' + padPointer(context[name]))
        .map(indent);
      return heading + '\n' + values.join('');
    })
    .join('\n\n');
}

function dumpRegistersJson () {
  return Process.enumerateThreadsSync();
}

function getOrSetEnv (args) {
  if (args.length === 0) {
    return getEnv().join('\n');
  }
  const {key, value} = getOrSetEnvJson(args);
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
  while (!envp.isNull() && !(env = Memory.readPointer(envp)).isNull()) {
    result.push(Memory.readCString(env));
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
  const path = args[0];
  const handle = _dlopen(Memory.allocUtf8String(path), RTLD_GLOBAL | RTLD_LAZY);
  if (handle.isNull()) {
    throw new Error('Failed to load: ' + path);
  }
  return handle.toString();
}

function formatArgs (args, fmt) {
  const a = [];
  let j = 0;
  for (let i = 0; i < fmt.length; i++, j++) {
    const arg = args[j];
    switch (fmt[i]) {
      case '+':
      case '^':
        j--;
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
      case 'O':
        if (ObjC.available) {
          if (!arg.isNull()) {
            const o = new ObjC.Object(arg);
            a.push(`${o.$className}: "${o.toString()}"`);
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
  return a;
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

function _readUntrustedUtf8 (address, length) {
  try {
    return Memory.readUtf8String(ptr(address), length);
  } catch (e) {
    if (e.message !== 'invalid UTF-8') {
      throw e;
    }
    return '(invalid utf8)';
  }
}

function traceList () {
  return traceListeners.map(_ => {
    return _.at.address + '\t' + _.at.moduleName + '\t' + _.at.name;
  }).join('\n');
}

function traceListJson () {
  return traceListeners.map(_ => JSON.stringify(_)).join('\n');
}

function getPtr (p) {
  p = p.trim();
  if (!p || p === '$$') {
    return ptr(offset);
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
  var arg = args[0];
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
  if (args.length === 2) {
    address = '' + getPtr(args[0]);
    format = args[1];
  } else {
    address = offset;
    format = args[0];
  }
  const traceOnEnter = format.indexOf('^') !== -1;
  const traceBacktrace = format.indexOf('+') !== -1;
  const at = nameFromAddress(address);

  const listener = Interceptor.attach(ptr(address), {
    myArgs: [],
    myBacktrace: [],
    onEnter: function (args) {
      if (!traceOnEnter) {
        this.keepArgs = cloneArgs(args, format);
      } else {
        this.myArgs = formatArgs(args, format);
      }
      if (traceBacktrace) {
        this.myBacktrace = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
      }
      if (traceOnEnter) {
        console.log(at, this.myArgs);
        if (traceBacktrace) {
          console.log(this.myBacktrace.join('\n    '));
        }
      }
    },
    onLeave: function (retval) {
      if (!traceOnEnter) {
        this.myArgs = formatArgs(this.keepArgs, format);
        console.log(at, this.myArgs, '=', retval);
        if (traceBacktrace) {
          console.log(this.myBacktrace.join('\n    '));
        }
      }
    }
  });
  traceListeners.push({
    at: at,
    format: format,
    listener: listener
  });
  return true;
}

function backtrace (args) {
  return 'TODO';
}

var log = '';
var traces = {};

function traceLogDump () {
  return log;
}

function traceLogClear () {
  const output = log;
  log = '';
  traces = {};
  return output;
}

function traceLog (msg) {
  if (typeof msg === 'string') {
    log += msg + '\n';
    return;
  }
  return traceLogClear();
}

function traceRegs (args) {
  if (args.length < 1) {
    return 'Usage: dtr [address] [reg ...]';
  }
  const address = getPtr(args[0]);
  const rest = args.slice(1);
  const listener = Interceptor.attach(address, traceFunction);
  function traceFunction (_) {
    const extra = (args[0] !== address) ? ` (${args[0]})` : '';
    const at = nameFromAddress(address);
    console.log(`\nTrace probe hit at ${address} ${extra} ${at}`);
    console.log('\t' + rest.map(r => {
      let tail = '';
      if (r.indexOf('=') !== -1) {
        const kv = r.split('=');
        this.context[kv[0]] = ptr(kv[1]);
      } else {
        const rv = ptr(this.context[r]);
        try {
          tail = Memory.readCString(rv);
          if (tail) {
            tail = ' (' + tail + ')';
          }
        } catch (e) {
          tail = '';
        }
      }
      return r + ' = ' + this.context[r] + tail;
    }).join('\n\t'));
    /* TODO: do we want to show backtrace too? */
    const showBacktrace = false;
    if (showBacktrace) {
      const bt = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
      console.log(bt.join('\n\t'));
    }
  }
  traceListeners.push({
    at: address,
    listener: listener,
    args: rest
  });
  return '';
}

function traceHere () {
  const args = [ offset ];
  args.forEach(address => {
    const at = DebugSymbol.fromAddress(ptr(address)) || '' + ptr(address);
    const listener = Interceptor.attach(ptr(address), function () {
      const bt = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
      const at = nameFromAddress(address);
      console.log('Trace probe hit at ' + address + '::' + at + '\n\t' + bt.join('\n\t'));
    });
    traceListeners.push({
      at: at,
      listener: listener
    });
  });
  return true;
}

function traceR2 (args) {
  return traceListeners.map(_ => `CC ${_.args} @ ${_.at}`).join('\n');
}

function traceJava (klass, method) {
  Java.perform(function () {
    var Throwable = Java.use('java.lang.Throwable');
    var Activity = Java.use('android.app.Activity');
    Activity.onResume.implementation = function () {
      console.log('[*] onResume() got called!');
      this.onResume();
      const message = Throwable.$new().getStackTrace().map(_ => _.toString()).join('\n');
      console.log('BACKTRACE', message);
    };
  });
}

function traceJson (args) {
  if (args.length === 0) {
    return traceListJson();
  }
  return new Promise(function (resolve, reject) {
    (function pull () {
      var arg = args.pop();
      if (arg === undefined) {
      	return resolve('');
      }
      numEval(arg).then(function (at) {
        console.log(traceReal(['' + at]));
        pull();
      }).catch(reject);
    })();
  });
}

function trace (args) {
  if (args.length === 0) {
    return traceList();
  }
  return traceJson(args);
}

var tracehooks = {};

function tracehookSet(name, format, callback) {
  if (name === null) {
    console.error('Cannot resolve name for ' + address);
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
    throw new TypeError('Expected input to be an ArrayBuffer')
  }

  var view = new Uint8Array(arrayBuffer)
  var result = ''
  var value

  for (var i = 0; i < view.length; i++) {
    value = view[i].toString(16)
    result += (value.length === 1 ? '0' + value : value)
  }

  return result
}

// \dth printf 0,1
function tracehook(address, args) {
  const at = nameFromAddress(address);
  const th = tracehooks[at];
  var fmtarg = [];
  if (th && th.format) {
    for (let fmt of th.format.split(' ')) {
      var [k, v] = fmt.split(':');
      switch (k) {
      case 'i':
        //console.log('int', args[v]);
        fmtarg.push(+args[v]);
        break;
      case 's':
        var [a, l] = v.split(',');
        var addr = ptr(args[a]);
        var size = +args[l];
        var buf = Memory.readByteArray(addr, size);
        //console.log('buf', arrayBufferToHex(buf));
        //console.log('string', Memory.readCString(addr, size));
        fmtarg.push(Memory.readCString(addr, size));
        break;
      case 'z':
        //console.log('string', Memory.readCString(args[+v]));
        fmtarg.push(Memory.readCString(ptr(args[+v])));
        break;
      case 'v':
        var [a, l] = v.split(',');
        var addr = ptr(args[a]);
        var buf = Memory.readByteArray(addr, +args[l]);
        fmtarg.push(arrayBufferToHex(buf));
        break;
      }
    }
  }
  console.log('[TRACE]', address, '(', at, ')', JSON.stringify(fmtarg));
}

function traceReal (args) {
  if (args.length === 0) {
    return traceList();
  }
  args.forEach(address => {
    if (address.startsWith('java:')) {
      const dot = address.lastIndexOf('.');
      if (dot !== -1) {
        const klass = address.substring(5, dot);
        const methd = address.substring(dot + 1);
        traceJava(klass, methd);
      } else {
        console.log('Invalid java method name. Use \\dt java:package.class.method');
      }
      return;
    }
    const at = DebugSymbol.fromAddress(ptr(address)) || '' + ptr(address);
    for (var i in traceListeners) {
      if (traceListeners[i].at === at) {
        console.error('There\'s a trace already in this address');
        return;
      }
    }
    const listener = Interceptor.attach(ptr(address), function (args) {
      tracehook(address, args);
      const frames = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
      traceLog('f trace.' + address + ' = ' + address);
      var prev = address;
      var prevName = nameFromAddress(prev);
      traceLog('agn ' + prevName);
      for (let i in frames) {
        var frame = frames[i];
        var addr = ('' + frame).split(' ')[0];
        var addrName = nameFromAddress(ptr(addr));
        console.log(' - ' + frame);
        traceLog('f trace.for.' + address + '.from.' + addr + ' = ' + prev);
        if (!traces[prev + addr]) {
          traceLog('agn ' + addrName);
          traceLog('agn ' + prevName);
          traceLog('age ' + prevName + ' ' + addrName);
          traces[prev + addr] = true;
        }
        prevName = addrName;
        prev = addr;
      }
    });
    traceListeners.push({
      at: at,
      listener: listener
    });
  });
}
// return true;

function clearTrace (args) {
  traceListeners.splice(0).forEach(lo => lo.listener.detach());
  return '';
}

function interceptHelp (args) {
  return 'Usage: di0, di1 or do-1 passing as argument the address to intercept';
}

function interceptRet0 (args) {
  const p = ptr(args[0]);
  Interceptor.attach(p, {
    onLeave (retval) {
      retval.replace(ptr('0'));
    }
  });
}

function interceptRet1 (args) {
  const p = ptr(args[0]);
  Interceptor.attach(p, {
    onLeave (retval) {
      retval.replace(ptr('1'));
    }
  });
}

function interceptRet_1 (args) { // eslint-disable-line
  const p = ptr(args[0]);
  Interceptor.attach(p, {
    onLeave (retval) {
      retval.replace(ptr('-1'));
    }
  });
}

function getenv (name) {
  return Memory.readUtf8String(_getenv(Memory.allocUtf8String(name)));
}

function setenv (name, value, overwrite) {
  return _setenv(Memory.allocUtf8String(name), Memory.allocUtf8String(value), overwrite ? 1 : 0);
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
  return _stalkTraceSomething(_stalkEverythingAndGetEvents, args);
}

function stalkTraceEverythingR2 (args) {
  return _stalkTraceSomethingR2(_stalkEverythingAndGetEvents, args);
}

function stalkTraceEverythingJson (args) {
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

    return result.join('\n');
  });

  function disasmOne (address, previousSymbolName, target) {
    let pd = disasm(address, 1, previousSymbolName);
    if (pd.charAt(pd.length - 1) === '\n') {
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

          return commands.join('\n');
        }));
      }
    }

    return result.join('\n');
  });
}

function _stalkTraceSomethingJson (getEvents, args) {
  return getEvents(args, (isBlock, events) => {
    const result = {
      event: config['stalker.event'],
      threads: events
    };

    return result;
  });
}

function _stalkFunctionAndGetEvents (args, eventsHandler) {
  _requireFridaVersion(10, 3, 13);

  const at = getPtr(args[0]);
  const conf = {
    event: config['stalker.event'],
    timeout: config['stalker.timeout'],
    stalkin: config['stalker.in']
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
    event: config['stalker.event'],
    timeout: config['stalker.timeout'],
    stalkin: config['stalker.in']
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
    // skip invalid instructions
    console.log(`warning: error parsing instruction @ ${cursor}`);
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
  read: read,
  write: write,
  state: state,
  perform: perform,
  evaluate: evaluate,
};

function read (params) {
  const {offset, count} = params;
  if (r2frida.hookedRead !== null) {
    return r2frida.hookedRead(offset, count);
  }
  try {
    const bytes = Memory.readByteArray(ptr(offset), count);
    return [{}, (bytes !== null) ? bytes : []];
  } catch (e) {
    return [{}, []];
  }
}

function isTrue (x) {
  return (x === true || x === 1 || x === 'true');
}

function write (params, data) {
  if (typeof r2frida.hookedWrite === 'function') {
    return r2frida.hookedWrite(params.offset, data);
  }
  if (isTrue(config['patch.code'])) {
    if (typeof Memory.patchCode !== 'function') {
      Memory.writeByteArray(ptr(params.offset), data);
    } else {
      Memory.patchCode(ptr(params.offset), 1, function (ptr) {
        Memory.writeByteArray(ptr, data);
      });
    }
  } else {
    Memory.writeByteArray(ptr(params.offset), data);
  }
  return [{}, null];
}

function state (params, data) {
  offset = params.offset;
  suspended = params.suspended;
  return [{}, null];
}

function isPromise(value) {
  return typeof value == 'object' && typeof value.then === 'function';
}

function perform (params) {
  const {command} = params;

  const tokens = command.split(/ /);
  const [name, ...args] = tokens;
  /*
  if (name.endsWith('?') && name !== 'e?') {
    console.error('TODO: show help of \\?~' + name.substring(0, name.length - 1));
    return;
  }
*/
  const userHandler = global.r2frida.commandHandler(name);
  const handler = userHandler !== undefined
    ? userHandler : commandHandlers[name];
  if (handler === undefined) {
    throw new Error('Unhandled command: ' + name);
  }

  if (isPromise(handler)) {
    throw new Error("The handler can't be a promise");
  }
  const value = handler(args);
  if (isPromise(value)) {
    return new Promise ((resolve, reject) => {
      return value.then(output => {
        resolve ([{
          value: normalizeValue(output)
        }, null]);
      }).catch(reject);
    });
    return value;
 }
  return [{
    value: normalizeValue(value)
  }, null];
}

function normalizeValue (value) {
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
    const {code} = params;

    if (ObjCAvailable && !suspended) {
      ObjC.schedule(ObjC.mainQueue, performEval);
    } else {
      performEval();
    }

    function performEval () {
      let result;
      try {
        const rawResult = (1, eval)(code); // eslint-disable-line
        global._ = rawResult;
        if (rawResult !== undefined && mjolner !== undefined) {
          result = mjolner.toCYON(rawResult);
        } else {
          result = 'undefined';
        }
      } catch (e) {
        result = 'throw new ' + e.name + '("' + e.message + '")';
      }

      resolve([{
        value: result
      }, null]);
    }
  });
}

if (ObjCAvailable) {
  mjolner.register();
}

Script.setGlobalAccessHandler({
  enumerate () {
    return [];
  },
  get (property) {
    if (mjolner !== undefined) {
      let result = mjolner.lookup(property);
      if (result !== null) {
        return result;
      }
    }
  }
});

function fridaVersion () {
  return { version: Frida.version };
}

function search (args) {
  return searchJson(args).then(hits => {
    return _readableHits(hits);
  });
}

function searchJson (args) {
  const pattern = _toHexPairs(args.join(' '));
  return _searchPatternJson(pattern).then(hits => {
    hits.forEach(hit => {
      try {
        const bytes = Memory.readByteArray(hit.address, 60);
        hit.content = _filterPrintable(bytes);
      } catch (e) {
      }
    });
    return hits.filter(hit => hit.content !== undefined);
  });
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
    .then(config => {
      const bigEndian = config['cfg.bigendian'];
      const bytes = _renderEndian(value, bigEndian, width);
      return searchHexJson([_toHexPairs(bytes)]);
    });
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
    if (c >= minPrintable && c <= maxPrintable) {
      printable.push(String.fromCharCode(c));
    }
  }
  return printable.join('');
}

function _readableHits (hits) {
  const output = hits.map(hit => {
    if (hit.flag !== undefined) {
      return `${hit.address} ${hit.flag} ${hit.content}`;
    }
    return `${hit.address} ${hit.content}`;
  });
  return output.join('\n');
}

function _searchPatternJson (pattern) {
  return hostCmdj('ej')
    .then(config => {
      const flags = config['search.flags'];
      const prefix = config['search.prefix'] || 'hit';
      const count = config['search.count'] || 0;
      const kwidx = config['search.kwidx'] || 0;

      const ranges = _getRanges(config['search.from'], config['search.to']);
      const nBytes = pattern.split(' ').length;

      qlog(`Searching ${nBytes} bytes: ${pattern}`);

      let results = [];
      const commands = [];
      let idx = 0;
      for (let range of ranges) {
        if (range.size === 0) {
          continue;
        }

        const rangeStr = `[${padPointer(range.address)}-${padPointer(range.address.add(range.size))}]`;
        qlog(`Searching ${nBytes} bytes in ${rangeStr}`);
        try {
          const partial = Memory.scanSync(range.address, range.size, pattern);

          partial.forEach((hit) => {
            if (flags) {
              hit.flag = `${prefix}${kwidx}_${idx + count}`;
              commands.push('fs+searches');
              commands.push(`f ${hit.flag} ${hit.size} ${hit.address}`);
              commands.push('fs-');
            }
            idx += 1;
          });

          results = results.concat(partial);
        } catch (e) {
        }
      }

      qlog(`hits: ${results.length}`);

      commands.push(`e search.kwidx=${kwidx + 1}`);

      return hostCmds(commands).then(() => {
        return results;
      });
    });

  function qlog (message) {
    if (!config['search.quiet']) {
      console.log(message);
    }
  }
}

function _configParseSearchIn () {
  const res = {
    current: false,
    perm: 'r--',
    path: null,
    heap: false
  };

  const c = config['search.in'];
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
    return Process.enumerateMallocRangesSync()
      .map(_ => {
        return {
          address: _.base,
          size: _.size
        };
      });
  }
  const ranges = Process.enumerateRangesSync({
    protection: searchIn.perm,
    coalesce: false
  }).filter(range => {
    const start = range.base;
    const end = start.add(range.size);
    const offPtr = ptr(offset);
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
  for (let h of hexSet) {
    inSet.delete(h);
  }
  return inSet.size === 0;
}

function fsList (args) {
  return fs.ls(args[0]);
}

function fsCat (args) {
  return fs.cat(args[0]);
}

function fsOpen (args) {
  return fs.open(args[0]);
}

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
  } else if (stanza.type === 'cmd') {
    onCmdResp(stanza.payload);
  } else {
    console.error('Unhandled stanza: ' + stanza.type);
  }
  recv(onStanza);
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
    cmdSerial += 1;
    pendingCmds[serial] = resolve;
    sendCommand(cmd, serial);
  });
}

function sendCommand (cmd, serial) {
  function sendIt () {
    sendingCommand = true;
    send(wrapStanza('cmd', {
      'cmd': cmd,
      'serial': serial
    }));
  }

  if (sendingCommand) {
    pendingCmdSends.push(sendIt);
  } else {
    sendIt();
  }
}

function onCmdResp (params) {
  const {serial, output} = params;

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
