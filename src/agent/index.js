'use strict';

const r2frida = require('./plugin');

/* ObjC.available is buggy on non-objc apps, so override this */
const ObjC_available = ObjC && ObjC.available && ObjC.classes && typeof ObjC.classes.NSString !== 'undefined';
const Java_available = Java && Java.available;

if (ObjC_available) {
  var mjolner = require('mjolner');
} else {
  console.error('Warning: r2frida cannot initialize mjolner');
}

const pointerSize = Process.pointerSize;

var offset = '0';

const commandHandlers = {
  '?V': fridaVersion,
  '.': interpretFile,
  'i': dumpInfo,
  'e': evalConfig,
  'i*': dumpInfoR2,
  'ij': dumpInfoJson,
  'db': breakpoint,
  'db-': breakpointUnset,
  'dc': breakpointContinue,
  'ii': listImports,
  'ii*': listImportsR2,
  'iij': listImportsJson,
  'il': listModules,
  'il*': listModulesR2,
  'ilj': listModulesJson,
  'ie': listExports,
  'ie*': listExportsR2,
  'iej': listExportsJson,
  'fD': lookupDebugInfo,
  'fd': lookupAddress,
  'fd.': lookupAddress,
  'fd*': lookupAddressR2,
  'fdj': lookupAddressJson,
  'ie.': lookupSymbolHere,
  'is.': lookupSymbolHere,
  'is': lookupSymbol,
  'is*': lookupSymbolR2,
  'isj': lookupSymbolJson,
  'ic': listClasses,
  'ic*': listClassesR2,
  'icj': listClassesJson,
  'ip': listProtocols,
  'ipj': listProtocolsJson,
  'dd': listFileDescriptors,
  'dd-': closeFileDescriptors,
  'dm': listMemoryRanges,
  'dmj': listMemoryRangesJson,
  'dmp': changeMemoryProtection,
  'dm.': listMemoryRangesHere,
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
  'drj': dumpRegistersJson,
  'env': getOrSetEnv,
  'envj': getOrSetEnvJson,
  'dl': dlopen,
  'dtf': traceFormat,
  'dt': trace,
  'dt.': traceHere,
  'dt-': clearTrace,
  'dtr': traceRegs,
  'di': interceptHelp,
  'di0': interceptRet0,
  'di1': interceptRet1,
  'di-1': interceptRet_1,
  'pd': disasmCode,
  'px': printHexdump,
  'x': printHexdump,
  'eval': evalCode,
};

const RTLD_GLOBAL = 0x8;
const RTLD_LAZY = 0x1;
const allocPool = {};

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
  const a = Memory.allocUtf8String(theString);
  return _addAlloc(a);
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
    .map(x => `${x}\t"${Memory.readUtf8String(x, 60)}"`)
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

function dxCall(args) {
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
  switch (nfArgsData.length) {
  case 0: return fun();
  case 1: return fun(nfArgsData[0]);
  case 2: return fun(nfArgsData[0], nfArgsData[1]);
  case 3: return fun(nfArgsData[0], nfArgsData[1], nfArgsData[2]);
  case 4: return fun(nfArgsData[0], nfArgsData[1], nfArgsData[2], nfArgsData[3]);
  case 5: return fun(nfArgsData[0], nfArgsData[1], nfArgsData[2], nfArgsData[3], nfArgsData[4]);
  }
  return fun();
}

function dxHexpairs(args) {
  return 'TODO';
}

function evalCode(args) {
  const code = args.join(' ');
  eval(code);
  return '';
}

function printHexdump(lenstr) {
  const len = +lenstr || 20;
  return hexdump(ptr(offset), len) || '';
}

function disasmCode(lenstr) {
  const len = +lenstr || 20;
  return disasm(offset, len);
}

function disasm(addr, len) {
  len = len || 20;
  if (typeof addr === 'string') {
    try {
      addr = Module.findExportByName(null, addr);
      if (!addr) {
        throw undefined;
      }
    } catch (e) {
      addr = ptr(offset);
    }
  }
  addr = ptr(addr)
  let oldName = null;
  let lastAt = null;
  let disco = '';
  for (let i = 0; i < len; i++) {
    const op = Instruction.parse(addr);
    const ds = DebugSymbol.fromAddress(addr);
    if (ds.name !== null && ds.name !== oldName) {
      console.log(';;;', ds.moduleName, ds.name);
      oldName = ds.name;
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
            //console.log(';  str:', str);
            disco += ';  str:' + str + '\n';
          } catch (e) {
            const p2 = Memory.readPointer(p);
            const str2 = Memory.readCString(p2);
            //console.log(';  str2:', str2);
            disco += ';  str2:' + str2 + '\n';
            console.log(e);
          }
        }
        lastAt = at;
        const di = DebugSymbol.fromAddress(ptr(at));
        if (di.name !== null) {
          comment = '\t; ' + (di.moduleName || '') + ' ' + di.name
        } else {
          const op2 = Instruction.parse(ptr(at));
          const id2 = op2.opStr.indexOf('#0x');
          const at2 = op2.opStr.substring(id2 + 1).split(' ')[0].split(',')[0].split(']')[0];
          const di2 = DebugSymbol.fromAddress(ptr(at2));
          if (di2.name !== null) {
            comment = '\t; -> ' + (di2.moduleName || '') + ' ' + di2.name
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

function sym(name, ret, arg) {
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
const _fstat = sym('fstat', 'int', ['int', 'pointer']);
const _close = sym('close', 'int', ['int']);
const __environ = Memory.readPointer(Module.findExportByName(null, 'environ'));

const traceListeners = [];
const config = {
  'patch.code': true
};

function evalConfig(args) {
  if (args.length === 0) {
    return Object.keys(config)
    .map(k => 'e ' + k + '\=' + config[k])
    .join('\n');
  }
  const kv = args[0].split(/=/);
  if (kv.length === 2) {
    if (config[kv[0]] !== undefined) {
      config[kv[0]] = kv[1];
    } else {
      console.error('unknown variable');
    }
    return '';
  }
  return config[args[0]];
}

function dumpInfo() {
  const properties = dumpInfoJson();
  return Object.keys(properties)
  .map(k => k + '\t' + properties[k])
  .join('\n');
}

function dumpInfoR2() {
  const properties = dumpInfoJson();
  return [
    'e asm.arch=' + properties.arch,
    'e asm.bits=' + properties.bits,
    'e asm.os=' + properties.os
  ].join('\n');
}

function getR2Arch(arch) {
  switch(arch) {
  case 'x64':
    return 'x86';
  case 'arm64':
    return 'arm';
  }
  return arch;
}

var breakpoints = {};

function breakpointUnset(args) {
  if (args.length === 1) {
    const symbol = Module.findExportByName(null, args[0]);
    const addr = symbol? symbol: ptr(args[0]);
    const newbps = [];
    for (let k of Object.keys(breakpoints)) {
      let bp = breakpoints[k];
      if (args[0] === '*' || bp.address === addr) {
        Interceptor.revert(ptr(bp.address));
      } else {
        newbps.push(bp);
      }
    }
    breakpoints = {};
    for (let bp of newbps) {
      breakpoints[bp.address] = bp;
    }
    return '';
  }
  return 'Usage: db- [addr|*]';
}

function breakpointExist(addr) {
  const bp = breakpoints['' + addr];
  return bp && !bp.continue;
}

function breakpointContinue(args) {
  let count = 0;
  for (let k of Object.keys(breakpoints)) {
    let bp = breakpoints[k];
    if (bp.stopped) {
      count ++;
      bp.continue = true;
    }
  }
  return 'Continue ' + count + ' thread(s).';
}

function breakpoint(args) {
  if (args.length === 1) {
    const symbol = Module.findExportByName(null, args[0]);
    const addr = symbol? symbol: ptr(args[0]);
    if (breakpointExist(addr)) {
      return 'Cant set a breakpoint twice';
    }
    const addrString = '' + addr;
    const bp = {
      name: args[0],
      stopped: false,
      address: addrString,
      continue: false,
      handler: Interceptor.attach(addr, {
        onEnter: function (args) {
          breakpoints[addrString].stopped = true;
          while (breakpointExist(addr)) {
            Thread.sleep(1);
          }
          breakpoints[addrString].stopped = false;
          breakpoints[addrString].continue = false;
        }
      })
    }
    breakpoints[addrString] = bp;
  }
  return JSON.stringify(breakpoints, null, '  ');
}

function dumpInfoJson() {
  return {
    arch: getR2Arch(Process.arch),
    bits: pointerSize * 8,
    os: Process.platform,
    pid: getPid(),
    uid: _getuid(),
    objc: ObjC_available,
    java: Java_available,
  };
}

function listModules() {
  return Process.enumerateModulesSync()
  .map(m => padPointer(m.base) + ' ' + m.name)
  .join('\n');
}

function listModulesR2() {
  return Process.enumerateModulesSync()
  .map(m => 'f lib.' + m.name + ' = ' + padPointer(m.base))
  .join('\n');
}

function listModulesJson() {
  return Process.enumerateModulesSync();
}

function listExports(args) {
  return listExportsJson(args)
  .map(({type, name, address}) => {
    return [address, type[0], name].join(' ');
  })
  .join('\n');
}

function listExportsR2(args) {
  return listExportsJson(args)
  .map(({type, name, address}) => {
    return ['f', 'sym.' + type.substring(0, 3) + '.' + name, '=', address].join(' ');
  })
  .join('\n');
}

function listExportsJson(args) {
  const modules = (args.length === 0) ? Process.enumerateModulesSync().map(m => m.path) : [args[0]];
  return modules.reduce((result, moduleName) => {
    return result.concat(Module.enumerateExportsSync(moduleName));
  }, []);
}

function lookupDebugInfo(args) {
  const o = DebugSymbol.fromAddress(ptr(''+args));
  console.log(o);
}

function lookupDebugInfoR2(args) {
  const o = DebugSymbol.fromAddress(ptr(''+args));
  console.log(o);
}

function lookupAddress(args) {
  if (args.length === 0) {
    args = [ptr(offset)];
  }
  return lookupAddressJson(args)
  .map(({type, name, address}) => [type, name, address].join(' '))
  .join('\n');
}

function lookupAddressR2(args) {
  return lookupAddressJson(args)
  .map(({type, name, address}) =>
    [ 'f', 'sym.' + name, '=', address].join(' '))
  .join('\n');
}

function lookupAddressJson(args) {
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

function lookupSymbolHere(args) {
  return lookupAddress([ptr(offset)]);
}

function lookupSymbol(args) {
  return lookupSymbolJson(args)
  //.map(({library, name, address}) => [library, name, address].join(' '))
  .map(({address}) => '' + address)
  .join('\n');
}

function lookupSymbolR2(args) {
  return lookupSymbolJson(args)
  .map(({name, address}) =>
    [ 'f', 'sym.' + name, '=', address].join(' '))
  .join('\n');
}

function lookupSymbolJson(args) {
  if (args.length === 2) {
    const [moduleName, exportName] = args;
    const address = Module.findExportByName(moduleName, exportName);
    if (address === null)
      return [];
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

function listImports(args) {
  return listImportsJson(args)
  .map(({type, name, module, address}) => [address, type[0], name, module].join(' '))
  .join('\n');
}

function listImportsR2(args) {
  return listImportsJson(args).map((x) => {
    return "f sym.imp." + x.name + ' = ' + x.address;
  }).join('\n');
}

function listImportsJson(args) {
  const alen = args.length;
  if (alen === 2) {
    const [moduleName, importName] = args;
    const imports = Module.enumerateImportsSync(moduleName);
    if (imports === null)
      return [];
    return imports.filter((x) => {
      return x.name === importName;
    });
  } else if (alen === 1) {
    return Module.enumerateImportsSync(args[0]) || [];
  }
  const modules = Process.enumerateModulesSync() || []
  if (modules.length > 0) {
    return Module.enumerateImportsSync(modules[0].name) || [];
  }
}

function listClasses(args) {
  const result = listClassesJson(args);
  if (result instanceof Array) {
    return result.join('\n');
  } else {
    return Object.keys(result)
    .map(methodName => {
      const address = result[methodName];
      return [padPointer(address), methodName].join(' ')
    })
    .join('\n');
  }
}

function classGlob(k, v) {
  if (!k || !v) {
    return true;
  }
  return k.indexOf(v.replace(/\*/g, '')) !== -1;
}

function listClassesR2(args) {
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
    function flagName(m) {
      return 'sym.objc.' +
        (className + '.' + m)
        .replace(':', '')
        .replace(' ', '')
        .replace('-', '')
        .replace('+', '');
    }
    return Object.keys(result)
    .map(methodName => {
      const address = result[methodName];
      return ['f', flagName(methodName) , '=', padPointer(address)].join(' ')
    })
    .join('\n');
  }
}

/* this ugly sync mehtod with while+settimeout is needed because
  returning a promise is not properly handled yet and makes r2
  lose track of the output of the command so you cant grep on it */
function listJavaClassesJsonSync(args) {
    if (args.length === 1) {
      let methods = undefined;
      /* list methods */
      Java.perform(function() {
        const obj = Java.use(args[0])
        methods = Object.getOwnPropertyNames(Object.getPrototypeOf(obj));
        // methods = Object.keys(obj).map(x => x + ':' + obj[x] );
      });
      while (methods === undefined) {
        /* wait here */
        setTimeout(null, 0);
      }
      return methods;
    }
    let classes = undefined;
    /* list all classes */
    Java.perform(function() {
      try {
        classes = Java.enumerateLoadedClassesSync();
      } catch (e) {
        classes = null;
      }
    });
    while (classes === undefined) {
      /* wait here */
      setTimeout(null, 0);
    }
    return classes;
}

function listJavaClassesJson(args) {
  return new Promise(function (reject, resolve) {
    if (args.length === 1) {
      /* list methods */
      Java.perform(function() {
        var obj = Java.use(args[0])
        resolve(JSON.stringify(obj, null, '  '));
      });
      return;
    }
    /* list all classes */
    Java.perform(function() {
      try {
        resolve(Java.enumerateLoadedClassesSync().join('\n'));
      } catch (e) {
        reject(e);
      }
    });
  });
}

function listClassesJson(args) {
  if (Java_available) {
    return listJavaClassesJsonSync(args);
    // return listJavaClassesJson(args);
  }
  if (args.length === 0) {
    return Object.keys(ObjC.classes);
  } else {
    const klass = ObjC.classes[args[0]];
    if (klass === undefined)
      throw new Error('Class ' + args[0] + ' not found');
    return klass.$ownMethods
    .reduce((result, methodName) => {
      try {
        result[methodName] = klass[methodName].implementation;
      } catch(_) {
        console.log('warning: unsupported method \'' + methodName + '\'');
      }
      return result;
    }, {});
  }
}

function listProtocols(args) {
  return listProtocolsJson(args)
  .join('\n');
}

function closeFileDescriptors(args) {
  if (args.length === 0) {
    return "Please, provide a file descriptor";
  }
  return _close(+args[0]);
}

function listFileDescriptors(args) {
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

function listProtocolsJson(args) {
  if (args.length === 0) {
    return Object.keys(ObjC.protocols);
  } else {
    const protocol = ObjC.protocols[args[0]];
    if (protocol === undefined)
      throw new Error('Protocol not found');
    return Object.keys(protocol.methods);
  }
}

function listMemoryRangesHere(args) {
  if (args.length != 1) {
    args = [ ptr(offset) ];
  }
  const addr = +args[0];
  return listMemoryRangesJson()
  .filter(({base, size}) => {
    return (addr >= +base && addr < (+base + size));
  }).map(({base, size, protection, file}) =>
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

function listMemoryRanges() {
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

function listMemoryRangesJson() {
  return Process.enumerateRangesSync({
    protection: '---',
    coalesce: false
  });
}

function changeMemoryProtection(args) {
  const [address, size, protection] = args;

  Memory.protect(ptr(address), parseInt(size), protection);

  return true;
}

function getPid() {
  return _getpid();
}

function listThreads() {
  return Process.enumerateThreadsSync()
  .map(thread => thread.id)
  .join('\n');
}

function listThreadsJson() {
  return Process.enumerateThreadsSync()
  .map(thread => thread.id);
}

function dumpRegisters() {
  return Process.enumerateThreadsSync()
    .map(thread => {
      const {id, state, context} = thread;

      const heading = `tid ${id} ${state}`;

      const names = Object.keys(context);
      names.sort(compareRegisterNames);
      const values = names
      .map((name, index) => alignRight(name, 3) + ' : ' + padPointer(context[name]))
      .map(indent);

      return heading + '\n' + values.join('');
    })
    .join('\n\n');
}

function dumpRegistersJson() {
  return Process.enumerateThreadsSync();
}

function getOrSetEnv(args) {
  if (args.length === 0) {
    return getEnv().join('\n');
  }
  const {key, value} = getOrSetEnvJson(args);
  return key + '=' + value;
}

function getOrSetEnvJson(args) {
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

function getEnv() {
  const result = [];
  let envp = __environ;
  let env;
  while (!envp.isNull() && !(env = Memory.readPointer(envp)).isNull()) {
    result.push(Memory.readCString(env));
    envp = envp.add(Process.pointerSize);
  }
  return result;
}

function getEnvJson() {
  return getEnv().map(kv => {
    const eq = kv.indexOf('=');
    return {
      key: kv.substring(0, eq),
      value: kv.substring(eq + 1)
    };
  });
}

function dlopen(args) {
  const path = args[0];
  const handle = _dlopen(Memory.allocUtf8String(path), RTLD_GLOBAL | RTLD_LAZY);
  if (handle.isNull())
    throw new Error('Failed to load: ' + path);
  return handle.toString();
}

function formatArgs(args, fmt) {
  const a = [];
  let j = 0;
  for (let i = 0; i < fmt.length; i++, j++) {
    const arg = args[j];
    switch(fmt[i]) {
    case '+':
    case '^':
      j--;
      break;
    case 'x':
      a.push ('' + ptr(arg));
      break;
    case 'c':
      a.push ("'" + arg + "'");
      break;
    case 'i':
      a.push ( +arg);
      break;
    case 'z': // *s
      const s = Memory.readUtf8String(ptr(arg));
      a.push (JSON.stringify(s));
      break;
    case 'Z': // *s[i]
      const len = +args[j + 1];
      const str = Memory.readUtf8String(ptr(arg), len);
      a.push (JSON.stringify(str));
      break;
    default:
      a.push (arg);
      break;
    }
  }
  return a;
}

function traceList() {
  traceListeners.forEach((tl) => {
    console.log('dt', JSON.stringify(tl));
  });
  return true;
}

function getPtr(p) {
  p = p.trim();
  if (!p || p === '$$') {
    return ptr(offset);
  }
  try {
    if (p.substring(0,2) === '0x') {
      return ptr(p);
    }
  } catch (e) {
   // console.error(e);
  }
  // return DebugSymbol.fromAddress(ptr_p) || '' + ptr_p;
  return Module.findExportByName(null, p);
}

function traceFormat(args) {
  if (args.length == 0) {
    return traceList();
  }
  if (args.length == 2) {
    var address = '' + getPtr(args[0]);
    var format = args[1];
  } else {
    var address = offset;
    var format = args[0];
  }
  const traceOnEnter = format.indexOf('^') !== -1;
  const traceBacktrace = format.indexOf('+') !== -1;

  var module = Process.enumerateModulesSync()[0].name;
  var imports = Module.enumerateImportsSync(module);
  var at = '';
  for (var index = 0; index < imports.length; index++) {
    if (imports[index].address == address) {
      at = imports[index].name;
      break;
    }
  }
  if (at == '') {
    '' + ptr(address);
  }
  //const at = DebugSymbol.fromAddress(ptr(address)) || '' + ptr(address);
  const listener = Interceptor.attach(ptr(address), {
    myArgs: [],
    myBacktrace: [],
    onEnter: function (args) {
      this.myArgs = formatArgs(args, format);
      if (traceBacktrace) {
        this.myBacktrace = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
      }
      if (traceOnEnter) {
        console.log (at, this.myArgs);
        if (traceBacktrace) {
          console.log(this.myBacktrace.join('\n    '));
        }
      }
    },
    onLeave: function (retval) {
      if (!traceOnEnter) {
        console.log (at, this.myArgs, '=', retval);
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

function traceRegs(args) {
  const address = getPtr(args[0]);
  const rest = args.slice(1);
  const listener = Interceptor.attach(address, function () {
    console.log('Trace probe hit at ' + address + ' @ ' + args[0] + ':'); // + bt.join('\n\t'));
    console.log('\t' + rest.map(r => {
      let tail = '';
      const rv = ptr(this.context[r]);
      try {
        tail = Memory.readCString(rv);
        if (tail) {
          tail = ' (' + tail + ')';
        }
      } catch (e) {
      }
      return r + ' = ' + this.context[r] + tail;
    }).join('\n\t'));
    /* TODO: do we want to show backtrace too? */
    var showBacktrace = false;
    if (showBacktrace) {
      const bt = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
      console.log(bt.join('\n\t'));
    }
  });
  traceListeners.push({
    at: address,
    listener: listener
  });
  return true;
}

function traceHere() {
  const args = [ offset ];
  args.forEach(address => {
    const at = DebugSymbol.fromAddress(ptr(address)) || '' + ptr(address);
    const listener = Interceptor.attach(ptr(address), function () {
      const bt = Thread.backtrace(this.context).map(DebugSymbol.fromAddress);
      console.log('Trace probe hit at ' + address + ':\n\t' + bt.join('\n\t'));
    });
    traceListeners.push({
      at: at,
      listener: listener
    });
  });
  return true;
}

function trace(args) {
  if (args.length == 0) {
    return traceList();
  }
  args.forEach(address => {
    const at = DebugSymbol.fromAddress(ptr(address)) || '' + ptr(address);
    const listener = Interceptor.attach(ptr(address), function () {
      console.log('Trace probe hit at ' + address + ':\n\t' + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join('\n\t'));
    });
    traceListeners.push({
      at: at,
      listener: listener
    });
  });
  return true;
}

function clearTrace(args) {
  traceListeners.splice(0).forEach(lo => lo.listener.detach());
}

function interceptHelp(args) {
  return 'Usage: di0, di1 or do-1 passing as argument the address to intercept';
}

function interceptRet0(args) {
  const p = ptr(args[0]);
  Interceptor.attach(p, {
    onLeave(retval) {
      retval.replace(ptr('0'));
    }
  });
}

function interceptRet1(args) {
  const p = ptr(args[0]);
  Interceptor.attach(p, {
    onLeave(retval) {
      retval.replace(ptr('1'));
    }
  });
}

function interceptRet_1(args) {
  const p = ptr(args[0]);
  Interceptor.attach(p, {
    onLeave(retval) {
      retval.replace(ptr('-1'));
    }
  });
}

function getenv(name) {
  return Memory.readUtf8String(_getenv(Memory.allocUtf8String(name)));
}

function setenv(name, value, overwrite) {
  return _setenv(Memory.allocUtf8String(name), Memory.allocUtf8String(value), overwrite ? 1 : 0);
}

function compareRegisterNames(lhs, rhs) {
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

function parseRegisterIndex(name) {
  const length = name.length;
  for (let index = 1; index < length; index++) {
    const value = parseInt(name.substr(index));
    if (!isNaN(value)) {
      return value;
    }
  }
  return null;
}

function indent(message, index) {
  if (index === 0) {
    return message;
  }
  if ((index % 3) === 0) {
    return '\n' + message;
  }
  return '\t' + message;
}

function alignRight(text, width) {
  let result = text;
  while (result.length < width) {
    result = ' ' + result;
  }
  return result;
}

function padPointer(value) {
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
  seek: seek,
  perform: perform,
  evaluate: evaluate,
};

function read(params) {
  const {offset, count} = params;
  try {
    const bytes = Memory.readByteArray(ptr(offset), count);
    return [{}, (bytes !== null) ? bytes : []];
  } catch (e) {
    return [{}, []];
  }
}

function isTrue(x) {
  return (x === true || x === 1 || x === 'true');
}

function write(params, data) {
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

function seek(params, data) {
  offset = params.offset;
  return [{}, null];
}

function perform(params) {
  const {command} = params;

  const tokens = command.split(/ /);
  const [name, ...args] = tokens;

  const userHandler = global.r2frida.commandHandler(name);
  const handler = userHandler !== undefined
    ? userHandler : commandHandlers[name];
  if (handler === undefined) {
    throw new Error('Unhandled command: ' + name);
  }

  const value = handler(args);
  return [{
    value: (typeof value === 'string') ? value : JSON.stringify(value),
  }, null];
}

function evaluate(params) {
  return new Promise(resolve => {
    const {code} = params;

    if (ObjC_available)
      ObjC.schedule(ObjC.mainQueue, performEval);
    else
      performEval();

    function performEval() {
      let result;
      try {
        const rawResult = (1, eval)(code);
        global._ = rawResult;
        if (rawResult !== undefined && mjolner !== undefined)
          result = mjolner.toCYON(rawResult);
        else
          result = 'undefined';
      } catch (e) {
        result = 'throw new ' + e.name + '("' + e.message + '")';
      }

      resolve([{
        value: result,
      }, null]);
    }
  });
}

if (ObjC_available) {
  mjolner.register();
}

Script.setGlobalAccessHandler({
  enumerate() {
    return [];
  },
  get(property) {
    if (mjolner !== undefined) {
      let result = mjolner.lookup(property);
      if (result !== null) {
        return result;
      }
    }
  }
});

function interpretFile(args) {
  console.log('TODO: interpretFile is not yet implemented');
  return {};
}

function fridaVersion() {
  return { version: Frida.version };
}

function onStanza(stanza, data) {
  const handler = requestHandlers[stanza.type];
  if (handler !== undefined) {
    try {
      const value = handler(stanza.payload, data);
      if (value instanceof Promise) {
        value
          .then(([replyStanza, replyBytes]) => {
            send(replyStanza, replyBytes);
          })
          .catch(e => {
            send({
              error: e.message
            });
          });
      } else {
        const [replyStanza, replyBytes] = value;
        send(replyStanza, replyBytes);
      }
    } catch (e) {
      send({
        error: e.message
      });
    }
  } else {
    console.error('Unhandled stanza: ' + stanza.type);
  }
  recv(onStanza);
}
recv(onStanza);
