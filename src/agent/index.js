'use strict';

/* ObjC.available is buggy on non-objc apps, so override this */
const ObjC_available = ObjC && ObjC.classes && typeof ObjC.classes.NSString !== 'undefined';

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
  'i*': dumpInfoR2,
  'ij': dumpInfoJson,
  'ii': listImports,
  'ii*': listImportsR2,
  'iij': listImportsJson,
  'il': listModules,
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
  'dp': getPid,
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
  'di0': interceptRet0,
  'di1': interceptRet1,
  'di-1': interceptRet_1,
};

const RTLD_GLOBAL = 0x8;
const RTLD_LAZY = 0x1;

function sym(name, ret, arg) {
  return new NativeFunction(Module.findExportByName(null, name), ret, arg);
}

const _getenv = sym('getenv', 'pointer', ['pointer']);
const _setenv = sym('setenv', 'int', ['pointer', 'pointer', 'int']);
const _getpid = sym('getpid', 'int', []);
const _dlopen = sym('dlopen', 'pointer', ['pointer', 'int']);
const _dup2 = sym('dup2', 'int', ['int', 'int']);
const _fstat = sym('fstat', 'int', ['int', 'pointer']);
const _close = sym('close', 'int', ['int']);

const traceListeners = [];

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

function dumpInfoJson() {
  return {
    arch: getR2Arch(Process.arch),
    bits: pointerSize * 8,
    os: Process.platform,
    pid: getPid(),
    objc: ObjC_available,
    java: Java.available,
  };
}

function listModules() {
  return Process.enumerateModulesSync()
  .map(m => padPointer(m.base) + ' ' + m.name)
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
  .map(({library, name, address}) => [library, name, address].join(' '))
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
  .map(({type, name, module, address}) => [type, name, module, address].join(' '))
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

function listClassesR2(args) {
  const className = args[0];
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
function listClassesJson(args) {
  if (args.length === 0) {
    return Object.keys(ObjC.classes);
  } else {
    const klass = ObjC.classes[args[0]];
    if (klass === undefined)
      throw new Error('Class not found');
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
  const {key, value} = getOrSetEnvJson(args);
  return key + '=' + value;
}

function getOrSetEnvJson(args) {
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
  if (!p || p === '$$') {
    return ptr(offset);
  }
  try {
    const ptr_p = ptr(p);
    if (p.startsWith('0x')) {
      return ptr_p;
    }
  } catch (e) {
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

  const at = DebugSymbol.fromAddress(ptr(address)) || '' + ptr(address);
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
    if (!isNaN(value))
      return value;
  }
  return null;
}

function indent(message, index) {
  if (index === 0)
    return message;

  if ((index % 3) === 0)
    return '\n' + message;

  return '\t' + message;
}

function alignRight(text, width) {
  let result = text;
  while (result.length < width)
    result = ' ' + result;
  return result;
}

function padPointer(value) {
  let result = value.toString(16);

  const paddedLength = 2 * pointerSize;
  while (result.length < paddedLength)
    result = '0' + result;

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

function write(params, data) {
  Memory.writeByteArray(ptr(params.offset), data);

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

  const handler = commandHandlers[name];
  if (handler === undefined)
    throw new Error('Unhandled command: ' + name);

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
        if (rawResult !== undefined)
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
  console.log("TODO: interpretFile is not yet implemented");
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
