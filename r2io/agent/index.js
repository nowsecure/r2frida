'use strict';

const mjolner = require('mjolner');

const pointerSize = Process.pointerSize;

const commandHandlers = {
  'i': dumpInfo,
  'ij': dumpInfoJson,
  'il': listModules,
  'ilj': listModulesJson,
  'ie': listExports,
  'iej': listExportsJson,
  'is': lookupSymbol,
  'isj': lookupSymbolJson,
  'ic': listClasses,
  'icj': listClassesJson,
  'ip': listProtocols,
  'ipj': listProtocolsJson,
  'dpt': listThreads,
  'dptj': listThreadsJson,
  'dm': listMemoryRanges,
  'dmj': listMemoryRangesJson,
  'dp': getPid,
  'dpj': getPid,
  'dr': dumpRegisters,
  'drj': dumpRegistersJson,
  'env': getOrSetEnv,
  'envj': getOrSetEnvJson,
};

function dumpInfo() {
  const properties = dumpInfoJson();
  return Object.keys(properties)
  .map(k => k + '\t' + properties[k])
  .join('\n');
}

function dumpInfoJson() {
  return {
    arch: Process.arch,
    bits: pointerSize * 8,
    os: Process.platform,
    pid: getPid(),
    objc: ObjC.available,
    dalvik: Dalvik.available,
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
    return [type[0], name, address].join(' ');
  })
  .join('\n');
}

function listExportsJson(args) {
  const modules = (args.length === 0) ? Process.enumerateModulesSync().map(m => m.path) : [args[0]];
  return modules.reduce((result, moduleName) => {
    return result.concat(Module.enumerateExportsSync(moduleName));
  }, []);
}

function lookupSymbol(args) {
  return lookupSymbolJson(args)
  .map(({library, name, address}) => [library, name, address].join(' '))
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
    return Process.enumerateModulesSync()
    .reduce((result, m) => {
      const address = Module.findExportByName(m.path, exportName);
      if (address !== null) {
        result.push({
          library: m.name,
          name: exportName,
          address: address
        });
      }
      return result;
    }, []);
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

function listClassesJson(args) {
  if (args.length === 0) {
    return Object.keys(ObjC.classes);
  } else {
    const klass = ObjC.classes[args[0]];
    if (klass === undefined)
      throw new Error('Class not found');
    return klass.$ownMethods
    .reduce((result, methodName) => {
      result[methodName] = klass[methodName].implementation;
      return result;
    }, {});
  }
}

function listProtocols(args) {
  return listProtocolsJson(args)
  .join('\n');
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

function listThreads() {
  return Process.enumerateThreadsSync()
  .map(thread => thread.id)
  .join('\n');
}

function listThreadsJson() {
  return Process.enumerateThreadsSync()
  .map(thread => thread.id);
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

function getPid() {
  return _getpid();
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
    setEnv(k, v, true);
    return {
      key: k,
      value: v
    };
  } else {
    return {
      key: kv,
      value: getEnv(kv)
    };
  }
}

const _getpid = new NativeFunction(Module.findExportByName(null, 'getpid'), 'int', []);

const getEnvImpl = new NativeFunction(Module.findExportByName(null, 'getenv'), 'pointer', ['pointer']);
const setEnvImpl = new NativeFunction(Module.findExportByName(null, 'setenv'), 'int', ['pointer', 'pointer', 'int']);

function getEnv(name) {
  return Memory.readUtf8String(getEnvImpl(Memory.allocUtf8String(name)));
}

function setEnv(name, value, overwrite) {
  return setEnvImpl(Memory.allocUtf8String(name), Memory.allocUtf8String(value), overwrite ? 1 : 0);
}

function compareRegisterNames(lhs, rhs) {
  const lhsIndex = parseRegisterIndex(lhs);
  const rhsIndex = parseRegisterIndex(rhs);

  const lhsHasIndex = lhsIndex !== null;
  const rhsHasIndex = rhsIndex !== null;

  if (lhsHasIndex && rhsHasIndex) {
    return lhsIndex - rhsIndex;
  } else if (lhsHasIndex === rhsHasIndex) {
    const lhsLength = lhs.length;
    const rhsLength = rhs.length;
    if (lhsLength === rhsLength)
      return lhs.localeCompare(rhs);
    else if (lhsLength > rhsLength)
      return 1;
    else
      return -1;
  } else if (lhsHasIndex) {
    return 1;
  } else {
    return -1;
  }
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
  perform: perform,
  evaluate: evaluate,
};

function read(params) {
  const {offset, count} = params;

  const bytes = Memory.readByteArray(ptr(offset), count);

  return [{}, bytes];
}

function write(params) {
  const {offset, bytes} = params;

  Memory.writeByteArray(ptr(offset), bytes);

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

    if (ObjC.available)
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

mjolner.register();

function onStanza(stanza) {
  const handler = requestHandlers[stanza.type];
  if (handler !== undefined) {
    try {
      const value = handler(stanza.payload);
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
