const commandHandlers = {};

function pluginRegister (name, ch) {
  if (commandHandlers.hasOwnPropertyDescriptor(name)) {
    console.log('Cannot register the same handler twice');
    return false;
  }
  commandHandlers[name] = ch;
  return true;
}

function pluginUnregister (name) {
  if (commandHandlers.hasOwnPropertyDescriptor(name)) {
    delete commandHandlers[name];
    return true;
  }
  return false;
}

function commandHandler (name) {
  for (const key of Object.keys(commandHandlers)) {
    const ch = commandHandlers[key];
    if (typeof ch === 'function') {
      const handler = ch(name);
      if (handler !== undefined) {
        return handler;
      }
    }
  }
  return undefined;
}

function pluginList () {
  return Object.keys(commandHandlers).join('\n');
}

global.r2frida = {
  version: require('../../package.json').version,
  commandHandler: commandHandler,
  pluginRegister: pluginRegister,
  pluginUnregister: pluginUnregister,
  pluginList: pluginList,
  // io hook plugin API //
  hookedRead: null,
  hookedWrite: null,
  hookedRanges: null,
  hookedScan: null
};

module.exports = global.r2frida;
