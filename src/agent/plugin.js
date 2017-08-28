const commandHandlers = {};

function pluginRegister (name, ch) {
  if (commandHandlers.hasOwnProperty(name)) {
    console.log('Cannot register the same handler twice');
    return false;
  }
  commandHandlers[name] = ch;
  return true;
}

function pluginUnregister (name) {
  if (commandHandlers.hasOwnProperty(name)) {
    delete commandHandlers[name];
    return true;
  }
  return false;
}

function commandHandler (name) {
  for (let key of Object.keys(commandHandlers)) {
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
  pluginList: pluginList
};

module.exports = global.r2frida;
