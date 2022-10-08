// import { version } from "../../package.json";
const version = '5.7.7';

const commandHandlers = {};

export function pluginRegister (name, ch) {
  if (commandHandlers.hasOwnPropertyDescriptor(name)) {
    console.log('Cannot register the same handler twice');
    return false;
  }
  commandHandlers[name] = ch;
  return true;
}
export function pluginUnregister (name) {
  if (commandHandlers.hasOwnPropertyDescriptor(name)) {
    delete commandHandlers[name];
    return true;
  }
  return false;
}
export function commandHandler (name) {
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
export function pluginList () {
  return Object.keys(commandHandlers).join('\n');
}

global.r2frida = {
  version: version,
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

export const r2frida = global.r2frida;

export default {
  pluginRegister,
  pluginUnregister,
  commandHandler,
  pluginList,
  r2frida
};
