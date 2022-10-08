import { wrapStanza } from './lib/utils.js';
import config from './config.js';
import { global } from './global.js';

export const logs = [];
export const traces = {};

export function traceEmit (msg) {
 const { wrapStanza } = require('./lib/utils'); // Workaround fix: By some reason the reference is not obtained globally
  const fileLog = config.getString('file.log');
  if (fileLog.length > 0) {
    send(wrapStanza('log-file', {
      filename: fileLog,
      message: msg
    }));
  } else {
    traceLog(msg);
  }
  if (config.getBoolean('hook.logs')) {
    logs.push(msg);
  }
  global.r2frida.logs = logs;
}
export function traceLog (msg) {
  if (config.getBoolean('hook.verbose')) {
    send(wrapStanza('log', {
      message: msg
    }));
  }
}
export default {
  traceEmit,
  traceLog
};
