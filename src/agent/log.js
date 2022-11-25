import config from './config.js';
import { wrapStanza } from './lib/utils.js';
'use strict';

export const logs = [];

export function traceEmit (msg) {
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
  logs,
  traceEmit,
  traceLog
};
