'use strict';

const config = require('./config');
const utils = require('./utils');

const logs = [];
const traces = {};

function traceEmit (msg) {
  const fileLog = config.getString('file.log');
  if (fileLog.length > 0) {
    send(utils.wrapStanza('log-file', {
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

function traceLog (msg) {
  if (config.getBoolean('hook.verbose')) {
    send(utils.wrapStanza('log', {
      message: msg
    }));
  }
}

module.exports = {
  logs,
  traces,
  traceEmit,
  traceLog
};
