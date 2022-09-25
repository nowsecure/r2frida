'use strict';

const config = require('./config');
const log = require('./log');
const utils = require('./utils');

const SwiftAvailable = function () {
  return config.getBoolean('want.swift') && Process.platform === 'darwin' && global.hasOwnProperty('Swift') && Swift.available;
};

function traceSwift (klass, method) {
  if (!SwiftAvailable()) {
    return;
  }
  const targetAddress = utils.getPtr('swift:' + klass + '.' + method);
  if (ptr(0).equals(targetAddress)) {
    console.error('Missing method ' + method + ' in class ' + klass);
    return;
  }

  const callback = function (args) {
    const msg = ['[SWIFT]', klass, method, JSON.stringify(args)];
    log.traceEmit(msg.join(' '));
  };
  Swift.Interceptor.Attach(targetAddress, callback);
}

module.exports = {
  SwiftAvailable,
  traceSwift
};
