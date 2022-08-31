'use strict';

const config = require('./config');

const SwiftAvailable = function () {
  return config.getBoolean('want.swift') && Process.platform === 'darwin' && global.hasOwnProperty('Swift') && Swift.available;
};

module.exports = {
  SwiftAvailable
};
