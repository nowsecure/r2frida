'use strict';

const SwiftAvailable = function () {
    return config.getBoolean('want.swift') && Process.platform === 'darwin' && global.hasOwnProperty('Swift') && Swift.available;
  };
