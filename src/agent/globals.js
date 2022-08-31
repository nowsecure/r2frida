'use strict';

/* globals */
const pointerSize = Process.pointerSize;
let Gcwd = '/';
const tracehooks = {};
const allocPool = {};
const pendingCmds = {};
const pendingCmdSends = [];
let sendingCommand = false;


module.exports = {
  pointerSize,
  tracehooks,
  allocPool,
  logs,
  traces,
  pendingCmds,
  pendingCmdSends,
  sendingCommand,
  Gcwd
};
