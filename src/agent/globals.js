'use strict';

/* globals */
const pointerSize = Process.pointerSize;
const tracehooks = {};
const allocPool = {};
const pendingCmds = {};
const pendingCmdSends = [];
let logs = [];
let traces = {};
let sendingCommand = false;
let Gcwd = '/';

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
