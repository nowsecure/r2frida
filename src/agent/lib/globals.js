'use strict';

/* globals */
const pointerSize = Process.pointerSize;
const allocPool = {};
const pendingCmds = {};
const pendingCmdSends = [];
let sendingCommand = false;

module.exports = {
  pointerSize,
  allocPool,
  pendingCmds,
  pendingCmdSends,
  sendingCommand
};
