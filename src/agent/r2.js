'use strict';

const utils = require('./utils');

let cmdSerial = 0;
const pendingCmds = {};
const pendingCmdSends = [];
let sendingCommand = false;

function hostCmds (commands) {
  let i = 0;
  function sendOne () {
    if (i < commands.length) {
      return hostCmd(commands[i]).then(() => {
        i += 1;
        return sendOne();
      });
    } else {
      return Promise.resolve();
    }
  }
  return sendOne();
}

function hostCmd (cmd) {
  return new Promise((resolve) => {
    const serial = cmdSerial;
    cmdSerial++;
    pendingCmds[serial] = resolve;
    _sendCommand(cmd, serial);
  });
}

function hostCmdj (cmd) {
  return hostCmd(cmd)
    .then(output => {
      return JSON.parse(output);
    });
}

function onCmdResp (params) {
  const { serial, output } = params;

  sendingCommand = false;

  if (serial in pendingCmds) {
    const onFinish = pendingCmds[serial];
    delete pendingCmds[serial];
    process.nextTick(() => onFinish(output));
  } else {
    throw new Error('Command response out of sync');
  }

  process.nextTick(() => {
    if (!sendingCommand) {
      const nextSend = pendingCmdSends.shift();
      if (nextSend !== undefined) {
        nextSend();
      }
    }
  });

  return [{}, null];
}

function _sendCommand (cmd, serial) {
  function sendIt () {
    sendingCommand = true;
    send(utils.wrapStanza('cmd', {
      cmd: cmd,
      serial: serial
    }));
  }

  if (sendingCommand) {
    pendingCmdSends.push(sendIt);
  } else {
    sendIt();
  }
}

module.exports = {
  hostCmds,
  hostCmd,
  hostCmdj,
  onCmdResp
};
