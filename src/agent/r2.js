'use strict';

const globals = require('./globals');
const utils = require('./utils');

let cmdSerial = 0;

function getR2Arch (arch) {
  switch (arch) {
    case 'ia32':
    case 'x64':
      return 'x86';
    case 'arm64':
      return 'arm';
  }
  return arch;
}

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
    globals.pendingCmds[serial] = resolve;
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

  globals.sendingCommand = false;

  if (serial in globals.pendingCmds) {
    const onFinish = globals.pendingCmds[serial];
    delete globals.pendingCmds[serial];
    process.nextTick(() => onFinish(output));
  } else {
    throw new Error('Command response out of sync');
  }

  process.nextTick(() => {
    if (!globals.sendingCommand) {
      const nextSend = globals.pendingCmdSends.shift();
      if (nextSend !== undefined) {
        nextSend();
      }
    }
  });

  return [{}, null];
}

function _sendCommand (cmd, serial) {
  function sendIt () {
    globals.sendingCommand = true;
    send(utils.wrapStanza('cmd', {
      cmd: cmd,
      serial: serial
    }));
  }

  if (globals.sendingCommand) {
    globals.pendingCmdSends.push(sendIt);
  } else {
    sendIt();
  }
}

module.exports = {
  getR2Arch,
  hostCmds,
  hostCmd,
  hostCmdj,
  onCmdResp
};
