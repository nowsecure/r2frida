'use strict';

const globals = require('./globals');
const { sym } = require('./sys');
const utils = require('./utils');

let cmdSerial = 0;

// r2->io->frida->r2pipe->r2
let _r2 = null;
let _r_core_new = null; // eslint-disable-line camelcase
let _r_core_cmd_str = null; // eslint-disable-line camelcase
let _r_core_free = null; // eslint-disable-line camelcase,no-unused-vars
let _free = null;

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

function radareSeek (args) {
  const addr = utils.getPtr('' + args);
  const cmdstr = 's ' + (addr || '' + args);
  return cmdstr;
  // XXX hangs
  // return r2.hostCmd(cmdstr);
}

function radareCommand (args) {
  const cmd = args.join(' ');
  if (cmd.length === 0) {
    return 'Usage: :r [cmd]';
  }
  if (_radareCommandInit()) {
    return _radareCommandString(cmd);
  }
  return ':dl /tmp/libr.dylib';
}

function _radareCommandInit () {
  if (_r2) {
    return true;
  }
  if (!_r_core_new) {
    _r_core_new = sym('r_core_new', 'pointer', []);
    if (!_r_core_new) {
      console.error('ERROR: Cannot find r_core_new. Do :dl /tmp/libr.dylib');
      return false;
    }
    _r_core_cmd_str = sym('r_core_cmd_str', 'pointer', ['pointer', 'pointer']);
    _r_core_free = sym('r_core_free', 'void', ['pointer']);
    _free = sym('free', 'void', ['pointer']);
    _r2 = _r_core_new();
  }
  return true;
}

function _radareCommandString (cmd) {
  if (_r2) {
    const aCmd = Memory.allocUtf8String(cmd);
    const ptr = _r_core_cmd_str(_r2, aCmd);
    const str = Memory.readCString(ptr);
    _free(ptr);
    return str;
  }
  console.error('Warning: not calling back r2');
  return '';
}

module.exports = {
  getR2Arch,
  hostCmds,
  hostCmd,
  hostCmdj,
  onCmdResp,
  radareSeek,
  radareCommand
};
