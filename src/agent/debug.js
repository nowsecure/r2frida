'use strict';

const r2 = require('./r2').default;
const sys = require('./sys');

/* Globals */
const newBreakpoints = new Map();
let suspended = false;

/* breakpoint handler */
Process.setExceptionHandler(({ address }) => {
  const bp = newBreakpoints.get(address.toString());
  if (!bp) {
    return false;
  }

  const index = bp.patches.findIndex(p => p.address.equals(address));
  if (index === 0) {
    send({ name: 'breakpoint-event', stanza: { cmd: bp.cmd } });

    let state = 'stopped';
    do {
      const op = recv('breakpoint-action', ({ action }) => {
        switch (action) {
          case 'register-change':
            console.log('TODO1');
            break;
          case 'resume':
            state = 'running';
            break;
          default:
            console.log('TODO2');
            break;
        }
      });
      op.wait();
    } while (state === 'stopped');
  }
  const afterBp = newBreakpoints.get(address.toString());
  if (afterBp) {
    for (const p of bp.patches) {
      p.toggle();
    }
  }

  return true;
});

class CodePatch {
  constructor (address) {
    const insn = Instruction.parse(address);
    this.address = address;
    this.insn = insn;

    const insnSize = insn.size;
    this._newData = breakpointInstruction();
    this._originalData = address.readByteArray(insnSize);
    this._applied = false;
  }

  toggle () {
    this._apply(this._applied ? this._originalData : this._newData);
    this._applied = !this._applied;
  }

  enable () {
    if (!this._applied) { this.toggle(); }
  }

  disable () {
    if (this._applied) { this.toggle(); }
  }

  _apply (data) {
    Memory.patchCode(this.address, data.byteLength, code => {
      code.writeByteArray(data);
    });
  }
}

function breakpointInstruction () {
  if (Process.arch === 'arm64') {
    return new Uint8Array([0x60, 0x00, 0x20, 0xd4]).buffer;
  }
  return new Uint8Array([0xcc]).buffer;
}

function breakpointNative (args) {
  if (args.length === 0) {
    _breakpointList([]);
  } else if (args[0].startsWith('-')) {
    const addr = args[0].substring(1);
    breakpointUnset([addr]);
  } else {
    _breakpointSet(args);
  }
}

function breakpointJson (args) {
  const json = {};
  for (const [address, bp] of newBreakpoints.entries()) {
    if (bp.patches[0].address.equals(ptr(address))) {
      const k = '' + bp.patches[0].address;
      json[k] = {};
      json[k].enabled = true;
      if (bp.cmd) {
        json[k].cmd = bp.cmd;
      }
    }
  }
  return JSON.stringify(json);
}

function breakpointNativeCommand (args) {
  if (args.length >= 2) {
    const address = args[0];
    const command = args.slice(1).join(' ');
    for (const [bpaddr, bp] of newBreakpoints.entries()) {
      if (bp.patches[0].address.equals(ptr(bpaddr))) {
        if (bpaddr === address) {
          bp.cmd = command;
          break;
        }
      }
    }
  } else {
    console.error('Usage: dbc [address-of-breakpoint] [r2-command-to-run-when-hit]');
  }
}

function breakpointUnset (args) {
  const addr = args[0];
  const bp = newBreakpoints.get(addr);
  for (const p of bp.patches) {
    p.disable();
    newBreakpoints.delete(p.address.toString());
  }
}

function breakpointContinue (args) {
  if (suspended) {
    suspended = false;
    return r2.hostCmd(':dc');
  }
  return 'Continue thread(s).';
}

function breakpointContinueUntil (args) {
  breakpointNative(args);
  breakpointContinue([]);
  breakpointNative(['-' + args[0]]);
}

function sendSignal (args) {
  const argsLength = args.length;
  console.error('WARNING: Frida hangs when signal is sent. But at least the process doesnt continue');
  if (argsLength === 1) {
    const sig = +args[0];
    sys._kill(sys._getpid(), sig);
  } else if (argsLength === 2) {
    const [pid, sig] = args;
    sys._kill(+pid, +sig);
  } else {
    return 'Usage: :dk ([pid]) [sig]';
  }
  return '';
}

function _breakpointList (args) {
  for (const [address, bp] of newBreakpoints.entries()) {
    if (bp.patches[0].address.equals(ptr(address))) {
      console.log(address);
    }
  }
}

function _breakpointSet (args) {
  const ptrAddr = ptr(args[0]);

  const p1 = new CodePatch(ptrAddr);
  const p2 = new CodePatch(p1.insn.next);

  const bp = {
    patches: [p1, p2]
  };

  newBreakpoints.set(p1.address.toString(), bp);
  newBreakpoints.set(p2.address.toString(), bp);

  p1.toggle();
}

module.exports = {
  suspended,
  breakpointNative,
  breakpointJson,
  breakpointNativeCommand,
  breakpointUnset,
  breakpointContinue,
  breakpointContinueUntil,
  sendSignal
};
