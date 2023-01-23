import { sym } from './sys.js';
import {wrapStanza, getPtr} from './utils.js';

type CommandFunction = () => void;
const pendingCmds: any = [];
const pendingCmdSends: CommandFunction[] = [];
let sendingCommand = false;
let cmdSerial = 0;
// r2->io->frida->r2pipe->r2
let _r2: any | null = null;
let _r_core_new: any | null = null; // eslint-disable-line camelcase
let _r_core_cmd_str: any | null = null; // eslint-disable-line camelcase
let _r_core_free: any | null = null; // eslint-disable-line camelcase,no-unused-vars
let _free: any | null = null;

export function getR2Arch(arch: string): string {
    switch (arch) {
        case 'ia32':
        case 'x64':
            return 'x86';
        case 'arm64':
            return 'arm';
    }
    return arch;
}

export function hostCmds(commands: string[]): any {
    let i = 0;
    function sendOne(): any {
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

export function hostCmd(cmd: string) {
    return new Promise((resolve) => {
        const serial = cmdSerial;
        cmdSerial++;
        pendingCmds[serial] = resolve;
        _sendCommand(cmd, serial);
    });
}

export function hostCmdj(cmd: string): any {
    return hostCmd(cmd)
        .then((output: any) => {
            return JSON.parse(output);
        });
}

export function onCmdResp(params: any) {
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

function _sendCommand(cmd: string, serial: number) {
    function sendIt() {
        sendingCommand = true;
        send(wrapStanza('cmd', {
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

export function radareSeek(args: string[]) {
    const addr = getPtr('' + args);
    const cmdstr = 's ' + (addr || '' + args);
    return cmdstr;
}

export function radareCommand(args: string[]) {
    const cmd = args.join(' ');
    if (cmd.length === 0) {
        return 'Usage: :r [cmd]';
    }
    if (_radareCommandInit()) {
        return _radareCommandString(cmd);
    }
    return ':dl /tmp/libr.dylib';
}

function _radareCommandInit() {
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

function _radareCommandString(cmd: string): string {
    if (_r2) {
        const aCmd = Memory.allocUtf8String(cmd);
        const ptr = _r_core_cmd_str(_r2, aCmd);
        const str = ptr.readCString();
        _free(ptr);
        return str;
    }
    console.error('Warning: not calling back r2');
    return '';
}

// TODO: eliminate all the default exports
export default {
    getR2Arch,
    hostCmds,
    hostCmd,
    hostCmdj,
    onCmdResp,
    radareSeek,
    radareCommand
};
