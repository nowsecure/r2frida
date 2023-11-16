import { sym, getenv } from './sys.js';
import { wrapStanza, getPtr } from './utils.js';

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

export function getArch(arch: string): string {
    switch (arch) {
        case 'ia32':
        case 'x64':
            return 'x86';
        case 'arm64':
            return 'arm';
    }
    return arch;
}

export async function hostCmds(commands: string[]): Promise<string[]> {
    let allPromises = [];
    for (let i=0; i<commands.length; i++) {
        allPromises.push(hostCmd(commands[i]));
    }
    const results = await Promise.allSettled(allPromises) as {status: 'fulfilled' | 'rejected', value: string}[];
    const succeeded = results.filter(o => o.status === "fulfilled").map(e => e.value);
    return succeeded;
}

export async function hostCmd(cmd: string): Promise<string> {
    return new Promise((resolve) => {
        const serial = cmdSerial;
        cmdSerial++;
        pendingCmds[serial] = resolve;
        _sendCommand(cmd, serial);
    });
}

export async function hostCmdj(cmd: string): Promise<JSON> {
    const output = await hostCmd(cmd);
    return JSON.parse(output);
}

export function onCmdResp(params: any) {
    const { serial, output } = params;
    sendingCommand = false;
    if (serial in pendingCmds) {
        const onFinish = pendingCmds[serial];
        delete pendingCmds[serial];
        Script.nextTick(() => onFinish(output));
    } else {
        throw new Error('Command response out of sync');
    }
    Script.nextTick(() => {
        if (!sendingCommand) {
            const nextSend = pendingCmdSends.shift();
            if (nextSend !== undefined) {
                nextSend();
            }
        }
    });
    return [{}, null];
}

function _sendCommand(cmd: string, serial: number): void {
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

export function seek(args: string[]) : string {
    const addr = getPtr('' + args);
    return 's ' + (addr || '' + args);
}

export function cmd(args: string[]) : string {
    const cmd = args.join(' ');
    if (cmd.length === 0) {
        return 'Usage: :r [cmd]';
    }
    if (_radareCommandInit()) {
        return _radareCommandString(cmd);
    }
    return ':dl /tmp/libr.dylib';
}

function _radareCommandInit(): boolean {
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
        const cpstr = getenv("R2CORE");
        if (cpstr !== null) {
          _r2 = ptr(cpstr);
        } else {
          _r2 = _r_core_new();
        }
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

export interface r2Config {
    search: r2SearchConfig
}

export interface r2SearchConfig {
    align: string;
    badpages: string;
    chunk: string;
    contiguous: string;
    distance: string;
    esilcombo: string;
    flags: string;
    kwidx: number;
    maxhits: string;
    named: string;
    overlap: string;
    prefix: string;
    show: string;
    from: string;
    to: string;
    verbose: string;
    count: number;
}

export default {
    getArch,
    hostCmds,
    hostCmd,
    hostCmdj,
    onCmdResp,
    seek,
    cmd,
};