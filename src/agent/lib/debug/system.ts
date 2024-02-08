import config from '../../config.js';
import r2 from '../r2.js';
import sys from '../sys.js';
import { autoType, getPtr, padPointer, byteArrayToHex } from '../utils.js';

export function runSystem(command: string) : string | null{
    const systemSymbol = Module.findExportByName(null, 'system');
    if (systemSymbol === null) {
        return null;
    }
    const libcCommand = Memory.allocUtf8String(command);
    const libcSystem = new NativeFunction(systemSymbol, 'int', ['pointer']);
    const result = libcSystem(libcCommand);
    return "" + result;
}

export function runSystemCommand(args: string[]) : string | null{
    return runSystem(args.join(" "));
}
