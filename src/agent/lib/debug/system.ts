import config from "../../config.js";
import r2 from "../r2.js";
import sys from "../sys.js";
import {
    autoType,
    byteArrayToHex,
    getGlobalExportByName,
    getPtr,
    padPointer,
} from "../utils.js";

export function runSystem(command: string): string | null {
    const systemSymbol = getGlobalExportByName("system");
    if (systemSymbol !== null) {
        const libcCommand = Memory.allocUtf8String(command);
        const libcSystem = new NativeFunction(systemSymbol, "int", ["pointer"]);
        const result = libcSystem(libcCommand);
        return "" + result;
    }
    return null;
}

export function runSystemCommand(args: string[]): string | null {
    return runSystem(args.join(" "));
}
