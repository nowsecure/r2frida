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

export function runCommandAsString(command: string): string | null {
    const popenSymbol = getGlobalExportByName("popen");
    const fgetsSymbol = getGlobalExportByName("fgets");
    const pcloseSymbol = getGlobalExportByName("pclose");

    if (popenSymbol !== null && fgetsSymbol !== null && pcloseSymbol !== null) {
        const popen = new NativeFunction(popenSymbol, "pointer", [
            "pointer",
            "pointer",
        ]);
        const fgets = new NativeFunction(fgetsSymbol, "pointer", [
            "pointer",
            "int",
            "pointer",
        ]);
        const pclose = new NativeFunction(pcloseSymbol, "int", ["pointer"]);

        const libcCommand = Memory.allocUtf8String(command);
        const libcCommandMode = Memory.allocUtf8String("r");

        const file = popen(libcCommand, libcCommandMode);
        if (file.isNull()) {
            return null;
        }

        const bufferSize: number = 1024;
        const buffer = Memory.alloc(bufferSize);
        let output = "";
        while (!(fgets(buffer, bufferSize, file)).isNull()) {
            output += buffer.readUtf8String();
        }
        pclose(file);

        return output;
    }

    return null;
}

export function runSystemCommandAsString(args: string[]): string | null {
    return runCommandAsString(args.join(" "));
}
