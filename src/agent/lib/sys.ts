import { exist, transformVirtualPath } from "./fs.js";
import { getGlobalExportByName } from "./utils.js";

// TODO: add proper Function<> type for each :any here
export let _getenv: any | null = null;
export let _setenv: any | null = null;
export let _getuid: any | null = null;
export let _dup2: any | null = null;
export let _readlink: any | null = null;
export let _fstat: any | null = null;
export let _close: any | null = null;
export let _kill: any | null = null;

if (Process.platform === "windows") {
    _getenv = sym("getenv", "pointer", ["pointer"]);
    _setenv = sym("SetEnvironmentVariableA", "int", ["pointer", "pointer"]);
    _getuid = getWindowsUserNameA;
    _dup2 = sym("_dup2", "int", ["int", "int"]);
    _fstat = sym("_fstat", "int", ["int", "pointer"]);
    _close = sym("_close", "int", ["int"]);
    _kill = sym("TerminateProcess", "int", ["int", "int"]);
} else {
    _getenv = sym("getenv", "pointer", ["pointer"]);
    _setenv = sym("setenv", "int", ["pointer", "pointer", "int"]);
    _getuid = sym("getuid", "int", []);
    _dup2 = sym("dup2", "int", ["int", "int"]);
    _readlink = sym("readlink", "int", ["pointer", "pointer", "int"]);
    _fstat = getGlobalExportByName("fstat")
        ? sym("fstat", "int", ["int", "pointer"])
        : sym("__fxstat", "int", ["int", "pointer"]);
    _close = sym("close", "int", ["int"]);
    _kill = sym("kill", "int", ["int", "int"]);
}

export function sym(
    name: string,
    ret: NativeFunctionReturnType,
    arg: NativeFunctionArgumentType[],
): any {
    try {
        return new NativeFunction(getGlobalExportByName(name), ret, arg);
    } catch (e) {
        return null;
    }
}

export function symf(
    name: string,
    ret: NativeFunctionReturnType,
    arg: NativeFunctionArgumentType[],
): any {
    try {
        return new SystemFunction(getGlobalExportByName(name), ret, arg);
    } catch (e) {
        return null;
    }
}

export function getWindowsUserNameA() {
    const _GetUserNameA = sym("GetUserNameA", "int", ["pointer", "pointer"]);
    const PATH_MAX = 4096;
    const buf = Memory.allocUtf8String("A".repeat(PATH_MAX));
    const charOut = Memory.allocUtf8String("A".repeat(PATH_MAX));
    const res = _GetUserNameA(buf, charOut);
    if (res) {
        return buf.readCString();
    }
    return "";
}

export function getPidJson(): any {
    return JSON.stringify({ pid: Process.id });
}

export function getPid(): number {
    return Process.id;
}

export function getOrSetEnv(args: string[]) {
    if (args.length === 0) {
        const environment = getEnv();
        if (environment === null) {
            return "";
        }
        return environment.join("\n");
    }
    const { value } = getOrSetEnvJson(args);
    return (args[0].indexOf("=") === -1) ? value : "";
}

function getOrSetEnvJson(args: string[]): any {
    if (args.length === 0) {
        return getEnvJson();
    }
    const kv = args.join("");
    const eq = kv.indexOf("=");
    if (eq !== -1) {
        const k = kv.substring(0, eq);
        const v = kv.substring(eq + 1);
        setenv(k, v, true);
        return {
            key: k,
            value: v,
        };
    }
    return {
        key: kv,
        value: getenv(kv),
    };
}

function getEnv(): string[] | null {
    const result: any = [];
    const enva = getGlobalExportByName("environ");
    if (enva === null || enva.isNull()) {
        return null;
    }
    let envp = enva.readPointer();
    while (!envp.isNull()) {
        const env = envp.readPointer();
        if (env.isNull()) {
            break;
        }
        result.push(env.readCString());
        envp = envp.add(Process.pointerSize);
    }
    return result;
}

function getEnvJson() {
    const environment = getEnv();
    if (environment === null) {
        return {};
    }
    return environment.map((kv) => {
        const eq = kv.indexOf("=");
        return {
            key: kv.substring(0, eq),
            value: kv.substring(eq + 1),
        };
    });
}

export function dlopen(args: string[]) {
    if (args.length < 1) {
        return "Usage: dl [path]";
    }
    const path = transformVirtualPath(args[0]);
    if (exist(path)) {
        return Module.load(path);
    }
    return Module.load(args[0]);
}

export function getenv(name: string): string | null {
    if (_getenv === null) {
        return null;
    }
    const data = _getenv(Memory.allocUtf8String(name));
    return data!.readUtf8String();
}

export function setenv(name: string, value: string, overwrite: boolean) {
    return _setenv!(
        Memory.allocUtf8String(name),
        Memory.allocUtf8String(value),
        overwrite ? 1 : 0,
    );
}

export function changeSelinuxContext(args: string[]) {
    if (Process.platform !== "linux") {
        console.error("This is only available on Android/Linux");
        return "";
    }
    const _setfilecon = symf("setfilecon", "int", ["pointer", "pointer"]);
    if (_setfilecon === null) {
        return "Error: cannot find setfilecon symbol";
    }
    // TODO This doesnt run yet because permissions
    // TODO If it runs as root, then file might be checked
    const file = args[0];
    const con = Memory.allocUtf8String("u:object_r:frida_file:s0");
    const path = Memory.allocUtf8String(file);
    const rv = _setfilecon(path, con);
    return JSON.stringify({ ret: rv.value, errno: rv.errno });
}

export default {
    sym,
    symf,
    _getuid,
    _dup2,
    _readlink,
    _fstat,
    _close,
    _kill,
    getPid,
    getPidJson,
    getOrSetEnv,
    getOrSetEnvJson,
    dlopen,
    changeSelinuxContext,
};
