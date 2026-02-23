/**
 * IO File Redirection Module
 * Allows redirecting r2frida IO to read/write from a file or remote process memory
 * Useful for reading /proc/pid/mem or any other remote file
 *
 * Supports:
 * - File paths: /proc/pid/mem, /dev/mem, /path/to/file
 * - Remote process memory via mach VM (macOS): pid://1234
 * - Remote process memory via process_vm_* (Linux): pid://1234
 */

import * as utils from "./utils.js";
import r2frida from "../plugin.js";

interface NativeSymbols {
    open: (pathPtr: NativePointer, flags: number) => number;
    close: (fd: number) => number;
    read: (fd: number, buf: NativePointer, count: number) => number;
    write: (fd: number, buf: NativePointer, count: number) => number;
    lseek: (fd: number, offset: Int64, whence: number) => Int64;
}

interface ProcessVMSymbols {
    process_vm_readv: (
        pid: number,
        lvec: NativePointer,
        liovcnt: number,
        rvec: NativePointer,
        riovcnt: number,
        flags: number,
    ) => Int64;
    process_vm_writev: (
        pid: number,
        lvec: NativePointer,
        liovcnt: number,
        rvec: NativePointer,
        riovcnt: number,
        flags: number,
    ) => Int64;
}

interface MachVMSymbols {
    task_for_pid: (
        hostPriv: NativePointer,
        pid: number,
        taskPtr: NativePointer,
    ) => number;
    vm_read: (
        task: NativePointer,
        addr: NativePointer,
        size: NativePointer,
        dataPtr: NativePointer,
        dataCntPtr: NativePointer,
    ) => number;
    vm_write: (
        task: NativePointer,
        addr: NativePointer,
        data: NativePointer,
        dataCnt: number,
    ) => number;
}

class IOFileManager {
    private currentFd: number = -1;
    private currentPath: string = "";
    private currentPid: number = -1;
    private currentTaskPort: NativePointer | null = null;
    private symbols: NativeSymbols;
    private processVMSymbols: Partial<ProcessVMSymbols> = {};
    private machVMSymbols: Partial<MachVMSymbols> = {};

    constructor() {
        this.symbols = this.initializeSymbols();
        this.initializeMachVMSymbols();
        this.initializeProcessVMSymbols();
    }

    private initSymbols<T>(
        config: Record<
            string,
            [NativeFunctionReturnType, NativeFunctionArgumentType[]]
        >,
    ): T {
        const sym = (
            name: string,
            ret: NativeFunctionReturnType,
            arg: NativeFunctionArgumentType[],
        ) => {
            try {
                return new NativeFunction(
                    Module.getGlobalExportByName(name),
                    ret,
                    arg,
                );
            } catch (e) {
                return null;
            }
        };

        return Object.fromEntries(
            Object.entries(config).map((
                [key, [ret, args]],
            ) => [key, sym(key, ret, args)]),
        ) as T;
    }

    constructor() {
        this.symbols = this.initSymbols({
            open: ["int", ["pointer", "int"] as NativeFunctionArgumentType[]],
            close: ["int", ["int"] as NativeFunctionArgumentType[]],
            read: [
                "int",
                ["int", "pointer", "int"] as NativeFunctionArgumentType[],
            ],
            write: [
                "int",
                ["int", "pointer", "int"] as NativeFunctionArgumentType[],
            ],
            lseek: [
                "int64",
                ["int", "int64", "int"] as NativeFunctionArgumentType[],
            ],
        });

        this.machVMSymbols = this.initSymbols({
            task_for_pid: [
                "int",
                ["pointer", "int", "pointer"] as NativeFunctionArgumentType[],
            ],
            vm_read: [
                "int",
                [
                    "pointer",
                    "pointer",
                    "pointer",
                    "pointer",
                    "pointer",
                ] as NativeFunctionArgumentType[],
            ],
            vm_write: [
                "int",
                [
                    "pointer",
                    "pointer",
                    "pointer",
                    "int",
                ] as NativeFunctionArgumentType[],
            ],
        });

        this.processVMSymbols = this.initSymbols({
            process_vm_readv: [
                "int64",
                [
                    "int",
                    "pointer",
                    "int",
                    "pointer",
                    "int",
                    "int",
                ] as NativeFunctionArgumentType[],
            ],
            process_vm_writev: [
                "int64",
                [
                    "int",
                    "pointer",
                    "int",
                    "pointer",
                    "int",
                    "int",
                ] as NativeFunctionArgumentType[],
            ],
        });
    }

    private showHelp(): string {
        return (
            "o Commands:\n" +
            "o [path]      - redirect IO to read/write from file or remote process\n" +
            "o             - show current status\n" +
            "o-            - close the file and restore normal IO\n" +
            "o?            - show help\n"
        );
    }

    private getStatus(): string {
        if (this.currentFd < 0 && this.currentPid < 0) {
            return "IO: normal (not redirected)";
        }
        if (this.currentPid >= 0) {
            return `IO redirected to: remote process ${this.currentPid} via ${this.getPlatformVMType()}`;
        }
        return `IO redirected to: ${this.currentPath} (fd=${this.currentFd})`;
    }

    private getPlatformVMType(): string {
        if (Process.platform === "darwin") {
            return "mach_vm";
        }
        return "process_vm";
    }

    private openRemoteProcess(pidStr: string): string {
        const pidNum = parseInt(pidStr, 10);
        if (isNaN(pidNum) || pidNum <= 0) {
            return `ERROR: invalid PID format: ${pidStr}`;
        }

        return Process.platform === "darwin"
            ? this.openRemoteProcessMachVM(pidNum)
            : this.openRemoteProcessLinux(pidNum);
    }

    private openRemoteProcessMachVM(pid: number): string {
        if (!this.machVMSymbols.task_for_pid) {
            return "ERROR: mach VM symbols not available";
        }

        const getHostPriv = (): NativePointer | null => {
            const trySymbol = (name: string) => {
                try {
                    return new NativeFunction(
                        Module.getGlobalExportByName(name),
                        "pointer",
                        [],
                    )();
                } catch (e) {
                    return null;
                }
            };
            return trySymbol("mach_task_self") || trySymbol("task_self") ||
                null;
        };

        const hostPriv = getHostPriv();
        if (!hostPriv) return "ERROR: cannot get mach task port";

        const taskPtr = Memory.alloc(Process.pointerSize);
        const result = this.machVMSymbols.task_for_pid!(hostPriv, pid, taskPtr);

        if (result !== 0) {
            const result2 = this.machVMSymbols.task_for_pid!(
                ptr(0),
                pid,
                taskPtr,
            );
            if (result2 !== 0) {
                return `ERROR: task_for_pid failed (error: ${result}/${result2}) for PID ${pid}`;
            }
        }

        const taskPort = taskPtr.readPointer();
        if (taskPort.isNull()) {
            return `ERROR: failed to get task port for PID ${pid}`;
        }

        this.setupRemoteProcess(pid, taskPort);
        return `IO redirected to: remote process ${pid} (mach_vm)`;
    }

    private openRemoteProcessLinux(pid: number): string {
        if (!this.processVMSymbols.process_vm_readv) {
            return "ERROR: process_vm symbols not available";
        }

        this.setupRemoteProcess(pid, null);
        return `IO redirected to: remote process ${pid} (process_vm)`;
    }

    private setupRemoteProcess(
        pid: number,
        taskPort: NativePointer | null,
    ): void {
        this.currentPid = pid;
        this.currentPath = `pid://${pid}`;
        this.currentFd = -1;
        this.currentTaskPort = taskPort;
        r2frida.hookedRead = (offset: any, count: number) =>
            this.hookedRead(offset, count);
        r2frida.hookedWrite = (offset: any, data: any) =>
            this.hookedWrite(offset, data);
    }

    private openFile(path: string): string {
        this.resetCurrentIO();

        const O_RDWR = 2, O_RDONLY = 0;
        const pathPtr = Memory.allocUtf8String(path);

        const fd = this.symbols.open(pathPtr, O_RDWR) >= 0
            ? this.symbols.open(pathPtr, O_RDWR)
            : this.symbols.open(pathPtr, O_RDONLY);

        if (fd < 0) return `ERROR: cannot open ${path}`;

        this.currentFd = fd;
        this.currentPath = path;
        r2frida.hookedRead = (offset: any, count: number) =>
            this.hookedRead(offset, count);
        r2frida.hookedWrite = (offset: any, data: any) =>
            this.hookedWrite(offset, data);

        return `IO redirected to: ${path} (fd=${fd})`;
    }

    private resetCurrentIO(): void {
        if (this.currentFd >= 0) {
            this.symbols.close(this.currentFd);
            this.currentFd = -1;
        }
        if (this.currentPid >= 0) {
            this.currentPid = -1;
            this.currentTaskPort = null;
        }
        this.currentPath = "";
    }

    private closeFile(): string {
        this.resetCurrentIO();
        r2frida.hookedRead = null;
        r2frida.hookedWrite = null;
        return "IO restored to normal";
    }

    private readRemoteProcessMachVM(
        offset: number,
        count: number,
    ): Uint8Array | null {
        if (!this.currentTaskPort || !this.machVMSymbols.vm_read) return null;

        const dataPtr = Memory.alloc(Process.pointerSize);
        const dataCntPtr = Memory.alloc(4).writeU32(0);

        const result = this.machVMSymbols.vm_read!(
            this.currentTaskPort,
            ptr(offset),
            ptr(count),
            dataPtr,
            dataCntPtr,
        );

        if (result !== 0) return null;

        const dataCnt = dataCntPtr.readU32();
        return dataCnt > 0
            ? this.arrayBufferToUint8(
                dataPtr.readPointer().readByteArray(dataCnt),
            )
            : null;
    }

    private arrayBufferToUint8(data: ArrayBuffer | null): Uint8Array | null {
        return data ? new Uint8Array(data) : null;
    }

    private readRemoteProcessLinux(
        offset: number,
        count: number,
    ): Uint8Array | null {
        if (!this.processVMSymbols.process_vm_readv || this.currentPid < 0) {
            return null;
        }

        const [localVec, remoteVec, buf] = [
            Memory.alloc(16),
            Memory.alloc(16),
            Memory.alloc(count),
        ];

        localVec.writePointer(buf).add(Process.pointerSize).writeULong(count);
        remoteVec.writePointer(ptr(offset)).add(Process.pointerSize).writeULong(
            count,
        );

        const bytesRead = this.processVMSymbols.process_vm_readv!(
            this.currentPid,
            localVec,
            1,
            remoteVec,
            1,
            0,
        );

        return (bytesRead as unknown as number) > 0
            ? this.arrayBufferToUint8(
                buf.readByteArray(bytesRead as unknown as number),
            )
            : null;
    }

    private writeRemoteProcessMachVM(
        offset: number,
        data: Uint8Array | ArrayBuffer,
    ): boolean {
        if (!this.currentTaskPort || !this.machVMSymbols.vm_write) return false;

        const dataBuf = Memory.alloc(data.byteLength);
        const dataArray = data instanceof Uint8Array
            ? data
            : new Uint8Array(data);
        dataBuf.writeByteArray(Array.from(dataArray));

        return this.machVMSymbols.vm_write!(
            this.currentTaskPort,
            ptr(offset),
            dataBuf,
            data.byteLength,
        ) === 0;
    }

    private writeRemoteProcessLinux(
        offset: number,
        data: Uint8Array | ArrayBuffer,
    ): boolean {
        if (!this.processVMSymbols.process_vm_writev || this.currentPid < 0) {
            return false;
        }

        const dataArray = data instanceof Uint8Array
            ? data
            : new Uint8Array(data);
        const [localVec, remoteVec, buf] = [
            Memory.alloc(16),
            Memory.alloc(16),
            Memory.alloc(dataArray.length),
        ];

        buf.writeByteArray(Array.from(dataArray));
        localVec.writePointer(buf).add(Process.pointerSize).writeULong(
            dataArray.length,
        );
        remoteVec.writePointer(ptr(offset)).add(Process.pointerSize).writeULong(
            dataArray.length,
        );

        const bytesWritten = this.processVMSymbols.process_vm_writev!(
            this.currentPid,
            localVec,
            1,
            remoteVec,
            1,
            0,
        );

        return (bytesWritten as unknown as number) === dataArray.length;
    }

    public hookedRead(offset: any, count: number): [any, any] {
        const offsetNum = typeof offset === "string"
            ? parseInt(offset, 16)
            : offset;

        if (this.currentPid >= 0) {
            const data = Process.platform === "darwin"
                ? this.readRemoteProcessMachVM(offsetNum, count)
                : this.readRemoteProcessLinux(offsetNum, count);
            return data ? [{}, Array.from(data)] : [{}, []];
        }

        if (this.currentFd < 0) return [{}, []];

        const seeked = this.symbols.lseek(
            this.currentFd,
            new Int64(offsetNum),
            0,
        );
        if ((seeked as unknown as number) < 0) return [{}, []];

        const buf = Memory.alloc(count);
        const bytesRead = this.symbols.read(this.currentFd, buf, count);

        return bytesRead > 0
            ? [
                {},
                Array.from(
                    new Uint8Array(
                        buf.readByteArray(bytesRead) || new ArrayBuffer(0),
                    ),
                ),
            ]
            : [{}, []];
    }

    public hookedWrite(offset: any, data: any): [any, null] {
        const offsetNum = typeof offset === "object"
            ? offset.toInt32()
            : typeof offset === "string"
            ? parseInt(offset, 16)
            : offset;

        if (this.currentPid >= 0) {
            const writeData = this.normalizeData(data);
            if (!writeData) return [{}, null];

            if (Process.platform === "darwin") {
                this.writeRemoteProcessMachVM(offsetNum, writeData);
            } else {
                this.writeRemoteProcessLinux(offsetNum, writeData);
            }
            return [{}, null];
        }

        if (this.currentFd < 0) return [{}, null];

        const seeked = this.symbols.lseek(
            this.currentFd,
            new Int64(offsetNum),
            0,
        );
        if ((seeked as unknown as number) < 0) return [{}, null];

        const count = data.byteLength;
        Memory.alloc(count).writeByteArray(data);
        this.symbols.write(this.currentFd, Memory.alloc(count), count);

        return [{}, null];
    }

    private normalizeData(data: any): Uint8Array | ArrayBuffer | null {
        if (data instanceof ArrayBuffer) return data;
        if (Array.isArray(data)) return new Uint8Array(data);
        if (typeof data.byteLength === "number") return data;
        return null;
    }

    public execute(args: string[]): string {
        // Check if required symbols are available
        if (
            !this.symbols.open ||
            !this.symbols.lseek ||
            !this.symbols.read
        ) {
            return "ERROR: required libc symbols not found";
        }

        if (args.length === 0) {
            if (this.currentFd < 0 && this.currentPid < 0) {
                return this.showHelp();
            }
            return this.getStatus();
        }

        const command = args[0];
        switch (command) {
            case "?":
                return this.showHelp();
            case "-":
                return this.closeFile();
            default:
                // Check if this is a pid:// URL
                if (command.startsWith("pid://")) {
                    const pidStr = command.substring(6); // Remove "pid://" prefix
                    return this.openRemoteProcess(pidStr);
                }
                return this.openFile(command);
        }
    }
}

let ioFileManager: IOFileManager | null = null;

export function initIOFile(): IOFileManager {
    if (ioFileManager === null) {
        ioFileManager = new IOFileManager();
    }
    return ioFileManager;
}

export function handleIOFile(args: string[]): string {
    const manager = initIOFile();
    return manager.execute(args);
}

export function handleIOFileHelp(args: string[]): string {
    const manager = initIOFile();
    return manager.execute(["?"]);
}

export function handleIOFileClose(args: string[]): string {
    const manager = initIOFile();
    return manager.execute(["-"]);
}

export function getIOFileManager(): IOFileManager {
    if (ioFileManager === null) {
        ioFileManager = new IOFileManager();
    }
    return ioFileManager;
}
