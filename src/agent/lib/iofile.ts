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
    process_vm_readv: (pid: number, lvec: NativePointer, liovcnt: number, rvec: NativePointer, riovcnt: number, flags: number) => Int64;
    process_vm_writev: (pid: number, lvec: NativePointer, liovcnt: number, rvec: NativePointer, riovcnt: number, flags: number) => Int64;
}

interface MachVMSymbols {
    task_for_pid: (hostPriv: NativePointer, pid: number, taskPtr: NativePointer) => number;
    vm_read: (task: NativePointer, addr: NativePointer, size: NativePointer, dataPtr: NativePointer, dataCntPtr: NativePointer) => number;
    vm_write: (task: NativePointer, addr: NativePointer, data: NativePointer, dataCnt: number) => number;
}

class IOFileManager {
    private currentFd: number = -1;
    private currentPath: string = "";
    private currentPid: number = -1;
    private currentTaskPort: NativePointer | null = null;
    private symbols: NativeSymbols;
    private processVMSymbols: Partial<ProcessVMSymbols> = {};
    private machVMSymbols: Partial<MachVMSymbols> = {};
    private allocatedPointers: NativePointer[] = []; // Keep references to prevent GC

    constructor() {
        this.symbols = this.initializeSymbols();
        this.initializeMachVMSymbols();
        this.initializeProcessVMSymbols();
    }

    private initializeSymbols(): NativeSymbols {
         const sym = (name: string, ret: NativeFunctionReturnType, arg: NativeFunctionArgumentType[]): any => {
             try {
                 return new NativeFunction(
                     Module.getGlobalExportByName(name),
                     ret,
                     arg
                 );
             } catch (e) {
                 return null;
             }
         };

         return {
             open: sym("open", "int" as NativeFunctionReturnType, ["pointer", "int"]),
             close: sym("close", "int" as NativeFunctionReturnType, ["int"]),
             read: sym("read", "int" as NativeFunctionReturnType, ["int", "pointer", "int"]),
             write: sym("write", "int" as NativeFunctionReturnType, ["int", "pointer", "int"]),
             lseek: sym("lseek", "int64" as NativeFunctionReturnType, ["int", "int64", "int"]),
         };
     }

    private initializeMachVMSymbols(): void {
        const sym = (name: string, ret: NativeFunctionReturnType, arg: NativeFunctionArgumentType[]): any => {
            try {
                return new NativeFunction(
                    Module.getGlobalExportByName(name),
                    ret,
                    arg
                );
            } catch (e) {
                return null;
            }
        };

        this.machVMSymbols = {
            task_for_pid: sym("task_for_pid", "int" as NativeFunctionReturnType, ["pointer", "int", "pointer"]),
            vm_read: sym("vm_read", "int" as NativeFunctionReturnType, ["pointer", "pointer", "pointer", "pointer", "pointer"]),
            vm_write: sym("vm_write", "int" as NativeFunctionReturnType, ["pointer", "pointer", "pointer", "int"]),
        };
    }

    private initializeProcessVMSymbols(): void {
        const sym = (name: string, ret: NativeFunctionReturnType, arg: NativeFunctionArgumentType[]): any => {
            try {
                return new NativeFunction(
                    Module.getGlobalExportByName(name),
                    ret,
                    arg
                );
            } catch (e) {
                return null;
            }
        };

        this.processVMSymbols = {
            process_vm_readv: sym("process_vm_readv", "int64" as NativeFunctionReturnType, ["int", "pointer", "int", "pointer", "int", "int"]),
            process_vm_writev: sym("process_vm_writev", "int64" as NativeFunctionReturnType, ["int", "pointer", "int", "pointer", "int", "int"]),
        };
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
        // Extract PID from pid://PIDNUM format
        const pidNum = parseInt(pidStr, 10);
        if (isNaN(pidNum) || pidNum <= 0) {
            return `ERROR: invalid PID format: ${pidStr}`;
        }

        if (Process.platform === "darwin") {
            return this.openRemoteProcessMachVM(pidNum);
        } else {
            return this.openRemoteProcessLinux(pidNum);
        }
    }

    private openRemoteProcessMachVM(pid: number): string {
        if (!this.machVMSymbols.task_for_pid) {
            return "ERROR: mach VM symbols not available";
        }

        // Get mach_task_self() for the current task as host privilege
        let hostPriv: NativePointer;
        try {
            const mach_task_self_sym = new NativeFunction(
                Module.getGlobalExportByName("mach_task_self"),
                "pointer",
                []
            );
            hostPriv = mach_task_self_sym();
        } catch (e) {
            // Fallback to task_self if mach_task_self not found
            try {
                const task_self_sym = new NativeFunction(
                    Module.getGlobalExportByName("task_self"),
                    "pointer",
                    []
                );
                hostPriv = task_self_sym();
            } catch (e2) {
                return "ERROR: cannot get mach task port";
            }
        }

        const taskPtr = Memory.alloc(Process.pointerSize);

        const result = this.machVMSymbols.task_for_pid!(hostPriv, pid, taskPtr);
        if (result !== 0) {
            // Try with different approaches for getting host privilege
            try {
                // Try using NULL host port (works sometimes)
                const result2 = this.machVMSymbols.task_for_pid!(ptr(0), pid, taskPtr);
                if (result2 !== 0) {
                    return `ERROR: task_for_pid failed (error: ${result}/${result2}) for PID ${pid}. Check if target process exists and you have permissions.`;
                }
            } catch (e) {
                return `ERROR: task_for_pid failed (error: ${result}) for PID ${pid}. Check if target process exists and you have permissions.`;
            }
        }

        const taskPort = taskPtr.readPointer();
        if (taskPort.isNull()) {
            return `ERROR: failed to get task port for PID ${pid}`;
        }

        this.currentPid = pid;
        this.currentTaskPort = taskPort;
        this.currentPath = `pid://${pid}`;
        this.currentFd = -1;

        // Set up the r2frida hooks for remote process I/O
        r2frida.hookedRead = (offset: any, count: number) => this.hookedRead(offset, count);
        r2frida.hookedWrite = (offset: any, data: any) => this.hookedWrite(offset, data);

        return `IO redirected to: remote process ${pid} (mach_vm)`;
    }

    private openRemoteProcessLinux(pid: number): string {
        if (!this.processVMSymbols.process_vm_readv) {
            return "ERROR: process_vm symbols not available";
        }

        // Just store the PID for later use
        this.currentPid = pid;
        this.currentPath = `pid://${pid}`;
        this.currentFd = -1;
        this.currentTaskPort = null;

        // Set up the r2frida hooks for remote process I/O
        r2frida.hookedRead = (offset: any, count: number) => this.hookedRead(offset, count);
        r2frida.hookedWrite = (offset: any, data: any) => this.hookedWrite(offset, data);

        return `IO redirected to: remote process ${pid} (process_vm)`;
    }

    private openFile(path: string): string {
        if (this.currentFd >= 0) {
            this.symbols.close(this.currentFd);
            this.currentFd = -1;
            this.currentPath = "";
        }
        
        if (this.currentPid >= 0) {
            this.currentPid = -1;
            this.currentTaskPort = null;
            this.currentPath = "";
        }

        const O_RDWR = 2;
        const O_RDONLY = 0;
        const pathPtr = Memory.allocUtf8String(path);
        this.allocatedPointers.push(pathPtr); // Keep reference to prevent GC

        let fd = this.symbols.open(pathPtr, O_RDWR);
        if (fd < 0) {
            fd = this.symbols.open(pathPtr, O_RDONLY);
        }

        if (fd < 0) {
            return `ERROR: cannot open ${path}`;
        }

        this.currentFd = fd;
        this.currentPath = path;

        // Set up the r2frida hooks for file I/O
        r2frida.hookedRead = (offset: any, count: number) => this.hookedRead(offset, count);
        r2frida.hookedWrite = (offset: any, data: any) => this.hookedWrite(offset, data);

        return `IO redirected to: ${path} (fd=${fd})`;
    }

    private closeFile(): string {
        if (this.currentFd >= 0) {
            this.symbols.close(this.currentFd);
            this.currentFd = -1;
            this.currentPath = "";
        }
        
        if (this.currentPid >= 0) {
            this.currentPid = -1;
            this.currentTaskPort = null;
            this.currentPath = "";
        }
        
        // Clear the r2frida hooks
        r2frida.hookedRead = null;
        r2frida.hookedWrite = null;

        // Clear allocated pointers to allow GC
        this.allocatedPointers = [];
        
        return "IO restored to normal";
    }

    private readRemoteProcessMachVM(offset: number, count: number): Uint8Array | null {
        if (!this.currentTaskPort || !this.machVMSymbols.vm_read) {
            return null;
        }

        const dataPtr = Memory.alloc(Process.pointerSize);
        const dataCntPtr = Memory.alloc(4);
        this.allocatedPointers.push(dataPtr, dataCntPtr); // Keep references
        dataCntPtr.writeU32(0);

        const addr = ptr(offset);
        const size = ptr(count);

        const result = this.machVMSymbols.vm_read!(
            this.currentTaskPort,
            addr,
            size,
            dataPtr,
            dataCntPtr
        );

        if (result !== 0) {
            return null;
        }

        const dataCnt = dataCntPtr.readU32();
        if (dataCnt <= 0) {
            return null;
        }

        const dataPtr2 = dataPtr.readPointer();
        const data = dataPtr2.readByteArray(dataCnt);
        return data instanceof ArrayBuffer ? new Uint8Array(data) : null;
    }

    private readRemoteProcessLinux(offset: number, count: number): Uint8Array | null {
        if (!this.processVMSymbols.process_vm_readv || this.currentPid < 0) {
            return null;
        }

        // Allocate local and remote iovec structures
        const localVec = Memory.alloc(16); // sizeof(struct iovec)
        const remoteVec = Memory.alloc(16);
        this.allocatedPointers.push(localVec, remoteVec); // Keep references

        // Allocate buffer for data
        const buf = Memory.alloc(count);
        this.allocatedPointers.push(buf); // Keep reference

        // Set up local iovec: iov_base = buf, iov_len = count
        localVec.writePointer(buf);
        localVec.add(Process.pointerSize).writeULong(count);

        // Set up remote iovec: iov_base = offset, iov_len = count
        remoteVec.writePointer(ptr(offset));
        remoteVec.add(Process.pointerSize).writeULong(count);

        const bytesRead = this.processVMSymbols.process_vm_readv!(
            this.currentPid,
            localVec,
            1,
            remoteVec,
            1,
            0
        );

        if ((bytesRead as unknown as number) <= 0) {
            return null;
        }

        const data = buf.readByteArray((bytesRead as unknown as number));
        return data instanceof ArrayBuffer ? new Uint8Array(data) : null;
    }

    private writeRemoteProcessMachVM(offset: number, data: Uint8Array | ArrayBuffer): boolean {
        if (!this.currentTaskPort || !this.machVMSymbols.vm_write) {
            return false;
        }

        const dataBuf = Memory.alloc(data.byteLength);
        this.allocatedPointers.push(dataBuf); // Keep reference
        if (data instanceof Uint8Array) {
            dataBuf.writeByteArray(Array.from(data));
        } else {
            dataBuf.writeByteArray(Array.from(new Uint8Array(data)));
        }

        const addr = ptr(offset);
        const result = this.machVMSymbols.vm_write!(
            this.currentTaskPort,
            addr,
            dataBuf,
            data.byteLength
        );

        return result === 0;
    }

    private writeRemoteProcessLinux(offset: number, data: Uint8Array | ArrayBuffer): boolean {
        if (!this.processVMSymbols.process_vm_writev || this.currentPid < 0) {
            return false;
        }

        const byteArray = data instanceof Uint8Array ? Array.from(data) : Array.from(new Uint8Array(data));

        // Allocate local and remote iovec structures
        const localVec = Memory.alloc(16);
        const remoteVec = Memory.alloc(16);
        this.allocatedPointers.push(localVec, remoteVec); // Keep references

        // Allocate buffer for data
        const buf = Memory.alloc(byteArray.length);
        this.allocatedPointers.push(buf); // Keep reference
        buf.writeByteArray(byteArray);

        // Set up local iovec: iov_base = buf, iov_len = datalen
        localVec.writePointer(buf);
        localVec.add(Process.pointerSize).writeULong(byteArray.length);

        // Set up remote iovec: iov_base = offset, iov_len = datalen
        remoteVec.writePointer(ptr(offset));
        remoteVec.add(Process.pointerSize).writeULong(byteArray.length);

        const bytesWritten = this.processVMSymbols.process_vm_writev!(
            this.currentPid,
            localVec,
            1,
            remoteVec,
            1,
            0
        );

        return (bytesWritten as unknown as number) === byteArray.length;
    }

    public hookedRead(offset: any, count: number): [any, any] {
        // Handle remote process read
        if (this.currentPid >= 0) {
            const offsetNum =
                typeof offset === "string" ? parseInt(offset, 16) : offset;

            let data: Uint8Array | null = null;
            if (Process.platform === "darwin") {
                data = this.readRemoteProcessMachVM(offsetNum, count);
            } else {
                data = this.readRemoteProcessLinux(offsetNum, count);
            }

            if (data === null) {
                return [{}, []];
            }

            return [{}, Array.from(data)];
        }

        // Handle file read
        if (this.currentFd < 0) {
            return [{}, []];
        }

        const offsetNum =
            typeof offset === "string" ? parseInt(offset, 16) : offset;
        
        // For file I/O, we don't seek to the offset from the command
        // The file is read sequentially from its current position
        // If we want to treat the file as memory starting at offset 0, we need to seek
        const seeked = this.symbols.lseek(
            this.currentFd,
            new Int64(offsetNum),
            0
        ); // SEEK_SET = 0

        if ((seeked as unknown as number) < 0) {
            return [{}, []];
        }

        const buf = Memory.alloc(count);
        const bytesRead = this.symbols.read(this.currentFd, buf, count);

        if (bytesRead <= 0) {
            return [{}, []];
        }

        const data = buf.readByteArray(bytesRead);
        // Convert ArrayBuffer to Array<number> format expected by r2frida
        if (data === null) {
            return [{}, []];
        }
        const uint8Array = new Uint8Array(data);
        return [{}, Array.from(uint8Array)];
    }

    public hookedWrite(offset: any, data: any): [any, null] {
        // Handle remote process write
        if (this.currentPid >= 0) {
            const offsetNum =
                typeof offset === "object"
                    ? offset.toInt32()
                    : typeof offset === "string"
                      ? parseInt(offset, 16)
                      : offset;

            let writeData: Uint8Array | ArrayBuffer;
            if (data instanceof ArrayBuffer) {
                writeData = data;
            } else if (Array.isArray(data)) {
                writeData = new Uint8Array(data);
            } else if (typeof data.byteLength === "number") {
                writeData = data;
            } else {
                return [{}, null];
            }

            if (Process.platform === "darwin") {
                this.writeRemoteProcessMachVM(offsetNum, writeData);
            } else {
                this.writeRemoteProcessLinux(offsetNum, writeData);
            }

            return [{}, null];
        }

        // Handle file write
        if (this.currentFd < 0) {
            return [{}, null];
        }

        const offsetNum =
            typeof offset === "object"
                ? offset.toInt32()
                : typeof offset === "string"
                  ? parseInt(offset, 16)
                  : offset;

        const seeked = this.symbols.lseek(
            this.currentFd,
            new Int64(offsetNum),
            0
        ); // SEEK_SET = 0

        if ((seeked as unknown as number) < 0) {
            return [{}, null];
        }

        const count = data.byteLength;
        const buf = Memory.alloc(count);
        buf.writeByteArray(data);
        this.symbols.write(this.currentFd, buf, count);

        return [{}, null];
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
