/**
 * IO File Redirection Module
 * Allows redirecting r2frida IO to read/write from a file
 * Useful for reading /proc/pid/mem or any other remote file
 */

import * as utils from "./utils.js";

interface NativeSymbols {
    open: (pathPtr: NativePointer, flags: number) => number;
    close: (fd: number) => number;
    read: (fd: number, buf: NativePointer, count: number) => number;
    write: (fd: number, buf: NativePointer, count: number) => number;
    lseek: (fd: number, offset: Int64, whence: number) => Int64;
}

class IOFileManager {
    private currentFd: number = -1;
    private currentPath: string = "";
    private symbols: NativeSymbols;

    constructor() {
        this.symbols = this.initializeSymbols();
    }

    private initializeSymbols(): NativeSymbols {
        const sym = (name: string, ret: string, arg: string[]): any => {
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
            open: sym("open", "int", ["pointer", "int"]),
            close: sym("close", "int", ["int"]),
            read: sym("read", "int", ["int", "pointer", "int"]),
            write: sym("write", "int", ["int", "pointer", "int"]),
            lseek: sym("lseek", "int64", ["int", "int64", "int"]),
        };
    }

    private showHelp(): string {
        return (
            "iofile Commands:\n" +
            "iofile [path]  - redirect IO to read/write from the given file\n" +
            "iofile         - show current status\n" +
            "iofile-        - close the file and restore normal IO\n" +
            "iofile?        - show help\n" +
            "\n" +
            "Examples:\n" +
            "  iofile /proc/1234/mem  - read memory of pid 1234\n" +
            "  iofile /dev/mem        - read physical memory (requires root)\n" +
            "  iofile /path/to/file   - read any file as if it were memory\n"
        );
    }

    private getStatus(): string {
        if (this.currentFd < 0) {
            return "IO: normal (not redirected)";
        }
        return `IO redirected to: ${this.currentPath} (fd=${this.currentFd})`;
    }

    private openFile(path: string): string {
        if (this.currentFd >= 0) {
            this.symbols.close(this.currentFd);
            this.currentFd = -1;
            this.currentPath = "";
        }

        const O_RDWR = 2;
        const O_RDONLY = 0;
        const pathPtr = Memory.allocUtf8String(path);

        let fd = this.symbols.open(pathPtr, O_RDWR);
        if (fd < 0) {
            fd = this.symbols.open(pathPtr, O_RDONLY);
        }

        if (fd < 0) {
            return `ERROR: cannot open ${path}`;
        }

        this.currentFd = fd;
        this.currentPath = path;

        return `IO redirected to: ${path} (fd=${fd})`;
    }

    private closeFile(): string {
        if (this.currentFd >= 0) {
            this.symbols.close(this.currentFd);
            this.currentFd = -1;
            this.currentPath = "";
        }
        return "IO restored to normal";
    }

    public hookedRead(offset: any, count: number): [any, any] {
        if (this.currentFd < 0) {
            return [{}, []];
        }

        const offsetNum =
            typeof offset === "string" ? parseInt(offset, 16) : offset;
        const seeked = this.symbols.lseek(
            this.currentFd,
            Int64(offsetNum),
            0
        ); // SEEK_SET = 0

        if (seeked < 0) {
            return [{}, []];
        }

        const buf = Memory.alloc(count);
        const bytesRead = this.symbols.read(this.currentFd, buf, count);

        if (bytesRead <= 0) {
            return [{}, []];
        }

        const data = buf.readByteArray(bytesRead);
        return [{}, data];
    }

    public hookedWrite(offset: any, data: any): [any, null] {
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
            Int64(offsetNum),
            0
        ); // SEEK_SET = 0

        if (seeked < 0) {
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
            if (this.currentFd < 0) {
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
