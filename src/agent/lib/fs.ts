import { toByteArray } from "./base64.js";
import path from "path";
import { sym, _readlink, _fstat, _dup2, _close } from "./sys.js";
import { isiOS, IOSPathTransform } from "./darwin/index.js";

function normalize(x: string) : string {
    /* no-op */
    return x;
}

const { platform, pointerSize } = Process;
let fs: any | null = null;
let Gcwd = '/';
const direntSpecs = {
    'linux-32': {
        d_name: [11, 'Utf8String'],
        d_type: [10, 'U8']
    },
    'linux-64': {
        d_name: [19, 'Utf8String'],
        d_type: [18, 'U8']
    },
    'darwin-32': {
        d_name: [21, 'Utf8String'],
        d_type: [20, 'U8']
    },
    'darwin-64': {
        d_name: [
            [8, 'Utf8String'],
            [21, 'Utf8String']
        ],
        d_type: [
            [6, 'U8'],
            [20, 'U8']
        ]
    }
};
const statSpecs = {
    'linux-32': {
        size: [44, 'S32']
    },
    'linux-64': {
        size: [48, 'S64']
    },
    'darwin-32': {
        size: [60, 'S64']
    },
    'darwin-64': {
        size: [96, 'S64']
    }
};
const statxSpecs = {
    'linux-64': {
        size: [40, 'S64']
    }
};
const STATX_SIZE = 0x200;
let has64BitInode: boolean | null = null;
const direntSpec = (direntSpecs as any)[`${platform}-${pointerSize * 8}`];
const statSpec = (statSpecs as any)[`${platform}-${pointerSize * 8}`] || null;
const statxSpec = (statxSpecs as any)[`${platform}-${pointerSize * 8}`] || null;

export function fsList(args: string[]) {
    return _ls(args[0] || Gcwd);
}

export function fsGet(args: string[]) {
    return _cat(args[0] || '', '*', +args[1] || 0, +args[2] || 0);
}

export function fsCat(args: string[]) {
    return _cat(args[0] || '');
}

export function fsOpen(args: string[]) {
    return _open(args[0] || Gcwd);
}

export function chDir(args: string[]) {
    const _chdir = sym('chdir', 'int', ['pointer']);
    if (_chdir && args.length > 0) {
        const arg = Memory.allocUtf8String(args[0]);
        _chdir(arg);
        getCwd(); // update Gcwd
    }
    return '';
}

export function getCwd(): string {
    let _getcwd: any | null = null;
    if (Process.platform === "windows") {
        _getcwd = sym('_getcwd', 'pointer', ['pointer', 'int']);
    } else {
        _getcwd = sym('getcwd', 'pointer', ['pointer', 'int']);
    }
    if (_getcwd) {
        const PATH_MAX = 4096;
        const buf = Memory.alloc(PATH_MAX);
        if (!buf.isNull()) {
            const ptr = _getcwd(buf, PATH_MAX);
            const str = ptr.readCString();
            Gcwd = str;
            return str;
        }
    }
    return '';
}

export function _ls(srcPath: string) {
    if (fs === null) {
        fs = new FridaFS();
    }
    return fs.ls(_debase(srcPath));
}

export function _cat(srcPath: string, mode?: string, offset?: number, size?: number) {
    if (fs === null) {
        fs = new FridaFS();
    }
    return fs.cat(_debase(srcPath), mode, offset, size);
}

export function _open(srcPath: string): any {
    if (fs === null) {
        fs = new FridaFS();
    }
    return fs.open(_debase(srcPath));
}

export function transformVirtualPath(srcPath: string) {
    if (fs === null) {
        fs = new FridaFS();
    }
    return fs.transformVirtualPath(normalize(srcPath));
}

export function exist(srcPath: string): boolean {
    if (fs === null) {
        fs = new FridaFS();
    }
    return fs.exist(_debase(srcPath));
}

export class FridaFS {
    _api: any | null;
    _entryTypes: any | null;
    _excludeSet: any | null;
    constructor() {
        this._api = null;
        this._entryTypes = null;
        this._excludeSet = new Set(['.', '..']);
        this._transform = null;
    }

    exist(srcPath: string): boolean {
        return this.api.getFileSize(srcPath) >= 0;
    }

    ls(srcPath: string): string {
        const result = [];
        const actualPath = this.transform.toActual(srcPath);
        if (actualPath !== null) {
            const entryBuf = Memory.alloc(Process.pageSize);
            const resultPtr = Memory.alloc(Process.pointerSize);
            const dir = this.api.opendir(actualPath);
            if (dir === null) {
                return '';
            }
            let entry;
            while ((entry = this.api.readdir(dir, entryBuf, resultPtr)) !== null) {
                if (!this._excludeSet.has(entry.name)) {
                    // result.push(`${this._getEntryType(entry.type)} ${entry.name}`);
                    result.push([this._getEntryType(entry.type), entry.name].join(' '));
                }
            }
            this.api.closedir(dir);
        } else {
            const virtualDir = this.transform.getVirtualDir(srcPath);
            for (const entry of virtualDir) {
                result.push(`d ${entry.name}`);
            }
        }
        return result.join('\n');
    }

    cat(srcPath: string, mode: string, offset: number, size: number) {
        const actualPath = this.transform.toActual(srcPath);
        if (actualPath !== null) {
            const fileSize = this.api.getFileSize(actualPath);
            if (fileSize < 0) {
                console.log(`ERROR: cannot stat ${actualPath}`);
                return '';
            }
            size = (size === null) ? fileSize : size;
            if (size < 0) {
                console.log(`ERROR: invalid size ${size}`);
                return '';
            }
            let weak = false;
            if (size === 0) {
                console.log('weak');
                weak = true;
                size = 1024 * 32;
            }
            if (size > 1024 * 4096) {
                console.log('ERROR: file chunk is too big. (' + size + ' bytes)');
                return '';
            }
            const buf = Memory.alloc(size);
            const f = this.api.fopen(actualPath, 'rb');
            if (offset > 0) {
                this.api.fseek(f, offset, 0);
            }
            const res = this.api.fread(buf, 1, size, f);
            if (!weak && res !== size) {
                console.log(`ERROR: reading ${actualPath} ${res} vs ${size}`);
                this.api.fclose(f);
                return '';
            }
            this.api.fclose(f);
            const format = (mode === '*') ? 'hex' : 'utf8';
            return encodeBuf(buf, size, format);
        }
        console.log('ERROR: no path ' + srcPath);
        return '';
    }

    open(srcPath: string): string {
        const actualPath = this.transform.toActual(srcPath);
        if (actualPath !== null) {
            const size = this.api.getFileSize(actualPath);
            if (size < 0) {
                console.log(`ERROR: cannot stat ${actualPath}`);
                return '';
            }
            return `${size}`;
        }
        return '';
    }

    transformVirtualPath(srcPath: string): string {
        for (const vPrefix of this.transform._mappedPrefixes) {
            const index = srcPath.indexOf(vPrefix);
            if (index >= 0) {
                srcPath = srcPath.slice(index);
                break;
            }
        }
        const actualPath = this.transform.toActual(srcPath);
        if (actualPath !== null) {
            return actualPath;
        }
        return srcPath;
    }
    _transform: any | null;
    get transform() {
        if (this._transform === null) {
            if (isiOS()) {
                this._transform = new IOSPathTransform();
            } else {
                this._transform = new NULLTransform();
            }
        }
        return this._transform;
    }

    get api() {
        if (this._api === null) {
            this._api = new PosixFSApi();
        }
        return this._api;
    }

    _getEntryType(entry: string) {
        if (this._entryTypes === null) {
            this._entryTypes = {
                0: '?',
                1: 'p',
                2: 'c',
                4: 'd',
                6: 'b',
                8: 'f',
                10: 'l',
                12: 's',
                14: 'w' // DT_WHT - (W)hat the (H)ell is (T)his
            };
        }
        const result = this._entryTypes[entry];
        if (result === undefined) {
            return '?';
        }
        return result;
    }
}

export class PathTransform {
    _virtualDirs: any;
    _mappedPrefixes: any;
    constructor() {
        this._virtualDirs = {};
        this._mappedPrefixes = [];
    }

    toActual(virtualPath: string) : string | null {
        for (const vPrefix of this._mappedPrefixes) {
            if (virtualPath.indexOf(vPrefix) === 0) {
                const replacement = this._virtualDirs[vPrefix];
                return virtualPath.replace(vPrefix, replacement);
            }
        }
        return virtualPath;
    }

    getVirtualDir(virtualPath: string): string[] {
        const result: string[] = this._virtualDirs[virtualPath];
        if (result === undefined) {
            return [];
        }
        return result;
    }
}

export class NULLTransform extends PathTransform {
    toActual(virtualPath: string) {
        return virtualPath;
    }
}

export class VirtualEnt {
    name: string;
    actualPath: string;
    subEnts: string[];

    constructor(name: string, actualPath: string | null = null) {
        this.name = name;
        this.actualPath = actualPath ?? ".";
        this.subEnts = [];
    }

    addSub(ent: any) {
        this.subEnts.push(ent);
    }

    hasActualPath(): boolean {
        return this.actualPath !== null;
    }
}

export class PosixFSApi {
    _api: any;

    constructor() {
        this._api = null;
    }

    get api() {
        if (this._api === null) {
            const exports = resolveExports(['opendir', 'readdir_r', 'closedir', 'fopen', 'fclose', 'fread', 'fseek']);
            const available = Object.keys(exports).filter(name => exports[name] === null).length === 0;
            if (!available) {
                throw new Error('ERROR: is this a POSIX system?');
            }
            this._api = {
                opendir: new NativeFunction(exports.opendir, 'pointer', ['pointer']),
                readdir: new NativeFunction(exports.readdir_r, 'int', ['pointer', 'pointer', 'pointer']),
                closedir: new NativeFunction(exports.closedir, 'int', ['pointer']),
                fopen: new NativeFunction(exports.fopen, 'pointer', ['pointer', 'pointer']),
                fclose: new NativeFunction(exports.fclose, 'int', ['pointer']),
                fread: new NativeFunction(exports.fread, 'int', ['pointer', 'int', 'int', 'pointer']),
                fseek: new NativeFunction(exports.fseek, 'int', ['pointer', 'int', 'int']),
                stat: null,
                statx: null
            };
            const stats = resolveExports(['stat', 'stat64', 'statx']);
            const stat = stats.stat64 || stats.stat;
            const { statx } = stats;
            if (stat !== null) {
                this._api.stat = new NativeFunction(stat, 'int', ['pointer', 'pointer']);
            } else if (statx !== null) {
                this._api.statx = new NativeFunction(statx, 'int', ['int', 'pointer', 'int', 'int', 'pointer']);
            }
        }
        return this._api;
    }

    opendir(srcPath: string): any | null {
        const result = this.api.opendir(Memory.allocUtf8String(srcPath));
        if (result.isNull()) {
            return null;
        }
        return result;
    }

    readdir(dir: any, entryBuf: any, resultPtr: any) {
        this.api.readdir(dir, entryBuf, resultPtr);
        const result = resultPtr.readPointer();
        if (result.isNull()) {
            return null;
        }
        return new DirEnt(result);
    }

    closedir(dir: string) {
        return this.api.closedir(dir);
    }

    fopen(srcPath: string, mode: string) {
        return this.api.fopen(Memory.allocUtf8String(srcPath), Memory.allocUtf8String(mode));
    }

    fclose(f: any) {
        return this.api.fclose(f);
    }

    fread(buf: any, size: number, nitems: number, f: any) {
        return this.api.fread(buf, size, nitems, f);
    }

    fseek(f: any, offset: number, whence: number) {
        return this.api.fseek(f, offset, whence);
    }

    getFileSize(srcPath: string) {
        const statPtr = Memory.alloc(Process.pageSize);
        const pathStr = Memory.allocUtf8String(srcPath);
        if (this.api.stat !== null) {
            const res = this.api.stat(pathStr, statPtr);
            if (res === -1) {
                return -1;
            }
            return readStatField(statPtr, 'size');
        } else if (this.api.statx) {
            const res = this.api.statx(0, pathStr, 0, STATX_SIZE, statPtr);
            if (res === -1) {
                return -1;
            }
            return readStatxField(statPtr, 'size');
        }
    }
}

class DirEnt {
    type: any;
    name: any;
    constructor(dirEntPtr: any) {
        this.type = readDirentField(dirEntPtr, 'd_type');
        this.name = readDirentField(dirEntPtr, 'd_name');
    }
}

function readDirentField(entry: any, name: string) {
    let spec = direntSpec[name];
    if (platform === 'darwin') {
        if (direntHas64BitInode(entry)) {
            spec = spec[1];
        } else {
            spec = spec[0];
        }
    }
    const [offset, type] = spec;
    const read = (typeof type === 'string') ? (Memory as any)['read' + type] : type;
    const value = read(entry.add(offset));
    if (value instanceof Int64 || value instanceof UInt64) {
        return value.valueOf();
    }
    return value;
}

function readStatField(entry: NativePointer, name: string) {
    const field = statSpec[name];
    if (field === undefined) {
        return undefined;
    }
    const [offset, type] = field;
    const read = (typeof type === 'string') ? (Memory as any)['read' + type] : type;
    const value = read(entry.add(offset));
    if (value instanceof Int64 || value instanceof UInt64) {
        return value.valueOf();
    }
    return value;
}

function readStatxField(entry: any, name: string) {
    const field = statxSpec[name];
    if (field === undefined) {
        return undefined;
    }
    const [offset, type] = field;
    const read = (typeof type === 'string') ? (Memory as any)[('read' + type)] : type;
    const value = read(entry.add(offset));
    if (value instanceof Int64 || value instanceof UInt64) {
        return value.valueOf();
    }
    return value;
}

export function direntHas64BitInode(dirEntPtr: NativePointer) {
    if (has64BitInode !== null) {
        return has64BitInode;
    }
    const recLen = dirEntPtr.add(4).readU16();
    const nameLen = dirEntPtr.add(7).readU8();
    const compLen = (8 + nameLen + 3) & ~3;
    has64BitInode = compLen !== recLen;
    return has64BitInode;
}

export function resolveExports(names: string[]) {
    return names.reduce((exports: any, name: string) => {
        exports[name] = Module.findExportByName(null, name);
        return exports;
    }, {});
}

export function flatify(result: any, vEnt: any, rootPath = "") {
    const myPath = normalize(path.join(rootPath, vEnt.name));
    if (vEnt.hasActualPath()) {
        result[myPath] = vEnt.actualPath;
        return;
    }
    result[myPath] = vEnt.subEnts;
    for (const sub of vEnt.subEnts) {
        flatify(result, sub, myPath);
    }
}

export function nsArrayMap(array: any, callback: any): any[] {
    const result = [];
    const count = array.count().valueOf();
    for (let index = 0; index !== count; index++) {
        result.push(callback(array.objectAtIndex_(index)));
    }
    return result;
}

export function encodeBuf(buf: NativePointer, size: number, encoding: string) {
    if (encoding !== 'hex') {
        return buf.readCString();
    }
    const result = [];
    for (let i = 0; i < size; i++) {
        const val = buf.add(i).readU8();
        const valHex = val.toString(16);
        if (valHex.length < 2) {
            result.push(`0${valHex}`);
        } else {
            result.push(valHex);
        }
    }
    return result.join('');
}

export function listFileDescriptors(args: string[]) {
    return listFileDescriptorsJson(args).map(([fd, name]: [any, any]) => {
        return fd + ' ' + name;
    }).join('\n');
}

export function listFileDescriptorsJson(args: string[]) {
    const PATH_MAX = 4096;
    function getFdName(fd: any) {
        if (_readlink && Process.platform === 'linux') {
            const fdPath = path.join('proc', '' + Process.id, 'fd', '' + fd);
            const buffer = Memory.alloc(PATH_MAX);
            const source = Memory.alloc(PATH_MAX);
            source.writeUtf8String(fdPath);
            buffer.writeUtf8String('');
            if (_readlink(source, buffer, PATH_MAX) !== -1) {
                return buffer.readUtf8String();
            }
            return undefined;
        }
        try {
            // TODO: port this to iOS
            const F_GETPATH = 50; // on macOS
            const buffer = Memory.alloc(PATH_MAX);
            const addr = Module.getExportByName(null, 'fcntl');
            const fcntl = new NativeFunction(addr, 'int', ['int', 'int', 'pointer']);
            fcntl(fd, F_GETPATH, buffer);
            return buffer.readCString();
        } catch (e) {
            return '';
        }
    }
    if (args.length === 0) {
        const statBuf = Memory.alloc(128);
        const fds = [];
        for (let i = 0; i < 1024; i++) {
            if (_fstat!(i, statBuf) === 0) {
                fds.push(i);
            }
        }
        return fds.map((fd) => {
            return [fd, getFdName(fd)];
        });
    } else {
        const rc = _dup2!(+args[0], +args[1]);
        return rc;
    }
}

export function closeFileDescriptors(args: string[]) {
    if (args.length === 0) {
        return 'Please, provide a file descriptor';
    }
    if (_close === null) {
        return "_close is null";
    }
    return _close(+args[0]);
}

function _debase(a: any) {
    if (a.startsWith('base64:')) {
        try {
            const data = toByteArray(a.slice(7));
            a = String.fromCharCode.apply(null, data as any);
        } catch (e) {
            // invalid base64
        }
    }
    return normalize(a);
}

export default {};
