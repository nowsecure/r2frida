'use strict';

const { normalize } = require('path');
const { platform, pointerSize } = Process;

module.exports = {
  ls,
  cat,
  open,
  transformVirtualPath,
  exist
};

let fs = null;

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

let has64BitInode = null;
const direntSpec = direntSpecs[`${platform}-${pointerSize * 8}`];
const statSpec = statSpecs[`${platform}-${pointerSize * 8}`] || null;
const statxSpec = statxSpecs[`${platform}-${pointerSize * 8}`] || null;

function ls (path) {
  if (fs === null) {
    fs = new FridaFS();
  }
  return fs.ls(normalize(path));
}

function cat (path, mode, offset, size) {
  if (fs === null) {
    fs = new FridaFS();
  }

  return fs.cat(normalize(path), mode, offset, size);
}

function open (path) {
  if (fs === null) {
    fs = new FridaFS();
  }

  return fs.open(normalize(path));
}

function transformVirtualPath (path) {
  if (fs === null) {
    fs = new FridaFS();
  }
  return fs.transformVirtualPath(normalize(path));
}

function exist (path) {
  if (fs === null) {
    fs = new FridaFS();
  }
  return fs.exist(normalize(path));
}

class FridaFS {
  constructor () {
    this._api = null;
    this._entryTypes = null;
    this._excludeSet = new Set(['.', '..']);
    this._transform = null;
  }

  exist (path) {
    return this.api.getFileSize(path) >= 0;
  }

  ls (path) {
    const result = [];

    const actualPath = this.transform.toActual(path);
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
      const virtualDir = this.transform.getVirtualDir(path);
      for (const entry of virtualDir) {
        result.push(`d ${entry.name}`);
      }
    }
    return result.join('\n');
  }

  cat (path, mode, offset, size) {
    const actualPath = this.transform.toActual(path);
    if (actualPath !== null) {
      const file_size = this.api.getFileSize(actualPath);
      if (file_size < 0) {
        console.log(`ERROR: cannot stat ${actualPath}`);
        return '';
      }

      size = parseInt(size);
      offset = parseInt(offset);
      size = (size === null) ? file_size : size;
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
      if (size > 1024 * 512) {
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
    console.log('ERROR: no path ' + path);
    return '';
  }

  open (path) {
    const actualPath = this.transform.toActual(path);
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

  transformVirtualPath (path) {
    for (const vPrefix of this.transform._mappedPrefixes) {
      const index = path.indexOf(vPrefix);
      if (index >= 0) {
        path = path.slice(index);
        break;
      }
    }
    const actualPath = this.transform.toActual(path);
    if (actualPath !== null) {
      return actualPath;
    }
    return path;
  }

  get transform () {
    if (this._transform === null) {
      if (isiOS()) {
        this._transform = new iOSPathTransform();
      } else {
        this._transform = new NULLTransform();
      }
    }
    return this._transform;
  }

  get api () {
    if (this._api === null) {
      this._api = new PosixFSApi();
    }

    return this._api;
  }

  _getEntryType (entry) {
    if (this._entryTypes === null) {
      this._entryTypes = {
        0: '?', // DT_UNKNOWN
        1: 'p', // DT_FIFO
        2: 'c', // DT_CHR
        4: 'd', // DT_DIR
        6: 'b', // DT_BLK
        8: 'f', // DT_REG
        10: 'l', // DT_LNK
        12: 's', // DT_SOCK
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

class PathTransform {
  constructor () {
    this._virtualDirs = {};
    this._mappedPrefixes = [];
  }

  toActual (virtualPath) {
    for (const vPrefix of this._mappedPrefixes) {
      if (virtualPath.indexOf(vPrefix) === 0) {
        const replacement = this._virtualDirs[vPrefix];
        return virtualPath.replace(vPrefix, replacement);
      }
    }
    return null;
  }

  getVirtualDir (virtualPath) {
    const result = this._virtualDirs[virtualPath];
    if (result === undefined) {
      return [];
    }
    return result;
  }
}

class NULLTransform extends PathTransform {
  toActual (virtualPath) {
    return virtualPath;
  }
}

class VirtualEnt {
  constructor (name, actualPath = null) {
    this.name = name;
    this.actualPath = actualPath;
    this.subEnts = [];
  }

  addSub (ent) {
    this.subEnts.push(ent);
  }

  hasActualPath () {
    return this.actualPath !== null;
  }
}

class iOSPathTransform extends PathTransform {
  constructor () {
    super();
    this._api = null;
    this._fillVirtualDirs();
  }

  _fillVirtualDirs () {
    const pool = this.api.NSAutoreleasePool.alloc().init();

    const appHome = new ObjC.Object(this.api.NSHomeDirectory()).toString();
    const appBundle = this.api.NSBundle.mainBundle().bundlePath().toString();

    const root = new VirtualEnt('/');
    root.addSub(new VirtualEnt('AppHome', appHome));
    root.addSub(new VirtualEnt('AppBundle', appBundle));

    const groupNames = this._getAppGroupNames();
    if (groupNames.length > 0) {
      const fileManager = this.api.NSFileManager.defaultManager();
      const appGroups = new VirtualEnt('AppGroups');
      root.addSub(appGroups);
      for (const groupName of groupNames) {
        const groupUrl = fileManager.containerURLForSecurityApplicationGroupIdentifier_(groupName);
        if (groupUrl !== null) {
          appGroups.addSub(new VirtualEnt(groupName, groupUrl.path().toString()));
        }
      }
    }

    root.addSub(new VirtualEnt('Device', '/'));

    flatify(this._virtualDirs, root);

    this._mappedPrefixes = Object.keys(this._virtualDirs)
      .filter(key => typeof this._virtualDirs[key] === 'string')
      .sort((x, y) => x.length - y.length);

    pool.release();
  }

  _getAppGroupNames () {
    const task = this.api.SecTaskCreateFromSelf(NULL);
    if (task.isNull()) {
      return [];
    }

    const key = this.api.NSString.stringWithString_('com.apple.security.application-groups');
    const ids = this.api.SecTaskCopyValueForEntitlement(task, key, NULL);
    if (ids.isNull()) {
      this.api.CFRelease(task);
      return [];
    }

    const idsObj = new ObjC.Object(ids).autorelease();
    const names = nsArrayMap(idsObj, group => {
      return group.toString();
    });

    this.api.CFRelease(task);

    return names;
  }

  get api () {
    if (this._api === null) {
      this._api = {
        NSAutoreleasePool: ObjC.classes.NSAutoreleasePool,
        NSBundle: ObjC.classes.NSBundle,
        NSFileManager: ObjC.classes.NSFileManager,
        NSHomeDirectory: new NativeFunction(
          Module.findExportByName(null, 'NSHomeDirectory'),
          'pointer', []
        ),
        NSString: ObjC.classes.NSString,
        SecTaskCreateFromSelf: new NativeFunction(
          Module.findExportByName(null, 'SecTaskCreateFromSelf'),
          'pointer', ['pointer']
        ),
        SecTaskCopyValueForEntitlement: new NativeFunction(
          Module.findExportByName(null, 'SecTaskCopyValueForEntitlement'),
          'pointer', ['pointer', 'pointer', 'pointer']
        ),
        CFRelease: new NativeFunction(
          Module.findExportByName(null, 'CFRelease'),
          'void', ['pointer']
        )
      };
    }

    return this._api;
  }
}

class PosixFSApi {
  constructor () {
    this._api = null;
  }

  get api () {
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

  opendir (path) {
    const result = this.api.opendir(Memory.allocUtf8String(path));
    if (result.isNull()) {
      return null;
    }
    return result;
  }

  readdir (dir, entryBuf, resultPtr) {
    const success = this.api.readdir(dir, entryBuf, resultPtr);
    const result = resultPtr.readPointer();
    if (result.isNull()) {
      return null;
    }
    return new DirEnt(result);
  }

  closedir (dir) {
    return this.api.closedir(dir);
  }

  fopen (path, mode) {
    return this.api.fopen(Memory.allocUtf8String(path), Memory.allocUtf8String(mode));
  }

  fclose (f) {
    return this.api.fclose(f);
  }

  fread (buf, size, nitems, f) {
    return this.api.fread(buf, size, nitems, f);
  }

  fseek (f, offset, whence) {
    return this.api.fseek(f, offset, whence);
  }

  getFileSize (path) {
    const statPtr = Memory.alloc(Process.pageSize);
    const pathStr = Memory.allocUtf8String(path);
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
  constructor (dirEntPtr) {
    this.type = readDirentField(dirEntPtr, 'd_type');
    this.name = readDirentField(dirEntPtr, 'd_name');
  }
}

function readDirentField (entry, name) {
  let spec = direntSpec[name];
  if (platform === 'darwin') {
    if (direntHas64BitInode(entry)) {
      spec = spec[1];
    } else {
      spec = spec[0];
    }
  }
  const [offset, type] = spec;

  const read = (typeof type === 'string') ? Memory['read' + type] : type;

  const value = read(entry.add(offset));
  if (value instanceof Int64 || value instanceof UInt64) { return value.valueOf(); }

  return value;
}

function readStatField (entry, name) {
  const field = statSpec[name];
  if (field === undefined) {
    return undefined;
  }

  const [offset, type] = field;

  const read = (typeof type === 'string') ? Memory['read' + type] : type;

  const value = read(entry.add(offset));
  if (value instanceof Int64 || value instanceof UInt64) { return value.valueOf(); }

  return value;
}

function readStatxField (entry, name) {
  const field = statxSpec[name];
  if (field === undefined) {
    return undefined;
  }

  const [offset, type] = field;

  const read = (typeof type === 'string') ? Memory['read' + type] : type;

  const value = read(entry.add(offset));
  if (value instanceof Int64 || value instanceof UInt64) { return value.valueOf(); }

  return value;
}

function direntHas64BitInode (dirEntPtr) {
  if (has64BitInode !== null) {
    return has64BitInode;
  }

  const recLen = dirEntPtr.add(4).readU16();
  const nameLen = dirEntPtr.add(7).readU8();
  const compLen = (8 + nameLen + 3) & ~3;

  has64BitInode = compLen !== recLen;
  return has64BitInode;
}

function resolveExports (names) {
  return names.reduce((exports, name) => {
    exports[name] = Module.findExportByName(null, name);
    return exports;
  }, {});
}

function flatify (result, vEnt, path = '') {
  const myPath = normalize(`${path}/${vEnt.name}`);

  if (vEnt.hasActualPath()) {
    result[myPath] = vEnt.actualPath;
    return;
  }

  result[myPath] = vEnt.subEnts;

  for (const sub of vEnt.subEnts) {
    flatify(result, sub, myPath);
  }
}

function nsArrayMap (array, callback) {
  const result = [];
  const count = array.count().valueOf();
  for (let index = 0; index !== count; index++) {
    result.push(callback(array.objectAtIndex_(index)));
  }
  return result;
}

function isiOS () {
  return platform === 'darwin' &&
    Process.arch.indexOf('arm') === 0 &&
    ObjC.available;
}

function encodeBuf (buf, size, encoding) {
  if (encoding !== 'hex') {
    return Memory.readCString(buf);
  }

  const result = [];

  for (let i = 0; i < size; i++) {
    const val = Memory.readU8(buf.add(i));
    const valHex = val.toString(16);
    if (valHex.length < 2) {
      result.push(`0${valHex}`);
    } else {
      result.push(valHex);
    }
  }

  return result.join('');
}
