'use strict';

const {normalize} = require('path');

module.exports = {
  ls,
  cat,
  open
};

let fs = null;

function ls (path) {
  if (fs === null) {
    fs = new FridaFS();
  }

  return fs.ls(normalize(path));
}

function cat (path) {
  if (fs === null) {
    fs = new FridaFS();
  }

  return fs.cat(normalize(path));
}

function open (path) {
  if (fs === null) {
    fs = new FridaFS();
  }

  return fs.open(normalize(path));
}

class FridaFS {
  constructor () {
    this._api = null;
    this._entryTypes = null;
    this._excludeSet = new Set(['.', '..']);
    this._transform = null;
  }

  ls (path) {
    const result = [];

    const actualPath = this.transform.toActual(path);
    if (actualPath !== null) {
      const dir = this.api.opendir(actualPath);
      if (dir === null) {
        return '';
      }
      let entry;
      while ((entry = this.api.readdir(dir)) !== null) {
        if (!this._excludeSet.has(entry.name)) {
          result.push(`${this._getEntryType(entry.type)} ${entry.name}`);
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

  cat (path) {
    const actualPath = this.transform.toActual(path);
    if (actualPath !== null) {
      const size = this.api.getFileSize(actualPath);
      if (size < 0) {
        console.log(`ERROR: cannot stat ${actualPath}`);
        return '';
      }

      const buf = Memory.alloc(size);
      const f = this.api.fopen(actualPath, 'rb');
      if (this.api.fread(buf, 1, size, f) !== size) {
        console.log(`ERROR: reading ${actualPath}`);
        this.api.fclose(f);
        return '';
      }

      this.api.fclose(f);

      return encodeBuf(buf, size, 'hex');
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
      const exports = resolveExports(['opendir', 'readdir', 'closedir', 'fopen', 'fclose', 'fread', 'stat']);
      const available = Object.keys(exports).filter(name => exports[name] === null).length === 0;
      if (!available) {
        throw new Error('ERROR: is this a POSIX system?');
      }

      this._api = {
        opendir: new NativeFunction(exports.opendir, 'pointer', ['pointer']),
        readdir: new NativeFunction(exports.readdir, 'pointer', ['pointer']),
        closedir: new NativeFunction(exports.closedir, 'int', ['pointer']),
        fopen: new NativeFunction(exports.fopen, 'pointer', ['pointer', 'pointer']),
        fclose: new NativeFunction(exports.fclose, 'int', ['pointer']),
        fread: new NativeFunction(exports.fread, 'int', ['pointer', 'int', 'int', 'pointer']),
        stat: new NativeFunction(exports.stat, 'int', ['pointer', 'pointer'])
      };
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

  readdir (dir) {
    const result = this.api.readdir(dir);
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

  getFileSize (path) {
    const statPtr = Memory.alloc(144);
    const res = this.api.stat(Memory.allocUtf8String(path), statPtr);
    if (res === -1) {
      return -1;
    }
    if (Process.pointerSize === 8) {
      return Memory.readU64(statPtr.add(96)).toNumber();
    } else {
      return Memory.readU64(statPtr.add(60)).toNumber();
    }
  }
}

class DirEnt {
  constructor (dirEntPtr) {
    this.type = Memory.readU8(dirEntPtr.add(20));
    this.name = Memory.readUtf8String(dirEntPtr.add(21));
  }
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
  return Process.platform === 'darwin' &&
    Process.arch.indexOf('arm') === 0 &&
    ObjC.available;
}

function encodeBuf (buf, size, encoding) {
  if (encoding !== 'hex') {
    return '';
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
