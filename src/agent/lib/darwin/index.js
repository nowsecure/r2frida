'use strict';

const { listClasses } = require('../info/classes');
const utils = require('../utils');
const { PathTransform, VirtualEnt, flatify, nsArrayMap } = require('../fs');

const MIN_PTR = ptr('0x100000000');
const ISA_MASK = ptr('0x0000000ffffffff8');
const ISA_MAGIC_MASK = ptr('0x000003f000000001');
const ISA_MAGIC_VALUE = ptr('0x000001a000000001');

/* ObjC.available is buggy on non-objc apps, so override this */
const ObjCAvailable = (Process.platform === 'darwin') && !(Java && Java.available) && ObjC && ObjC.available && ObjC.classes && typeof ObjC.classes.NSString !== 'undefined';

function initFoundation () {
  // required for early instrumentation
  try {
    Module.load('/System/Library/Frameworks/Foundation.framework/Foundation');
  } catch (e) {
    // ignored
  }
}

function getIOSVersion () {
  const processInfo = ObjC.classes.NSProcessInfo.processInfo();
  const versionString = processInfo.operatingSystemVersionString().UTF8String().toString();
  // E.g. "Version 13.5 (Build 17F75)"
  const version = versionString.split(' ')[1];
  // E.g. 13.5
  return version;
}

function isiOS () {
  return Process.platform === 'darwin' &&
    Process.arch.indexOf('arm') === 0 &&
    ObjC.available;
}

function isObjC (p) {
  const klass = getObjCClassPtr(p);
  if (klass.isNull()) {
    return false;
  }
  return true;
}

function getObjCClassPtr (p) {
  if (!looksValid(p)) {
    return NULL;
  }
  const isa = p.readPointer();
  let classP = isa;
  if (classP.and(ISA_MAGIC_MASK).equals(ISA_MAGIC_VALUE)) {
    classP = isa.and(ISA_MASK);
  }
  return looksValid(classP) ? classP : NULL;
}

function looksValid (p) {
  return p.compare(MIN_PTR) >= 0 && isReadable(p);
}

function isReadable (p) {
  // TODO: catching access violation isn't compatible with jailed testing
  try {
    p.readU8(p);
    return true;
  } catch (e) {
    return false;
  }
}

function dxObjc (args) {
  if (!ObjCAvailable) {
    return 'dxo requires the objc runtime to be available to work.';
  }
  if (args.length === 0) {
    return 'Usage: dxo [klassname|instancepointer] [methodname] [args...]';
  }
  if (args.length === 1) {
    return listClasses(args);
  }
  // Usage: "dxo instance-pointer [arg0 arg1]"
  let instancePointer = null;
  if (args[0].startsWith('0x')) {
    instancePointer = new ObjC.Object(ptr(args[0]));
  } else {
    const klassName = args[0];
    if (!ObjC.classes[klassName]) {
      return 'Cannot find objc class ' + klassName;
    }
    const instances = ObjC.chooseSync(ObjC.classes[klassName]);
    if (!instances) {
      return 'Cannot find any instance for klass ' + klassName;
    }
    instancePointer = instances[0];
  }
  const methodName = args[1];
  const [v, t] = utils.autoType(args.slice(2));
  try {
    ObjC.schedule(ObjC.mainQueue, function () {
      if (instancePointer.hasOwnProperty(methodName)) {
        instancePointer[methodName](...t);
      } else {
        console.error('unknown method ' + methodName + ' for objc instance at ' + padPointer(ptr(instancePointer)));
      }
    });
  } catch (e) {
    console.error(e);
  }
  return '';
}

function hasMainLoop () {
  const getMainPtr = Module.findExportByName(null, 'CFRunLoopGetMain');
  if (getMainPtr === null) {
    return false;
  }

  const copyCurrentModePtr = Module.findExportByName(null, 'CFRunLoopCopyCurrentMode');
  if (copyCurrentModePtr === null) {
    return false;
  }

  const getMain = new NativeFunction(getMainPtr, 'pointer', []);
  const copyCurrentMode = new NativeFunction(copyCurrentModePtr, 'pointer', ['pointer']);

  const main = getMain();
  if (main.isNull()) {
    return false;
  }

  const mode = copyCurrentMode(main);
  const hasLoop = !mode.isNull();

  if (hasLoop) {
    new ObjC.Object(mode).release();
  }

  return hasLoop;
}

function uiAlert (args) {
  if (args.length < 2) {
    return 'Usage: ?E title message';
  }
  const title = args[0];
  const message = args.slice(1).join(' ');
  ObjC.schedule(ObjC.mainQueue, function () {
    const UIAlertView = ObjC.classes.UIAlertView; /* iOS 7 */
    const view = UIAlertView.alloc().initWithTitle_message_delegate_cancelButtonTitle_otherButtonTitles_(
      title,
      message,
      NULL,
      'OK',
      NULL);
    view.show();
    view.release();
  });
}

function listMachoSections (baseAddr) {
  const result = [];
  if (!_isMachoHeaderAtOffset(baseAddr)) {
    throw new Error(`Not a valid Mach0 module found at ${baseAddr}`);
  }
  const machoHeader = parseMachoHeader(baseAddr);
  if (machoHeader !== undefined) {
    const segments = getSegments(baseAddr, machoHeader.ncmds);
    segments
      .filter((segment) => segment.name === '__TEXT' || segment.name === '__DATA')
      .forEach((segment) => {
        result.push(...getSections(segment));
      });
  }
  return result;
}

function parseMachoHeader (offset) {
  const header = {
    magic: offset.readU32(),
    cputype: offset.add(0x4).readU32(),
    cpusubtype: offset.add(0x8).readU32(),
    filetype: offset.add(0x0c).readU32(),
    ncmds: offset.add(0x10).readU32(),
    sizeofcmds: offset.add(0x14).readU32(),
    flags: offset.add(0x18).readU32()
  };
  if (header.cputype === 0x0100000c) {
    // arm64
    return header;
  }
  if (header.cputype === 0x01000007) {
    // x86-64
    return header;
  }
  throw new Error('Only support for 64-bit apps');
}

function _isMachoHeaderAtOffset (offset) {
  const cursor = utils.trunc4k(offset);
  if (cursor.readU32() === 0xfeedfacf) {
    return true;
  }
  return false;
}

function getSections (segment) {
  let { name, nsects, sectionsPtr, slide } = segment;
  const sects = [];
  while (nsects--) {
    sects.push({
      name: `${name}.${sectionsPtr.readUtf8String()}`,
      vmaddr: sectionsPtr.add(32).readPointer().add(slide),
      vmsize: sectionsPtr.add(40).readU64()
    });
    sectionsPtr = sectionsPtr.add(80);
  }
  return sects;
}

function getSegments (baseAddr, ncmds) {
  const LC_SEGMENT_64 = 0x19;
  let cursor = baseAddr.add(0x20);
  const segments = [];
  let slide = 0;
  while (ncmds-- > 0) {
    const command = cursor.readU32();
    const cmdSize = cursor.add(4).readU32();
    if (command !== LC_SEGMENT_64) {
      cursor = cursor.add(cmdSize);
      continue;
    }
    const segment = {
      name: cursor.add(0x8).readUtf8String(),
      vmaddr: cursor.add(0x18).readPointer(),
      vmsize: cursor.add(0x18).add(8).readPointer(),
      nsects: cursor.add(64).readU32(),
      sectionsPtr: cursor.add(72)
    };
    if (segment.name === '__TEXT') {
      slide = baseAddr.sub(segment.vmaddr);
    }
    cursor = cursor.add(cmdSize);
    segments.push(segment);
  }
  segments
    .filter(seg => seg.name !== '__PAGEZERO')
    .forEach((seg) => {
      seg.vmaddr = seg.vmaddr.add(slide);
      seg.slide = slide;
    });
  return segments;
}

function loadFrameworkBundle (args) {
  if (!ObjCAvailable) {
    console.log('dlf: This command requires the objc runtime');
    return false;
  }
  const path = args[0];
  const appPath = ObjC.classes.NSBundle.mainBundle().bundlePath();
  const fullPath = appPath.stringByAppendingPathComponent_(path);
  const bundle = ObjC.classes.NSBundle.bundleWithPath_(fullPath);
  if (bundle.isLoaded()) {
    console.log('Bundle already loaded');
    return false;
  }
  return bundle.load();
}

function unloadFrameworkBundle (args) {
  if (!ObjCAvailable) {
    console.log('dlf: This command requires the objc runtime');
    return false;
  }
  const path = args[0];
  const appPath = ObjC.classes.NSBundle.mainBundle().bundlePath();
  const fullPath = appPath.stringByAppendingPathComponent_(path);
  const bundle = ObjC.classes.NSBundle.bundleWithPath_(fullPath);
  if (!bundle.isLoaded()) {
    console.log('Bundle already unloaded');
    return false;
  }
  return bundle.unload();
}

class IOSPathTransform extends PathTransform {
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

module.exports = {
  initFoundation,
  getIOSVersion,
  isiOS,
  isObjC,
  ObjCAvailable,
  hasMainLoop,
  dxObjc,
  uiAlert,
  listMachoSections,
  parseMachoHeader,
  getSections,
  getSegments,
  loadFrameworkBundle,
  unloadFrameworkBundle,
  IOSPathTransform
};