'use strict';

const MIN_PTR = ptr('0x100000000');
const ISA_MASK = ptr('0x0000000ffffffff8');
const ISA_MAGIC_MASK = ptr('0x000003f000000001');
const ISA_MAGIC_VALUE = ptr('0x000001a000000001');

/* ObjC.available is buggy on non-objc apps, so override this */
const ObjCAvailable = (Process.platform === 'darwin') && ObjC && ObjC.available && ObjC.classes && typeof ObjC.classes.NSString !== 'undefined';

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
  const [v, t] = autoType(args.slice(2));
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

module.exports = {
  isObjC,
  ObjCAvailable,
  hasMainLoop,
  dxObjc,
  uiAlert
};
