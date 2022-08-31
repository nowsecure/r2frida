'use strict';

const debug = require('./debug');
const globals = require('./globals');
const darwin = require('./darwin/index');
const swift = require('./darwin/swift');
const java = require('./java/index');
const sys = require('./sys');
const r2 = require('./r2').default;

async function dumpInfo () {
  const padding = (x) => ''.padStart(20 - x, ' ');
  const properties = await dumpInfoJson();
  return Object.keys(properties)
    .map(k => k + padding(k.length) + properties[k])
    .join('\n');
}

async function dumpInfoR2 () {
  const properties = await dumpInfoJson();
  const jnienv = properties.jniEnv !== undefined ? properties.jniEnv : '';
  return [
    'e asm.arch=' + properties.arch,
    'e asm.bits=' + properties.bits,
    'e asm.os=' + properties.os,
    'f r2f.modulebase=' + properties.modulebase,
  ].join('\n') + jnienv;
}

async function dumpInfoJson () {
  const res = {
    arch: r2.getR2Arch(Process.arch),
    bits: globals.pointerSize * 8,
    os: Process.platform,
    pid: sys.getPid(),
    uid: sys._getuid(),
    objc: darwin.ObjCAvailable,
    runtime: Script.runtime,
    swift: swift.SwiftAvailable(),
    java: java.JavaAvailable,
    mainLoop: darwin.hasMainLoop(),
    pageSize: Process.pageSize,
    pointerSize: Process.pointerSize,
    codeSigningPolicy: Process.codeSigningPolicy,
    isDebuggerAttached: Process.isDebuggerAttached(),
    cwd: sys.getCwd()
  };

  if (darwin.ObjCAvailable && !debug.suspended) {
    try {
      const mb = (ObjC && ObjC.classes && ObjC.classes.NSBundle) ? ObjC.classes.NSBundle.mainBundle() : '';
      const id = mb ? mb.infoDictionary() : '';
      function get (k) {
        const v = id ? id.objectForKey_(k) : '';
        return v ? v.toString() : '';
      }
      const NSHomeDirectory = new NativeFunction(
        Module.getExportByName(null, 'NSHomeDirectory'),
        'pointer', []);
      const NSTemporaryDirectory = new NativeFunction(
        Module.getExportByName(null, 'NSTemporaryDirectory'),
        'pointer', []);

      const bundleIdentifier = get('CFBundleIdentifier');
      if (bundleIdentifier) {
        res.bundle = bundleIdentifier;
        res.exename = get('CFBundleExecutable');
        res.appname = get('CFBundleDisplayName');
        res.appversion = get('CFBundleShortVersionString');
        res.appnumversion = get('CFBundleNumericVersion');
        res.minOS = get('MinimumOSVersion');
      }
      res.modulename = Process.enumerateModulesSync()[0].name;
      res.modulebase = Process.enumerateModulesSync()[0].base;
      res.homedir = (new ObjC.Object(NSHomeDirectory()).toString());
      res.tmpdir = (new ObjC.Object(NSTemporaryDirectory()).toString());
      res.bundledir = ObjC.classes.NSBundle.mainBundle().bundleURL().path();
    } catch (e) {
      console.error(e);
    }
  }
  if (java.JavaAvailable) {
    await performOnJavaVM(() => {
      const ActivityThread = Java.use('android.app.ActivityThread');
      const app = ActivityThread.currentApplication();
      if (app !== null) {
        const ctx = app.getApplicationContext();
        if (ctx !== null) {
          function tryTo (x) {
            let r = '';
            try {
              r = x();
            } catch (e) {
              // ignored
            }
            return r;
          }
          res.dataDir = tryTo(() => ctx.getDataDir().getAbsolutePath());
          res.codeCacheDir = tryTo(() => ctx.getCodeCacheDir().getAbsolutePath());
          res.extCacheDir = tryTo(() => ctx.getExternalCacheDir().getAbsolutePath());
          res.obbDir = tryTo(() => ctx.getObbDir().getAbsolutePath());
          res.filesDir = tryTo(() => ctx.getFilesDir().getAbsolutePath());
          res.noBackupDir = tryTo(() => ctx.getNoBackupFilesDir().getAbsolutePath());
          res.codePath = tryTo(() => ctx.getPackageCodePath());
          res.packageName = tryTo(() => ctx.getPackageName());
        }

        try {
          function getContext () {
            return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext().getContentResolver();
          }

          res.androidId = Java.use('android.provider.Settings$Secure').getString(getContext(), 'android_id');
        } catch (ignoredError) {
        }
      }
      res.cacheDir = Java.classFactory.cacheDir;
      const jniEnv = ptr(Java.vm.getEnv());
      if (jniEnv) {
        res.jniEnv = jniEnv.toString();
      }
    });
  }

  return res;
}

module.exports = {
  dumpInfo,
  dumpInfoR2,
  dumpInfoJson
};
