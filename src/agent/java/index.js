'use strict';

const log = require('./log');

const JavaAvailable = Java && Java.available;

function javaUse (name) {
  const initialLoader = Java.classFactory.loader;
  let res = null;
  javaPerform(function () {
    for (const kl of Java.enumerateClassLoadersSync()) {
      try {
        Java.classFactory.loader = kl;
        res = Java.use(name);
        break;
      } catch (e) {
        // do nothing
      }
    }
  });
  Java.classFactory.loader = initialLoader;
  return res;
}

function javaTraceExample () {
  javaPerform(function () {
    const System = Java.use('java.lang.System');
    System.loadLibrary.implementation = function (library) {
      try {
        log.traceEmit('System.loadLibrary ' + library);
        const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
        return loaded;
      } catch (e) {
        console.error(e);
      }
    };
  });
}

function waitForJava () {
  javaPerform(function () {
    const ActivityThread = Java.use('android.app.ActivityThread');
    const app = ActivityThread.currentApplication();
    const ctx = app.getApplicationContext();
    console.log('Done: ' + ctx);
  });
}

function performOnJavaVM (fn) {
  return new Promise((resolve, reject) => {
    javaPerform(function () {
      try {
        const result = fn();
        resolve(result);
      } catch (e) {
        reject(e);
      }
    });
  });
}

module.exports = {
  JavaAvailable,
  javaUse,
  javaTraceExample,
  performOnJavaVM,
  waitForJava
};
