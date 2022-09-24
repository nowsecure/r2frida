'use strict';

const config = require('./config');
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

/* this ugly sync method with while+settimeout is needed because
  returning a promise is not properly handled yet and makes r2
  lose track of the output of the command so you cant grep on it */
function listJavaClassesJsonSync (args) {
  if (args.length === 1) {
    let methods;
    /* list methods */
    javaPerform(function () {
      const obj = javaUse(args[0]);
      methods = Object.getOwnPropertyNames(Object.getPrototypeOf(obj));
      // methods = Object.keys(obj).map(x => x + ':' + obj[x] );
    });
    // eslint-disable-next-line
    while (methods === undefined) {
      /* wait here */
      setTimeout(null, 0);
    }
    return methods;
  }
  let classes;
  javaPerform(function () {
    try {
      classes = Java.enumerateLoadedClassesSync();
    } catch (e) {
      classes = null;
    }
  });
  return classes;
}

// eslint-disable-next-line
function listJavaClassesJson (args, classMethodsOnly) {
  let res = [];
  if (args.length === 1) {
    javaPerform(function () {
      try {
        const arg = args[0];
        const handle = javaUse(arg);
        if (handle === null || !handle.class) {
          throw new Error('Cannot find a classloader for this class');
        }
        const klass = handle.class;
        try {
          if (classMethodsOnly) {
            klass.getMethods().filter(x => x.toString().indexOf(arg) !== -1).map(_ => res.push(_.toString()));
          } else {
            klass.getMethods().map(_ => res.push(_.toString()));
          }
          klass.getFields().map(_ => res.push(_.toString()));
          try {
            klass.getConstructors().map(_ => res.push(_.toString()));
          } catch (ignore) {
          }
        } catch (e) {
          console.error(e.message);
          console.error(Object.keys(klass), JSON.stringify(klass), klass);
        }
      } catch (e) {
        console.error(e.message);
      }
    });
  } else {
    javaPerform(function () {
      try {
        res = Java.enumerateLoadedClassesSync();
      } catch (e) {
        console.error(e);
      }
    });
  }
  return res;
}

function javaPerform (fn) {
  if (config.getBoolean('java.wait')) {
    return Java.perform(fn);
  }
  return Java.performNow(fn);
}

module.exports = {
  JavaAvailable,
  javaUse,
  javaTraceExample,
  performOnJavaVM,
  waitForJava,
  listJavaClassesJson,
  listJavaClassesJsonSync,
  javaPerform
};
