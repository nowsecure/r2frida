import config from "../../config.js";
import log from "../../log.js";
'use strict';
const JavaAvailable = Java && Java.available;
function javaUse(name) {
    const initialLoader = Java.classFactory.loader;
    let res = null;
    javaPerform(function () {
        for (const kl of Java.enumerateClassLoadersSync()) {
            try {
                Java.classFactory.loader = kl;
                res = Java.use(name);
                break;
            }
            catch (e) {
                // do nothing
            }
        }
    });
    Java.classFactory.loader = initialLoader;
    return res;
}
function javaTraceExample() {
    javaPerform(function () {
        const System = Java.use('java.lang.System');
        System.loadLibrary.implementation = function (library) {
            try {
                log.traceEmit('System.loadLibrary ' + library);
                const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
                return loaded;
            }
            catch (e) {
                console.error(e);
            }
        };
    });
}
function waitForJava() {
    javaPerform(function () {
        const ActivityThread = Java.use('android.app.ActivityThread');
        const app = ActivityThread.currentApplication();
        const ctx = app.getApplicationContext();
        console.log('Done: ' + ctx);
    });
}
function performOnJavaVM(fn) {
    return new Promise((resolve, reject) => {
        javaPerform(function () {
            try {
                const result = fn();
                resolve(result);
            }
            catch (e) {
                reject(e);
            }
        });
    });
}
/* this ugly sync method with while+settimeout is needed because
  returning a promise is not properly handled yet and makes r2
  lose track of the output of the command so you cant grep on it */
function listJavaClassesJsonSync(args) {
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
        }
        catch (e) {
            classes = null;
        }
    });
    return classes;
}
// eslint-disable-next-line
function listJavaClassesJson(args, classMethodsOnly) {
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
                    }
                    else {
                        klass.getMethods().map(_ => res.push(_.toString()));
                    }
                    klass.getFields().map(_ => res.push(_.toString()));
                    try {
                        klass.getConstructors().map(_ => res.push(_.toString()));
                    }
                    catch (ignore) {
                    }
                }
                catch (e) {
                    console.error(e.message);
                    console.error(Object.keys(klass), JSON.stringify(klass), klass);
                }
            }
            catch (e) {
                console.error(e.message);
            }
        });
    }
    else {
        javaPerform(function () {
            try {
                res = Java.enumerateLoadedClassesSync();
            }
            catch (e) {
                console.error(e);
            }
        });
    }
    return res;
}
function javaPerform(fn) {
    if (config.getBoolean('java.wait')) {
        return Java.perform(fn);
    }
    return Java.performNow(fn);
}
function traceJava(klass, method) {
    javaPerform(function () {
        const Throwable = Java.use('java.lang.Throwable');
        const k = javaUse(klass);
        k[method].implementation = function (args) {
            const res = this[method]();
            const bt = config.getBoolean('hook.backtrace')
                ? Throwable.$new().getStackTrace().map(_ => _.toString())
                : [];
            const traceMessage = {
                source: 'dt',
                klass: klass,
                method: method,
                backtrace: bt,
                timestamp: new Date(),
                result: res,
                values: args
            };
            if (config.getString('hook.output') === 'json') {
                log.traceEmit(traceMessage);
            }
            else {
                let msg = `[JAVA TRACE][${traceMessage.timestamp}] ${klass}:${method} - args: ${JSON.stringify(args)}. Return value: ${res.toString()}`;
                if (config.getBoolean('hook.backtrace')) {
                    msg += ` backtrace: \n${traceMessage.backtrace.toString().split(',').join('\nat ')}\n`;
                }
                log.traceEmit(msg);
            }
            return res;
        };
    });
}
function parseTargetJavaExpression(target) {
    let klass = target.substring('java:'.length);
    const lastDot = klass.lastIndexOf('.');
    if (lastDot !== -1) {
        const method = klass.substring(lastDot + 1);
        klass = klass.substring(0, lastDot);
        return [klass, method];
    }
    throw new Error('Error: Wrong java method syntax');
}
function interceptRetJava(klass, method, value) {
    javaPerform(function () {
        const targetClass = javaUse(klass);
        targetClass[method].implementation = function (library) {
            const timestamp = new Date();
            if (config.getString('hook.output') === 'json') {
                log.traceEmit({
                    source: 'java',
                    class: klass,
                    method,
                    returnValue: value,
                    timestamp
                });
            }
            else {
                log.traceEmit(`[JAVA TRACE][${timestamp}] Intercept return for ${klass}:${method} with ${value}`);
            }
            switch (value) {
                case 0: return false;
                case 1: return true;
                case -1: return -1; // TODO should throw an error?
                case true: return Java.use("java.lang.Boolean").$new(true);
                case false: return Java.use("java.lang.Boolean").$new(false);
                case null: return;
            }
            return value;
        };
    });
}
function interceptFunRetJava(className, methodName, value, paramTypes) {
    javaPerform(function () {
        const targetClass = javaUse(className);
        targetClass[methodName].overload(paramTypes).implementation = function (args) {
            const timestamp = new Date();
            if (config.getString('hook.output') === 'json') {
                log.traceEmit({
                    source: 'java',
                    class: className,
                    methodName,
                    returnValue: value,
                    timestamp
                });
            }
            else {
                log.traceEmit(`[JAVA TRACE][${timestamp}] Intercept return for ${className}:${methodName} with ${value}`);
            }
            this[methodName](args);
            switch (value) {
                case 0: return false;
                case 1: return true;
                case -1: return -1; // TODO should throw an error?
            }
            return value;
        };
    });
}
function traceJavaConstructors(className) {
    javaPerform(function () {
        const foo = Java.use(className).$init.overloads;
        foo.forEach((over) => {
            over.implementation = function () {
                console.log('dt', className, '(', _dumpJavaArguments(arguments), ')');
                if (config.getBoolean('hook.backtrace')) {
                    const Throwable = Java.use('java.lang.Throwable');
                    const bt = Throwable.$new().getStackTrace().map(_ => _.toString()).join('\n- ') + '\n';
                    console.log('-', bt);
                }
                return over.apply(this, arguments);
            };
        });
    });
}
function _dumpJavaArguments(args) {
    let res = '';
    try {
        for (const a of args) {
            try {
                res += a.toString() + ' ';
            }
            catch (ee) {
            }
        }
    }
    catch (e) {
    }
    return res;
}
export { JavaAvailable };
export { javaUse };
export { javaTraceExample };
export { performOnJavaVM };
export { waitForJava };
export { listJavaClassesJson };
export { listJavaClassesJsonSync };
export { javaPerform };
export { traceJava };
export { parseTargetJavaExpression };
export { interceptRetJava };
export { interceptFunRetJava };
export { traceJavaConstructors };
export default {
    JavaAvailable,
    javaUse,
    javaTraceExample,
    performOnJavaVM,
    waitForJava,
    listJavaClassesJson,
    listJavaClassesJsonSync,
    javaPerform,
    traceJava,
    parseTargetJavaExpression,
    interceptRetJava,
    interceptFunRetJava,
    traceJavaConstructors
};
