import config from "../../config.js";
import log from "../../log.js";
import Java from "frida-java-bridge";

export const JavaAvailable = Java && Java.available;

export function javaUse(name: string): Java.Wrapper | null {
    // XXX this is broken and needs to be rewritten
    /*
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
    */
    let res = null;
    try {
        res = Java.use(name);
    } catch (err) {
    }
    return res;
}

export function javaTraceExample(): void {
    javaPerform(function () {
        const System = Java.use("java.lang.System");
        System.loadLibrary.implementation = function (library: string) {
            try {
                log.traceEmit("System.loadLibrary " + library);
                const Runtime = Java.use("Java.lang.Runtime");
                const VMStack = Java.use("dalvik.lang.VMStack");
                const loaded = Runtime.getRuntime().loadLibrary0(
                    VMStack.getCallingClassLoader(),
                    library,
                );
                return loaded;
            } catch (e) {
                console.error(e);
            }
        };
    });
}

export function waitForJava(): void {
    javaPerform(function () {
        const ActivityThread = Java.use("android.app.ActivityThread");
        const app = ActivityThread.currentApplication();
        const ctx = app.getApplicationContext();
        console.log("Done: " + ctx);
    });
}

export function performOnJavaVM(fn: any): Promise<unknown> {
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
export function listJavaClassesJsonSync(args: string[]): string[] | null {
    if (args.length === 1) {
        let methods = null;
        /* list methods */
        javaPerform(function () {
            const obj = javaUse(args[0]);
            if (obj !== null) {
                methods = Object.getOwnPropertyNames(
                    Object.getPrototypeOf(obj),
                );
            }
            // methods = Object.keys(obj).map(x => x + ':' + obj[x] );
        });
        while (methods === null) {
            setTimeout(() => {/* wait here */}, 0);
        }
        return methods;
    }
    let classes = null;
    javaPerform(function () {
        try {
            classes = Java.enumerateLoadedClassesSync();
        } catch (e) {
            classes = null;
        }
    });
    return classes;
}

export function listJavaClassesJson(
    args: string[],
    classMethodsOnly?: boolean,
): string[] {
    let res: string[] = [];
    if (args.length === 1) {
        javaPerform(function () {
            try {
                const arg = args[0];
                const handle: Java.Wrapper | null = javaUse(arg);
                if (handle === null || handle.class === null) {
                    throw new Error("Cannot find a classloader for this class");
                }
                const klass: Java.Wrapper = handle.class;
                try {
                    if (classMethodsOnly) {
                        klass.getMethods()
                            .filter((x: any) =>
                                x.toString().indexOf(arg) !== -1
                            )
                            .map((_: any) => res.push(_.toString()));
                    } else {
                        klass.getMethods()
                            .map((_: any) => res.push(_.toString()));
                    }
                    klass.getFields()
                        .map((_: any) => res.push(_.toString()));
                    try {
                        klass.getConstructors()
                            .map((_: any) => res.push(_.toString()));
                    } catch (ignore: unknown) {
                    }
                } catch (e: any) {
                    console.error(e.message);
                    console.error(
                        Object.keys(klass),
                        JSON.stringify(klass),
                        klass,
                    );
                }
            } catch (e: any) {
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

export function javaPerform(fn: any): void {
    if (config.getBoolean("java.wait")) {
        return Java.perform(fn);
    }
    return Java.performNow(fn);
}

export function traceJava(klassName: string, method: string): void {
    javaPerform(function () {
        const Throwable = Java.use("java.lang.Throwable");
        const klass = javaUse(klassName);
        if (klass == null) {
            log.traceEmit("Didn't find class \"" + klassName + '"');
            return;
        }

        for (let i = 0; i < klass[method].overloads.length; i++) {
            klass[method].overloads[i].implementation = function () {
                // eslint-disable-next-line prefer-spread, prefer-rest-params
                const res = this[method].apply(this, arguments);
                const bt = config.getBoolean("hook.backtrace")
                    ? Throwable.$new().getStackTrace().map((_: any) =>
                        _.toString()
                    )
                    : [];
                const traceMessage = {
                    source: "dt",
                    klass: klassName,
                    method: method,
                    backtrace: bt,
                    timestamp: new Date(),
                    result: res,
                    // eslint-disable-next-line prefer-rest-params
                    values: arguments,
                };
                if (config.getString("hook.output") === "json") {
                    log.traceEmit(JSON.stringify(traceMessage));
                } else {
                    let msg =
                        `[JAVA TRACE][${traceMessage.timestamp}] ${klassName}:${method} - args: ${
                            // eslint-disable-next-line prefer-rest-params
                            JSON.stringify(
                                arguments,
                            )}. Return value: ${res.toString()}`;
                    if (config.getBoolean("hook.backtrace")) {
                        msg += ` backtrace: \n${
                            traceMessage.backtrace.toString().split(",").join(
                                "\nat ",
                            )
                        }\n`;
                    }
                    log.traceEmit(msg);
                }
                return res;
            };
        }
    });
}

export function parseTargetJavaExpression(target: string) {
    let klass = target.substring("java:".length);
    const lastDot = klass.lastIndexOf(".");
    if (lastDot !== -1) {
        const method = klass.substring(lastDot + 1);
        klass = klass.substring(0, lastDot);
        return [klass, method];
    }
    throw new Error("Error: Wrong java method syntax");
}

export function interceptRetJava(
    klass: string,
    method: string,
    value: any,
): void {
    javaPerform(function () {
        const targetClass = javaUse(klass);
        if (targetClass !== null) {
            targetClass[method].implementation = function (library: string) {
                const timestamp = new Date();
                if (config.getString("hook.output") === "json") {
                    const msg = JSON.stringify({
                        source: "java",
                        class: klass,
                        method,
                        returnValue: value,
                        timestamp,
                    });
                    log.traceEmit(msg);
                } else {
                    log.traceEmit(
                        `[JAVA TRACE][${timestamp}] Intercept return for ${klass}:${method} with ${value}`,
                    );
                }
                switch (value) {
                    case 0:
                        return false;
                    case 1:
                        return true;
                    case -1:
                        return -1; // TODO should throw an error?
                    case true:
                        return Java.use("java.lang.Boolean").$new(true);
                    case false:
                        return Java.use("java.lang.Boolean").$new(false);
                    case null:
                        return;
                }
                return value;
            };
        }
    });
}

export function interceptFunRetJava(
    className: string,
    methodName: string,
    value: any,
    paramTypes: string,
): void {
    javaPerform(function () {
        const targetClass = javaUse(className);
        if (targetClass !== null) {
            targetClass[methodName].overload(paramTypes).implementation =
                function (args: string[]) {
                    const timestamp = new Date();
                    if (config.getString("hook.output") === "json") {
                        const msg = JSON.stringify({
                            source: "java",
                            class: className,
                            methodName,
                            returnValue: value,
                            timestamp,
                        });
                        log.traceEmit(msg);
                    } else {
                        log.traceEmit(
                            `[JAVA TRACE][${timestamp}] Intercept return for ${className}:${methodName} with ${value}`,
                        );
                    }
                    this[methodName](args);
                    switch (value) {
                        case 0:
                            return false;
                        case 1:
                            return true;
                        case -1:
                            return -1; // TODO should throw an error?
                    }
                    return value;
                };
        }
    });
}

export function traceJavaConstructors(className: string): void {
    if (className === "") {
        console.error("className cannot be null");
        return;
    }
    javaPerform(function () {
        const foo = Java.use(className).$init.overloads;
        foo.forEach((over) => {
            over.implementation = function (args: string[]) {
                console.log(
                    "dt",
                    className,
                    "(",
                    _dumpJavaArguments(args),
                    ")",
                );
                if (config.getBoolean("hook.backtrace")) {
                    const Throwable = Java.use("java.lang.Throwable");
                    const bt = Throwable.$new().getStackTrace().map((_: any) =>
                        _.toString()
                    ).join("\n- ") + "\n";
                    console.log("-", bt);
                }
                return over.apply(this, args);
            };
        });
    });
}

function _dumpJavaArguments(args: string[]): string {
    let res = "";
    try {
        for (const arg of args) {
            try {
                res += arg.toString() + " ";
            } catch (ee) {
            }
        }
    } catch (e) {
    }
    return res;
}

export function getPackageName(): string {
    let result = "";
    javaPerform(function () {
        const ActivityThread = Java.use("android.app.ActivityThread");
        const application = ActivityThread.currentApplication();
        result = application.getPackageName();
    });
    return result;
}
