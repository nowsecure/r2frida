import { listClasses } from './info/classes.js';
import { ObjCAvailable } from './darwin/index.js';
import ObjC from 'frida-objc-bridge';

enum METHOD_TYPE {
    CLASS,
    INSTANCE
}


export function analFunctionSignature(args: string[]) : string {

    if (!ObjCAvailable) {
        return 'Error: afs is only implemented for ObjC methods.';
    }
    if (args.length !== 1) {
        return 'Usage: afs [class].[+/-][method] (p.e. :afs ViewController.-isJailbroken)';
    }

    let [klassName, methodName] = args[0].split(".");
    if (methodName === undefined || methodName === "") {
        return listClasses(args);
    }

    const methodType = methodName[0] === "+" ? METHOD_TYPE.CLASS : METHOD_TYPE.INSTANCE;
    if (methodName[0].indexOf("+") === 0 || methodName[0].indexOf("-") === 0) {
        methodName = methodName.substring(1);
    }

    const klass = ObjC.classes[klassName];
    if (!klass) {
        // try to resolve from DebugSymbol
        const at = klassName.startsWith("0x") ? DebugSymbol.fromAddress(ptr(klassName)) : DebugSymbol.fromName(klassName);
        if (at) {
            return JSON.stringify(at);
        }
        return 'Cannot find class named ' + klassName;
    }

    let method = undefined;
    if (methodType === METHOD_TYPE.CLASS) {
        methodName = `+ ${methodName}`;
        method = klass[methodName];
    } else {
        const instance = ObjC.chooseSync(klass)[0];
        if (!instance) {
            return 'Cannot find any instance for ' + klassName;
        }
        methodName = `- ${methodName}`;
        method = instance[methodName];
    }
    if (!method) {
        return 'Cannot find method ' + methodName + ' for class ' + klassName;
    }
    return method.returnType + ' (' + method.argumentTypes.join(', ') + ');';
}
