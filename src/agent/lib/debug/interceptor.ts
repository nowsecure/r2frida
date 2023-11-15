import config from '../../config.js';
import { parseTargetJavaExpression, interceptFunRetJava, interceptRetJava } from '../java/index.js';
import { getPtr } from '../utils.js';

function interceptHelp(args: string[]) : string {
    return "Usage: di[0,1,-1,s,v] [addr] : intercept function method and replace the return value.\n" +
        "di0 0x808080  # when program calls this address, the original function is not called, then return value is replaced.\n" +
        "div java:org.ex.class.method  # when program calls this address, the original function is not called and no value is returned.\n";
}

function interceptFunHelp(args: string[]): string {
    return "Usage: dif[0,1,-1,s] [addr] [str] [param_types]: intercepts function method, call it, and replace the return value.\n"+
        "dif0 0x808080  # when program calls this address, the original function is called, then return value is replaced.\n" +
        "dif0 java:com.example.MainActivity.method1 int,java.lang.String  # Only with JVM methods. You need to define param_types when overload a Java method.\n" +
        "dis 0x808080 str  #.\n";
}

export function interceptRetString(args: string[]) {
    const target = args[0];
    return _interceptRet(target, args[1]);
}

export function interceptRetFalse(args: string[]) {
    const target = args[0];
    return _interceptRet(target, false);
}

export function interceptRetTrue(args: string[]) {
    const target = args[0];
    return _interceptRet(target, true);
}

export function interceptRet0(args: string[]) {
    const target = args[0];
    return _interceptRet(target, 0);
}

export function interceptRet1(args: string[]) {
    const target = args[0];
    return _interceptRet(target, 1);
}

export function interceptRetInt(args: string[]) {
    const target = args[0];
    return _interceptRet(target, args[1]);
}

export function interceptRet_1(args: string[]) {
    const target = args[0];
    return _interceptRet(target, -1);
}

export function interceptRetVoid(args: string[]) {
    const target = args[0];
    return _interceptRet(target, null);
}

export function interceptFunRetString(args: string[]) {
    const target = args[0];
    const paramTypes = args[2];
    return _interceptFunRet(target, args[1], paramTypes);
}

export function interceptFunRet0(args: string[]) {
    const target = args[0];
    const paramTypes = args[1];
    return _interceptFunRet(target, 0, paramTypes);
}

export function interceptFunRet1(args: string[]) {
    const target = args[0];
    const paramTypes = args[1];
    return _interceptFunRet(target, 1, paramTypes);
}

export function interceptFunRetInt(args: string[]) {
    const target = args[0];
    const paramTypes = args[2];
    return _interceptFunRet(target, args[1], paramTypes);
}

export function interceptFunRet_1(args: string[]) {
    const target = args[0];
    const paramTypes = args[1];
    return _interceptFunRet(target, -1, paramTypes);
}

function _interceptRet(target: any, value: any) {
    if (target.startsWith('java:')) {
        try {
            const javaTarget = parseTargetJavaExpression(target);
            return interceptRetJava(javaTarget[0], javaTarget[1], value);
        } catch (e: any) {
            return e.message;
        }
    }
    const funcPtr = getPtr(target);
    const useCmd = config.getString('hook.usecmd');
    Interceptor.replace(funcPtr, new NativeCallback(function () {
        if (useCmd.length > 0) {
            console.log('[r2cmd]' + useCmd);
        }
        return ptr(value);
    }, 'pointer', ['pointer']));
}

function _interceptFunRet(target: string, value: string | number, paramTypes: string) {
    if (target.startsWith('java:')) {
        const javaTarget = parseTargetJavaExpression(target);
        return interceptFunRetJava(javaTarget[0], javaTarget[1], value, paramTypes);
    }
    const p = getPtr(target);
    Interceptor.attach(p, {
        onLeave(retval) {
            retval.replace(ptr(value));
        }
    });
}

export default {
    interceptHelp,
    interceptFunHelp,
    interceptRetString,
    interceptRetFalse,
    interceptRetTrue,
    interceptRet0,
    interceptRet1,
    interceptRetInt,
    interceptRet_1,
    interceptRetVoid,
    interceptFunRetString,
    interceptFunRet0,
    interceptFunRet1,
    interceptFunRetInt,
    interceptFunRet_1
};
