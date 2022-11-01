'use strict';

const config = require('../../config');
const java = require('../java');
const utils = require('../utils');

function interceptHelp (args) {
  return 'Usage: di[0,1,-1,s,v] [addr] : intercept function method and replace the return value.\n' /
  'di0 0x808080  # when program calls this address, the original function is not called, then return value is replaced.\n' /
  'div java:org.ex.class.method  # when program calls this address, the original function is not called and no value is returned.\n';
}

function interceptFunHelp (args) {
  return 'Usage: dif[0,1,-1,s] [addr] [str] [param_types]: intercepts function method, call it, and replace the return value.\n' /
  'dif0 0x808080  # when program calls this address, the original function is called, then return value is replaced.\n' /
  'dif0 java:com.example.MainActivity.method1 int,java.lang.String  # Only with JVM methods. You need to define param_types when overload a Java method.\n' /
  'dis 0x808080 str  #.\n';
}

function interceptRetString (args) {
  const target = args[0];
  return _interceptRet(target, args[1]);
}

function interceptRetFalse (args) {
  const target = args[0];
  return _interceptRet(target, false);
}

function interceptRetTrue (args) {
  const target = args[0];
  return _interceptRet(target, true);
}

function interceptRet0 (args) {
  const target = args[0];
  return _interceptRet(target, 0);
}

function interceptRet1 (args) {
  const target = args[0];
  return _interceptRet(target, 1);
}

function interceptRetInt (args) {
  const target = args[0];
  return _interceptRet(target, args[1]);
}

function interceptRet_1 (args) { // eslint-disable-line
  const target = args[0];
  return _interceptRet(target, -1);
}

function interceptRetVoid (args) { // eslint-disable-line
  const target = args[0];
  return _interceptRet(target, null);
}

function interceptFunRetString (args) {
  const target = args[0];
  const paramTypes = args[2];
  return _interceptFunRet(target, args[1], paramTypes);
}

function interceptFunRet0 (args) {
  const target = args[0];
  const paramTypes = args[1];
  return _interceptFunRet(target, 0, paramTypes);
}

function interceptFunRet1 (args) {
  const target = args[0];
  const paramTypes = args[1];
  return _interceptFunRet(target, 1, paramTypes);
}

function interceptFunRetInt (args) {
  const target = args[0];
  const paramTypes = args[2];
  return _interceptFunRet(target, args[1], paramTypes);
}

function interceptFunRet_1 (args) { // eslint-disable-line
  const target = args[0];
  const paramTypes = args[1];
  return _interceptFunRet(target, -1, paramTypes);
}

function _interceptRet (target, value) {
  if (target.startsWith('java:')) {
    try {
      const javaTarget = java.parseTargetJavaExpression(target, value);
      return java.interceptRetJava(javaTarget[0], javaTarget[1], value);
    } catch (e) {
      return e.message;
    }
  }
  const funcPtr = utils.getPtr(target);
  const useCmd = config.getString('hook.usecmd');
  Interceptor.replace(funcPtr, new NativeCallback(function () {
    if (useCmd.length > 0) {
      console.log('[r2cmd]' + useCmd);
    }
    return ptr(value);
  }, 'pointer', ['pointer']));
}

function _interceptFunRet (target, value, paramTypes) {
  if (target.startsWith('java:')) {
    const javaTarget = java.parseTargetJavaExpression(target, value);
    return java.interceptFunRetJava(javaTarget[0], javaTarget[1], value, paramTypes);
  }
  const p = utils.getPtr(target);
  Interceptor.attach(p, {
    onLeave (retval) {
      retval.replace(ptr(value));
    }
  });
}

module.exports = {
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
