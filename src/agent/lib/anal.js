'use strict';

const classes = require('./info/classes');
const darwin = require('./darwin');
const classes = require('./info/classes');
const darwin = require('./darwin');

function analFunctionSignature (args) {
  if (!darwin.ObjCAvailable) {
    return 'Error: afs is only implemented for ObjC methods.';
  }
  if (args.length === 0) {
    return 'Usage: afs [class] [method]';
  }
  if (args.length === 1) {
    return classes.listClasses(args);
  }
  if (args.length > 1) {
    const klassName = args[0];
    const methodName = args[1].replace(/:/g, '_');
    const klass = ObjC.classes[klassName];
    if (!klass) {
      // try to resolve from DebugSymbol
      const at = klassName.startsWith('0x') ? DebugSymbol.fromAddress(ptr(klassName)) : DebugSymbol.fromName(klassName);
      if (at) {
        return JSON.stringify(at);
      }
      return 'Cannot find class named ' + klassName;
    }
    // const instance = ObjC.chooseSync(ObjC.classes[klassName])[0];
    const instance = ObjC.chooseSync(klass)[0];
    if (!instance) {
      return 'Cannot find any instance for ' + klassName;
    }
    const method = instance[methodName];
    if (!method) {
      return 'Cannot find method ' + methodName + ' for class ' + klassName;
    }
    return method.returnType + ' (' + method.argumentTypes.join(', ') + ');';
  }
  return 'Usage: afs [klassName] [methodName]';
}

module.exports = {
  analFunctionSignature
};
