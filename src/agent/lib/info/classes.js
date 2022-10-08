import { ObjCAvailable } from '../darwin/index.js';
import java from '../java/index.js';
import search from '../search.js';
import utils from '../utils.js';
export function listClassesLoadedJson (args) {
  if (java.JavaAvailable) {
    return java.listClasses(args);
  }
  if (ObjCAvailable) {
    return JSON.stringify(ObjC.enumerateLoadedClassesSync());
  }
}
export function listClassesLoaders (args) {
  if (!java.JavaAvailable) {
    return 'Error: icL is only available on Android targets.';
  }
  let res = '';
  javaPerform(function () {
    function s2o (s) {
      let indent = 0;
      let res = '';
      for (const ch of s.toString()) {
        switch (ch) {
          case '[':
            indent++;
            res += '[\n' + Array(indent + 1).join(' ');
            break;
          case ']':
            indent--;
            res += ']\n' + Array(indent + 1).join(' ');
            break;
          case ',':
            res += ',\n' + Array(indent + 1).join(' ');
            break;
          default:
            res += ch;
            break;
        }
      }
      return res;
    }
    const c = Java.enumerateClassLoadersSync();
    for (const cl in c) {
      const cs = s2o(c[cl].toString());
      res += cs;
    }
  });
  return res;
}
export function listClassesLoaded (args) {
  if (java.JavaAvailable) {
    return listClasses(args);
  }
  if (ObjCAvailable) {
    const results = ObjC.enumerateLoadedClassesSync();
    const loadedClasses = [];
    for (const module of Object.keys(results)) {
      loadedClasses.push(...results[module]);
    }
    return loadedClasses.join('\n');
  }
  return [];
}
// only for java
export function listAllClassesNatives (args) {
  return listClassesNatives(['.']);
}
export function listClassesNatives (args) {
  const natives = [];
  const vkn = args[0] || 'com';
  javaPerform(function () {
    const klasses = listClassesJson([]);
    for (let kn of klasses) {
      kn = kn.toString();
      // if (kn.indexOf('android') !== -1) { continue; }
      if (kn.indexOf(vkn) === -1) {
        continue;
      }
      try {
        const handle = java.javaUse(kn);
        const klass = handle.class;
        const klassNatives = klass.getMethods().map(_ => _.toString()).filter(_ => _.indexOf('static native') !== -1);
        if (klassNatives.length > 0) {
          const kns = klassNatives.map((n) => {
            const p = n.indexOf('(');
            let sn = '';
            if (p !== -1) {
              const s = n.substring(0, p);
              const w = s.split(' ');
              sn = w[w.length - 1];
              return sn;
            }
            return n; // { name: sn, fullname: n };
          });
          console.error(kns.join('\n'));
          for (const tkn of kns) {
            if (natives.indexOf(tkn) === -1) {
              natives.push(tkn);
            }
          }
        }
      } catch (ignoreError) {
      }
    }
  });
  return natives;
}
export function listClassesAllMethods (args) {
  return listClassesJson(args, 'all').join('\n');
}
export function listClassSuperMethods (args) {
  return listClassesJson(args, 'super').join('\n');
}
export function listClassVariables (args) {
  return listClassesJson(args, 'ivars').join('\n');
}
export function listClassesHooks (args, mode) {
  let out = '';
  if (args.length === 0) {
    return 'Usage: :ich [kw]';
  }
  const moduleNames = {};
  const result = listClassesJson([]);
  if (ObjCAvailable) {
    const klasses = ObjC.classes;
    for (const k of result) {
      moduleNames[k] = klasses[k].$moduleName;
    }
  }
  for (const k of result) {
    const modName = moduleNames[k];
    if (k.indexOf(args[0]) !== -1 || (modName && modName.indexOf(args[0]) !== -1)) {
      // const ins = search.searchInstancesJson([k]);
      // const inss = ins.map((x) => { return x.address; }).join(' ');
      const a = 'OOO';
      const klass = ObjC.classes[k];
      if (klass) {
        for (const m of klass.$ownMethods) {
          // TODO: use instance.argumentTypes to generate the 'OOO'
          out += ':dtf objc:' + k + '.' + m + ' ' + a + '\n';
        }
      }
    }
  }
  return out;
}
export function listClassesWhere (args, mode) {
  let out = '';
  if (args.length === 0) {
    const moduleNames = {};
    const result = listClassesJson([]);
    if (ObjCAvailable) {
      const klasses = ObjC.classes;
      for (const k of result) {
        moduleNames[k] = klasses[k].$moduleName;
      }
    }
    for (const klass of result) {
      const modName = moduleNames[klass];
      out += [modName, klass].join(' ') + '\n';
    }
    return out;
  } else {
    const moduleNames = {};
    const result = listClassesJson([]);
    if (ObjCAvailable) {
      const klasses = ObjC.classes;
      for (const k of result) {
        moduleNames[k] = klasses[k].$moduleName;
      }
    }
    for (const k of result) {
      const modName = moduleNames[k];
      if (modName && modName.indexOf(args[0]) !== -1) {
        const ins = search.searchInstancesJson([k]);
        const inss = ins.map((x) => { return x.address; }).join(' ');
        out += k + ' # ' + inss + '\n';
        if (mode === 'ivars') {
          for (const a of ins) {
            out += 'instance ' + utils.padPointer(a.address) + '\n';
            const i = new ObjC.Object(ptr(a.address));
            out += (JSON.stringify(i.$ivars)) + '\n';
          }
        }
      }
    }
    return out;
  }
}
export function listClasses (args) {
  const result = listClassesJson(args);
  if (result instanceof Array) {
    return result.join('\n');
  }
  return Object.keys(result)
    .map(methodName => {
      const address = result[methodName];
      return [utils.padPointer(address), methodName].join(' ');
    })
    .join('\n');
}
export function listClassesR2 (args) {
  const className = args[0];
  if (args.length === 0 || args[0].indexOf('*') !== -1) {
    let methods = '';
    if (ObjCAvailable) {
      for (const cn of Object.keys(ObjC.classes)) {
        if (_classGlob(cn, args[0])) {
          methods += listClassesR2([cn]);
        }
      }
    }
    return methods;
  }
  const result = listClassesJson(args);
  return Object.keys(result)
    .map(methodName => {
      const address = result[methodName];
      return ['f', flagName(methodName), '=', utils.padPointer(address)].join(' ');
    })
    .join('\n') + '\n';
  function flagName (m) {
    return 'sym.objc.' +
            (className + '.' + m)
              .replace(':', '')
              .replace(' ', '')
              .replace('-', '')
              .replace('+', '');
  }
}
export function listClassMethods (args) {
  return listClassesJson(args, 'methods').join('\n');
}
export function listClassMethodsJson (args) {
  return listClassesJson(args, 'methods');
}
export function listClassesJson (args, mode) {
  if (java.JavaAvailable) {
    return java.listJavaClassesJson(args, mode === 'methods');
  }
  if (!ObjCAvailable) {
    return [];
  }
  if (args.length === 0) {
    return Object.keys(ObjC.classes);
  }
  const klassName = args[0];
  const klass = ObjC.classes[klassName];
  if (klass === undefined) {
    throw new Error('Class ' + klassName + ' not found');
  }
  let out = '';
  if (mode === 'ivars') {
    const ins = search.searchInstancesJson([klassName]);
    out += klassName + ': ';
    for (const i of ins) {
      out += 'instance ' + utils.padPointer(ptr(i.address)) + ': ';
      const ii = new ObjC.Object(ptr(i.address));
      out += JSON.stringify(ii.$ivars, null, '  ');
    }
    return [out];
  }
  const methods = (mode === 'methods')
    ? klass.$ownMethods
    : (mode === 'super')
        ? klass.$super.$ownMethods
        : (mode === 'all')
            ? klass.$methods
            : klass.$ownMethods;
  const getImpl = ObjC.api.method_getImplementation;
  try {
    return methods
      .reduce((result, methodName) => {
        try {
          result[methodName] = getImpl(klass[methodName].handle);
        } catch (e) {
          console.error(e, ' in \'' + methodName + '\' of ' + klassName);
        }
        return result;
      }, {});
  } catch (e) {
    return methods;
  }
}
export function listProtocols (args) {
  return listProtocolsJson(args)
    .join('\n');
}
export function listProtocolsJson (args) {
  if (!ObjCAvailable) {
    return [];
  }
  if (args.length === 0) {
    return Object.keys(ObjC.protocols);
  } else {
    const protocol = ObjC.protocols[args[0]];
    if (protocol === undefined) {
      throw new Error('Protocol not found');
    }
    return Object.keys(protocol.methods);
  }
}
function _classGlob (k, v) {
  if (!k || !v) {
    return true;
  }
  return k.indexOf(v.replace(/\*/g, '')) !== -1;
}

export default {
  listClassesLoadedJson,
  listClassesLoaders,
  listClassesLoaded,
  listAllClassesNatives,
  listClassesNatives,
  listClassesAllMethods,
  listClassSuperMethods,
  listClassVariables,
  listClassesHooks,
  listClassesWhere,
  listClasses,
  listClassesR2,
  listClassMethods,
  listClassMethodsJson,
  listClassesJson,
  listProtocols,
  listProtocolsJson
};
