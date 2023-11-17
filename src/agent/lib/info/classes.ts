import { ObjCAvailable } from '../darwin/index.js';
import { JavaAvailable, listJavaClassesJson } from '../java/index.js';
import {searchInstancesJson} from '../search.js';
import {padPointer} from '../utils.js';

export function listClassesLoadedJson(args: string[]) {
    if (JavaAvailable) {
        return listJavaClassesJson(args);
    }
    if (ObjCAvailable) {
        return JSON.stringify(ObjC.enumerateLoadedClassesSync());
    }
}

export function listClassesLoaders(args: string[]) {
    if (!JavaAvailable) {
        return 'Error: icL is only available on Android targets.';
    }
    let res = '';
    Java.perform(function () {
        function s2o(s: any) {
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

export function listClassesLoaded(args: string[]) {
    if (JavaAvailable) {
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
export function listAllClassesNatives(args: string[]) {
    return listClassesNatives(['.']);
}

export function listClassesNatives(args: string[]) {
    const natives: any[] = [];
    const vkn = args[0] || 'com';
    Java.perform(function () {
        const klasses = listClassesJson();
        for (let kn of klasses) {
            kn = kn.toString();
            // if (kn.indexOf('android') !== -1) { continue; }
            if (kn.indexOf(vkn) === -1) {
                continue;
            }
            try {
                const handle : any = Java.use(kn);
                const klass = handle.class;
                const klassNatives = klass.getMethods().map((_: any) => _.toString()).filter((_: any) => _.indexOf('static native') !== -1);
                if (klassNatives.length > 0) {
                    const kns = klassNatives.map((n: any) => {
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

export function listClassesAllMethods(args: string[]) {
    return listClassesJson(args, 'all').join('\n');
}

export function listClassSuperMethods(args: string[]) {
    return listClassesJson(args, 'super').join('\n');
}

export function listClassVariables(args: string[]) {
    return listClassesJson(args, 'ivars').join('\n');
}

export function listClassesHooks(args: string[], mode: string) {
    if (!ObjCAvailable) {
        return 'ich only available on Objective-C environments.';
    }
    if (args.length === 0) {
        return 'Usage: :ich [className|moduleName]';
    }
    const moduleNames : any = {};
    const result = listClassesJson([]);
    if (ObjCAvailable) {
        for (const k of result) {
            moduleNames[k] = ObjC.classes[k].$moduleName;
        }
    }
    let out = '';
    for (const klassname of result) {
        const modName = moduleNames[klassname];
        if (klassname.indexOf(args[0]) !== -1 || (modName && modName.indexOf(args[0]) !== -1)) {
            const klass = ObjC.classes[klassname];
            if (klass) {
                for (const methodName of klass.$ownMethods) {
                    // TODO: use instance.argumentTypes to generate the 'OOO'
                    const normalizeMethodName = _normalizeToFridaMethod(methodName);
                    const method = klass[methodName];
                    if (method !== undefined) {
                        let format = '';
                        for (const arg of method.argumentTypes) {
                            switch (arg) {
                                case 'pointer': // We return an hex pointer until a good type information is exposed by frida-objc-bridge
                                    format += 'x';
                                    break;
                                case 'uint64':
                                    format += 'i';
                                    break;
                                case 'bool': // TODO: Implement bool formatting at dtf
                                    format += 'i';
                                    break;
                                default:
                                    format += 'x';
                                    break;
                            }
                        }
                        out += `:dtf objc:${klassname}.^${normalizeMethodName}$ ${format}\n`;
                    }
                }
            }
        }
    }
    return out;
}

function _normalizeToFridaMethod(methodName: string): string {
    return methodName.replace('- ', '').replace('+ ', '');
}

export function listClassesWhere(args: string[], mode: string) {
    let out = '';
    const moduleNames : any = {};
    if (args.length === 0) {
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
    } else {
        const result = listClassesJson([]);
        if (ObjCAvailable) {
            const klasses = ObjC.classes;
            for (const k of result) {
                moduleNames[k] = ObjC.classes[k].$moduleName;
            }
        }
        for (const k of result) {
            const modName = moduleNames[k];
            if (modName && modName.indexOf(args[0]) !== -1) {
                const ins = searchInstancesJson([k]);
                const inss = ins.map((x: any) => { return x.address; }).join(' ');
                out += k + ' # ' + inss + '\n';
                if (mode === 'ivars') {
                    for (const a of ins) {
                        out += 'instance ' + padPointer(a.address) + '\n';
                        const i = new ObjC.Object(a.address);
                        out += (JSON.stringify(i.$ivars)) + '\n';
                    }
                }
            }
        }
    }
       return out;
}

export function listClasses(args : string[]) {
    const result = listClassesJson(args);
    if (result instanceof Array) {
        return result.join('\n');
    }
    return Object.keys(result)
        .map(methodName => {
            const address = result[methodName];
            return [padPointer(address), methodName].join(' ');
        })
        .join('\n');
}

export function listClassesR2(args: string[]) {
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
    const result : any = listClassesJson(args);
    return Object.keys(result)
        .map((methodName: string) => {
            const address = result[methodName];
            return ['f', flagName(methodName), '=', padPointer(address)].join(' ');
        })
        .join('\n') + '\n';
    function flagName(m: string) {
        return 'sym.objc.' +
            (className + '.' + m)
                .replace(':', '')
                .replace(' ', '')
                .replace('-', '')
                .replace('+', '');
    }
}

export function listClassMethods(args: string[]) {
    return listClassesJson(args, 'methods').join('\n');
}

export function listClassMethodsJson(args: string[]) {
    return listClassesJson(args, 'methods');
}

export function listClassesJson(args?: string[], mode?: string): any[] {
    if (args === undefined) {
        args = [];
    }
    if (mode === undefined) {
        mode = "";
    }
    if (JavaAvailable) {
        return listJavaClassesJson(args, mode === 'methods');
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
        const ins = searchInstancesJson([klassName]);
        out += klassName + ': ';
        for (const i of ins) {
            out += 'instance ' + padPointer(i.address) + ': ';
            const ii = new ObjC.Object(i.address);
            out += JSON.stringify(ii.$ivars, null, '  ');
        }
        return [out];
    }
    const methods: any[] = (mode === 'methods')
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

export function listProtocols(args: string[]) {
    return listProtocolsJson(args)
        .join('\n');
}

export function listProtocolsJson(args: string[]) {
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

function _classGlob(k: string, v: string) {
    if (!k || !v) {
        return true;
    }
    return k.indexOf(v.replace(/\*/g, '')) !== -1;
}

/*
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
*/