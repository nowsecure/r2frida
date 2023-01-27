import * as utils from './utils.js';

declare let global: any;

export function disasmCode(lenstr: number): string {
    const len = +lenstr || 32;
    return disasm(global.r2frida.offset, len);
}

// internal
export function disasm(addr: NativePointer, len: number, initialOldName?: string) {
    if (len < 1) {
        len = 32;
    }
    if (typeof addr === 'string') {
        try {
            const newaddr = Module.findExportByName(null, addr);
            if (newaddr === null) {
                throw new Error();
            }
            addr = newaddr;
        } catch (e) {
            addr = ptr(global.r2frida.offset);
        }
    }
    let oldName = initialOldName !== undefined ? initialOldName : null;
    let lastAt = null;
    let disco = '';
    for (let i = 0; i < len; i++) {
        const [op, next] = tolerantInstructionParse(addr);
        const vaddr = utils.padPointer(addr);
        if (op === null) {
            disco += `${vaddr}\tinvalid\n`;
            if (next === null) {
                break;
            }
            addr = next;
            continue;
        }
        const ds = DebugSymbol.fromAddress(addr!);
        let dsName = (ds.name === null || ds.name.indexOf('0x') === 0) ? '' : ds.name;
        let moduleName = ds.moduleName;
        if (!ds.moduleName) {
            moduleName = '';
        }
        if (!dsName) {
            dsName = '';
        }
        if ((moduleName || dsName) && dsName !== oldName) {
            disco += ';;; ' + (moduleName || dsName) + '\n';
            oldName = dsName;
        }
        let comment = '';
        const id = op.opStr.indexOf('#0x');
        if (id !== -1) {
            try {
                const at = op.opStr.substring(id + 1).split(' ')[0].split(',')[0].split(']')[0];
                if (op.opStr.indexOf(']') !== -1) {
                    try {
                        const p = ptr(lastAt).add(at).readPointer();
                        const str = p.readCString();
                        // console.log(';  str:', str);
                        disco += ';  str:' + str + '\n';
                    } catch (e) {
                        const str2 = ptr(at).readPointer().readCString();
                        // console.log(';  str2:', str2);
                        disco += ';  str2:' + str2 + '\n';
                        console.log(e);
                    }
                }
                lastAt = at;
                const di = DebugSymbol.fromAddress(ptr(at));
                if (di.name !== null) {
                    comment = '\t; ' + (di.moduleName || '') + ' ' + di.name;
                } else {
                    const op2 = Instruction.parse(ptr(at));
                    const id2 = op2.opStr.indexOf('#0x');
                    const at2 = op2.opStr.substring(id2 + 1).split(' ')[0].split(',')[0].split(']')[0];
                    const di2 = DebugSymbol.fromAddress(ptr(at2));
                    if (di2.name !== null) {
                        comment = '\t; -> ' + (di2.moduleName || '') + ' ' + di2.name;
                    }
                }
            } catch (e) {
                // console.log(e);
            }
        }
        // console.log([op.address, op.mnemonic, op.opStr, comment].join('\t'));
        disco += [utils.padPointer(op.address), op.mnemonic, op.opStr, comment].join('\t') + '\n';
        if (op.size < 1) {
            // break; // continue after invalid
            op.size = 1;
        }
        addr = addr!.add(op.size);
    }
    return disco;
}

export function tolerantInstructionParse(address: NativePointer): [any, any] {
    let instr = null;
    let cursor = address;
    try {
        instr = Instruction.parse(cursor);
        cursor = instr.next;
    } catch (e: any) {
        if (e.message !== 'invalid instruction' &&
            e.message !== `access violation accessing ${cursor}`) {
            throw e;
        }
        if (e.message.indexOf('access violation') !== -1) {
            // cannot access the memory
        } else {
            // console.log(`warning: error parsing instruction at ${cursor}`);
        }
        // skip invalid instructions
        switch (Process.arch) {
            case 'arm64':
                cursor = cursor.add(4);
                break;
            case 'arm':
                cursor = cursor.add(2);
                break;
            default:
                cursor = cursor.add(1);
                break;
        }
    }
    return [instr, cursor];
}

export default {
    disasm,
    disasmCode,
    tolerantInstructionParse
};
