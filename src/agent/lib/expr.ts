import r2 from './r2.js';

export async function numEval(expr: string): Promise<NativePointer> {
    return new Promise((resolve, reject) => {
        const symbol = DebugSymbol.fromName(expr);
        if (symbol && symbol.name) {
            return resolve(symbol.address);
        }
        r2.hostCmd('?v ' + expr).then((_: any) => resolve(_.trim())).catch(reject);
    });
}

export function evalNum(args: string[]) {
    return new Promise((resolve, reject) => {
        numEval(args.join(' ')).then(res => {
            resolve(res);
        });
    });
}

export function evalCode(args: string[]) {
    const code = args.join(' ');
    const result = eval(code); // eslint-disable-line
    return (result !== undefined) ? result : '';
}

export default {
    numEval,
    evalNum,
    evalCode
};
