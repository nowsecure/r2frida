import r2 from "./r2.js";

export function numEval(expr) {
    return new Promise((resolve, reject) => {
        const symbol = DebugSymbol.fromName(expr);
        if (symbol && symbol.name) {
            return resolve(symbol.address);
        }
        r2.hostCmd('?v ' + expr).then(_ => resolve(_.trim())).catch(reject);
    });
}
export function evalNum(args) {
    return new Promise((resolve, reject) => {
        numEval(args.join(' ')).then(res => {
            resolve(res);
        });
    });
}
export function evalCode(args) {
    const code = args.join(' ');
    const result = eval(code); // eslint-disable-line
    return (result !== undefined) ? result : '';
}
export default {
	numEval
		,evalNum,
		evalCode
};
