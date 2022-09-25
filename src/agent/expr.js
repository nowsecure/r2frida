'use strict';

const r2 = require('./r2');

function numEval (expr) {
  return new Promise((resolve, reject) => {
    const symbol = DebugSymbol.fromName(expr);
    if (symbol && symbol.name) {
      return resolve(symbol.address);
    }
    r2.hostCmd('?v ' + expr).then(_ => resolve(_.trim())).catch(reject);
  });
}

function evalNum (args) {
  return new Promise((resolve, reject) => {
    numEval(args.join(' ')).then(res => {
      resolve(res);
    });
  });
}

module.exports = {
  numEval,
  evalNum
};
