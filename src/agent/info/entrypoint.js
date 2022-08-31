'use strict';

function listEntrypointJson (args) {
  function isEntrypoint (s) {
    if (s.type === 'section') {
      switch (s.name) {
        case '_start':
        case 'start':
        case 'main':
        return true;
      }
    }
    return false;
  }
  if (Process.platform === 'linux') {
    const at = DebugSymbol.fromName('main');
    if (at) {
      return [at];
    }
  }
  const firstModule = Process.enumerateModules()[0];
  return Module.enumerateSymbols(firstModule.name)
    .filter((symbol) => {
      return isEntrypoint(symbol);
    }).map((symbol) => {
      symbol.moduleName = getModuleByAddress(symbol.address).name;
      return symbol;
    });
}

function listEntrypointR2 (args) {
  let n = 0;
  return listEntrypointJson()
    .map((entry) => {
      return 'f entry' + (n++) + ' = ' + entry.address;
    }).join('\n');
}

function listEntrypointQuiet (args) {
  return listEntrypointJson()
    .map((entry) => {
      return entry.address;
    }).join('\n');
}

function listEntrypoint (args) {
  return listEntrypointJson()
    .map((entry) => {
      return entry.address + ' ' + entry.name + '  # ' + entry.moduleName;
    }).join('\n');
}

module.exports = {
  listEntrypointJson,
  listEntrypointR2,
  listEntrypointQuiet,
  listEntrypoint
};
