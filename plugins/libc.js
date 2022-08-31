// run ':. plugin.js' inside an 'r2 frida://' session to load it
// run ':.-test' to unload it and ':.' to list hem all


function sym(name, ret, arg) {
  try {
    return new NativeFunction(Module.findExportByName(null, name), ret, arg);
  } catch (e) {
    console.error(name, ':', e);
  }
}

var libcCommands = {
  'getuid': sym('getuid', 'int', []),
  'getgid': sym('getgid', 'int', []),
  'setuid': sym('setuid', 'int', ['int']),
  'setgid': sym('setgid', 'int', ['int']),
  'remove': sym('remove', 'int', ['pointer']),
  'system': sym('system', 'int', ['pointer'])
};

r2frida.pluginRegister('libc', function(name) {
  if (name === 'libc') {
    return function(args) {
      if (args.length === 0) {
        return Object.keys(libcCommands).join('\n');
      }
      const command = args.shift();
      for (var arg in args) {
        if (+args[arg] || args[arg] === '0') {
          args[arg] = +args[arg];
        } else if (args[arg].substring(0, 2) === '0x') {
          args[arg] = ptr(args[arg]);
        } else if (args[arg] === 'true' || args[arg] === 'false') {
          args[arg] = args[arg] === 'true';
        }
      }
      return libcCommands[command].apply(null, args);
    }
  }
});
