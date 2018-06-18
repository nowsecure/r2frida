// run '\. plugin.js' inside an 'r2 frida://' session to load it
// run '\.-test' to unload it and '\.' to list hem all


function sym(mod, name, ret, arg) {
  const modules = Process.enumerateModulesSync().filter(function (m) { return m.name.indexOf(mod) !== -1; });
  if (modules.length === -1) {
    console.error('Cannot find symbol');
    return null;
  }
  for (var m in modules) {
    const symbols = Module.enumerateSymbolsSync(modules[m].name).filter(function (s) {
      return (s.name === name);
    });
    if (symbols.length !== 0) {
      return new NativeFunction(symbols[0].address, ret, arg);
    }
  }
  return null;
}

function showHelp() {
  return 'qemu Commands:\n'
  + 'qemu io    - make r2frida read/write gameboy memory\n'
  + 'qemu noio  - disable that hook and go back to process io\n'
}

// void cpu_physical_memory_rw(hwaddr addr, uint8_t *buf, int len, int is_write);
const cpuPhysicalMemoryRW = sym('qemu', 'cpu_physical_memory_rw',
  'void', ['uint64', 'pointer', 'int', 'int']);

if (cpuPhysicalMemoryRW === null) {
  console.error('Cannot find important symbol to make the qemu plugin work :(');
}

function hookedRead (offset, count) {
  var ptr = Memory.alloc(count);
  cpuPhysicalMemoryRW(offset, ptr, count, 0);
  var data = Memory.readByteArray(ptr, count);
  return [{}, data];
};

function hookedWrite (offset, data) {
  var count = data.byteLength;
  var ptr = Memory.alloc(count);
  Memory.writeByteArray(ptr, data);
  cpuPhysicalMemoryRW(offset, ptr, count, 1);
  return [{}, null];
};

r2frida.pluginRegister('qemu', function(name) {
  if (name === 'qemu') {
    return function(args) {
      if (args.length === 0) {
        return showHelp();
      }
      const command = args.shift();
      switch(command) {
      case 'io':
        r2frida.hookedRead = hookedRead;
        r2frida.hookedWrite = hookedWrite;
        return 'io is hooked now';
        break;
      case 'noio':
        r2frida.hookedRead = null;
        r2frida.hookedWrite = null;
        break;
      default:
        return showHelp();
        break;
      }
      return '';
    }
  }
});
