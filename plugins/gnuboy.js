// run '\. plugin.js' inside an 'r2 frida://' session to load it
// run '\.-test' to unload it and '\.' to list hem all


function sym(name, ret, arg) {
  try {
    return new NativeFunction(Module.findExportByName(null, name), ret, arg);
  } catch (e) {
    console.error(name, ':', e);
  }
}

function showHelp() {
  return 'gnuboy Commands:\n'
  + 'gb io    - make r2frida read/write gameboy memory\n'
  + 'gb noio  - disable that hook and go back to process io\n'
}

const gnuboyRead = sym('mem_read', 'int', ['int']);
const gnuboyWrite = sym('mem_write', 'void', ['int', 'uint8']);

function hookedRead (offset, count) {
  var i = 0;
  var data = new Buffer(count);
  for (i = 0; i < count; i++) {
    data[i] = gnuboyRead(offset + i);
  }
  return [{}, data];
};

function hookedWrite (offset, data) {
  var i = 0;
  var b = new Buffer(data);
  for (i = 0; i < b.length; i++) {
    gnuboyWrite(offset + i, b[i]);
  }
  return [{}, null];
};

r2frida.pluginRegister('gb', function(name) {
  if (name === 'gb') {
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
