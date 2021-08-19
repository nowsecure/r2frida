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
  + '# This plugin requires to be attached to "r2pm -ci gnuboy"\n'
  + 'gb io    - make r2frida read/write gameboy memory\n'
  + 'gb noio  - disable that hook and go back to process io\n'
  + '# CPU\n'
  + 'gb reset - clear screen\n'
  + 'gb cpu   - show contents of cpu struct\n'
  + 'gb stop  - stop execution\n'
  + 'gb step  - perform one step\n'
  + 'gb cont  - continue execution\n'
  + '# APU\n'
  + 'gb mute  - mute audio\n'
  + '# LCD\n'
  + 'gb cls   - clear screen\n'
}

const gnuboyRead = sym('mem_read', 'int', ['int']);
const gnuboyWrite = sym('mem_write', 'void', ['int', 'uint8']);

function hookedRead (offset, count) {
  var i = 0;
  var data = []; // new ArrayBuffer(count);
  for (i = 0; i < count; i++) {
    data[i] = gnuboyRead(offset + i);
  }
  return [{}, data];
};

function hookedWrite (offset, data) {
  var i = 0;
  var b = []; // new ArrayBuffer(data);
  for (i = 0; i < b.length; i++) {
    gnuboyWrite(offset + i, b[i]);
  }
  return [{}, null];
};

function showCpu() {
  const cpu_addr = Module.findExportByName(null, 'cpu');
  let r = '?e f cpu = ' + cpu_addr + '\n';
  r += 's '+cpu_addr+';pf wwwwwwxxxxxxxx pc sp bc de hl af ime ima speed halt div tim lcdc snd;s--\n'
  return r;
}

var cpu_emulate = sym('cpu_emulate', 'void', ['int']);
var cpu_emulate_orig = cpu_emulate;
var cpu_emulate_hooked = false;
var cpu_emulate_intercepted = false;
var usleep = sym('usleep', 'void', ['int']);


function cpu_emulate_callback(cycles) {
  if (cpu_emulate_hooked) {
    return
  }
  cpu_emulate(cycles);
}

function cpuStop() {
  if (cpu_emulate_hooked) {
    return;
  }
  if (cpu_emulate_intercepted) {
    cpuStop();
  } else {
    cpu_emulate_orig = sym('cpu_emulate', 'void', ['int']);
    const cb = new NativeCallback(cpu_emulate_callback, 'void', ['int']);
    Interceptor.replace(cpu_emulate, cb);
    cpu_emulate_intercepted = true;
  }
  cpu_emulate_hooked = true;
}

function cpuStep() {
  if (!cpu_emulate_intercepted) {
    cpuStop();
  }
  cpu_emulate_hooked = false;
  cpu_emulate(1);
  cpu_emulate_hooked = true;
}

function cpuCont() {
  cpu_emulate_hooked = false;
}

function soundOff() {
  const sound_reset = sym('sound_reset', 'void', []);
  if (sound_reset) {
    sound_reset();
  }
  const sound_write = sym('sound_write', 'void', []);
  const cb = new NativeCallback(function (cycles){}, 'void', ['int']);
  Interceptor.replace(sound_write, cb);
}

function cpuReset() {
  const cpu_reset = sym('cpu_reset', 'void', []);
  if (cpu_reset) {
    cpu_reset();
  }
}

function clearScreen() {
  const clear_screen = sym('lcd_reset', 'void', []);
  if (cpu_reset) {
    cpu_reset();
  }
}

r2frida.pluginUnregister('gb');

r2frida.pluginRegister('gb', function(name) {
  if (name === 'gb') {
    return function(args) {
      if (args.length === 0) {
        return showHelp();
      }
      const command = args.shift();
      switch(command) {
      case 'reset':
        cpuReset();
        break;
      case 'stop':
        cpuStop();
        break;
      case 'step':
        cpuStep();
        break;
      case 'mute':
        soundOff();
        break;
      case 'cont':
        cpuCont();
        break;
      case 'cls':
        clearScreen();
        break;
      case 'cpu':
        return showCpu();
        break;
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
