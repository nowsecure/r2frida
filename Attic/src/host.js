/* entrypoint for host.js frida's host-side code */

const spawnSync = require('child_process').spawnSync;
const frida = require('frida');
const fs = require("fs");
const hex = require("./hexdump");

var rl;
var scriptFileName = 'target.js';
var remoteScript = "" + fs.readFileSync(scriptFileName);

/* globals are bad */
var grep = undefined;
var currentOffset = 0;
var current_blocksize = 64; // 
var Sym = {};
var Cfg = {};
/*
// defaults should be propagated to target on start
{
  'asm.arch': 'arm',
  'asm.bits': 16,
};
*/

function exec(cmd, args) {
  var res = spawnSync(cmd, args, {
    stdio: [0, 1, 2]
  });
  return res.status;
}

function dataIsString(data) {
  const min = 32; // ' '
  const max = 126; // '~'
  var ret = '';
  for (var i = 0; i < data.length; i++) {
    var nc = +data[i];
    var ch = String.fromCharCode(nc);
    if (nc == 0 || nc == 0xff) {
      break;
    }
    if (nc >= min && nc <= max) {
      ret += ch;
    } else {
      return false;
    }
  }
  return i ? ret : false;
}
// TODO: optimize tracing by moving this code to target.js
function traceInRange(t, from, to) {
  if (t.addr >= from && t.addr <= to) {
    return true;
  }
  for (var b in t.bt) {
    var bt = t.bt[b];
    console.log(from, t.bt, to);
    if (bt >= from && bt <= to) {
      return true;
    }
  }
  return false;
}

function Offset(num, pad) {
  const hexNum = num.toString(16);
  if (hexNum.length < 8) {
    return '0x' + Array(8 - hexNum.length + 1).join('0') + hexNum;
  }
  return '0x' + hexNum;
}

function log() {
  var args = [];
  for (var a in arguments) {
    if (typeof (arguments[a]) == 'object') {
      args.push(JSON.stringify(arguments[a]));
    } else {
      args.push(arguments[a]);
    }
  }
  var str = args.join(' ');
  if (grep && str.indexOf(grep) == -1) {
    return;
  }
  console.error(str);
  return str;
}

function gotMessageFromFrida(script, msg, data) {
  //console.log ("GOT PWNFUL", msg);
  if (msg && msg.type == 'error') {
    return true;
  }
  function getRegionString(r) {
    var fin = "0x" + (+r.base + r.size).toString (16);
    var mod = "";
    //if (r.path) mod = r.path.substring (r.path.lastIndexOf('/')+1);
    if (r.path) mod = r.path;
    return r.base + " " + fin + " " + r.protection + "  "+mod;
  }
  if (!msg || !msg.payload) {
    console.error("This message have no payload", msg);
    return false;
  }
  var payload = msg.payload;
  //log();
  switch (payload.name) {
    case 'pong':
      log();
      log("PONG RECEIVED");
      break;
    case 'pd':
      log('\n' + payload.data.text);
      break;
    case 'p8':
      var str = '';
      var sdata = '' + data;
      for (var ch = 0; ch < data.length; ch++) {
        var n = String.fromCharCode(data[ch]);
        var a = data[ch].toString(16);
        switch (a.length) {
          case 1:
            str += '0' + a;
            break;
          case 2:
            str += '' + a;
            break;
          default:
            console.error("Invalid hex");
            break;
        }
      }
      log(str);
      break;
    case 'px':
    case 'x':
      var xd = payload.data;
      var opt = {
        offset: xd.offset
      }
      if (xd.exception) {
        console.error("Hexdump Exception:", xd.exception);
      } else {
        if (data.length == 0) {
          console.error("Invalid address");
        }
        var hd = new hex.Hexdump(data, opt);
        if (hd && hd.output) {
          log();
          log(hd.output);
        }
      }
      break;
    case 'ie?':
      console.log("Symbols: " + Object.keys(Sym).length / 2);
      break;
    case 'ie':
      if (payload.data) {
        for (var i in payload.data) {
          var s = payload.data[i];
          log(s.address, s.library, s.name);
          Sym[s.address] = s.name;
          Sym[s.name] = s.address;
        }
      } else {
        function Symbol(addr, name) {
          return "f " + name + ' = ' + addr;
        }
        for (var s in Sym) {
          if (s[0] == '0') {
            console.log(Symbol(s, Sym[s]));
          }
        }
      }
      break;
    case 'is':
      if (payload.data) {
        for (var i in payload.data) {
          var s = payload.data[i];
          log(s.library, s.name, s.address);
          Sym[s.address] = s.name;
          Sym[s.name] = s.address;
        }
      } else {
        //console.error ("no data");
      }
      break;
    case 'i?':
      log('Usage: i[escl] show info');
      log(' i     show process info');
      log(' ie    show exports');
      log(' ic    show (ObjC) classes');
      log(' ip    show (ObjC) protocols');
      break;
    case 'i':
      const info = payload.data;
      const conf = {
        'asm.arch': info.arch,
        'asm.bits': info.bits,
        'asm.os': info.os,
        'bin.lang': info.objc ? 'objc' : info.dalvik ? 'dalvik' : '',
      };
      if (conf['asm.arch'] == 'arm64') {
        conf['asm.arch'] = 'arm';
        conf['asm.bits'] = 64;
      }
      for (let k in conf) {
        const line = 'e ' + k + ' = ' + conf[k];
        log(line);
        processLine(script, line);
      }
      log('# pid ' + info.pid);
      break;
    case 'ic':
      var xd = payload.data;
      // console.log(xd.classes);
      if (xd.exception) {
        console.log("Exception:", xd.exception);
      } else {
        if (xd.methods) {
          for (var name in xd.methods) {
            var addr = xd.methods[name];
            log('=> ', addr, name); //xd.methods[index]);
          }
        } else {
          for (var index in xd.classes) {
            log('=> ' + xd.classes[index]);
          }
        }
      }
      break;
    case 'ip':
      var xd = payload.data;
      //console.log(xd.protocols);
      if (xd.exception) {
        console.log("Exception:", xd.exception);
      } else {
        for (var index in xd.protocols) {
          log('=> ' + xd.protocols[index]);
        }
      }
      break;
    case 'il':
      for (var index in payload.data) {
        var r = payload.data[index];
        log(r.base + " " + r.name);
      }
      break;
    case 'dt-':
      console.log("All traces removed", payload.data);
      break;
    case 'dt':
      var t = payload.data;
      t.bt = t.bt.split(/ /);
      t.name = t.name || Sym[t.addr];
      if (Cfg['trace.user']) {
        var from = +Cfg['trace.from'];
        var to = +Cfg['trace.to'];
        var cur = +t.bt[0];
        if (cur < from || cur > to) {
          break;
        }
      }
      if (Cfg['trace.from'] && Cfg['trace.to']) {
        var from = +Cfg['trace.from'];
        var to = +Cfg['trace.to'];
        if (!traceInRange(t, from, to)) {
          console.log("Skipped not in trace range for ", t.addr);
          break;
        }
      }
      var str = dataIsString(data);
      log("Trace at", t.addr, t.name, str ? str : '');
      if (Cfg['trace.args']) {
        log("Strings", t.a0s, t.a1s);
        log("Args:", t.a0, t.a1, t.a2, t.a3);
      }
      if (Cfg['trace.bt']) {
        log("Backtrace: ", t.addr, t.bt);
      }
      if (data && Cfg['trace.hex']) {
        var hd = new hex.Hexdump(data, {
          offset: t.a1
        });
        if (hd && hd.output) {
          log(hd.output);
        }
      }
      break;
    case 'dm':
      for (var index in payload.data) {
        var r = payload.data[index];
        log(getRegionString(r));
      }
      break;
    case 'dr':
      var threads = payload.data.threads;
      var pid = payload.data.pid;
      for (var index in threads) {
        var t = threads[index];
        if (t.id == pid) {
          log("[current thread]");
        } else {
          log("tid", t.id, t.state);
          var c = 0;
          function getPrefix(msg) {
            c++;
            if (c == 1)
              return msg;
            if (((c - 1) % 4) == 0)
              return '\n' + msg;
            return '\t' + msg;
          }
          var regs = '';
          for (var r in t.context) {
            var msg = r + ' : ' + t.context[r];
            regs += (getPrefix(msg));
          }
          log(regs);
        //   log (t.context);
        }
      }
      break;
    case 'dpt':
      for (var index in payload.data) {
        var t = payload.data[index];
        log(t.id);
      }
      break;
    case 'dk':
      // TODO: kill a specific thread
      break;
    default:
      log("unkmsg", msg);
      break;
  }
  if (rl) {
    rl.prompt();
  }
}

function processLine(script, chunk, cb) {
  function fin(r) {
    if (cb) {
      cb(r);
    }
  }
  var r = '';
  var offset = currentOffset;
  var blocksize = current_blocksize;
  grep = undefined;
  if (chunk !== null) {
    chunk = chunk.trim();
    var wave = chunk.indexOf('~');
    if (wave != -1) {
      grep = chunk.substring(wave + 1);
      chunk = chunk.substring(0, wave);
    }
    var arroba = chunk.indexOf('@');
    if (arroba != -1) {
      offset = chunk.substring(arroba + 1)
      chunk = chunk.substring(0, arroba).trim();
    //console.log('Temporary offset ' + offset);
    }
    var words = chunk.split(/ /);
    if (words[0][0] == '!') {
      var args = chunk.substring(1).split(/ /);
      exec(args[0], args.slice(1));
    } else {
      switch (words[0]) {
        case 'help':
        case 'h':
        case '?':
          if (words.length > 1) {
            try {
              var off = Offset(+eval(chunk.substring(2)));
              log(off);
            } catch (e) {
              console.error(e);
            }
          } else {
            r += log("Available r2frida commands\n"
              + "+ Use '@' for temporal seeks and ~ for internal grep\n"
              + "!ls -l /       - execute shell command\n"
              + "b <size>       - change blocksize\n"
              + "dr             - show thread regs (see dpt)\n"
              + "dt <addr> ..   - trace list of addresses\n"
              + "dt-            - clear all tracing\n"
              + "di addr arg..  - call function at addr with given args\n"
              + "dl libname     - dlopen\n"
              + "dm             - show memory regions\n"
              + "dp             - show current pid\n"
              + "dpt            - show threads\n"
              + "e [k[=v]]      - evaluate Cfg var (host+target)\n"
              + "env [k[=v]]    - get/set environment variable\n"
              + "p8             - show blocksize in hexpairs\n"
              + "pa mov r0, 33  - assemble instruction at current offset\n"
              + "pad 90909090   - disassemble bytes at current offset\n"
              + "s <addr>       - seek to address\n"
              + "i              - show target information\n"
              + "ic <class>     - list classes or methods of <class>\n"
              + "ip             - list objc protocols\n"
              + "ie <lib>       - list exports/entrypoints of lib\n"
              + "is <sym>       - show address of symbol\n"
              + "is <lib> <sym> - show address of symbol\n"
              + "il             - list libraries\n"
              + "x @ addr       - hexdump at address\n"
              + "q              - quit\n"
              + "ping           - ping the frida-server\n");
            fin(r);
            return true;
          }
          break;
        //console.log ("w hexpair@addr  - write hexpairs to addr");
        case 'b':
          var tmp = +chunk.substring(2);
          if (tmp) {
            current_blocksize = blocksize = tmp;
          }
          r += log(blocksize);
          break;
        case 'e?':
          r += log('Eval variables shared between target and host:\n'
            + 'trace.from=0x9000   - only trace functions from this\n'
            + 'trace.to=0xac00     - ... range in the backtrace\n');
          break;
        case 'pa':
          exec('rasm2', [
            '-a', Cfg['asm.arch'],
            '-b', Cfg['asm.bits'],
            '-o', currentOffset,
            words.slice(1).join()]);
          break;
        case 'pad':
          exec('rasm2', [
            '-a', Cfg['asm.arch'],
            '-b', Cfg['asm.bits'],
            '-o', currentOffset,
            '-D', words.slice(1).join()]);
          break;
        case 'e':
          if (words.length > 1) {
            var kv = words.slice(1).join('');
            var io = kv.indexOf('=');
            if (io != -1) {
              var k = kv.substring(0, io);
              var v = kv.substring(io + 1);
              if (v == 'false') {
                v = false;
              }
              Cfg[k] = v;
            } else {
              console.log(Cfg[kv]);
            }
          } else {
            for (var e in Cfg) {
              console.log('e ' + e + ' = ' + Cfg[e]);
            }
          }
          break;
        case 's':
          currentOffset = offset = +chunk.substring(2);
          r += log(offset);
          break;
        case 'q':
          fin(r);
          process.exit(+words[1] || 0);
          return true;
        default:
          script.postMessage({
            "name": chunk,
            "offset": offset,
            "blocksize": blocksize
          });
          break;
      }
    }
  }
  fin(r);
  return false;
}

function spawnAndAttach(channel, pid, on_load, on_message) {
  resolveDevice(channel).then(function(device) {
    console.error('Attaching to ' + pid + ' using ' + device.name);
    pid = +pid || pid;
    device.spawn(pid).then(function () {
      device.attach(pid).then(function(session) {
        device.resume(pid);
        return session.createScript(remoteScript);
      }).then(function (script) {
        script.events.listen('message', function (msg, data) {
          // console.error(msg);
          if (msg && msg.type == 'error') {
            msg.payload = {
              name: 'x'
            }
          }
          if (on_message && on_message(msg, data)) {
            return;
          }
          gotMessageFromFrida(script, msg, data);
        });
        script.load().then(function() {
          on_load(script);
        });
      }).catch(function(err) {
        console.error(err);
      });
    });
  });
}

function resolveDevice(device) {
  console.error('[+] Using', device, 'target');
  switch (device) {
    case 'usb':
      return frida.getUsbDevice();
    case 'local':
      return frida.getLocalDevice();
    case 'tcp':
      return frida.getRemoteDevice();
      break;
  }
  return function() {
    this.then = function() {
      throw(new Error('invalid device'));
    }
  }
}

function attachAndRun(channel, pid, on_load, on_message) {
  resolveDevice(channel).then(function (device) {
    console.error("Attaching to " + pid + " using " + device.name);
    pid = +pid || pid;
    device.attach(pid).then(function(session) {
      return session.createScript(remoteScript);
    }).then(function(script) {
      script.events.listen('message', function(msg, data) {
        // console.error(msg);
        if (msg && msg.type == 'error') {
          msg.payload = {
            name: 'x'
          }
        }
        if (on_message && on_message(msg, data)) {
          return;
        }
        gotMessageFromFrida(script, msg, data);
      });
      script.load().then(function() {
        on_load(script);
      });
    }).catch(function(err) {
      console.error(err);
    });
  });
}

module.exports.spawnAndAttach = spawnAndAttach;
module.exports.attachAndRun = attachAndRun;
module.exports.processLine = processLine;
module.exports.getCurrentOffset = function() {
  return currentOffset;
}
module.exports.Offset = Offset;
module.exports.setConfig = function(script, kv) {
  for (var a in kv) {
    var line = 'e ' + a + '=' + kv[a];
    processLine(script, line);
  }
}
