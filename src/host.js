/* entrypoint for host.js frida's host-side code */

var frida = require ('frida');
var fs = require ("fs");
var hex = require ("./hexdump");

var rl;
var scriptFileName = 'target.js';
var remoteScript = "" + fs.readFileSync (scriptFileName);

/* globals are bad */
var grep = undefined;
var currentOffset = 0;
var current_blocksize = 64;
var symbols = {};

function Offset(num, pad) {
  var offset = num.toString(16);
  if (offset.length < 8) {
    offset = '0x' + Array(8 - offset.length + 1).join('0') + offset;
  } else {
    offset = '0x' + offset;
  }
  return offset;
}

function log() {
  var args = [];
  for (var a in arguments) {
    if (typeof (arguments[a]) == 'object') {
      args.push (JSON.stringify(arguments[a]));
    } else {
      args.push (arguments[a]);
    }
  }
  var str = args.join (' ');
  if (grep && str.indexOf (grep) == -1) {
    return;
  }
  console.log (str);
  return str;
}

function gotMessageFromFrida(msg, data) {
  //console.log ("GOT PWNFUL", msg);
  function getRegionString(r) {
    var fin = "0x" + (+r.base + r.size).toString(16);
    return r.base + " " + fin + " " + r.protection;
  }
  if (!msg || !msg.payload) {
    console.error("This message have no payload", msg);
    return false;
  }
  var payload = msg.payload;
  log();
  switch (payload.name) {
    case 'x':
      var opt = {
        offset: payload.offset
      }
      var hd = new hex.Hexdump(data, opt);
      if (hd && hd.output) {
        log(hd.output);
      } else {
        console.error ("no data");
      }
      break;
    case 'ie':
      if (payload.data) {
        for (var i in payload.data) {
          var s = payload.data[i];
          log (s.address, s.library, s.name);
          symbols[s.address] = s.name;
          symbols[s.name] = s.address;
        }
      } else {
        console.error ("no data");
      }
      break;
    case 'is':
      if (payload.data) {
        for (var i in payload.data) {
          var s = payload.data[i];
          log (s.library, s.name, s.address);
          symbols[s.address] = s.name;
          symbols[s.name] = s.address;
        }
      } else {
        console.error ("no data");
      }
      break;
    case 'dt':
      var t = payload.data;
      t.name = t.name || symbols[t.addr];
      log(t.addr, t.name, t.a0, "0x" + t.a1.toString(16), t.a2, t.a3);
      log(t.addr, t.bt);
      if (data) {
        var hd = new hex.Hexdump(data, {
          offset: t.a1
        });
        if (hd && hd.output) {
          log (hd.output);
        }
      }
      break;
    case 'dm':
      for (var index in payload.data) {
        var r = payload.data[index];
        log (getRegionString (r));
      }
      break;
    case 'dr':
      var threads = payload.data.threads;
      var pid = payload.data.pid;
      for (var index in threads) {
        var t = threads[index];
        if (t.id == pid) {
          log ("[current thread]");
        } else {
          log ("tid", t.id);
          log(t.context);
        }
      }
      break;
    case 'dpt':
      for (var index in payload.data) {
        var t = payload.data[index];
        log (t.id);
      }
      break;
    case 'dk':
      // TODO: kill a specific thread
      break;
    case 'i':
      var info = payload.data;
      log ("e asm.arch=" + info.arch);
      log ("e asm.bits=" + info.bits);
      log ("e asm.os=" + info.os);
      log ("e lang.objc=" + info.objc);
      log ("e lang.dalvik=" + info.dalvik);
      log ("# pid " + info.pid);
      break;
    case 'ic':
      for (var index in payload.data) {
        log(payload.data[index]);
      }
      break;
    case 'il':
      for (var index in payload.data) {
        var r = payload.data[index];
        log (r.base + " " + r.name);
      }
      break;
    default:
      log ("unkmsg", msg);
      break;
  }
  if (rl) {
    rl.prompt();
  }
}

function processLine(script, chunk, cb) {
  function fin(r) {
    if (cb) {
      cb (r);
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
    switch (words[0]) {
      case '?':
        if (words.length > 1) {
          var off = Offset(+eval(chunk.substring(2)));
          log (off);
        } else {
          r += log ("Available r2frida commands\n"
          + "dm             - show memory regions\n"
          + "dp             - show current pid\n"
          + "dpt            - show threads\n"
          + "s <addr>       - seek to address\n"
          + "b <size>       - change blocksize\n"
          + "is <lib> <sym> - show address of symbol\n"
          + "ie <lib>       - list exports/entrypoints of lib\n"
          + "i              - show target information\n"
          + "il             - list libraries\n"
          + "dr             - show thread regs (see dpt)\n"
          + "dt <addr> ..   - trace list of addresses\n"
          + "dt-            - clear all tracing\n"
          + "x @ addr       - hexdump at address\n"
          + "q              - quit\n");
          fin (r);
          return true;
      }
      //console.log ("w hexpair@addr  - write hexpairs to addr");
      case 'b':
        var tmp = +chunk.substring(2);
        if (tmp) {
          current_blocksize = blocksize = tmp;
        }
        r += log(blocksize);
        break;
      case 's':
        currentOffset = offset = +chunk.substring(2);
        r += log(offset);
        break;
      case 'q':
        fin (r);
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
  fin (r);
  return false;
}

function attachAndRun(pid, on_load, on_message) {
  frida.getRemoteDevice().then(function(device) {
    console.log ("Attaching to " + pid + " using " + device.name);
    device.attach(pid).then(function(session) {
      return session.createScript(remoteScript);
    }).then(function(script) {
      script.events.listen('message', function(msg, data) {
        //console.log ("ONMSG",on_message)
        if (on_message && on_message (msg, data)) {
          return;
        }
        gotMessageFromFrida (msg, data);
      });
      script.load ().then (function() {
        on_load (script);
      });
    }).catch (function(err) {
      console.error (err);
    });
  });
}

module.exports.attachAndRun = attachAndRun;
module.exports.processLine = processLine;
module.exports.currentOffset = currentOffset;
module.exports.Offset = Offset;
