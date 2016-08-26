/* entrypoint for r2frida.js */

var r2p = require("r2pipe");
var r2f = require("./host");

var expectRead = false;
var send = function() {
  console.error("NO SEND");
};

/* receive message from r2 io plugin wrapper */
/* parses the message to read ... */
function onFridaMessage(msg, data) {
console.log("fridamsg");
  var payload = msg.payload;
  var obj = {
    'result': data.length || 0,
    'data': []
  };
  if (!payload) {
    send(obj);
    return false;
  }
  var cmd = payload.name;
  var addr = payload.offset;
  if (cmd != 'x') {
    return false;
  // read memory operation done
  }
  if (!expectRead) {
    return false;
  }
  expectRead = false;
  /* read nothing here */
  for (let i in data) {
    obj.data.push(data[i]);
  }
  send(obj);
  return true;
}

function onFridaLoad(script) {
  function runRead(script, msg) {
    var addr = msg.address;
    var size = msg.count;
    expectRead = true;
    r2f.processLine(script, 'x ' + size + '@' + addr, function(res) {
      /*
          expectRead = false;
          console.log ("DONE");
          var obj = {
            "result": 3,
            "data": [1, 2, 3]
          };
          r2p2.writeObject (obj);
      */
      //  console.log ("Message ", msg, " processed, waiting for reply");
    });
  }
  console.log("[+] r2frida attached");
  r2p.ioplugin(function(me, msg) {
    send = me.send;
    //console.log ("Got Message From R2", msg);
    switch (msg.op) {
      case 'close':
        console.error("close not yet implemented");
        break;
      case 'read':
        runRead(script, msg);
        break;
      case 'write':
        me.send();
        break;
      case 'system':
        r2f.processLine(script, msg.cmd, function(res) {
          me.send({
            result: res
          });
        });
        break;
      default:
        me.send();
        break;
    }
  });
}

const argv = process.argv.slice(2);

if (argv.length < 1) {
  console.error("Use: r2 r2pipe://\"node r2io-frida.js [pid | processname]\"")
  console.error("Use: r2 r2pipe://\"node r2io-frida.js -U [pid | processname]\"")
  console.error("Use frida-ps -R to list all the processes");
  process.exit(1);
}

var targetDevice = 'local';
if (argv[0] == '-R') {
  targetDevice = 'tcp';
  targetProcess = argv[1];
} else if (argv[0] == '-U') {
  targetDevice = 'usb';
  targetProcess = argv[1];
} else {
  targetProcess = argv[0];
}
r2f.attachAndRun(targetDevice, argv[0], onFridaLoad, onFridaMessage);
