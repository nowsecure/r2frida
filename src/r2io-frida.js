/* entrypoint for r2frida.js */

var r2p2 = require ("./r2pipe2");
var r2f = require ("./r2frida");

var expectRead = false;

/* receive message from r2 io plugin wrapper */
/* parses the message to read ... */
function onFridaMessage(msg, data) {
  var cmd = msg.payload.name;
  var addr = msg.payload.offset;
  if (cmd != 'x') {
    return false;
    // read memory operation done
  }
  if (!expectRead) {
    return false;
  }
  expectRead = false;
  /* read nothing here */
  var obj = {
    "result": data.length,
    "data": []
  };
  for (var i = 0; i < data.length; i++) {
    obj.data.push (data[i]);
  }
  r2p2.writeObject (obj);
  return true;
}

function runSystem(script, cmd) {
  r2f.processLine(script, cmd, function(res) {
    r2p2.writeObject ({
      result: res
    });
  });
}

function runRead(script, msg) {
  var addr = msg.address;
  var size = msg.count;
  //console.log(addr, size)
  expectRead = true;
  r2f.processLine (script, 'x ' + size + '@' + addr, function(res) {
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

function onFridaLoad(script) {
  console.log ("Attached");
  r2p2.onObject (function(msg) {
    //console.log ("Got Message From R2", msg);
    switch (msg.op) {
      case 'read':
        runRead(script, msg);
        break;
      case 'write':
        r2p2.writeObject();
        break;
      case 'system':
        runSystem(script, msg.cmd);
        break;
      default:
        r2p2.writeObject();
        break;
    }
  });
}

if (process.argv.length < 3) {
  console.log ("Use: r2frida.js [pid | processname]")
  console.log ("Use frida-ps -R to list all the processes");
  process.exit(1);
}

r2f.attachAndRun (process.argv[2], onFridaLoad, onFridaMessage);
