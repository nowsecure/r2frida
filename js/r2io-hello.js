/* entrypoint for r2frida.js */

var r2p2 = require ("./r2pipe2");

function runRead(msg) {
  var obj = {
    result: msg.count,
    data: [1, 2, 3]
  };
  r2p2.writeObject (obj);
}

r2p2.onObject (function(msg) {
  //console.log ("Got Message", msg);
  switch (msg.op) {
    case 'read':
      runRead(msg);
      break;
    case 'write':
      /* not implemented */
      r2p2.writeObject();
      break;
    case 'system':
      r2p2.writeObject({
        result: 'Hello World'
      });
      break;
    default:
      r2p2.writeObject();
      break;
  }
});
