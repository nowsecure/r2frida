var frida = require ('frida');
var fs = require ("fs");

var scriptFileName = 'target.js';

if (process.argv < 2) {
  console.log ("Use: test.js [pid]")
  process.exit(1);
}
var script = fs.readFileSync (scriptFileName);
//script = script.replace("\n", "");

var pid = +process.argv[2];
console.log ("Connecting to", pid)
function attachAndDump() {
  frida.getRemoteDevice()
    .then(function(device) {
      console.log ("lets attach");
      device.attach(pid)
        .catch(function(error) {
          console.log('error:', error.message);
        })
        .then(function(session) {
          console.log ("[+] Connected", session);
          console.log ("[+] Session", session);
          session.createScript(script).then(function() {
            console.log ("[+] Script created");
          });
        }).then (function(script) {
        console.log("[+] Loading script...")
        script.events.listen('message', function(msg, data) {
          console.log ("[+] Got message", msg, data);
        });
        script.load ()
          .then (function() {
            console.log ("[+] Ready to send messages");
            script.postMessage({
              name: 'dm'
            });
            setInterval (function() {
              script.postMessage({
                name: 'ping'
              });
            }, 1000);
          });
        console.log ("[+] Done");
      });
    }).catch(function(er) {
    console.error("error", er);
  });
}
attachAndDump ();
