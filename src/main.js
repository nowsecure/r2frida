var r2f = require ("./host");
var useReadline = true;

if (process.argv.length < 3) {
  console.log ("Use: main.js [pid | processname]")
  console.log ("Use frida-ps -R to list all the processes");
  process.exit(1);
}

function setupPrompt(script) {
  if (useReadline) {
    var readline = require('readline');
    rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    rl.setPrompt("[" + r2f.Offset(r2f.currentOffset, 8) + "]> ");
    rl.prompt();
    rl.on('line', function(line) {
      r2f.processLine (script, line);
      rl.setPrompt("[" + r2f.Offset(r2f.currentOffset, 8) + "]> ");
      rl.prompt();
      if (line == "q") {
        rl.close();
        process.exit (0);
      }
    });
  } else {
    process.stdin.setEncoding('utf8');
    process.stdin.on('ready', function() {
      process.stdout.write("> ");
    });
    process.stdin.on('readable', function() {
      r2f.processLine (script, process.stdin.read());
    });
    process.stdin.on('end', function() {
      console.log("^D");
      process.exit(0);
    });
  }
}

function onLoad(script) {
  setupPrompt(script);
}

r2f.attachAndRun (process.argv[2], onLoad);
