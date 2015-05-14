#!/usr/bin/env node
/*
** r2frida main commandline program
** --pancake 2015
*/

var spawnSync = require('child_process').spawnSync;
var colors = require ('colors');
var fs = require ('fs');

/* actions */

const Option = {
  showHelp: function() {
    die ('Usage: r2frida [-h|-v] [-s] [-l|procname|pid]', 0);
  },
  showVersion: function() {
    const package_json = '' + fs.readFileSync('../package.json');
    const version = JSON.parse (package_json).version;
    die (version, 0);
  },
  enterShell: function(target) {
    target && exec (process.execPath, ['main.js', target]);
    die ('Missing target', 1);
  },
  startR2: function(target) {
    exec ('r2', ['r2pipe://node r2io-frida.js ' + target]);
  },
  listProcesses: function() {
    exec ('frida-ps', ['-R']);
  }
}

/* main */

Main (process.argv.slice(2), {
  '-h': Option.showHelp,
  '-v': Option.showVersion,
  '-s': Option.enterShell,
  '-l': Option.listProcesses
});

function Main(argv, options) {
  var target = undefined;
  process.chdir (__dirname + '/../src');
  for (var i in argv) {
    var opt = options [argv[+i]];
    if (opt) {
      opt (argv[+i + 1]);
    } else {
      if (target) {
        die ("Invalid parameter: '" + argv[+i] + "'", 1);
      }
      target = argv[+i];
    }
  }
  target && Option.startR2(target);
  Option.showHelp ();
}

/* utils */

function die(msg, ret) {
  var println = ret ? console.error : console.log;
  var color = ret ? colors.red : colors.yellow;
  println (color (msg));
  process.exit (ret);
}

function exec(cmd, args) {
  var res = spawnSync (cmd, args, {
    stdio: [0, 1, 2]
  });
  process.exit (res.status);
}
