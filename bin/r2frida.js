#!/usr/bin/env node
/*
** r2frida main commandline program
** --pancake 2015
*/

var spawnSync = require('child_process').spawnSync;
var colors = require ('colors');
var fs = require ('fs');

/* actions */

const helpmsg = 'Usage: r2frida [-h|-v] [-f adb|ip] [-n|-s] [-l|-L|procname|pid]';

const Option = {
  showLongHelp: function() {
    die ([helpmsg,
    ' -l            list processes',
    ' -L            list applications',
    ' -f [adb|ip]   forward port to frida-server',
    ' -v            show version information',
    ' -n            batch mode no prompt',
    ' -s            enter the r2node shell'].join('\n'));
  },
  showHelp: function() {
    die (helpmsg, 0);
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
  enterBatchShell: function(target) {
    target && exec (process.execPath, ['main.js', '-n', target]);
    die ('Missing target', 1);
  },
  forwardPort: function(target) {
    target || die ('Missing target', 1);
    if (target == 'adb') {
      exec ('adb', ['forward', 'tcp:27042', 'tcp:27042']);
    } else {
      exec ('ssh', ['-L', '27042:localhost:27042', 'root@'+target]);
    }
    exec ('r2', ['r2pipe://node r2io-frida.js ' + target]);
  },
  startR2: function(target) {
    exec ('r2', ['r2pipe://node r2io-frida.js ' + target]);
  },
  listProcesses: function() {
    var frida = require ('frida');
    frida.getRemoteDevice().then(function(device) {
      device.enumerateProcesses().then (function(procs) {
        for (var i in procs.reverse()) {
          var p = procs[i];
          console.log(p.pid + '\t' + p.name);
        }
      })
    });
  },
  listApplications: function() {
    var frida = require ('frida');
    frida.getRemoteDevice().then(function(device) {
      device.enumerateApplications().then (function(procs) {
        for (var i in procs.reverse()) {
          var p = procs[i];
          console.log(p.pid + '\t' + p.name);
        }
      })
    });
  }
}

/* main */

Main (process.argv.slice(2), {
  '-h': Option.showLongHelp,
  '-v': Option.showVersion,
  '-s': Option.enterShell,
  '-n': Option.enterBatchShell,
  '-f': Option.forwardPort,
  '-l': Option.listProcesses,
  '-L': Option.listApplications
});

function Main(argv, options) {
  var target = undefined;
  process.chdir (__dirname + '/../src');
  for (var i in argv) {
    var opt = options [argv[+i]];
    if (opt) {
      return opt (argv[+i + 1]);
    }
    if (target) {
      die ("Invalid parameter: '" + argv[+i] + "'", 1);
    }
    target = argv[+i];
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
