// Find Method NSURL, generate QR codes from all the strings
// need access to the logs

r2frida.pluginRegister('hookurl', hookUrl);

function hookUrl (command) {
  return (command === 'hookurl')
    ? hookUrlCommand: undefined;
}

function hookUrlCommand(args) {
  return new Promise((resolve, reject) => {
    if (args.length < 1) {
      return resolve('Usage: hookurl [test|urls|qrs|btgraph]');
    }
    switch (args[0]) {
      case 'test':
        try {
          urlsFromLogs().map((url) => {
            r2frida.hostCmd('pqz@s:' + url).then(res => {
              console.error('WINS', res);
              resolve('Smile');
            }).catch(reject);
          });
        } catch (reject) {
          return reject(e);
        }
        return;
      case 'qrs':
        return resolve(urlsFromLogs().map((url) => '?E ' + url + '\npqz @s:' + url).join('\n'));
      case 'urls':
        return resolve(urlsFromLogs().map((url) => '* ' + url).join('\n'));
      case 'btgraph':
        return resolve(scriptFromBacktraces());
    }
    return resolve('nothing to see');
  });
}

console.log(`
Welcome to the 'hookurl' plugin!

Add a hook to the NSURL::URLWithString method

\\dtf objc:NSURL.^URLWithString:$ ooo
`);
//console.log('=!ic NSURL~URLWithString');
//console.log('=!dtf addr~[0] ooo');

function urlsFromLogs () {
  return r2frida.logs
    .filter((log) => log.values.length > 1)
    .map((log) => log.values[2].split('"')[1]);
/*
  const urls = [];
  for (let log of r2frida.logs) {
    if (log.values.length > 1) {
      const url = log.values[2].split('"')[1];
      urls.push(url);
    }
  }
  return urls;
*/
}

function scriptFromBacktraces () {
  const backtraces = r2frida.logs.filter((l) => l.backtrace);
  let script = [];
  for (let appTrace of backtraces) {
    let previousTrace = null;
    for (let trace of appTrace.backtrace) {
      if (previousTrace === null) {
        previousTrace = trace;
        continue;
      }
      const ca = trace.name.replace(/ /g, '_') || trace.address;
      const pa = previousTrace.name.replace(/ /g, '_') || previousTrace.address;
      script.push('"agn ' + ca + '"');
      script.push('"agn ' + pa + '"');
      script.push('"age ' + pa + ' ' + ca + '"');
      previousTrace = trace;
    }
  }
  return script.join('\n');
}

