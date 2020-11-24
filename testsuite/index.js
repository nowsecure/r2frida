'use strict';

const r2pipe = require('r2pipe-promise');

async function testres (res, name) {
  console.error(res? '\x1b[32m[OK]\x1b[0m': '\x1b[31m[XX]\x1b[0m', name);
}

async function test (name, uri, check) {
  const r2 = await r2pipe.open(uri);
  const res = await check(r2);
  testres(res, name);
  return r2.quit();
}

async function r2fridaTestArgs() {
  // the behaviour shuold be the same as frida://attach/123 but it's not.. because the pid is not processed yet so cant be valid
  await testuri('frida://923999', `local-device
device: local
pname: 923999
pid: 923999
spawn: false
run: false
pid_valid: false
`);
  await testuri('frida://ls', `local-device
device: local
pname: /bin/ls
pid: 0
spawn: true
run: false
pid_valid: false
`);
  // list processes in current system.. probably not useful to test
  await testuri('frida://', `local-device
dump-apps
dump-procs
device: local
pname: 
pid: 0
spawn: true
run: false
pid_valid: false
`);
  await testuri('frida://spawn/ls', `local-device
device: local
pname: /bin/ls
pid: 0
spawn: true
run: false
pid_valid: false
`);
  await testuri('frida://usb/', `dump-devices
local-device
dump-apps
dump-procs
device: local
pname: (null)
pid: 0
spawn: false
run: false
pid_valid: false
`);
  await testuri('frida://usb//', `get-usb-device
get-usb-device
dump-apps
dump-procs
device: usb
pname: 
pid: 0
spawn: true
run: false
pid_valid: false
`);
  await testuri('frida://usb/device-id', `get-usb-device
device: usb
pname: device-id
pid: 0
spawn: false
run: false
pid_valid: false
`);
}

function testuri(uri, expect) {
  process.env.R2FRIDA_DEBUG = '1';
  return new Promise((resolve, reject) => {
    r2pipe.syscmd('r2 ' + uri, (out, err, res) => {
      delete process.env.R2FRIDA_DEBUG;
/*
console.error(out);
console.error('---');
console.error(expect);
*/
      testres(err === expect, uri);
      if (err !== expect) {
        return reject(err);
      }
      return resolve('args');
    });
  });
}

async function r2fridaTestSpawn() {
  return test('spawn', 'frida://spawn/rax2', async function (r2) {
    const res = await r2.cmd('=!?V');
    const r2fVersion = JSON.parse(res);
    return r2fVersion.hasOwnProperty('version');
  });
}

async function r2fridaTestEntrypoint() {
  await test('entrypoint', 'frida://spawn/rax2', async function (r2) {
    const entry = await r2.cmd('=!ie');
    return entry.startsWith('0x');
  });
  await test('entrypoint code', 'frida://spawn/rax2', async function (r2) {
    await r2.cmd('.=!ie*;s entry0');
    const entry = await r2.cmd('pd 10~invalid?');
    return entry.trim() === '0';
  });
}

async function r2fridaTestLibs() {
  return test('libraries', 'frida://spawn/rax2', async function (r2) {
    const libs = await r2.cmd('=!ilq');
    return libs.length > 10;
  });
}

async function r2fridaTestDlopen() {
  return test('dlopen', 'frida://0', async function (r2) {
    // macOS-specific test
    const mustBeEmpty = await r2.cmd('\\il~r_util');
    const ra = await r2.cmd('\\dl libr_util.dylib');
    const mustBeLoaded = await r2.cmd('\\il~r_util');
    // console.error(mustBeEmpty)
    // console.error(mustBeLoaded)
    return mustBeEmpty.trim() === '' && mustBeLoaded.trim() !== '';
  });
}

async function r2fridaTestSearch() {
  return test('finding nemo', 'frida://0', async function (r2) {
    const r = await r2.cmd('\\/ NEMO');
    return (r.split('hit0').length > 2);
  });
}


async function r2fridaTestFrida() {
  return test('frida', 'frida://0', async function (r2) {
    // XXX cant read console output
    // await r2.cmd('\\ console.log(123) > .a');
    // const n123 = await r2.cmd('cat .a;rm .a');
    const r = await r2.cmd('\\dxc write 1 "" 4');
    return r.indexOf('"0x4"') !== -1;
  });
}

async function run() {
  console.log('[--] Running the r2frida testsuite...');
  await r2fridaTestArgs();
  await r2fridaTestSpawn();
  await r2fridaTestEntrypoint();
  await r2fridaTestLibs();
  await r2fridaTestDlopen();
  await r2fridaTestFrida();
  await r2fridaTestSearch();
}

run().then((x) => {
  console.log('[--] Done');
}).catch(console.error);
