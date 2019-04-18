'use strict';

const r2pipe = require('r2pipe-promise');

async function test (name, uri, check) {
  const r2 = await r2pipe.open(uri);
  const res = await check(r2);
  console.error(res? '\x1b[32m[OK]\x1b[0m': '\x1b[31m[XX]\x1b[0m', name);
  return r2.quit();
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
