const r2pipe = require('r2pipe-promise');

async function test(name, uri, check) {
  const r2 = await r2pipe.open('frida://spawn/rax2');
  const res = await check(r2);
  if (res) {
    console.error('[OK]', name);
  } else {
    console.error('[XX]', name);
  }
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
  return test('entrypoint', 'frida://spawn/rax2', async function (r2) {
    const entry = await r2.cmd('=!ie');
    return entry.startsWith('0x');
  });
}

async function r2fridaTestLibs() {
  return test('libraries', 'frida://spawn/rax2', async function (r2) {
    const libs = await r2.cmd('=!ilq');
    return libs.length > 10;
  });
}

async function run() {
  console.log('[--] Running the r2frida testsuite...');
  await r2fridaTestSpawn();
  await r2fridaTestEntrypoint();
  await r2fridaTestLibs();
}

run().then((x) => {
  console.log('[--] Done');
}).catch(console.error);
