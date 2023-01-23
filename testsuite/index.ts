const r2pipe = require("r2pipe-promise");
const colors = require("colors");

async function testres(res: boolean, name: string) {
    console.error(res ? '\x1b[32m[OK]\x1b[0m' : '\x1b[31m[XX]\x1b[0m', name);
}

async function test(name: string, uri: string, check: Function) {
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
pid_valid: true
`);
    await testuri('frida://ls', `local-device
device: local
pname: /bin/ls
pid: -1
spawn: true
run: false
pid_valid: false
`);
    // list processes in current system.. probably not useful to test
    await testuri('frida://', `local-device
dump-procs
`);
    await testuri('frida://apps/local', `local-device
dump-apps
`);
    await testuri('frida://spawn/ls', `local-device
device: local
pname: /bin/ls
pid: -1
spawn: true
run: false
pid_valid: false
`);
    /*
      await testuri('frida://usb/', `dump-devices
    local-device
    dump-apps
    dump-procs
    device: local
    pname: (null)
    pid: -1
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
    pid: -1
    spawn: true
    run: false
    pid_valid: false
    `);
      await testuri('frida://usb/device-id', `get-usb-device
    device: usb
    pname: device-id
    pid: -1
    spawn: false
    run: false
    pid_valid: false
    `);
    */
}

function testuri(uri: string, expect: string) {
    process.env.R2FRIDA_DEBUG = '1';
    return new Promise((resolve, reject) => {
        r2pipe.syscmd('r2 ' + uri, (out: any, err: any, res: any) => {
            delete process.env.R2FRIDA_DEBUG;
            testres(err === expect, uri);
            if (err !== expect) {
                console.error("---\n" + colors.magenta(expect));
                console.error("+++\n" + colors.yellow(err));
                return reject(err);
            }
            return resolve('args');
        });
    });
}

async function r2fridaTestSpawn() {
    return test('spawn', 'frida://spawn/rax2', async function (r2: any) {
        const res = await r2.cmd(':?V');
        const r2fVersion = JSON.parse(res);
        return r2fVersion.hasOwnProperty('version');
    });
}

async function r2fridaTestEntrypoint() {
    await test('entrypoint', 'frida://spawn/rax2', async function (r2: any) {
        const entry = await r2.cmd(':ie');
        return entry.startsWith('0x');
    });
    await test('entrypoint code', 'frida://spawn/rax2', async function (r2: any) {
        await r2.cmd('.:ie*;s entry0');
        const entry = await r2.cmd('pd 10~invalid?');
        return entry.trim() === '0';
    });
}

async function r2fridaTestLibs() {
    return test('libraries', 'frida://spawn/rax2', async function (r2: any) {
        const libs = await r2.cmd(':ilq');
        return libs.length > 10;
    });
}

async function r2fridaTestDlopen() {
    return test('dlopen', 'frida://0', async function (r2: any) {
        // macOS-specific test
        const mustBeEmpty = await r2.cmd(':il~r_util');
        const ra = await r2.cmd(':dl libr_util.dylib');
        const mustBeLoaded = await r2.cmd(':il~r_util');
        // console.error(mustBeEmpty)
        // console.error(mustBeLoaded)
        return mustBeEmpty.trim() === '' && mustBeLoaded.trim() !== '';
    });
}

async function r2fridaTestSearch() {
    return test('finding nemo', 'frida://0', async function (r2: any) {
        const r = await r2.cmd(':/ NEMO');
        return (r.split('hit0').length > 2);
    });
}


async function r2fridaTestFrida() {
    return test('frida', 'frida://0', async function (r2: any) {
        // XXX cant read console output
        // await r2.cmd(': console.log(123) > .a');
        // const n123 = await r2.cmd('cat .a;rm .a');
        const r = await r2.cmd(':dxc write 1 "" 4');
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
