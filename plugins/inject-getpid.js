"use strict";
if (Process.arch == "arm64" && Process.platform == "linux") {
    var getBaseCode = Memory.alloc(Process.pageSize);
    Memory.patchCode(getBaseCode, Process.pageSize, function(code) {
        var arm64Writer = new Arm64Writer(code, {
            pc: getBaseCode
        });
        arm64Writer.putInstruction(0xd2801588);
        arm64Writer.putInstruction(0xd2800020);
        arm64Writer.putInstruction(0xd4000001);
        arm64Writer.putRet();
        arm64Writer.flush();
    });
    const fun = new NativeFunction(getBaseCode, 'int', []);
    console.log('getPid From syscall : ', fun());
} else {
    console.log('Unsupported arch');
}    





