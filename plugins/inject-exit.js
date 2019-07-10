
function injectCode() {
	const arm64code = [
		48,0,128,210, // movz x16, 1
		32,0,128,210, // movz x0, 1
		1,16,0,212 // svc 0x80
	];
	const x86code = [
		72,199,192,1,0,0,2, // mov rax, 0x2000001
		72,199,199,0,0,0,0, // mov rdi, 0
		15,5 // syscall
	];
	// const code = arm64code;
	const code = x86code;
	const getBaseCode = Memory.alloc(Process.pageSize);
	Memory.protect(getBaseCode, Process.pageSize, 'r-x');

	Memory.patchCode(getBaseCode, code.length, function (target) {
			target.writeByteArray(code);
		});

	const fun = new NativeFunction(getBaseCode, 'void', []);
	fun();
}

injectCode();
