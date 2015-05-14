FILES=hexdump.js main.js r2frida.js
FILES+=r2io-frida.js r2io-hello.js
FILES+=r2pipe2.js target.js test.js

all:
	cd .. ; npm install

indent: ${FILES}

${FILES}:
	jsfmt -w $@

.PHONY: ${FILES} all indent
