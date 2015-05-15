FILES=hexdump.js main.js
FILES+=r2io-frida.js test.js
FILES+=target.js host.js

all:
	cd .. ; npm install

indent: ${FILES}

${FILES}:
	jsfmt -w $@

.PHONY: ${FILES} all indent
