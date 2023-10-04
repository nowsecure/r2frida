all: r2f-objection-agent.js

r2f-objection-agent.js: objection-agent.js
	cat objection-agent.js index.js > r2f-objection-plugin.js
	@echo make run to start an app with that plugin

run:
	r2 -c ':. r2f-objection-plugin.js' frida://spawn/usb//Twitter

objection-agent.js:
	git clone https://github.com/sensepost/objection
	cd objection/agent && npm i
	cp objection/objection/agent.js objection-agent.js
	rm -rf objection

R2_PREFIX=$(shell r2 -H R2_PREFIX)

install: r2f-objection-agent.js
	mkdir -p $(R2_PREFIX)/share/r2frida/scripts/
	cp -f r2f-objection-plugin.js $(R2_PREFIX)/share/r2frida/scripts/

user-install: r2f-objection-agent.js
	mkdir -p $(HOME)/.local/share/radare2/r2frida/scripts/
	cp -f r2f-objection-plugin.js $(HOME)/.local/share/radare2/r2frida/scripts/
