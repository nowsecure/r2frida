all: objection-agent.js
	cat objection-agent.js index.js > r2f-objection-plugin.js
	@echo make run to start an app with that plugin

run:
	r2 -c ':. r2f-objection-plugin.js' frida://spawn/usb//Twitter

objection-agent.js:
	git clone https://github.com/sensepost/objection
	cd objection/agent && npm i
	cp objection/objection/agent.js objection-agent.js
	rm -rf objection
