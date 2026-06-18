AGENT_UNIT_OUT=/tmp/r2frida-agent-unit

all: agent-unit new

agent-unit:
	rm -rf $(AGENT_UNIT_OUT)
	mkdir -p $(AGENT_UNIT_OUT)
	../node_modules/.bin/tsc --ignoreConfig --target es2020 --module node16 --moduleResolution node16 --types node --strict --skipLibCheck --outDir $(AGENT_UNIT_OUT) ../src/agent/lib/debug/breakpoint-model.ts agent/breakpoint-model.test.ts
	node $(AGENT_UNIT_OUT)/test/agent/breakpoint-model.test.js

new:
	r2r -u db/extras

# old testsuite used in travis not used nowadays, needs care
old:
	mkdir -p suite/node_modules
	cd suite && npm i
	cd suite && npm run build
	cd suite && node index.js

.PHONY: all agent-unit new old
