all: new

new:
	r2r -u db/extras

# old testsuite used in travis not used nowadays, needs care
old:
	mkdir -p suite/node_modules
	cd suite && npm i
	cd suite && npm run build
	cd suite && node index.js

.PHONY: all new old
