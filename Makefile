DESTDIR?=
PREFIX?=/usr
PFX=${DESTDIR}/${PREFIX}
PWD=$(shell pwd)
BINDIR=$(PFX)/bin
FRIDA_ROOT?=

node_modules/frida:
	npm install
	cp -rf $(FRIDA_ROOT)/build/frida_stripped-*/lib/node_modules/frida node_modules/frida

run:
	cd src ; r2 r2pipe://"node r2io-frida.js vim"

install:
	ln -fs $(PWD)/bin/r2frida.js $(BINDIR)/r2frida
