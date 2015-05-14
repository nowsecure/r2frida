DESTDIR?=
PREFIX?=/usr
PFX=${DESTDIR}/${PREFIX}
PWD=$(shell pwd)
BINDIR=$(PFX)/bin
FRIDA_ROOT?=$(PWD)/deps/frida
FRIDA_NODE=/build/frida_stripped-*/lib/node_modules/frida

all: node_modules/frida
	@echo "Usage: make [target]"
	@echo "make deps     build and install frida and radare2 from git"
	@echo "make run      run r2frida"
	@echo "make install  install r2frida in $(BINDIR)"
	@echo "make help     show r2frida's help"

help:
	@grep ' - ' README.md

node_modules/frida:
	npm install
	cp -rf $(FRIDA_ROOT)/$(FRIDA_NODE) node_modules/frida

deps:
	$(MAKE) -C deps

run:
	cd src ; r2 r2pipe://"node r2io-frida.js vim"

install:
	ln -fs $(PWD)/bin/r2frida.js $(BINDIR)/r2frida

.PHONY: all help deps run install
