include config.mk

frida_version = 8.2.0
frida_os := $(shell uname -s | tr '[A-Z]' '[a-z]' | sed 's,^darwin$$,mac,')
frida_arch := $(shell uname -m | sed 's,i[0-9]86,i386,g')
frida_os_arch := $(frida_os)-$(frida_arch)

SO_EXT=dylib
CC?=gcc
CXX?=g++
CFLAGS+=-fPIC
LDFLAGS+=-shared

# R2
CFLAGS+=$(shell pkg-config --cflags r_io)
LDFLAGS+=$(shell pkg-config --libs r_io)
R2_PLUGDIR=$(shell r2 -hh | grep '^ 'RHOMEDIR | awk '{print $$2}')/plugins

# FRIDA
FRIDA_SDK=ext/frida/libfrida-core.a
FRIDA_SDK_URL=https://github.com/frida/frida/releases/download/$(frida_version)/frida-core-devkit-$(frida_version)-$(frida_os_arch).tar.xz
FRIDA_CPPFLAGS+=-Iext/frida
FRIDA_LDFLAGS+=-Wl,-no_compact_unwind
FRIDA_LIBS+=ext/frida/libfrida-core.a -lresolv
# OSX-FRIDA
ifeq ($(shell uname),Darwin)
FRIDA_LIBS+=-framework Foundation
FRIDA_LIBS+=-framework AppKit
endif

# CYCRIPT
CFLAGS+=-DWITH_CYCRIPT=$(WITH_CYCRIPT)
ifeq ($(WITH_CYCRIPT),1)
CYCRIPT_CPPFLAGS+=-Iext/cycript/src
CYCRIPT_ARCHIVE=ext/cycript/src/.libs/libcycript.a
CYCRIPT_LIBS+=$(CYCRIPT_ARCHIVE)
CYCRIPT_OBJ=src/cylang.o
else
CYCRIPT_CPPFLAGS=
CYCRIPT_ARCHIVE=
CYCRIPT_LIBS=
CYCRIPT_OBJ=
endif

all: io_frida.$(SO_EXT) ext/frida-$(frida_version)

config.mk:
	cp -f config.def.mk config.mk

io_frida.$(SO_EXT): src/io_frida.o $(CYCRIPT_OBJ)
	pkg-config --cflags r_core
	$(CXX) $^ -o $@ $(LDFLAGS) $(FRIDA_LDFLAGS) $(FRIDA_LIBS) $(CYCRIPT_LIBS)

src/io_frida.o: src/io_frida.c ext/frida/libfrida-core.a src/_agent.h
	$(CC) -c $(CFLAGS) $(FRIDA_CPPFLAGS) $< -o $@

src/_agent.h: src/_agent.js
	( \
		/bin/echo -n '"'; \
		awk '{ \
			gsub("\\\\", "\\\\"); \
			gsub("\"", "\\\""); \
			printf "%s\\n", $$0; \
		}' $<; \
		echo '"'; \
	) > $@

src/_agent.js: src/agent/index.js node_modules
	npm run build

node_modules: package.json
	npm install

clean:
	$(RM) src/*.o src/_agent.js src/_agent.h
	-$(MAKE) -C ext/cycript clean

mrproper: clean
	$(RM) $(FRIDA_SDK)
	$(RM) -r ext/cycript
	$(RM) -r ext/frida-$(frida_version)
	$(RM) ext/frida
	$(RM) -r ext/node


install:
	mkdir -p "$(R2_PLUGDIR)"
	cp -f io_frida.$(SO_EXT) "$(R2_PLUGDIR)"

uninstall:
	$(RM) "$(R2_PLUGDIR)/io_frida.$(SO_EXT)"

frida-sdk $(FRIDA_SDK):
	mkdir -p $(@D)/_
	curl -Ls $(FRIDA_SDK_URL) | xz -d | tar -C $(@D)/_ -xf -
	mv $(@D)/_/* $(@D)
	cd ext && mv frida frida-$(frida_version) ; ln -fs frida-$(frida_version) frida
	rmdir $(@D)/_

ext/frida-$(frida_version):
	$(MAKE) frida-sdk

update: ext/cycript/ext/node/lib
	-cd ext/cycript && git submodule update && rm -f ext/frida/libfrida-core.a

ifeq ($(WITH_CYCRIPT),1)
ext/cycript/ext/node/lib:
	mkdir -p ext/cycript ext/node/lib
	cd ext/cycript && git submodule init && git submodule update

ext/cycript/configure: ext/cycript/ext/node/lib
	cd ext/cycript && $(SHELL) ./autogen.sh

ext/cycript/Makefile: ext/cycript/configure
	cd ext/cycript && \
		$(SHELL) ./configure \
			--disable-console \
			--disable-engine \
			--disable-shared \
			--enable-static \
			--with-libclang="-rpath /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/libclang.dylib" \
			--with-python=/usr/bin/python-config

ext/cycript/src/.libs/libcycript.a: ext/cycript/Makefile
	$(MAKE) -C ext/cycript

src/cylang.o: src/cylang.cpp $(CYCRIPT_ARCHIVE)
	$(CXX) -c -std=c++11 $(CFLAGS) $(CXXFLAGS) $(FRIDA_CPPFLAGS) $(CYCRIPT_CPPFLAGS) $< -o $@
else
ext/cycript/ext/node/lib:
	@echo do nothing

src/cylang.o:
	touch src/cylong.o
endif

.PHONY: all clean install uninstall
