frida_version = 8.0.0
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
FRIDA_CPPFLAGS+=-Iext/frida
FRIDA_LDFLAGS+=-Wl,-no_compact_unwind
FRIDA_LIBS+=ext/frida/libfrida-core.a -lresolv
# OSX-FRIDA
FRIDA_LIBS+=-framework Foundation
FRIDA_LIBS+=-framework AppKit

# CYCRIPT
CYCRIPT_CPPFLAGS+=-Iext/cycript/src
CYCRIPT_LIBS+=ext/cycript/src/.libs/libcycript.a

all: io_frida.$(SO_EXT)

io_frida.$(SO_EXT): src/io_frida.o src/cylang.o
	pkg-config --cflags r_core
	$(CXX) $^ -o $@ $(LDFLAGS) $(FRIDA_LDFLAGS) $(FRIDA_LIBS) $(CYCRIPT_LIBS)

src/io_frida.o: src/io_frida.c ext/frida/libfrida-core.a src/_agent.h
	$(CC) -c $(CFLAGS) $(FRIDA_CPPFLAGS) $< -o $@

src/cylang.o: src/cylang.cpp ext/cycript/src/.libs/libcycript.a
	$(CXX) -c -std=c++11 $(CFLAGS) $(CXXFLAGS) $(FRIDA_CPPFLAGS) $(CYCRIPT_CPPFLAGS) $< -o $@

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
	$(MAKE) -C ext/cycript clean

install: all
	mkdir -p "$(R2_PLUGDIR)"
	cp -f io_frida.$(SO_EXT) "$(R2_PLUGDIR)"

uninstall:
	rm -f "$(R2_PLUGDIR)/io_frida.$(SO_EXT)"

ext/frida/libfrida-core.a:
	mkdir -p $(@D)/_
	curl -Ls https://github.com/frida/frida/releases/download/$(frida_version)/frida-core-devkit-$(frida_version)-$(frida_os_arch).tar.xz | xz -d | tar -C $(@D)/_ -xf -
	mv $(@D)/_/* $(@D)
	rmdir $(@D)/_

ext/cycript/ext/node/lib:
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

.PHONY: all clean install uninstall
