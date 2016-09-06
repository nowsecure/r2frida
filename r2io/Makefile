frida_version = 7.3.5
frida_os_arch = mac-x86_64

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
FRIDA_CPPFLAGS+=-Ifrida-sdk
FRIDA_LDFLAGS+=-Wl,-no_compact_unwind
FRIDA_LIBS+=frida-sdk/libfrida-core.a -lresolv
# OSX-FRIDA
FRIDA_LIBS+=-framework Foundation
FRIDA_LIBS+=-framework AppKit

# CYCRIPT
CYCRIPT_CPPFLAGS+=-Icycript/src
CYCRIPT_LIBS+=cycript/src/.libs/libcycript.a

all: io_frida.o cylang.o
	$(CXX) $^ -o io_frida.$(SO_EXT) $(LDFLAGS) $(FRIDA_LDFLAGS) $(FRIDA_LIBS) $(CYCRIPT_LIBS)

io_frida.o: io_frida.c frida-sdk/libfrida-core.a _agent.h
	$(CC) -c $(CFLAGS) $(FRIDA_CPPFLAGS) io_frida.c

cylang.o: cylang.cpp cycript/src/.libs/libcycript.a
	$(CXX) -c -std=c++11 $(CFLAGS) $(CXXFLAGS) $(FRIDA_CPPFLAGS) $(CYCRIPT_CPPFLAGS) cylang.cpp

_agent.h: _agent.js
	( \
		/bin/echo -n '"'; \
		awk '{ \
			gsub("\\\\", "\\\\"); \
			gsub("\"", "\\\""); \
			printf "%s\\n", $$0; \
		}' $<; \
		echo '"'; \
	) > $@

_agent.js: agent/index.js
	npm install

install: all
	mkdir -p "$(R2_PLUGDIR)"
	cp -f io_frida.$(SO_EXT) "$(R2_PLUGDIR)"

frida-sdk/libfrida-core.a:
	mkdir -p $(@D)/_
	curl -Ls https://github.com/frida/frida/releases/download/$(frida_version)/frida-core-devkit-$(frida_version)-$(frida_os_arch).tar.xz | xz -d | tar -C $(@D)/_ -xf -
	mv $(@D)/_/* $(@D)
	rmdir $(@D)/_

cycript/ext/node/lib:
	cd cycript && git submodule init && git submodule update

cycript/configure: cycript/ext/node/lib
	cd cycript && $(SHELL) ./autogen.sh

cycript/Makefile: cycript/configure
	cd cycript && \
		$(SHELL) ./configure \
			--disable-console \
			--disable-engine \
			--disable-shared \
			--enable-static \
			--with-libclang="-rpath /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/libclang.dylib" \
			--with-python=/usr/bin/python-config

cycript/src/.libs/libcycript.a: cycript/Makefile
	$(MAKE) -C cycript
