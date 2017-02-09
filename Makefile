include config.mk

frida_version = 9.1.6
frida_os := $(shell uname -s | tr '[A-Z]' '[a-z]' | sed 's,^darwin$$,mac,')
frida_arch := $(shell uname -m | sed 's,i[0-9]86,i386,g')
frida_os_arch := $(frida_os)-$(frida_arch)

DESTDIR?=

ifeq ($(shell uname),Darwin)
SO_EXT=dylib
else
SO_EXT=so
endif
CC?=gcc
CXX?=g++
CFLAGS+=-fPIC
LDFLAGS+=-shared -fPIC

# R2
CFLAGS+=$(shell pkg-config --cflags r_io)
LDFLAGS+=$(shell pkg-config --libs r_io)
R2_PLUGDIR=$(shell r2 -hh | grep '^ 'RHOMEDIR | awk '{print $$2}')/plugins

CXXFLAGS+=$(CFLAGS)

# FRIDA
FRIDA_SDK=ext/frida-$(frida_os)-$(frida_version)/libfrida-core.a
FRIDA_SDK_URL=https://github.com/frida/frida/releases/download/$(frida_version)/frida-core-devkit-$(frida_version)-$(frida_os_arch).tar.xz
FRIDA_CPPFLAGS+=-Iext/frida
FRIDA_LIBS+=ext/frida/libfrida-core.a -lresolv
# OSX-FRIDA
ifeq ($(shell uname),Darwin)
FRIDA_LDFLAGS+=-Wl,-no_compact_unwind
FRIDA_LIBS+=-framework Foundation
ifeq ($(frida_os),ios)
FRIDA_LIBS+=-framework UIKit
FRIDA_LIBS+=-framework CoreGraphics
else
FRIDA_LIBS+=-lbsm
endif
ifeq ($(frida_os),mac)
FRIDA_LIBS+=-framework AppKit
endif
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

all: ext/frida
	$(MAKE) io_frida.$(SO_EXT)

IOS_ARCH=arm64 armv7
IOS_ARCH_CFLAGS=$(addprefix -arch ,$(IOS_ARCH))
IOS_CC=xcrun --sdk iphoneos gcc $(IOS_ARCH_CFLAGS)
IOS_CXX=xcrun --sdk iphoneos g++ $(IOS_ARCH_CFLAGS)

.PHONY: io_frida.$(SO_EXT)

ios:
	$(MAKE) CC="$(IOS_CC)" CXX="$(IOS_CXX)" frida_os=ios frida_arch=arm64

.PHONY: ext/frida

ext/frida: $(FRIDA_SDK)
	[ "`readlink ext/frida`" = frida-$(frida_os)-$(frida_version) ] || \
		(cd ext && rm frida ; ln -fs frida-$(frida_os)-$(frida_version) frida)

config.mk:
	cp -f config.def.mk config.mk

io_frida.$(SO_EXT): src/io_frida.o $(CYCRIPT_OBJ)
	pkg-config --cflags r_core
	$(CXX) $^ -o $@ $(LDFLAGS) $(FRIDA_LDFLAGS) $(FRIDA_LIBS) $(CYCRIPT_LIBS)

src/io_frida.o: src/io_frida.c $(FRIDA_SDK) src/_agent.h
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

src/_agent.js: src/agent/index.js src/agent/plugin.js node_modules
	npm run build

node_modules: package.json
	npm install

clean:
	$(RM) src/*.o src/_agent.js src/_agent.h

cycript-clean clean2:
	-$(MAKE) -C ext/cycript clean

mrproper: clean
	$(RM) $(FRIDA_SDK)
	$(RM) -r ext/cycript
	$(RM) -r ext/frida-$(frida_version)
	$(RM) ext/frida
	$(RM) -r ext/node

install:
	mkdir -p $(DESTDIR)/"$(R2_PLUGDIR)"
	cp -f io_frida.$(SO_EXT) $(DESTDIR)/"$(R2_PLUGDIR)"

uninstall:
	$(RM) $(DESTDIR)/"$(R2_PLUGDIR)/io_frida.$(SO_EXT)"

frida-sdk: ext/frida-$(frida_os)-$(frida_version)
	rm -f ext/frida
	cd ext && ln -fs frida-$(frida_os)-$(frida_version) frida

ext/frida-$(frida_os)-$(frida_version):
	echo $(FRIDA_SDK)
	$(MAKE) $(FRIDA_SDK)

$(FRIDA_SDK):
	rm -f ext/frida
	mkdir -p $(@D)/_
	curl -Ls $(FRIDA_SDK_URL) | xz -d | tar -C $(@D)/_ -xf -
	mv $(@D)/_/* $(@D)
	rmdir $(@D)/_
	#mv ext/frida ext/frida-$(frida_os)-$(frida_version)
	cd ext && ln -fs frida-$(frida_os)-$(frida_version) frida

update: ext/cycript/ext/node/lib
	-cd ext/cycript && git submodule update && $(RM) ext/frida/libfrida-core.a

ifeq ($(WITH_CYCRIPT),1)
ext/cycript/ext/node/lib:
	mkdir -p ext/cycript ext/node/lib
	cd ext/cycript && git submodule init && git submodule update
	-cd ext/cycript && yes n | patch -p1 < ../../cycript.patch

ext/cycript/configure: ext/cycript/ext/node/lib
	cd ext/cycript && $(SHELL) ./autogen.sh

ifeq ($(shell uname),Darwin)
CLANG=-rpath /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/libclang.dylib
else
CLANG=no
endif

ext/cycript/Makefile: ext/cycript/configure
	CFLAGS="$(CFLAGS)" \
	CXXFLAGS="$(CXXFLAGS)" \
	LDFLAGS="$(LDFLAGS)" \
	cd ext/cycript && \
		$(SHELL) ./configure \
			--disable-console \
			--disable-engine \
			--disable-shared \
			--enable-static \
			--with-libclang="$(CLANG)" \
			--with-python=/usr/bin/python-config

ext/cycript/src/.libs/libcycript.a: ext/cycript/Makefile
	$(MAKE) -C ext/cycript CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)" LDFLAGS="$(LDFLAGS)" V=1 -j4

src/cylang.o: src/cylang.cpp $(CYCRIPT_ARCHIVE)
	$(CXX) -c -std=c++11 $(CFLAGS) $(CXXFLAGS) $(FRIDA_CPPFLAGS) $(CYCRIPT_CPPFLAGS) $< -o $@
else
ext/cycript/ext/node/lib:
	@echo do nothing

src/cylang.o:
	touch src/cylong.o
endif

.PHONY: all clean install uninstall
