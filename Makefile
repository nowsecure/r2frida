include config.mk

r2_version = 2.5.0
frida_version = 11.0.0

ifeq ($(shell uname -o 2> /dev/null),Android)
frida_os := android
else
frida_os := $(shell uname -s | tr '[A-Z]' '[a-z]' | sed 's,^darwin$$,macos,')
endif
frida_arch := $(shell uname -m | sed -e 's,i[0-9]86,i386,g' -e 's,armv7l,arm,g' -e 's,aarch64,arm64,g')
frida_os_arch := $(frida_os)-$(frida_arch)

WGET?=wget
CURL?=curl
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
CFLAGS+=$(shell pkg-config --cflags r_core r_io r_util)
LDFLAGS+=$(shell pkg-config --libs r_core r_io r_util)
R2_PLUGDIR=$(shell r2 -H USER_PLUGINS)

CXXFLAGS+=$(CFLAGS)

# FRIDA
FRIDA_SDK=ext/frida-$(frida_os)-$(frida_version)/libfrida-core.a
FRIDA_SDK_URL=https://github.com/frida/frida/releases/download/$(frida_version)/frida-core-devkit-$(frida_version)-$(frida_os_arch).tar.xz
FRIDA_CPPFLAGS+=-Iext/frida
ifeq ($(frida_os),android)
FRIDA_LIBS+=ext/frida/libfrida-core.a
else
FRIDA_LIBS+=ext/frida/libfrida-core.a -lresolv
endif

# OSX-FRIDA
ifeq ($(shell uname),Darwin)
  ifeq ($(frida_os),macos)
FRIDA_LDFLAGS+=-Wl,-no_compact_unwind
FRIDA_LIBS+=-framework Foundation
  endif
  ifeq ($(frida_os),ios)
FRIDA_LIBS+=-framework UIKit
FRIDA_LIBS+=-framework CoreGraphics
  else
  ifeq ($(frida_os),macos)
FRIDA_LIBS+=-lbsm
endif
  endif
  ifeq ($(frida_os),macos)
FRIDA_LIBS+=-framework AppKit
  endif
endif

ifeq ($(frida_os),android)
LDFLAGS+=-landroid -llog -lm
STRIP_SYMBOLS=yes
endif

ifeq ($(STRIP_SYMBOLS),yes)
LD_FLAGS+=-Wl,--version-script,ld.script
LD_FLAGS+=-Wl,--gc-sections
LD_FLAGS+=-Wl,-dead_strip
endif

# CYLANG
CFLAGS+=-DWITH_CYLANG=$(WITH_CYLANG)
ifeq ($(WITH_CYLANG),1)
CYLANG_CPPFLAGS+=-Iext/cycript/src
CYLANG_ARCHIVE=ext/cycript/src/.libs/libcycript.a
CYLANG_LIBS+=$(CYLANG_ARCHIVE)
CYLANG_OBJ=src/cylang.o
else
CYLANG_CPPFLAGS=
CYLANG_ARCHIVE=
CYLANG_LIBS=
CYLANG_OBJ=
endif

all: ext/frida
	$(MAKE) io_frida.$(SO_EXT)

IOS_ARCH=arm64
#armv7
IOS_ARCH_CFLAGS=$(addprefix -arch ,$(IOS_ARCH))
IOS_CC=xcrun --sdk iphoneos gcc $(IOS_ARCH_CFLAGS)
IOS_CXX=xcrun --sdk iphoneos g++ $(IOS_ARCH_CFLAGS)

.PHONY: io_frida.$(SO_EXT)

# XXX we are statically linking to the .a we should use shared libs if exist
ios: r2-sdk-ios/$(r2_version)
	$(MAKE) \
	CFLAGS="-Ir2-sdk-ios/include -Ir2-sdk-ios/include/libr" \
	LDFLAGS="-Lr2-sdk-ios/lib -lr -shared -fPIC" \
	CC="$(IOS_CC)" CXX="$(IOS_CXX)" frida_os=ios frida_arch=arm64

r2-sdk-ios/$(r2_version):
	rm -rf r2-sdk-ios
	wget http://radare.mikelloc.com/get/$(r2_version)/radare2-ios-arm64-$(r2_version).tar.gz
	mkdir -p r2-sdk-ios/$(r2_version)
	tar xzvf radare2-ios-arm64-$(r2_version).tar.gz -C r2-sdk-ios
	mv r2-sdk-ios/*/* r2-sdk-ios
	rm -f radare2-ios-arm64-$(r2_version).tar.gz

.PHONY: ext/frida

ext/frida: $(FRIDA_SDK)
	[ "`readlink ext/frida`" = frida-$(frida_os)-$(frida_version) ] || \
		(cd ext && rm -f frida ; ln -fs frida-$(frida_os)-$(frida_version) frida)

config.mk:
	./configure

io_frida.$(SO_EXT): src/io_frida.o $(CYLANG_OBJ)
	pkg-config --cflags r_core
	$(CXX) $^ -o $@ $(LDFLAGS) $(FRIDA_LDFLAGS) $(FRIDA_LIBS) $(CYLANG_LIBS)

src/io_frida.o: src/io_frida.c $(FRIDA_SDK) src/_agent.h
	$(CC) -c $(CFLAGS) $(FRIDA_CPPFLAGS) $< -o $@

src/_agent.h: src/_agent.js
	xxd -i < $< > $@

src/_agent.js: src/agent/index.js src/agent/plugin.js node_modules
	npm run build

node_modules: package.json
	npm install

radare2-android-arm64-libs:
	wget -c http://termux.net/dists/stable/main/binary-aarch64/radare2_2.4.0_aarch64.deb
	wget -c http://termux.net/dists/stable/main/binary-aarch64/radare2-dev_2.4.0_aarch64.deb
	mkdir -p radare2-android-arm64-libs
	cd radare2-android-arm64-libs ; 7z x ../radare2_2.4.0_aarch64.deb ; tar xzvf data.tar.gz || tar xJvf data.tar.xz
	cd radare2-android-arm64-libs ; 7z x ../radare2-dev_2.4.0_aarch64.deb ; tar xzvf data.tar.gz || tar xJvf data.tar.xz
	ln -fs radare2-android-arm64-libs//data/data/com.termux/files/
	
R2A_DIR=$(shell pwd)/radare2-android-arm64-libs/data/data/com.termux/files/usr

android-arm64: radare2-android-arm64-libs
	$(MAKE) frida_os=android frida_arch=arm64 CC=ndk-gcc CXX=ndk-g++ \
		CFLAGS="$(CFLAGS) -I$(R2A_DIR)/include" \
		LDFLAGS="$(LDFLAGS) -L$(R2A_DIR)/lib" SO_EXT=so

clean:
	$(RM) src/*.o src/_agent.js src/_agent.h
	$(RM) -rf radare2-android-arm64-libs

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
	@echo FRIDA_SDK=$(FRIDA_SDK)
	$(MAKE) $(FRIDA_SDK)

$(FRIDA_SDK):
	rm -f ext/frida
	mkdir -p $(@D)/_
ifeq ($(USE_WGET),1)
	$(WGET) -cO frida-sdk.tar.xz $(FRIDA_SDK_URL)
	tar xJvf frida-sdk.tar.xz -C $(@D)/_
else
	curl -Ls $(FRIDA_SDK_URL) | xz -d | tar -C $(@D)/_ -xf -
endif
	mv $(@D)/_/* $(@D)
	rmdir $(@D)/_
	#mv ext/frida ext/frida-$(frida_os)-$(frida_version)
	cd ext && ln -fs frida-$(frida_os)-$(frida_version) frida

update: ext/cycript/ext/node/lib
	-cd ext/cycript && git submodule update && $(RM) ext/frida/libfrida-core.a

ifeq ($(WITH_CYLANG),1)
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

src/cylang.o: src/cylang.cpp $(CYLANG_ARCHIVE)
	$(CXX) -c -std=c++11 $(CFLAGS) $(CXXFLAGS) $(FRIDA_CPPFLAGS) $(CYLANG_CPPFLAGS) $< -o $@
else
ext/cycript/ext/node/lib:
	@echo do nothing

src/cylang.o:
	touch src/cylang.o
endif

.PHONY: all clean install uninstall
