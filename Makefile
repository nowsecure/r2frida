include config.mk

R2V=$(VERSION)
R2V=5.7.2
frida_version=15.2.2
R2FRIDA_PRECOMPILED_AGENT?=0
R2FRIDA_PRECOMPILED_AGENT_URL=https://github.com/nowsecure/r2frida/releases/download/5.7.4/_agent.js

CFLAGS+=-DFRIDA_VERSION_STRING=\"${frida_version}\"

ifeq ($(strip $(frida_os)),)
ifeq ($(shell uname -o 2> /dev/null),Android)
frida_os := android
else
frida_os := $(shell uname -s | tr '[A-Z]' '[a-z]' | sed 's,^darwin$$,macos,')
endif
endif

ifeq ($(frida_os),android)
frida_arch := $(shell uname -m | sed -e 's,i[0-9]86,x86,g' -e 's,armv.*,arm,g' -e 's,aarch64,arm64,g')
else
frida_arch := $(shell uname -m | sed -e 's,i[0-9]86,x86,g' -e 's,armv.*,armhf,g' -e 's,aarch64,arm64,g')
endif
frida_os_arch := $(frida_os)-$(frida_arch)

WGET?=wget
CURL?=curl

ifneq ($(shell $(WGET) --help > /dev/null 2>&1),)
USE_WGET=1
DLCMD=$(WGET) -c
else
USE_WGET=0
DLCMD=$(CURL) -L
endif

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

CFLAGS+=-g
LDFLAGS+=-g

# R2
CFLAGS+=$(shell pkg-config --cflags r_core r_io r_util)
ifeq ($(frida_os),android)
LDFLAGS+=$(subst -lssl,,$(shell pkg-config --libs r_core r_io r_util))
else
LDFLAGS+=$(shell pkg-config --libs r_core r_io r_util)
endif
R2_PLUGDIR=$(shell r2 -H R2_USER_PLUGINS)
R2_PLUGSYS=$(shell r2 -H R2_LIBR_PLUGINS)
ifeq ($(R2_PLUGDIR),)
r2:
	@echo Please install r2
	@exit 1
endif

CXXFLAGS+=$(CFLAGS)

USE_ASAN?=0
ifeq ($(USE_ASAN),1)
ASAN_CFLAGS=-fsanitize=address,undefined,signed-integer-overflow,integer-divide-by-zero
ASAN_LDFLAGS=$(ASAN_CFLAGS)
CFLAGS+=$(ASAN_CFLAGS)
LDFLAGS+=$(ASAN_LDFLAGS)
endif

WANT_SESSION_DEBUGGER?=1

CFLAGS+=-DWANT_SESSION_DEBUGGER=$(WANT_SESSION_DEBUGGER)

# FRIDA
FRIDA_SDK=ext/frida-$(frida_os)-$(frida_version)/libfrida-core.a
FRIDA_SDK_URL=https://github.com/frida/frida/releases/download/$(frida_version)/frida-core-devkit-$(frida_version)-$(frida_os_arch).tar.xz
FRIDA_CPPFLAGS+=-Iext/frida
FRIDA_CORE_LIBS=ext/frida/libfrida-core.a
#FRIDA_CORE_LIBS=$(shell find /tmp/lib/*.a)
ifneq ($(frida_os),android)
FRIDA_LIBS+=-lresolv
endif

FRIDA_LIBS+=$(FRIDA_CORE_LIBS)

# OSX-FRIDA
ifeq ($(shell uname),Darwin)
LDFLAGS+=-Wl,-exported_symbol,_radare_plugin
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
LDFLAGS+=-Wl,--version-script,ld.script
LDFLAGS+=-Wl,--gc-sections
endif

all: .git/modules/ext ext/frida
	$(MAKE) io_frida.$(SO_EXT)

deb:
	$(MAKE) -C dist/debian

IOS_ARCH=arm64
#armv7
IOS_ARCH_CFLAGS=$(addprefix -arch ,$(IOS_ARCH))
IOS_CC=xcrun --sdk iphoneos gcc $(IOS_ARCH_CFLAGS)
IOS_CXX=xcrun --sdk iphoneos g++ $(IOS_ARCH_CFLAGS)

.PHONY: io_frida.$(SO_EXT)

# XXX we are statically linking to the .a we should use shared libs if exist
ios: r2-sdk-ios/$(R2V)
	$(MAKE) \
	CFLAGS="-Ir2-sdk-ios/include -Ir2-sdk-ios/include/libr" \
	LDFLAGS="-Lr2-sdk-ios/lib -lr -shared -fPIC" \
	CC="$(IOS_CC)" CXX="$(IOS_CXX)" frida_os=ios frida_arch=arm64

r2-sdk-ios/$(R2V):
	rm -rf r2-sdk-ios
	$(DLCMD) https://github.com/radareorg/radare2/releases/download/$(R2V)/r2ios-sdk-$(R2V).zip
	mkdir -p r2-sdk-ios/$(R2V)
	tar xzvf radare2-ios-arm64-$(R2V).tar.gz -C r2-sdk-ios
	mv r2-sdk-ios/*/* r2-sdk-ios
	rm -f radare2-ios-arm64-$(R2V).tar.gz

.PHONY: ext/frida asan

asan:
	$(MAKE) clean
	$(MAKE) USE_ASAN=1

ext/frida: $(FRIDA_SDK)
	[ "`readlink ext/frida`" = frida-$(frida_os)-$(frida_version) ] || \
		(cd ext && rm -f frida ; ln -fs frida-$(frida_os)-$(frida_version) frida)

config.mk:
	./configure

io_frida.$(SO_EXT): src/io_frida.o
	pkg-config --cflags r_core
	$(CXX) $^ -o $@ $(LDFLAGS) $(FRIDA_LDFLAGS) $(FRIDA_LIBS)

src/io_frida.o: src/io_frida.c $(FRIDA_SDK) src/_agent.h
	$(CC) -c $(CFLAGS) $(FRIDA_CPPFLAGS) $< -o $@

.git/modules/ext:
	git submodule update --init

src/_agent.h: src/_agent.js
	r2 -nfqcpc $< | grep 0x > $@

ifeq ($(R2FRIDA_PRECOMPILED_AGENT),1)
src/_agent.js:
ifeq ($(USE_WGET),1)
	$(WGET) -O src/_agent.js $(R2FRIDA_PRECOMPILED_AGENT_URL)
else
	$(CURL) -Lo src/_agent.js $(R2FRIDA_PRECOMPILED_AGENT_URL)
endif
else
src/_agent.js: src/agent/index.js src/agent/plugin.js node_modules
	npm run build
endif

node_modules: package.json
	mkdir -p node_modules
	npm i

R2A_ROOT=$(shell pwd)/radare2-android-libs

R2S=~/prg/radare2/sys/android-shell.sh

android:
	# git clean -xdf
	rm -rf ext
	# building for arm64
	touch src/io_frida.c
	$(R2S) aarch64 $(MAKE) android-arm64 frida_os=android
ifeq ($(STRIP_SYMBOLS),yes)
	$(R2S) aarch64 aarch64-linux-android-strip io_frida.so
endif
	cp -f io_frida.so /tmp/io_frida-$(R2V)-android-arm64.so
	# git clean -xdf
	touch src/io_frida.c
	rm -rf ext
	# building for arm
	$(R2S) arm $(MAKE) android-arm frida_os=android
ifeq ($(STRIP_SYMBOLS),yes)
	$(R2S) arm arm-linux-androideabi-strip io_frida.so
endif
	cp -f io_frida.so /tmp/io_frida-$(R2V)-android-arm.so

radare2-android-arm64-libs:
	$(DLCMD) http://termux.net/dists/stable/main/binary-aarch64/radare2_${R2V}_aarch64.deb
	$(DLCMD) http://termux.net/dists/stable/main/binary-aarch64/radare2-dev_${R2V}_aarch64.deb
	mkdir -p $(R2A_ROOT)
	cd $(R2A_ROOT) && 7z x -y ../radare2_${R2V}_aarch64.deb && tar xzvf data.tar.gz || tar xJvf data.tar.xz
	cd $(R2A_ROOT) && 7z x -y ../radare2-dev_${R2V}_aarch64.deb && tar xzvf data.tar.gz || tar xJvf data.tar.xz
	ln -fs $(R2A_ROOT)/data/data/com.termux/files/

R2A_DIR=$(R2A_ROOT)/data/data/com.termux/files/usr

android-arm64: radare2-android-arm64-libs
	$(MAKE) frida_os=android frida_arch=arm64 CC=ndk-gcc CXX=ndk-g++ \
		CFLAGS="-I$(R2A_DIR)/include/libr $(CFLAGS)" \
		LDFLAGS="-L$(R2A_DIR)/lib $(LDFLAGS)" SO_EXT=so

radare2-android-arm-libs:
	$(DLCMD) http://termux.net/dists/stable/main/binary-arm/radare2_$(R2V)_arm.deb
	$(DLCMD) http://termux.net/dists/stable/main/binary-arm/radare2-dev_$(R2V)_arm.deb
	mkdir -p $(R2A_ROOT)
	cd $(R2A_ROOT) ; 7z x -y ../radare2_$(R2V)_arm.deb ; tar xzvf data.tar.gz || tar xJvf data.tar.xz
	cd $(R2A_ROOT) ; 7z x -y ../radare2-dev_$(R2V)_arm.deb ; tar xzvf data.tar.gz || tar xJvf data.tar.xz
	ln -fs $(R2A_ROOT)/data/data/com.termux/files/

android-arm: radare2-android-arm-libs
	$(MAKE) frida_os=android frida_arch=arm CC=ndk-gcc CXX=ndk-g++ \
		CFLAGS="-I$(R2A_DIR)/include/libr $(CFLAGS)" \
		LDFLAGS="-L$(R2A_DIR)/lib $(LDFLAGS)" SO_EXT=so

clean:
	$(RM) src/*.o src/_agent.js src/_agent.h
	$(RM) -rf $(R2A_DIR)

mrproper: clean
	$(RM) $(FRIDA_SDK)
	$(RM) -r ext/frida-$(frida_version)
	$(RM) ext/frida
	$(RM) -r ext/node

# user wide

user-install:
	mkdir -p $(DESTDIR)/"$(R2_PLUGDIR)"
	$(RM) "$(DESTDIR)/$(R2_PLUGDIR)/io_frida.$(SO_EXT)"
	cp -f io_frida.$(SO_EXT)* $(DESTDIR)/"$(R2_PLUGDIR)"

user-uninstall:
	$(RM) "$(DESTDIR)/$(R2_PLUGDIR)/io_frida.$(SO_EXT)"

user-symstall:
	mkdir -p "$(DESTDIR)/$(R2_PLUGDIR)"
	ln -fs $(shell pwd)/io_frida.$(SO_EXT)* $(DESTDIR)/"$(R2_PLUGDIR)"

# system wide

install:
	mkdir -p "$(DESTDIR)/$(R2_PLUGSYS)"
	cp -f io_frida.$(SO_EXT)* $(DESTDIR)/"$(R2_PLUGSYS)"

symstall:
	mkdir -p "$(DESTDIR)/$(R2_PLUGSYS)"
	ln -fs $(shell pwd)/io_frida.$(SO_EXT)* $(DESTDIR)/"$(R2_PLUGSYS)"

uninstall:
	$(RM) "$(DESTDIR)/$(R2_PLUGSYS)/io_frida.$(SO_EXT)"

release:
	$(MAKE) android STRIP_SYMBOLS=yes
	$(MAKE) -C dist/debian

indent fix: node_modules
	node_modules/.bin/semistandard --fix src/agent/*.js

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

update:
	git submodule update && $(RM) ext/frida/libfrida-core.a

.PHONY: all clean install uninstall release symstall
