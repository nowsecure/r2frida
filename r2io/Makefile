frida_version = 7.3.5
frida_os_arch = mac-x86_64

SO_EXT=dylib
CC?=gcc
CFLAGS+=-shared -fPIC

# R2
CFLAGS+=$(shell pkg-config --cflags r_io)
LDFLAGS+=$(shell pkg-config --libs r_io)
R2_PLUGDIR=$(shell r2 -hh | grep '^ 'RHOMEDIR | awk '{print $$2}')/plugins

# FRIDA
CFLAGS+=-Ifrida-sdk
CFLAGS+=-Wl,-no_compact_unwind
LDFLAGS+=frida-sdk/libfrida-core.a -lresolv
# OSX-FRIDA
LDFLAGS+=-framework Foundation
LDFLAGS+=-framework AppKit

all: frida-sdk/libfrida-core.a _agent.h
	$(CC) $(CFLAGS) $(LDFLAGS) io_frida.c -o io_frida.$(SO_EXT)

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
