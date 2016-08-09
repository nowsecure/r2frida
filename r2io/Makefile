
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

all: frida-sdk
	$(CC) $(CFLAGS) $(LDFLAGS) io_frida.c -o io_frida.$(SO_EXT)

install:
	mkdir -p "$(R2_PLUGDIR)"
	cp -f io_frida.$(SO_EXT) "$(R2_PLUGDIR)"

frida-sdk:
	@echo Please grab it from https://github.com/frida/frida/releases
