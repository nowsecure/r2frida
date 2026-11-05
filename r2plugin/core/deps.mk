R2FRIDA_WD=$(LIBR)/xps/p/r2frida
R2FRIDA_BD=$(R2FRIDA_WD)/build/r2plugin
CFLAGS+=-I$(R2FRIDA_WD)/ext/frida
R2FRIDA_OBJ=\
	$(R2FRIDA_BD)/src/io_frida.o \
	$(R2FRIDA_BD)/src/diagnostics.o \
	$(R2FRIDA_BD)/src/systrace.o \
	$(R2FRIDA_BD)/r2plugin/core/core_r2frida.o
EXTERNAL_STATIC_OBJS+=$(R2FRIDA_OBJ)

# frida-core devkit, config.h and the precompiled agent
R2FRIDA_PREPARED=$(R2FRIDA_WD)/ext/frida/frida-core.h $(R2FRIDA_WD)/config.h $(R2FRIDA_WD)/src/_agent.h

$(R2FRIDA_PREPARED):
	$(MAKE) -C $(R2FRIDA_WD)/r2plugin

$(R2FRIDA_OBJ): $(R2FRIDA_PREPARED) $(R2FRIDA_WD)/src/io_frida.h

# separate build dir to not reuse objects from the standalone (non-incore) build
$(R2FRIDA_BD)/%.o: $(R2FRIDA_WD)/%.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) -o $@ $<

LINK+=$(R2FRIDA_WD)/ext/frida/libfrida-core.a
ifeq ($(OSTYPE),darwin)
LINK+=-Wl,-no_compact_unwind -lbsm -lresolv
LINK+=-framework Foundation -framework IOKit -framework Security
LINK+=-framework AppKit -framework CoreFoundation -framework CoreServices
else ifeq ($(OSTYPE),android)
LINK+=-landroid -llog -lm -ldl
else
LINK+=-lresolv -lm -ldl -lpthread
endif
