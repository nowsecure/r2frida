# Prepare the r2frida sources to be statically linked inside radare2.
# Downloads the frida-core devkit and the precompiled agent and generates
# config.h without requiring radare2 to be installed. See README.md

R2FRIDA_ROOT=..
FRIDA_VERSION=$(shell sed -n 's/^set frida_version=//p' $(R2FRIDA_ROOT)/make.bat | tr -d '\r')
R2FRIDA_VERSION=$(shell sed -n 's/^set r2frida_version=//p' $(R2FRIDA_ROOT)/make.bat | tr -d '\r')
PREFIX?=/usr/local

FRIDA_OS?=$(shell uname -s | tr '[A-Z]' '[a-z]' | sed 's,^darwin$$,macos,')
FRIDA_ARCH?=$(shell uname -m | sed -e 's,i[0-9]86,x86,g' -e 's,armv.*,armhf,g' -e 's,aarch64,arm64,g')
FRIDA_OS_ARCH?=$(FRIDA_OS)-$(FRIDA_ARCH)
FRIDA_SDK_DIR=$(R2FRIDA_ROOT)/ext/frida-$(FRIDA_OS)-$(FRIDA_VERSION)
FRIDA_SDK_URL=https://github.com/frida/frida/releases/download/$(FRIDA_VERSION)/frida-core-devkit-$(FRIDA_VERSION)-$(FRIDA_OS_ARCH).tar.xz
R2FRIDA_AGENT_URL?=https://github.com/nowsecure/r2frida/releases/download/$(R2FRIDA_VERSION)/_agent.js

DLCMD=$(shell command -v curl > /dev/null && echo 'curl -Lfso' || echo 'wget -qO')

all: $(R2FRIDA_ROOT)/ext/frida/frida-core.h $(R2FRIDA_ROOT)/config.h $(R2FRIDA_ROOT)/src/_agent.h

$(R2FRIDA_ROOT)/ext/frida/frida-core.h: $(FRIDA_SDK_DIR)/frida-core.h
	cd $(R2FRIDA_ROOT)/ext && rm -f frida && ln -fs frida-$(FRIDA_OS)-$(FRIDA_VERSION) frida

$(FRIDA_SDK_DIR)/frida-core.h:
	mkdir -p $(FRIDA_SDK_DIR)
	$(DLCMD) $(FRIDA_SDK_DIR)/sdk.tar.xz $(FRIDA_SDK_URL)
	xz -dc $(FRIDA_SDK_DIR)/sdk.tar.xz | tar -C $(FRIDA_SDK_DIR) -xf -
	rm -f $(FRIDA_SDK_DIR)/sdk.tar.xz

$(R2FRIDA_ROOT)/config.h: $(R2FRIDA_ROOT)/config.h.acr $(R2FRIDA_ROOT)/make.bat
	sed -e 's,@PREFIX@,$(PREFIX),' -e 's,@DATADIR@,$(PREFIX)/share,' \
		-e 's,@VERSION@,$(R2FRIDA_VERSION),' -e '/^#endif/d' $< > $@.tmp
	echo '#ifndef FRIDA_VERSION_STRING' >> $@.tmp
	echo '#define FRIDA_VERSION_STRING "$(FRIDA_VERSION)"' >> $@.tmp
	echo '#define FRIDA_VERSION_MAJOR $(firstword $(subst ., ,$(FRIDA_VERSION)))' >> $@.tmp
	echo '#endif' >> $@.tmp
	echo '#ifndef WANT_SESSION_DEBUGGER' >> $@.tmp
	echo '#define WANT_SESSION_DEBUGGER 1' >> $@.tmp
	echo '#endif' >> $@.tmp
	echo '#endif' >> $@.tmp
	mv $@.tmp $@

# reuses src/_agent.js if it was already built with `make -C src/agent`
$(R2FRIDA_ROOT)/src/_agent.h: $(R2FRIDA_ROOT)/src/_agent.js
	od -An -v -tx1 $< | sed -e 's/ *\([0-9a-f][0-9a-f]\)/0x\1, /g' -e 's/ *$$//' > $@

# the agent is only published once a release is cut, so an unreleased
# version (i.e. master right after a version bump) must build it locally
$(R2FRIDA_ROOT)/src/_agent.js:
	$(DLCMD) $@ $(R2FRIDA_AGENT_URL) || { rm -f $@; \
		echo "Cannot download $(R2FRIDA_AGENT_URL)"; \
		echo "Build the agent with 'make -C $(R2FRIDA_ROOT) src/_agent.js' or set R2FRIDA_AGENT_URL"; \
		exit 1; }
	test -s $@ || { rm -f $@; exit 1; }

clean:
	rm -rf $(R2FRIDA_ROOT)/build/r2plugin

.PHONY: all clean
