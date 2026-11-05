EXTERNAL_PLUGINS+=r2frida

.PHONY: r2frida

r2frida: p/r2frida

p/r2frida:
	cd p && git clone --depth=1 https://github.com/nowsecure/r2frida
	$(MAKE) -C p/r2frida/r2plugin
