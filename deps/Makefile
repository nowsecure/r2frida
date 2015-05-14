all: frida radare2

frida:
	git clone https://github.com/frida/frida
	./frida-git.sh update

radare2:
	git clone https://github.com/radare/radare2
	cd radare2 ; sys/install.sh

.PHONY: all
