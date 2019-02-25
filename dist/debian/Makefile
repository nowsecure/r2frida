include ./CONFIG

DEPENDS=
CROSSARCH=x64
PWD=$(shell pwd)
PACKAGE_DIR?=${PWD}

DOCKCROSS=$(PWD)/../dockcross
R2PLUGDIR=/usr/lib/radare2/$(VERSION)

all: root
	sudo rm -rf control data
	${MAKE} clean
	mkdir -p data
	cp -rf root/* data
	${MAKE} control
	${MAKE} deb

root:
	cd ../.. && $(MAKE) clean ; ./configure --prefix=/usr ; npm i ; \
	$(DOCKCROSS) --image dockcross/linux-$(CROSSARCH) bash -c 'sh dist/build.sh'
	mkdir -p root/$(R2PLUGDIR)
	cp -f ../../io_frida.so root/$(R2PLUGDIR)

purge: clean
	rm -rf root

summary:
	echo $(VERSION)

include deb.mk
