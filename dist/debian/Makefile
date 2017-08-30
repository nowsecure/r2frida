include ./CONFIG

DEPENDS=
ARCH=amd64
PWD=$(shell pwd)
PACKAGE_DIR?=${PWD}

DOCKCROSS=$(PWD)/../dockcross
R2PLUGDIR=/usr/lib/radare2/last


all: root
	sudo rm -rf control data
	${MAKE} clean
	mkdir -p data
	cp -rf root/* data
	${MAKE} control
	${MAKE} deb

root:
	cd ../.. ; \
	$(DOCKCROSS) --image dockcross/linux-$(ARCH) bash -c \
	"R2_PLUGDIR=$(R2PLUGDIR) DESTDIR=$(PWD)/root bash dist/deps.sh"
	mkdir -p root/$(R2PLUGDIR)
	cp ../../io_frida.so root/$(R2PLUGDIR)

include deb.mk
