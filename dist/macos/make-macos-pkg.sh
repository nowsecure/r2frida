#!/bin/sh

# to uninstall:
# pkgutil --only-files --files org.radare.r2frida | (cd / && sudo xargs rm -f)
# sudo pkgutil --forget org.radare.r2frida

SRC=/tmp/r2frida-macos
PREFIX=/usr/local
ARM64CHK=`echo "$CFLAGS $ARCHFLAGS" | grep arm64`
if [ -n "$ARM64CHK" ]; then
        # crossbuild arm64 build
        ARCH=m1
elif [ "`uname -m`" = arm64 ]; then
        # local arm64 build
        ARCH=m1
else
        ARCH=x64
fi
if [ -n "$1" ]; then
	VERSION="$1"
else
	VERSION="`../../configure -qV`"
	[ -z "${VERSION}" ] && VERSION=5.2.2
fi
[ -z "${MAKE}" ] && MAKE=make

while : ; do
	[ -x "$PWD/configure" ] && break
	[ "$PWD" = / ] && break
	cd ..
done

[ ! -x "$PWD/configure" ] && exit 1

pwd
if [ ! -d build/r2frida.app ]; then
	rm -rf "${SRC}"
	${MAKE} mrproper 2>/dev/null
	# ${MAKE} -j4 || exit 1
fi
export CFLAGS=-O2
./configure --prefix="${PREFIX}" || exit 1
${MAKE}
${MAKE} install PREFIX="${PREFIX}" DESTDIR=${SRC} || exit 1
if [ -d "${SRC}" ]; then
	pkgbuild --root "${SRC}" --identifier org.radare.r2frida --version "${VERSION}" \
		--install-location / "dist/macos/r2frida-${VERSION}-${ARCH}.pkg" || exit 1
	cp -f dist/macos/*.pkg .
else
	echo "Failed install. DESTDIR is empty" > /dev/stderr
	exit 1
fi
