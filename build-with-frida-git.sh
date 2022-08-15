#!/bin/sh
OS=`uname -s`
case "${OS}" in
Darwin)
	OS="macos"
	;;
*)
	echo "Unknown OS $OS"
	exit 1
	;;
esac
ARCH=`uname -m` # arm64
cd ext
if [ ! -d frida-git ]; then
	git clone https://github.com/frida/frida frida-git
fi
cd frida-git
pwd
export MACOS_CERTID=org.radare.radare2
make > /dev/null || exit 1
#make core-${OS} FRIDA_MAPPER=-Dmapper=disabled FRIDA_FLAGS_COMMON="-Doptimization=s -Db_ndebug=true" || exit 1
make core-${OS} FRIDA_FLAGS_COMMON="-Doptimization=s -Db_ndebug=true" || exit 1
# make gum-macos FRIDA_MAPPER=disabled FRIDA_FLAGS_COMMON="-Doptimization=s -Db_ndebug=true" || exit 1
mkdir -p /tmp/lib || exit 1
cp -rf build/frida-${OS}-${ARCH}/lib/*.a /tmp/lib/ || exit 1
cp -rf build/sdk-${OS}-${ARCH}/lib/*.a /tmp/lib/ || exit 1
cp -rf build/sdk-${OS}-${ARCH}/lib/gio/modules/libgioopenssl.a /tmp/lib/ || exit 1
cd ..
cd ..
pwd
# build r2frida
make STRIP_SYMBOLS=no FRIDA_CORE_LIBS="$(echo `find /tmp/lib/*.a`)" WANT_SESSION_DEBUGGER=0
make user-install || exit 1
