#!/bin/sh
cd ext
if [ ! -d frida-git ]; then
	git clone https://github.com/frida/frida frida-git
fi
cd frida-git
pwd
export MACOS_CERTID=org.radare.radare2
make FRIDA_MAPPER=disabled FRIDA_FLAGS_COMMON="-Doptimization=s -Db_ndebug=true" || exit 1
make core-macos || exit 1
make gum-macos || exit 1
mkdir -p /tmp/lib || exit 1
cp -rf build/frida-macos-arm64/lib/*.a /tmp/lib/ || exit 1
cp -rf build/sdk-macos-arm64/lib/*.a /tmp/lib/ || exit 1
cp -rf build/sdk-macos-arm64/lib/gio/modules/libgioopenssl.a /tmp/lib/ || exit 1
cd ..
cd ..
pwd
# build r2frida
make FRIDA_CORE_LIBS="$(echo `find /tmp/lib/*.a`)" WANT_SESSION_DEBUGGER=0
make user-install || exit 1
