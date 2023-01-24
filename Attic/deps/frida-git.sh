#!/bin/sh
# pancake@nowsecure.com

case "$1" in
clone)
	make frida
	;;
mrproper)
	rm -rf frida
	;;
update)
	cd frida || exit 1
	git pull
	for a in core gum node python ; do
	(
		cd frida-$a
		git reset --hard @~10
		git checkout master
		git pull
	)
	done
	if [ "`uname`" = Darwin ]; then
		make node-mac
	else
		make node-64
	fi
	;;
clean)
	cd frida
	make clean
	;;
android)
	export ANDROID_NDK_ROOT=/home/pancake/Downloads/android-ndk-r10d
	make server-android
	;;
ios)
	make server-ios
	;;
*)
	echo "Usage: frida-git.sh [android|ios|clean|mrproper|update]"
	echo "Warning: This build requires ~3GB of disk"
	;;
esac
