#!/bin/sh
# pancake@nowsecure.com

case "$1" in
update)
	cd frida
	git pull
	git submodule update
	for a in core gum node python ; do
	(
		cd frida-$a
		git checkout master
		git pull
	)
	done
	make node-64
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
	echo "Usage: frida-git.sh [android|ios|clean|update]"
	echo "Warning: This build requires ~3GB of disk"
	;;
esac
