#!/bin/sh
#
# Look for the 'acr' tool here: https://github.com/radare/acr
# Clone last version of ACR from here:
#  git clone https://github.com/radare/acr
#
# -- pancake
acr -p
if [ -n "$1" ]; then
	echo "./configure $*"
	./configure $*
fi

V=`./configure -qV`
jq ".version=\"$V\"" package.json > p
mv p package.json
