#!/bin/sh

V="$1"
if [ -n "$V" ]; then
	sed -i -e "s/^set frida_version=.*/set frida_version=$V/" make.bat
	exit 0
fi
A=`curl -fsSL "https://api.github.com/repos/frida/frida/releases/latest" | jq -r '.tag_name // empty'`
B=`grep frida_version make.bat |cut -d = -f2 |head -n1`

echo "Last Release: $A"
echo "In r2frida:   $B"

if [ "$A" != "$B" ]; then
	echo "Version mismatch, run: ./version-frida.sh $A"
fi
