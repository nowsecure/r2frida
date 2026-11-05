#!/bin/sh
V="$1"
if [ -n "$V" ]; then
	sed -i "s/^VERSION .*/VERSION $V/" configure.acr
	./autogen.sh
else
	./configure -qV
fi
