#!/bin/sh
# Usage: meson-agent.sh r2frida-compile srcdir index.ts out.js out.h
set -e
COMPILE=$1
SRCDIR=$2
INDEX=$3
OUTJS=$4
OUTH=$5

R2PM_OFFLINE=1 "$COMPILE" -q -r "$SRCDIR" -i
"$COMPILE" -r "$SRCDIR" -H "$OUTH" -o "$OUTJS" -Sc "$INDEX"
test -s "$OUTJS"
test -s "$OUTH"
