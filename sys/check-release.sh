#!/bin/sh
set -eu

commit=${1:-HEAD}
version=$(./configure -qV)
is=no
tag=-

# A release commit can reach master before its tag is pushed.
case "${GITHUB_REF:-refs/heads/master}" in
refs/heads/master)
	if [ "$(git log -1 --format=%s "$commit")" = "Release $version" ] ||
		git tag --points-at "$commit" | grep -qxF "$version"; then
		is=yes
		tag=$version
	fi
	;;
refs/tags/"$version")
	is=yes
	tag=$version
	;;
esac

printf 'is=%s\ntag=%s\n' "$is" "$tag"
