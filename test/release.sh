#!/bin/sh
set -eu

script="$(cd .. && pwd)/sys/check-release.sh"
fixture=$(mktemp -d "${TMPDIR:-/tmp}/r2frida-release.XXXXXX")
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
cd "$fixture"
git init -q
git config user.name "r2frida test"
git config user.email "test@example.invalid"
printf '#!/bin/sh\necho 1.2.3\n' > configure
chmod +x configure
git add configure
git -c commit.gpgsign=false commit -qm 'Ordinary change'

check() {
	actual=$(GITHUB_REF="$1" sh "$script" HEAD)
	expected=$(printf 'is=%s\ntag=%s\n' "$2" "$3")
	if [ "$actual" != "$expected" ]; then
		printf 'Release check failed for %s\nExpected:\n%s\nActual:\n%s\n' "$1" "$expected" "$actual" >&2
		exit 1
	fi
}

check refs/heads/master no -
check refs/heads/feature no -
git -c commit.gpgsign=false commit --allow-empty -qm 'Release 1.2.2'
check refs/heads/master no -
git -c commit.gpgsign=false commit --allow-empty -qm 'Release 1.2.3'
check refs/heads/master yes 1.2.3
check refs/heads/feature no -
check refs/tags/conti no -
check refs/tags/1.2.2 no -
git tag 1.2.3
check refs/heads/master yes 1.2.3
check refs/tags/1.2.3 yes 1.2.3
git -c commit.gpgsign=false commit --allow-empty -qm 'Ordinary tagged change'
git tag -d 1.2.3 > /dev/null
git tag 1.2.3
check refs/heads/master yes 1.2.3
check refs/tags/1.2.3 yes 1.2.3
printf 'Release detection tests passed\n'
