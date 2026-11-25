#!/bin/sh
set -eu
ulimit -c 0
probe=$1
bst=$2
abi=$3
launcher=$4

run() {
	rc=0
	"$@" || rc=$?
}

# Missing kernel ABI support returns 126; an inherited seccomp architecture
# restriction can kill the probe with SIGSYS (159). Other results are failures.
run "$launcher" exec "$probe"
case "$rc" in
	9) ;;
	126|159) echo "$abi syscall execution unavailable (status $rc)" >&2; exit 77 ;;
	*) echo "$abi baseline returned unexpected status $rc" >&2; exit 1 ;;
esac
run timeout 20 "$bst" --mock-syscall nr=fsync,ret=0 --no-init "$probe"
if [ "$rc" -ne 0 ]; then
	echo "$abi mocked fsync returned status $rc" >&2
	exit 1
fi
if [ "$abi" = i386 ]; then
	run timeout 20 "$bst" --fix-stat-32bit-overflow \
		--mock-syscall nr=stat64,arch=i386,ret=-5 --no-init "$probe" s
	if [ "$rc" -ne 5 ]; then
		echo "i386 mocked stat64 returned status $rc" >&2
		exit 1
	fi
fi
