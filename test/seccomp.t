#!/usr/bin/env cram.sh

mknod should work for safe devices unprivileged

	$ bst --emulate-mknod mknod null c 1 3
	> rm -f null

Invalid fds show normal errors, zero results, and injected errors without
syncing any host filesystem. Unselected calls keep their original behavior.

	$ timeout 21 test/mock_probe syncs
	fsync -1 9
	fdatasync -1 9
	syncfs -1 9

	$ timeout 20 bst --mock-syscall nr=fsync,ret=0 --mock-syscall nr=syncfs,ret=-5 --no-init test/mock_probe syncs
	fsync 0 0
	fdatasync -1 9
	syncfs -1 5

	$ timeout 20 bst --mock-syscall nr=fsync,ret=-5 --mock-syscall nr=fdatasync,ret=-5 --mock-syscall nr=syncfs,ret=-5 --no-init test/mock_probe syncs
	fsync -1 5
	fdatasync -1 5
	syncfs -1 5

	$ timeout 20 bst --mock-syscall nr=fsync,ret=0 --mock-syscall nr=fdatasync,ret=0 --mock-syscall nr=syncfs,ret=0 test/mock_probe fork-exec
	fsync 0 0
	fdatasync 0 0
	syncfs 0 0

The filter also applies to setup, while the invoking host remains unaffected.

	$ timeout 20 bst --mock-syscall nr=fsync,ret=-5 --setup='test/mock_probe syncs' --no-init test/mock_probe syncs
	fsync -1 5
	fdatasync -1 9
	syncfs -1 9
	fsync -1 5
	fdatasync -1 9
	syncfs -1 9

	$ timeout 20 test/mock_probe syncs
	fsync -1 9
	fdatasync -1 9
	syncfs -1 9

Mocked success skips the syscall body and does not create the directory.

	$ d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; timeout 20 bst --no-init --mock-syscall nr=mkdirat,ret=0 test/mock_probe mkdir "$d/absent"; test ! -e "$d/absent"
	mkdirat 0 0

Explicit mocks win over notification emulation independent of option order.

	$ timeout 20 bst --emulate-mknod --mock-syscall nr=mknodat,ret=-5 --no-init test/mock_probe mknod
	mknodat -1 5

	$ timeout 20 bst --mock-syscall nr=mknodat,ret=-5 --emulate-mknod --no-init test/mock_probe mknod
	mknodat -1 5

Mocking sendmsg must not block the earlier listener handoff. Loopback setup
is disabled because it uses sendmsg after the mock is installed.

	$ timeout 20 bst --no-loopback-setup --mock-syscall nr=sendmsg,ret=-5 --no-init test/mock_probe syncs
	fsync -1 9
	fdatasync -1 9
	syncfs -1 9

	$ timeout 20 bst --no-loopback-setup --mock-syscall nr=sendmsg,ret=-5 test/mock_probe syncs
	fsync -1 9
	fdatasync -1 9
	syncfs -1 9

Nested mocks persist; a newer ERRNO action can replace the parent's result.

	$ timeout 20 bst --mock-syscall nr=fsync,ret=-5 --no-init bst --mock-syscall nr=syncfs,ret=0 --no-init test/mock_probe syncs
	fsync -1 5
	fdatasync -1 9
	syncfs 0 0

	$ timeout 20 bst --mock-syscall nr=fsync,ret=-5 --no-init bst --mock-syscall nr=fsync,ret=0 --no-init test/mock_probe syncs
	fsync 0 0
	fdatasync -1 9
	syncfs -1 9

Bad rules fail before setup, and a failed filter install stops setup and command.

	$ d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; if timeout 20 bst --setup="touch $d/setup" --mock-syscall nr=fsync,ret=1 true >"$d/log" 2>&1; then exit 1; else rc=$?; fi; test "$rc" = 2; test ! -e "$d/setup"; grep -q -- '--mock-syscall: ret must be 0' "$d/log"

	$ d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; for rule in 'nr=fsync,,ret=0' 'nr=fsync,ret=0,arch=unsupported'; do if timeout 20 bst --setup="touch $d/setup" --mock-syscall "$rule" true >"$d/log" 2>&1; then exit 1; else rc=$?; fi; test "$rc" = 2; test ! -e "$d/setup"; grep -q -- '--mock-syscall:' "$d/log"; done

	$ d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; if timeout 20 bst --setup="touch $d/setup" --mock-syscall nr=fsync,ret=0 --mock-syscall nr=fsync,ret=0 true >"$d/log" 2>&1; then exit 1; else rc=$?; fi; test "$rc" = 2; test ! -e "$d/setup"; grep -q -- '--mock-syscall: overlapping' "$d/log"

	$ d=$(mktemp -d); trap 'rm -rf "$d"' EXIT; if timeout 20 test/mock_probe deny-install bst --mock-syscall nr=fsync,ret=0 --setup="touch $d/setup" --no-init sh -c "touch $d/command" >"$d/log" 2>&1; then exit 1; else rc=$?; fi; test "$rc" = 1; test ! -e "$d/setup"; test ! -e "$d/command"; grep -q -- '--mock-syscall: seccomp filter installation failed' "$d/log"

Many valid rules install together, rather than truncating the list.

	$ abi=$(uname -m); case "$abi" in x86_64|aarch64) ;; i?86) abi=i386 ;; *) echo "unsupported ABI: $abi" >&2; exit 1 ;; esac; set --; i=0; while [ "$i" -lt 1500 ]; do set -- "$@" "--mock-syscall=nr=$((10000+i)),arch=$abi,ret=-5"; i=$((i+1)); done; timeout 30 bst "$@" --no-init test/mock_probe number 11499
	syscall -1 5
