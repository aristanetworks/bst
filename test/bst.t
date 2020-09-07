#!/usr/bin/env cram.sh

Basic usage

	$ bst echo hello
	hello

Testing that we are in our own namespaces by default

	$ [ "$(bst readlink /proc/self/ns/user)" != "$(readlink /proc/self/ns/user)" ]
	$ [ "$(bst readlink /proc/self/ns/cgroup)" != "$(readlink /proc/self/ns/cgroup)" ]
	$ [ "$(bst readlink /proc/self/ns/ipc)" != "$(readlink /proc/self/ns/ipc)" ]
	$ [ "$(bst readlink /proc/self/ns/mnt)" != "$(readlink /proc/self/ns/mnt)" ]
	$ [ "$(bst readlink /proc/self/ns/net)" != "$(readlink /proc/self/ns/net)" ]
	$ [ "$(bst readlink /proc/self/ns/uts)" != "$(readlink /proc/self/ns/uts)" ]
	$ [ "$(bst readlink /proc/self/ns/pid)" != "$(readlink /proc/self/ns/pid)" ]

Testing namespace sharing

	$ [ "$(bst --share-all readlink /proc/self/ns/user)" = "$(readlink /proc/self/ns/user)" ]
	$ [ "$(bst --share-cgroup readlink /proc/self/ns/cgroup)" = "$(readlink /proc/self/ns/cgroup)" ]
	$ [ "$(bst --share-ipc readlink /proc/self/ns/ipc)" = "$(readlink /proc/self/ns/ipc)" ]
	$ [ "$(bst --share-mnt readlink /proc/self/ns/mnt)" = "$(readlink /proc/self/ns/mnt)" ]
	$ [ "$(bst --share-net readlink /proc/self/ns/net)" = "$(readlink /proc/self/ns/net)" ]
	$ [ "$(bst --share-uts readlink /proc/self/ns/uts)" = "$(readlink /proc/self/ns/uts)" ]
	$ [ "$(bst --share-pid readlink /proc/self/ns/pid)" = "$(readlink /proc/self/ns/pid)" ]
	$ [ "$(bst --share-all ls -l /proc/self/ns)" = "$(ls -l /proc/self/ns)" ]

Testing uid/gid/groups semantics

	$ bst id | sed -e 's/,65534([^)]*)//'
	uid=0(root) gid=0(root) groups=0(root)

	$ [ "$(bst --share-all id)" = "$(id)" ]

	$ bst --workdir=/ --uid=1 --gid=2 --groups=3,4 sh -c 'id -u; id -g; id -G'
	1
	2
	2 3 4

Program must be init of its pid namespace if no init is specified

	$ bst --init='' sh -c 'echo $$'
	1

Program must be a child of init of its pid namespace

	$ bst sh -c 'echo $$'
	2

Testing mount semantics

	$ bst --mount tmp,/tmp,tmpfs,defaults sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//" -e "s/,seclabel//"'
	tmp /tmp tmpfs rw,relatime 0 0

	$ [ "$(bst --mount /dev/shm,/mnt,none,bind sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//" -e "s|/mnt|/dev/shm|"')" = "$(grep /dev/shm /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//")" ]

	$ bst --mount tmp,/tmp,tmpfs,dirsync,noatime,nodev,nodiratime,noexec,nosuid,relatime,ro,silent,strictatime,sync sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//" -e "s/,seclabel//"'
	tmp /tmp tmpfs ro,sync,dirsync,nosuid,nodev,noexec,nodiratime 0 0

	$ bst --mount tmp,/tmp,tmpfs,noatime,atime,nodev,dev,nodiratime,diratime,noexec,exec,nosuid,suid,relatime,norelatime,ro,rw,silent,loud,strictatime,nostrictatime,sync,async sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//" -e "s/,seclabel//"'
	tmp /tmp tmpfs rw,relatime 0 0

	$ bst --mount tmp,/tmp,tmpfs,foo=bar true
	bst: mount_entries: mount("tmp", "/tmp", "tmpfs", 0, "foo=bar"): Invalid argument
	[1]

	$ bst --mount foo
	bst: missing argument(s) to --mount
	[1]

Testing umask semantics

	$ bst --umask 000 sh -c umask
	0000

	$ bst --umask 012 sh -c umask
	0012

Testing workdir semantics

	$ [ "$(bst pwd)" = "$(pwd)" ]

	$ bst --workdir=/tmp pwd
	/tmp

Testing arch semantics

	$ [ "$(uname -m)" = "$(bst uname -m)" ]

	$ [ "$(setarch linux32 uname -m)" = "$(bst --arch=linux32 uname -m)" ]

Testing exit code handling

	$ bst sh -c "exit 17"
	[17]

	$ bst --share-pid sh -c 'kill -9 $$'
	[137]

Testing --argv0

	$ bst sh -c 'echo $0'
	sh

	$ bst --init='' --argv0 ash sh -c 'echo $0'
	ash

Testing hostname semantics

	$ bst uname -n
	localhost

	$ bst --hostname foobar uname -n
	foobar

	$ bst --share-uts --hostname foobar false
	bst: attempted to set host or domain names on the host UTS namespace.
	[1]

Testing persistence

	$ mkdir -p foo bar; trap 'bst-unpersist foo && rmdir foo bar' EXIT; bst --persist=foo sh -c 'mount -t tmpfs none bar && echo hello > bar/greeting' && [ ! -f bar/greeting ] && bst --share-mnt=foo/mnt --share-user=foo/user sh -c '[ "$(cat '"$PWD"'/bar/greeting)" = "hello" ]'

Testing --limit-core / general tests
	$ bst --limit-core=0 test/print_limits core
	core: hard=0 soft=0

	$ bst --limit-core=-1
	bst: error in --limit-core value: Invalid argument
	[1]

	$ bst --limit-core=0:-1
	bst: error in --limit-core value: Invalid argument
	[1]

	$ bst --limit-core=0xffffffffffffffffffffffffe
	bst: error in --limit-core value: Numerical result out of range
	[1]

Testing limit-copying
	$ bst --no-copy-hard-limits true  # smoke test

	$ bst test/print_limits --soft-only
	as: soft=hard
	core: soft=hard
	cpu: soft=hard
	data: soft=hard
	fsize: soft=hard
	locks: soft=hard
	memlock: soft=hard
	msgqueue: soft=hard
	nice: soft=hard
	nofile: soft=hard
	nproc: soft=hard
	rss: soft=hard
	rtprio: soft=hard
	rttime: soft=hard
	sigpending: soft=hard
	stack: soft=hard

Testing --limit-nofile
	$ bst --limit-nofile=750 test/print_limits nofile
	nofile: hard=750 soft=750

	$ bst --limit-nofile=750:740 test/print_limits nofile
	nofile: hard=750 soft=740

Testing --limit-nproc
	$ bst --limit-nproc=3500 test/print_limits nproc
	nproc: hard=3500 soft=3500

	$ bst --limit-nproc=3500:3499 test/print_limits nproc
	nproc: hard=3500 soft=3499

Testing --limit-as
	$ bst --limit-as=: test/print_limits --soft-only as
	as: soft=hard

Testing --limit-core
	$ bst --limit-core=: test/print_limits --soft-only core
	core: soft=hard

Testing --limit-cpu
	$ bst --limit-cpu=: test/print_limits --soft-only cpu
	cpu: soft=hard

Testing --limit-data
	$ bst --limit-data=: test/print_limits --soft-only data
	data: soft=hard

Testing --limit-fsize
	$ bst --limit-fsize=: test/print_limits --soft-only fsize
	fsize: soft=hard

Testing --limit-locks
	$ bst --limit-locks=: test/print_limits --soft-only locks
	locks: soft=hard

Testing --limit-memlock
	$ bst --limit-memlock=: test/print_limits --soft-only memlock
	memlock: soft=hard

Testing --limit-msgqueue
	$ bst --limit-msgqueue=: test/print_limits --soft-only msgqueue
	msgqueue: soft=hard

Testing --limit-nice
	$ bst --limit-nice=: test/print_limits --soft-only nice
	nice: soft=hard

Testing --limit-nofile
	$ bst --limit-nofile=: test/print_limits --soft-only nofile
	nofile: soft=hard

Testing --limit-nproc
	$ bst --limit-nproc=: test/print_limits --soft-only nproc
	nproc: soft=hard

Testing --limit-rss
	$ bst --limit-rss=: test/print_limits --soft-only rss
	rss: soft=hard

Testing --limit-rtprio
	$ bst --limit-rtprio=: test/print_limits --soft-only rtprio
	rtprio: soft=hard

Testing --limit-rttime
	$ bst --limit-rttime=: test/print_limits --soft-only rttime
	rttime: soft=hard

Testing --limit-sigpending
	$ bst --limit-sigpending=: test/print_limits --soft-only sigpending
	sigpending: soft=hard

Testing --limit-stack
	$ bst --limit-stack=: test/print_limits --soft-only stack
	stack: soft=hard
