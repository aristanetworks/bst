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

	$ bst sh -c '[ "$(bst --share user readlink /proc/self/ns/user)" = "$(readlink /proc/self/ns/user)" ]'
	$ [ "$(bst --share cgroup readlink /proc/self/ns/cgroup)" = "$(readlink /proc/self/ns/cgroup)" ]
	$ [ "$(bst --share ipc readlink /proc/self/ns/ipc)" = "$(readlink /proc/self/ns/ipc)" ]
	$ [ "$(bst --share mnt readlink /proc/self/ns/mnt)" = "$(readlink /proc/self/ns/mnt)" ]
	$ [ "$(bst --share net readlink /proc/self/ns/net)" = "$(readlink /proc/self/ns/net)" ]
	$ [ "$(bst --share uts readlink /proc/self/ns/uts)" = "$(readlink /proc/self/ns/uts)" ]
	$ [ "$(bst --share pid readlink /proc/self/ns/pid)" = "$(readlink /proc/self/ns/pid)" ]
	$ [ "$(bst --share all ls -l /proc/self/ns)" = "$(ls -l /proc/self/ns)" ]

Testing uid/gid/groups semantics

	$ bst id | sed -e 's/,65534([^)]*)//'
	uid=0(root) gid=0(root) groups=0(root)

	$ [ "$(bst --share all id)" = "$(id)" ]

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

	$ bst --mount tmp,/tmp,tmpfs,defaults sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//" -e "s/,seclabel//" -e "s/,inode64//"'
	tmp /tmp tmpfs rw,relatime 0 0

	$ [ "$(bst --mount /dev/shm,/mnt,none,bind sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//" -e "s|/mnt|/dev/shm|"')" = "$(grep /dev/shm /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//")" ]

	$ bst --mount tmp,/tmp,tmpfs,dirsync,noatime,nodev,nodiratime,noexec,nosuid,relatime,ro,silent,strictatime,sync sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//" -e "s/,seclabel//" -e "s/,inode64//"'
	tmp /tmp tmpfs ro,sync,dirsync,nosuid,nodev,noexec,nodiratime 0 0

	$ bst --mount tmp,/tmp,tmpfs,noatime,atime,nodev,dev,nodiratime,diratime,noexec,exec,nosuid,suid,relatime,norelatime,ro,rw,silent,loud,strictatime,nostrictatime,sync,async sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//" -e "s/,seclabel//" -e "s/,inode64//"'
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

	$ bst --share pid sh -c 'kill -9 $$'
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

	$ bst --share uts --hostname foobar false
	bst: attempted to set host or domain names on the host UTS namespace.
	[1]

Testing persistence

	$ mkdir -p foo bar; trap 'bst-unpersist foo && rmdir foo bar' EXIT; bst --persist=foo sh -c 'mount -t tmpfs none bar && echo hello > bar/greeting' && [ ! -f bar/greeting ] && bst --share mnt,user=foo sh -c '[ "$(cat '"$PWD"'/bar/greeting)" = "hello" ]'

Testing --rlimit core / general tests
	$ bst --rlimit core=0 test/print_limits core
	core: hard=0 soft=0

	$ bst --rlimit core=-1
	bst: error in --rlimit core value: Invalid argument
	[1]

	$ bst --rlimit core=0:-1
	bst: error in --rlimit core value: Invalid argument
	[1]

	$ bst --rlimit core=0xffffffffffffffffffffffffe 2>&1 | sed -e 's/Result not representable/Numerical result out of range/'
	bst: error in --rlimit core value: Numerical result out of range

Testing rlimit-copying
	$ bst --no-copy-hard-rlimits true  # smoke test

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

Testing --rlimit nofile
	$ bst --rlimit nofile=750 test/print_limits nofile
	nofile: hard=750 soft=750

	$ bst --rlimit nofile=750:740 test/print_limits nofile
	nofile: hard=750 soft=740

Testing --rlimit nproc
	$ bst --rlimit nproc=3500 test/print_limits nproc
	nproc: hard=3500 soft=3500

	$ bst --rlimit nproc=3500:3499 test/print_limits nproc
	nproc: hard=3500 soft=3499

Testing --rlimit as
	$ bst --rlimit as=: test/print_limits --soft-only as
	as: soft=hard

Testing --rlimit core
	$ bst --rlimit core=: test/print_limits --soft-only core
	core: soft=hard

Testing --rlimit cpu
	$ bst --rlimit cpu=: test/print_limits --soft-only cpu
	cpu: soft=hard

Testing --rlimit data
	$ bst --rlimit data=: test/print_limits --soft-only data
	data: soft=hard

Testing --rlimit fsize
	$ bst --rlimit fsize=: test/print_limits --soft-only fsize
	fsize: soft=hard

Testing --rlimit locks
	$ bst --rlimit locks=: test/print_limits --soft-only locks
	locks: soft=hard

Testing --rlimit memlock
	$ bst --rlimit memlock=: test/print_limits --soft-only memlock
	memlock: soft=hard

Testing --rlimit msgqueue
	$ bst --rlimit msgqueue=: test/print_limits --soft-only msgqueue
	msgqueue: soft=hard

Testing --rlimit nice
	$ bst --rlimit nice=: test/print_limits --soft-only nice
	nice: soft=hard

Testing --rlimit nofile
	$ bst --rlimit nofile=: test/print_limits --soft-only nofile
	nofile: soft=hard

Testing --rlimit nproc
	$ bst --rlimit nproc=: test/print_limits --soft-only nproc
	nproc: soft=hard

Testing --rlimit rss
	$ bst --rlimit rss=: test/print_limits --soft-only rss
	rss: soft=hard

Testing --rlimit rtprio
	$ bst --rlimit rtprio=: test/print_limits --soft-only rtprio
	rtprio: soft=hard

Testing --rlimit rttime
	$ bst --rlimit rttime=: test/print_limits --soft-only rttime
	rttime: soft=hard

Testing --rlimit sigpending
	$ bst --rlimit sigpending=: test/print_limits --soft-only sigpending
	sigpending: soft=hard

Testing --rlimit stack
	$ bst --rlimit stack=: test/print_limits --soft-only stack
	stack: soft=hard

Testing Environment

	$ bst --no-env FOO=bar env
	FOO=bar

	$ env -i FOO=bar $(which bst) --setup-exe /usr/bin/env /bin/true
	FOO=bar
	ROOT=/
	EXECUTABLE=/bin/true

Ensure /sys/fs/cgroup

	$ if [ -d "/sys/fs/cgroup" ]; then exit 0; else exit 80; fi

Test overspecified --limits no --cgroup

	$ ! bst --limit cpu.max=2222 \
	> --limit cpu.max=1111 \
	bst: double specified --limit argument

Test cpu.max cgroup usage no --cgroup

	$ bst --limit cpu.max="max 100000" \
	> cat /sys/fs/cgroup/cpu.max
	max 100000

	$ bst --limit cpu.max=3333 \
	> cat /sys/fs/cgroup/cpu.max
	3333 100000

	$ bst --limit cpu.max="2222 66666" \
	> cat /sys/fs/cgroup/cpu.max
	2222 66666

	$ bst --limit cpu.max=1111 \
	> cat /sys/fs/cgroup/cpu.max
	1111 100000

	$ ! bst --limit cpu.max="0 500000" 2>/dev/null

Test cpu.weight cgroup usage no --cgroup

	$ bst --limit cpu.weight=333 \
	> cat /sys/fs/cgroup/cpu.weight
	333

	$ bst --limit cpu.weight=555 \
	> cat /sys/fs/cgroup/cpu.weight
	555

	$ ! bst --limit cpu.weight=3333333 2>/dev/null

Test memory.min cgroup usage no --cgroup

	$ bst --limit memory.min=1M \
	> cat /sys/fs/cgroup/memory.min
	1048576

	$ bst --limit memory.min=1G \
	> cat /sys/fs/cgroup/memory.min
	1073741824

	$ ! bst --limit memory.min=-1G \
	> cat /sys/fs/cgroup/memory.min 2>/dev/null

Test memory.low cgroup usage no --cgroup

	$ bst --limit memory.low=1M \
	> cat /sys/fs/cgroup/memory.low
	1048576

	$ bst --limit memory.low=1G \
	> cat /sys/fs/cgroup/memory.low
	1073741824

	$ ! bst --limit memory.low=-1G \
	> cat /sys/fs/cgroup/memory.low 2>/dev/null

Test memory.high cgroup usage no --cgroup

	$ bst --limit memory.high=1M \
	> cat /sys/fs/cgroup/memory.high
	1048576

	$ bst --limit memory.high=1G \
	> cat /sys/fs/cgroup/memory.high
	1073741824

	$ ! bst --limit memory.high=-1G \
	> cat /sys/fs/cgroup/memory.high 2>/dev/null

Test memory.max cgroup usage no --cgroup

	$ bst --limit memory.max=1M \
	> cat /sys/fs/cgroup/memory.max
	1048576

	$ bst --limit memory.max=1G \
	> cat /sys/fs/cgroup/memory.max
	1073741824

	$ ! bst --limit memory.max=-1G \
	> cat /sys/fs/cgroup/memory.max 2>/dev/null

Test io.weight cgroup usage no --cgroup

	$ bst --limit io.weight=1 \
	> cat /sys/fs/cgroup/io.weight
	default 1

	$ bst --limit io.weight="default 50" \
	> cat /sys/fs/cgroup/io.weight
	default 50

	$ ! bst --limit io.weight=0 \
	> cat /sys/fs/cgroup/io.weight 2>/dev/null

Test pids.max cgroup usage no --cgroup

	$ bst --limit pids.max=40 \
	> cat /sys/fs/cgroup/pids.max
	40

	$ bst --limit pids.max=19 \
	> cat /sys/fs/cgroup/pids.max
	19

	$ ! bst --limit pids.max=-1 \
	> cat /sys/fs/cgroup/max 2>/dev/null

Test mutliple climits in conjunction no --cgroup
	$ bst --limit cpu.max="5000 7000" \
	> --limit cpu.weight=100 \
	> --limit memory.min=1M \
	> --limit memory.low=1M \
	> --limit memory.high=1M \
	> --limit memory.max=1G \
	> --limit pids.max=50 \
	> --workdir /sys/fs/cgroup \
	> cat cpu.max cpu.weight memory.min memory.low memory.high memory.max io.weight pids.max
	5000 7000
	100
	1048576
	1048576
	1048576
	1073741824
	default 100
	50

Verifying --cgroup system config

	$ if [ -d /sys/fs/cgroup/bst             ]     ; then exit 0; else exit 80; fi
	$ if [ -f /sys/fs/cgroup/cgroup.procs    ]     ; then exit 0; else exit 80; fi
	$ if [ -f /sys/fs/cgroup/bst/cpu.max     ]     ; then exit 0; else exit 80; fi
	$ if [ -f /sys/fs/cgroup/bst/cpu.weight  ]     ; then exit 0; else exit 80; fi
	$ if [ -f /sys/fs/cgroup/bst/memory.min  ]     ; then exit 0; else exit 80; fi
	$ if [ -f /sys/fs/cgroup/bst/memory.low  ]     ; then exit 0; else exit 80; fi
	$ if [ -f /sys/fs/cgroup/bst/memory.high ]     ; then exit 0; else exit 80; fi
	$ if [ -f /sys/fs/cgroup/bst/memory.max  ]     ; then exit 0; else exit 80; fi
	$ if [ -f /sys/fs/cgroup/bst/io.weight   ]     ; then exit 0; else exit 80; fi
	$ if [ -f /sys/fs/cgroup/bst/pids.max    ]     ; then exit 0; else exit 80; fi

Test --no-cgroup-remount disabling mount over

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --no-cgroup-remount \
	> cat /sys/fs/cgroup/bst/cgroup.procs

	$ ! bst --cgroup /sys/fs/cgroup/bst \
	> test -f /sys/fs/cgroup/bst/cgroup.procs

Test --share cgroup disabling mount over

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --share cgroup \
	> cat /sys/fs/cgroup/bst/cgroup.procs

	$ ! bst --cgroup /sys/fs/cgroup/bst \
	> test -f /sys/fs/cgroup/bst/cgroup.procs

Test --share mount disabling mount over

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --share mount \
	> cat /sys/fs/cgroup/bst/cgroup.procs

	$ ! bst --cgroup /sys/fs/cgroup/bst \
	> test -f /sys/fs/cgroup/bst/cgroup.procs

Test overspecified --limits
	$ ! bst --cgroup /sys/fs/cgroup/bst \
	> --limit cpu.max=2222 \
	> --limit cpu.max=1111 \
	bst: double specified --limit argument

Test cpu.max cgroup usage
	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit cpu.max="max 100000" \
	> cat /sys/fs/cgroup/cpu.max
	max 100000

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit cpu.max=3333 \
	> cat /sys/fs/cgroup/cpu.max
	3333 100000

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit cpu.max="2222 66666" \
	> cat /sys/fs/cgroup/cpu.max
	2222 66666

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit cpu.max=1111 \
	> cat /sys/fs/cgroup/cpu.max
	1111 100000

	$ ! bst --cgroup /sys/fs/cgroup/bst \
	> --limit cpu.max="0 500000" 2>/dev/null

Test cpu.weight cgroup usage

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit cpu.weight=333 \
	> cat /sys/fs/cgroup/cpu.weight
	333

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit cpu.weight=555 \
	> cat /sys/fs/cgroup/cpu.weight
	555

	$ ! bst --cgroup /sys/fs/cgroup/bst \
	> --limit cpu.weight=3333333 2>/dev/null

Test memory.min cgroup usage

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit memory.min=1M \
	> cat /sys/fs/cgroup/memory.min
	1048576

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit memory.min=1G \
	> cat /sys/fs/cgroup/memory.min
	1073741824

	$ ! bst --cgroup /sys/fs/cgroup/bst \
	> --limit memory.min=-1G \
	> cat /sys/fs/cgroup/memory.min 2>/dev/null

Test memory.low cgroup usage

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit memory.low=1M \
	> cat /sys/fs/cgroup/memory.low
	1048576

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit memory.low=1G \
	> cat /sys/fs/cgroup/memory.low
	1073741824

	$ ! bst --cgroup /sys/fs/cgroup/bst \
	> --limit memory.low=-1G \
	> cat /sys/fs/cgroup/memory.low 2>/dev/null

Test memory.high cgroup usage

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit memory.high=1M \
	> cat /sys/fs/cgroup/memory.high
	1048576

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit memory.high=1G \
	> cat /sys/fs/cgroup/memory.high
	1073741824

	$ ! bst --cgroup /sys/fs/cgroup/bst \
	> --limit memory.high=-1G \
	> cat /sys/fs/cgroup/memory.high 2>/dev/null

Test memory.max cgroup usage

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit memory.max=1M \
	> cat /sys/fs/cgroup/memory.max
	1048576

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit memory.max=1G \
	> cat /sys/fs/cgroup/memory.max
	1073741824

	$ ! bst --cgroup /sys/fs/cgroup/bst \
	> --limit memory.max=-1G \
	> cat /sys/fs/cgroup/memory.max 2>/dev/null

Test io.weight cgroup usage

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit io.weight=1 \
	> cat /sys/fs/cgroup/io.weight
	default 1

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit io.weight="default 50" \
	> cat /sys/fs/cgroup/io.weight
	default 50

	$ ! bst --cgroup /sys/fs/cgroup/bst \
	> --limit io.weight=0 \
	> cat /sys/fs/cgroup/io.weight 2>/dev/null

Test pids.max cgroup usage

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit pids.max=40 \
	> cat /sys/fs/cgroup/pids.max
	40

	$ bst --cgroup /sys/fs/cgroup/bst \
	> --limit pids.max=19 \
	> cat /sys/fs/cgroup/pids.max
	19

	$ ! bst --cgroup /sys/fs/cgroup/bst \
	> --limit pids.max=-1 \
	> cat /sys/fs/cgroup/max 2>/dev/null

Test mutliple climits in conjunction
	$ bst --cgroup=/sys/fs/cgroup/bst \
	> --limit cpu.max="5000 7000" \
	> --limit cpu.weight=100 \
	> --limit memory.min=1M \
	> --limit memory.low=1M \
	> --limit memory.high=1M \
	> --limit memory.max=1G \
	> --limit pids.max=50 \
	> --workdir /sys/fs/cgroup \
	> cat cpu.max cpu.weight memory.min memory.low memory.high memory.max io.weight pids.max
	5000 7000
	100
	1048576
	1048576
	1048576
	1073741824
	default 100
	50
