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

	$ bst id -u
	0

	$ bst id -g
	0

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


	$ act=$(bst --mount /dev/shm,/mnt,none,bind sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//" -e "s|/mnt|/dev/shm|"')
	> exp=$(grep /dev/shm /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//")
	> [ "$exp" = "$act" ] || echo -e "-$exp\n+$act"

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

	$ bst --no-env -- FOO-BAR=baz env
	FOO-BAR=baz

	$ bst --no-env -- FOO-BAR=baz -- env
	FOO-BAR=baz

	$ bst --no-env -- FOO-BAR=baz -- -- env
	bst-init: execvpe --: No such file or directory
	[1]

	$ bst --no-env -- -- env
	bst-init: execvpe --: No such file or directory
	[1]

	$ bst --no-env -- env

Testing close-fds

	$ echo -n '--close-fd=3 should close fd 3: '
	> bst --close-fd=3 --setup='cat 0<&3 && echo -n "setup OK, "' sh <<'EOF' 3</dev/null
	> sh -c "cat 0<&3" 2>/dev/null \
	>   && ( echo "exe KO: fd 3 was open in the spacetime"; exit 1 ) \
	>   || echo "exe OK"
	> EOF
	--close-fd=3 should close fd 3: setup OK, exe OK

	$ echo -n '--close-fd=3-7 should close fd 7: '
	> bst --close-fd=3-7 --setup='cat 0<&7 && echo -n "setup OK, "' sh <<'EOF' 7</dev/null
	> sh -c "cat 0<&7" 2>/dev/null \
	>   && ( echo "exe KO: fd 7 was open in the spacetime"; exit 1 ) \
	>   || echo "exe OK"
	> EOF
	--close-fd=3-7 should close fd 7: setup OK, exe OK

	$ echo -n '--close-fd=3- should close fd 7: '
	> bst --close-fd=3- --setup='cat 0<&7 && echo -n "setup OK, "' sh <<'EOF' 7</dev/null
	> sh -c "cat 0<&7" 2>/dev/null \
	>   && ( echo "exe KO: fd 7 was open in the spacetime"; exit 1 ) \
	>   || echo "exe OK"
	> EOF
	--close-fd=3- should close fd 7: setup OK, exe OK

	$ echo -n '--close-fd=3-7 should not close fd 8: '
	> bst --close-fd=3-7 sh <<'EOF' 8</dev/null
	> sh -c "cat 0<&8" 2>/dev/null \
	>   && echo "OK" \
	>   || ( echo "KO: fd 8 was closed in the spacetime"; exit 1 )
	> EOF
	--close-fd=3-7 should not close fd 8: OK
