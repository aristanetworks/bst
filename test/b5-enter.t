#!/usr/bin/env cram.sh

Basic usage

	$ bst -U / echo echo hello
	hello

Testing that we are on the host namespaces by default

	$ [ "$(bst / readlink readlink /proc/self/ns/user)" = "$(readlink /proc/self/ns/user)" ]
	$ [ "$(bst / readlink readlink /proc/self/ns/cgroup)" = "$(readlink /proc/self/ns/cgroup)" ]
	$ [ "$(bst / readlink readlink /proc/self/ns/ipc)" = "$(readlink /proc/self/ns/ipc)" ]
	$ [ "$(bst / readlink readlink /proc/self/ns/mnt)" = "$(readlink /proc/self/ns/mnt)" ]
	$ [ "$(bst / readlink readlink /proc/self/ns/net)" = "$(readlink /proc/self/ns/net)" ]
	$ [ "$(bst / readlink readlink /proc/self/ns/uts)" = "$(readlink /proc/self/ns/uts)" ]
	$ [ "$(bst / readlink readlink /proc/self/ns/pid)" = "$(readlink /proc/self/ns/pid)" ]

Testing namespace unsharing

	$ [ "$(bst -U / readlink readlink /proc/self/ns/user)" != "$(readlink /proc/self/ns/user)" ]
	$ [ "$(bst -U -c / readlink readlink /proc/self/ns/cgroup)" != "$(readlink /proc/self/ns/cgroup)" ]
	$ [ "$(bst -U -i / readlink readlink /proc/self/ns/ipc)" != "$(readlink /proc/self/ns/ipc)" ]
	$ [ "$(bst -U -m / readlink readlink /proc/self/ns/mnt)" != "$(readlink /proc/self/ns/mnt)" ]
	$ [ "$(bst -U -n / readlink readlink /proc/self/ns/net)" != "$(readlink /proc/self/ns/net)" ]
	$ [ "$(bst -U -u / readlink readlink /proc/self/ns/uts)" != "$(readlink /proc/self/ns/uts)" ]
	$ [ "$(bst -U -p / readlink readlink /proc/self/ns/pid)" != "$(readlink /proc/self/ns/pid)" ]

Testing uid/gid/groups semantics

	$ bst -U / id id
	uid=0(root) gid=0(root) groups=0(root),65534(nobody)

	$ [ "$(bst / id id)" = "$(id)" ]

	$ bst -U --uid=1 --gid=2 --groups=3,4 / sh sh -c 'id -u; id -g; id -G'
	1
	2
	2 3 4

Program must be init of its pid namespace

	$ bst -U -p / sh sh -c 'echo $$'
	1

Testing mount semantics

	$ bst -U -m --mount tmp,/tmp,tmpfs,defaults / sh sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//"'
	tmp /tmp tmpfs rw,relatime 0 0

	$ bst -U -m --mount /tmp,/mnt,none,bind / sh sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//"'
	tmpfs /mnt tmpfs rw,nosuid,nodev 0 0

	$ bst -U -m --mount tmp,/tmp,tmpfs,dirsync,noatime,nodev,nodiratime,noexec,nosuid,relatime,ro,silent,strictatime,sync / sh sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//"'
	tmp /tmp tmpfs ro,sync,dirsync,nosuid,nodev,noexec,nodiratime 0 0

	$ bst -U -m --mount tmp,/tmp,tmpfs,noatime,atime,nodev,dev,nodiratime,diratime,noexec,exec,nosuid,suid,relatime,norelatime,ro,rw,silent,loud,strictatime,nostrictatime,sync,async / sh sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//"'
	tmp /tmp tmpfs rw,relatime 0 0

	$ bst -U -m --mount tmp,/tmp,tmpfs,foo=bar / true true
	bst: mount_entries: mount("tmp", "/tmp", "tmpfs", 0, "foo=bar"): Invalid argument
	[1]

Testing workdir semantics

	$ bst -U / pwd pwd
	/

	$ bst -U --workdir=/tmp / pwd pwd
	/tmp

Testing arch semantics

	$ [ "$(uname -m)" = "$(bst -U / uname uname -m)" ]

	$ [ "$(setarch linux32 uname -m)" = "$(bst -U --arch=linux32 / uname uname -m)" ]

Testing exit code handling

	$ bst -U / bash bash -c "exit 17"
	[17]

	$ bst -U / bash bash -c 'bash -c "kill -9 $$"'
	[137]
