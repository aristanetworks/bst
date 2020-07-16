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

	$ [ "$(bst --share=all readlink /proc/self/ns/user)" = "$(readlink /proc/self/ns/user)" ]
	$ [ "$(bst --share=cgroup readlink /proc/self/ns/cgroup)" = "$(readlink /proc/self/ns/cgroup)" ]
	$ [ "$(bst --share=ipc readlink /proc/self/ns/ipc)" = "$(readlink /proc/self/ns/ipc)" ]
	$ [ "$(bst --share=mount readlink /proc/self/ns/mnt)" = "$(readlink /proc/self/ns/mnt)" ]
	$ [ "$(bst --share=network readlink /proc/self/ns/net)" = "$(readlink /proc/self/ns/net)" ]
	$ [ "$(bst --share=uts readlink /proc/self/ns/uts)" = "$(readlink /proc/self/ns/uts)" ]
	$ [ "$(bst --share=pid readlink /proc/self/ns/pid)" = "$(readlink /proc/self/ns/pid)" ]
	$ [ "$(bst --share=pid,cgroup,ipc,user,mount,network,uts ls -l)" = "$(bst --share=all ls -l)" ]

Testing uid/gid/groups semantics

	$ bst id
	uid=0(root) gid=0(root) groups=0(root)

	$ [ "$(bst --share=all id)" = "$(id)" ]

	$ bst --uid=1 --gid=2 --groups=3,4 sh -c 'id -u; id -g; id -G'
	1
	2
	2 3 4

Program must be init of its pid namespace

	$ bst --no-init sh -c 'echo $$'
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

Testing workdir semantics

	$ bst pwd
	/

	$ bst --workdir=/tmp pwd
	/tmp

Testing arch semantics

	$ [ "$(uname -m)" = "$(bst uname -m)" ]

	$ [ "$(setarch linux32 uname -m)" = "$(bst --arch=linux32 uname -m)" ]

Testing exit code handling

	$ bst sh -c "exit 17"
	[17]

	$ bst --share=pid sh -c 'kill -9 $$'
	[137]

Testing --argv0

	$ bst sh -c 'echo $0'
	sh

	$ bst --argv0 ash sh -c 'echo $0'
	ash

Testing hostname semantics

	$ bst uname -n
	localhost

	$ bst --hostname foobar uname -n
	foobar

	$ bst --share=uts --hostname foobar false
	bst: attempted to set host or domain names on the host UTS namespace.
	[1]
