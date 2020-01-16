#!/usr/bin/env cram.sh

Basic usage

	$ bst / echo echo hello
	hello

Testing that we are in our own namespaces by default

	$ [ "$(bst / readlink readlink /proc/self/ns/user)" != "$(readlink /proc/self/ns/user)" ]
	$ [ "$(bst / readlink readlink /proc/self/ns/cgroup)" != "$(readlink /proc/self/ns/cgroup)" ]
	$ [ "$(bst / readlink readlink /proc/self/ns/ipc)" != "$(readlink /proc/self/ns/ipc)" ]
	$ [ "$(bst / readlink readlink /proc/self/ns/mnt)" != "$(readlink /proc/self/ns/mnt)" ]
	$ [ "$(bst / readlink readlink /proc/self/ns/net)" != "$(readlink /proc/self/ns/net)" ]
	$ [ "$(bst / readlink readlink /proc/self/ns/uts)" != "$(readlink /proc/self/ns/uts)" ]
	$ [ "$(bst / readlink readlink /proc/self/ns/pid)" != "$(readlink /proc/self/ns/pid)" ]

Testing namespace sharing

	$ [ "$(bst --share=all / readlink readlink /proc/self/ns/user)" = "$(readlink /proc/self/ns/user)" ]
	$ [ "$(bst --share=cgroup / readlink readlink /proc/self/ns/cgroup)" = "$(readlink /proc/self/ns/cgroup)" ]
	$ [ "$(bst --share=ipc / readlink readlink /proc/self/ns/ipc)" = "$(readlink /proc/self/ns/ipc)" ]
	$ [ "$(bst --share=mount / readlink readlink /proc/self/ns/mnt)" = "$(readlink /proc/self/ns/mnt)" ]
	$ [ "$(bst --share=network / readlink readlink /proc/self/ns/net)" = "$(readlink /proc/self/ns/net)" ]
	$ [ "$(bst --share=uts / readlink readlink /proc/self/ns/uts)" = "$(readlink /proc/self/ns/uts)" ]
	$ [ "$(bst --share=pid / readlink readlink /proc/self/ns/pid)" = "$(readlink /proc/self/ns/pid)" ]
	$ [ "$(bst --share=pid,cgroup,ipc,user,mount,network,uts / ls ls -l)" = "$(bst --share=all / ls ls -l)" ]

Testing uid/gid/groups semantics

	$ bst / id id
	uid=0(root) gid=0(root) groups=0(root),65534(nobody)

	$ [ "$(bst --share=all / id id)" = "$(id)" ]

	$ bst --uid=1 --gid=2 --groups=3,4 / sh sh -c 'id -u; id -g; id -G'
	1
	2
	2 3 4

Program must be init of its pid namespace

	$ bst / sh sh -c 'echo $$'
	1

Testing mount semantics

	$ bst --mount tmp,/tmp,tmpfs,defaults / sh sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//"'
	tmp /tmp tmpfs rw,relatime 0 0

	$ bst --mount /tmp,/mnt,none,bind / sh sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//"'
	tmpfs /mnt tmpfs rw,nosuid,nodev 0 0

	$ bst --mount tmp,/tmp,tmpfs,dirsync,noatime,nodev,nodiratime,noexec,nosuid,relatime,ro,silent,strictatime,sync / sh sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//"'
	tmp /tmp tmpfs ro,sync,dirsync,nosuid,nodev,noexec,nodiratime 0 0

	$ bst --mount tmp,/tmp,tmpfs,noatime,atime,nodev,dev,nodiratime,diratime,noexec,exec,nosuid,suid,relatime,norelatime,ro,rw,silent,loud,strictatime,nostrictatime,sync,async / sh sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//"'
	tmp /tmp tmpfs rw,relatime 0 0

	$ bst --mount tmp,/tmp,tmpfs,foo=bar / true true
	bst: mount_entries: mount("tmp", "/tmp", "tmpfs", 0, "foo=bar"): Invalid argument
	[1]

Testing workdir semantics

	$ bst / pwd pwd
	/

	$ bst --workdir=/tmp / pwd pwd
	/tmp

Testing arch semantics

	$ [ "$(uname -m)" = "$(bst / uname uname -m)" ]

	$ [ "$(setarch linux32 uname -m)" = "$(bst --arch=linux32 / uname uname -m)" ]

Testing exit code handling

	$ bst / bash bash -c "exit 17"
	[17]

	$ bst --share=pid / bash bash -c 'kill -9 $$'
	[137]
