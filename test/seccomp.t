#!/usr/bin/env cram.sh

mknod should work for safe devices unprivileged

	$ bst --emulate-mknod mknod null c 1 3
	> rm -f null
