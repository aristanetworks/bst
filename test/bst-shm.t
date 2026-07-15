#!/usr/bin/env cram.sh

Testing bind mount with /dev/shm

	$ [ "$(bst --mount /dev/shm,/mnt,none,bind sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//" -e "s|/mnt|/dev/shm|"')" = "$(grep /dev/shm /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//")" ]


	$ act=$(bst --mount /dev/shm,/mnt,none,bind sh -c 'tail -n 1 /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//" -e "s|/mnt|/dev/shm|"')
	> exp=$(grep /dev/shm /proc/mounts | sed -Ee "s/,uid=[[:digit:]]+,gid=[[:digit:]]+//")
	> [ "$exp" = "$act" ] || echo -e "-$exp\n+$act"
