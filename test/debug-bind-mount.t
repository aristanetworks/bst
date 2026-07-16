#!/usr/bin/env cram.sh

[DO-NOT-MERGE] Debug bind mount environment

Host /dev/shm state

	$ findmnt /dev/shm 2>&1 || true
	$ grep '/dev/shm\|/mnt' /proc/self/mountinfo || echo "no /dev/shm or /mnt in host mountinfo"

Inside bst with bind mount: mountinfo lines for /dev/shm and /mnt

	$ bst --mount /dev/shm,/mnt,none,bind sh -c 'grep "/dev/shm\|/mnt" /proc/self/mountinfo'

Inside bst with bind mount: /proc/mounts lines for /dev/shm and /mnt

	$ bst --mount /dev/shm,/mnt,none,bind sh -c 'grep "/dev/shm\|/mnt" /proc/mounts'

The actual test assertion (should print OK if device IDs match)

	$ bst --mount /dev/shm,/mnt,none,bind awk '/\/dev\/shm/ { shm=$3 } /\/mnt/ { mnt=$3 } END { printf "shm=%s mnt=%s => ", shm, mnt; if (shm == mnt) { print "OK" } else { print "KO" } }' /proc/self/mountinfo
