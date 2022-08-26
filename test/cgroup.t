#!/usr/bin/env cram.sh

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
