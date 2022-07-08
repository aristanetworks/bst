/* Copyright © 2022 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "outer.h"
#include "cgroups.h"
#include "path.h"

const struct cmap cgroup_map[] = {
	{ CGROUPS_CLIMIT_CPU_MAX,          "cpu.max"          },
	{ CGROUPS_CLIMIT_CPU_WEIGHT,       "cpu.weight"       },
	{ CGROUPS_CLIMIT_MEMORY_MIN,       "memory.min"       },
	{ CGROUPS_CLIMIT_MEMORY_LOW,       "memory.low"       },
	{ CGROUPS_CLIMIT_MEMORY_HIGH,      "memory.high"      },
	{ CGROUPS_CLIMIT_MEMORY_MAX,       "memory.max"       },
	{ CGROUPS_CLIMIT_MEMORY_SWAP_HIGH, "memory.swap.high" },
	{ CGROUPS_CLIMIT_MEMORY_SWAP_MAX,  "memory.swap.max"  },
	{ CGROUPS_CLIMIT_IO_WEIGHT,        "io.weight"        },
	{ CGROUPS_CLIMIT_IO_MAX,           "io.max"           },
	{ CGROUPS_CLIMIT_IO_LATENCY,       "io.latency"       },
	{ CGROUPS_CLIMIT_PIDS_MAX,         "pids.max"         },
};

/*
 * Apply a limit, which contains a controller filename and quota value where cgroup_path
 * specifies the name of the cgroup and cgroupfd is the open fd of the cgroup directory.
 */
void apply_climits(int cgroupfd, const struct climit *limits)  {
	for (size_t i = 0; i < CGROUPS_NLIMIT; ++i) {
		if (limits[i].present) {
			burn(cgroupfd, limits[i].fname, limits[i].clim);
		}
	}
}

/*
 * Called when bst terminates. This removes the created bst directory at the given
 * cleanfd file descriptor.
 */
void cgroup_clean(int cleanfd, pid_t rootpid) {
	char *subcgroup = makepath("bst.%d", rootpid);

	if (unlinkat(cleanfd, subcgroup, AT_REMOVEDIR) == -1) {
		err(1, "unable to clean cgroup %s", subcgroup);
	}
}
