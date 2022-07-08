/* Copyright © 2022 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef CGROUPS_H_
#define CGROUPS_H_

#include <stdbool.h>

enum {
	CGROUPS_CLIMIT_CPU_MAX,
	CGROUPS_CLIMIT_CPU_WEIGHT,
	CGROUPS_CLIMIT_MEMORY_MIN,
	CGROUPS_CLIMIT_MEMORY_LOW,
	CGROUPS_CLIMIT_MEMORY_HIGH,
	CGROUPS_CLIMIT_MEMORY_MAX,
	CGROUPS_CLIMIT_MEMORY_SWAP_HIGH,
	CGROUPS_CLIMIT_MEMORY_SWAP_MAX,
	CGROUPS_CLIMIT_IO_WEIGHT,
	CGROUPS_CLIMIT_IO_MAX,
	CGROUPS_CLIMIT_IO_LATENCY,
	CGROUPS_CLIMIT_PIDS_MAX,

	CGROUPS_NLIMIT
};

struct cmap {
	int resource;
	const char *fname;
};

extern const struct cmap cgroup_map[CGROUPS_NLIMIT];

struct climit {
	bool present;
	int resource;
	char *clim;
	char *fname;
};

void apply_climits(int cgroupfd, const struct climit *limits);
void cgroup_clean(int cleanfd, pid_t rootpid);

#endif /* !CGROUPS_H_ */
