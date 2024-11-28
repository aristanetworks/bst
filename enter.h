/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef ENTER_H_
# define ENTER_H_

# include <limits.h>
# include <stdbool.h>
# include <sys/resource.h>
# include <sys/stat.h>
# include <time.h>
# include <unistd.h>

# include "bst_limits.h"
# include "cgroup.h"
# include "mount.h"
# include "net.h"
# include "ns.h"
# include "timens.h"
# include "userns.h"
# include "tty.h"

struct bst_rlimit {
	bool present;
	struct rlimit rlim;
};

struct climit {
	char *limit;
	char *fname;
	bool critical;
};

struct close_range {
	int from;
	int to;
};

enum {
	MAX_MOUNT = 4096,
	MAX_NICS = 4096,
	MAX_ADDRS = 4096,
	MAX_ROUTES = 4096,
	MAX_CGROUPS = 4096,
	MAX_CLOSE_FDS = 4096,
};

struct entry_settings {
	/* nsactions[] is indexed by NS_CGROUP, etc.  */
	enum nsaction nsactions[MAX_NS];
	const char *persist[MAX_NS];

	const char *pathname;
	char *const *argv;
	char *const *envp;
	const char *init;
	char *root;
	char *workdir;

	char *hostname;
	char *domainname;

	uid_t uid;
	gid_t gid;
	gid_t groups[NGROUPS_MAX];
	size_t ngroups;
	id_map uid_map;
	id_map gid_map;

	struct mount_entry mounts[MAX_MOUNT];
	size_t nmounts;

	struct timespec clockspecs[MAX_CLOCK];

	struct nic_options nics[MAX_NICS];
	size_t nnics;
	struct addr_options addrs[MAX_ADDRS];
	size_t naddrs;
	struct route_options routes[MAX_ROUTES];
	size_t nroutes;

	mode_t umask;

	enum cgroup_driver cgroup_driver;
	char *cgroup_path;

	struct climit climits[MAX_CGROUPS];
	size_t nactiveclimits;

	const char *arch;

	struct bst_rlimit rlimits[BST_NLIMIT];

	const char *setup_program;
	char *const *setup_argv;

	const char *pidfile;

	bool tty;
	struct tty_opts ttyopts;

	size_t nclose_fds;
	struct close_range close_fds[MAX_CLOSE_FDS];

	int no_copy_hard_rlimits;
	int no_fake_devtmpfs;
	int no_derandomize;
	int no_proc_remount;
	int no_cgroup_remount;
	int no_init;
	int no_loopback_setup;
	int no_env;
};

int enter(struct entry_settings *opts);

#endif /* !ENTER_H_ */
