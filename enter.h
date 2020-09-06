/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef ENTER_H_
# define ENTER_H_

# include <limits.h>
# include <sys/resource.h>
# include <sys/stat.h>
# include <time.h>
# include <unistd.h>
# include "mount.h"
# include "net.h"
# include "ns.h"
# include "timens.h"
# include "userns.h"

enum {
	MAX_MOUNT = 4096,
	MAX_NICS = 4096,
};

/* SHARE_WITH_PARENT is a special value for entry_settings.shares[ns]. */
# define SHARE_WITH_PARENT ((char *) -1)

struct entry_settings {
	/* shares[] is indexed by SHARE_CGROUP, etc.  Legal values are:
	   NULL: unshare.
	   SHARE_WITH_PARENT: special marker meaning don't unshare or setns.
	   filename: setns to the given namespace file. */
	const char *shares[MAX_NS];

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
	const char *mutables[MAX_MOUNT];
	size_t nmutables;

	struct timespec clockspecs[MAX_CLOCK + 1];

	struct nic_options nics[MAX_NICS];
	size_t nnics;

	mode_t umask;

	const char *arch;

	// Set the `limits' pointer when the option has been provided.
	struct rlimit limits_storage[RLIM_NLIMITS];
	struct rlimit *limits[RLIM_NLIMITS];

	const char *setup_program;
	char *const *setup_argv;

	int no_fake_devtmpfs;
	int no_derandomize;
	int no_proc_remount;
	int no_init;
	int no_loopback_setup;

	const char *persist;
};

int enter(struct entry_settings *opts);

#endif /* !ENTER_H_ */
