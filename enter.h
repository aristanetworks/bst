/* Copyright (c) 2020 Arista Networks, Inc.  All rights reserved.
   Arista Networks, Inc. Confidential and Proprietary. */

#ifndef ENTER_H_
# define ENTER_H_

# include <unistd.h>
# include <limits.h>
# include "mount.h"

enum {
	MAX_MOUNT = 4096,

	/* this is a very generous upper bound for the number of supported
	   namespaces. unshare(2) takes an int for its CLONE_* flags, so we can
	   use the number of bits in an int as upper bound. */
	MAX_SHARES = CHAR_BIT * sizeof (int),
};

struct entry_settings {
	const char *shares[MAX_SHARES];
	size_t nshares;

	const char *pathname;
	char *const *argv;
	char *const *envp;
	char *root;
	char *workdir;

	uid_t uid;
	gid_t gid;
	gid_t groups[NGROUPS_MAX];
	size_t ngroups;

	struct mount_entry mounts[MAX_MOUNT];
	size_t nmounts;
	const char *mutables[MAX_MOUNT];
	size_t nmutables;

	const char *arch;
};

int enter(const struct entry_settings *opts);

#endif /* !ENTER_H_ */
