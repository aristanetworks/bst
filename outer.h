/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef OUTER_H
# define OUTER_H

# include <unistd.h>

# include "userns.h"
# include "cgroups.h"
# include "net.h"

struct outer_helper {
	int unshare_user;
	int unshare_net;
	const char **persist;
	id_map uid_desired;
	id_map gid_desired;
	struct nic_options *nics;
	size_t nnics;

	bool cgroup_enabled;

	char *cgroup_path;
	struct climit *climits;

	pid_t pid;
	int fd;
};

void burn(int dirfd, char *path, char *data);
void outer_helper_spawn(struct outer_helper *helper);
void outer_helper_sendpid(const struct outer_helper *helper, pid_t pid);
void outer_helper_sync(const struct outer_helper *helper);
void outer_helper_close(struct outer_helper *helper);

#endif /* !OUTER_H */
