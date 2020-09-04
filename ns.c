/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>

#include "capable.h"
#include "enter.h"
#include "ns.h"
#include "util.h"

static struct {
	int flag;
	const char *proc_ns_name;
} flags[] = {
	[NS_CGROUP] = { BST_CLONE_NEWCGROUP, "cgroup" },
	[NS_IPC]    = { BST_CLONE_NEWIPC,    "ipc",   },
	[NS_MNT]    = { BST_CLONE_NEWNS,     "mnt"    },
	[NS_NET]    = { BST_CLONE_NEWNET,    "net"    },
	[NS_PID]    = { BST_CLONE_NEWPID,    "pid"    },
	[NS_TIME]   = { BST_CLONE_NEWTIME,   "time"   },
	[NS_USER]   = { BST_CLONE_NEWUSER,   "user"   },
	[NS_UTS]    = { BST_CLONE_NEWUTS,    "uts"    },
};

const char *ns_name(enum nstype ns)
{
	return flags[ns].proc_ns_name;
}

int ns_cloneflag(enum nstype ns)
{
	return flags[ns].flag;
}

void opts_to_nsactions(const char *shares[], enum nsaction *nsactions)
{
	for (size_t i = 0; i < MAX_NS; i++) {
		const char *share = shares[i];
		if (share == NULL) {
			nsactions[i] = NSACTION_UNSHARE;
		} else if (share == SHARE_WITH_PARENT) {
			nsactions[i] = NSACTION_SHARE_WITH_PARENT;
		} else {
			nsactions[i] = open(share, O_RDONLY | O_CLOEXEC);
			if (nsactions[i] < 0) {
				err(1, "open %s", share);
			}
		}
	}
}

struct nsid {
	int ns;
	enum nsaction action;
};

static int is_setns(const struct nsid *ns)
{
	switch (ns->action) {
	case NSACTION_UNSHARE:
	case NSACTION_SHARE_WITH_PARENT:
		return 0;
	default:
		return 1;
	}
}

/* cmp_nsids compares two ns IDs in a stable manner, such that
   namespaces that are entered via setns are sorted before those that
   are entered via unshare (or not changed at all). */
static int cmp_nsids(const void *lhs, const void *rhs)
{
	int diff = is_setns(rhs) - is_setns(lhs);
	if (diff != 0) {
		return diff;
	}
	/* Both namespaces are the same kind -- keep ordering intact by comparing
	   pointer values. */
	return (int) ((intptr_t) lhs - (intptr_t) rhs);
}

void ns_enter(enum nsaction *nsactions)
{
	/* Enter all relevant namespaces. It's hard to check in advance which
	   namespaces are supported, so we unshare them one by one in order. */

	struct nsid namespaces[] = {
		/* User namespace must be entered first and foremost. */
		{ NS_USER,   nsactions[NS_USER] },
		{ NS_NET,    nsactions[NS_NET] },
		{ NS_MNT,    nsactions[NS_MNT] },
		{ NS_IPC,    nsactions[NS_IPC] },
		{ NS_PID,    nsactions[NS_PID] },
		{ NS_CGROUP, nsactions[NS_CGROUP] },
		{ NS_UTS,    nsactions[NS_UTS] },
		{ NS_TIME,   nsactions[NS_TIME] },
	};

	/* If we have CAP_SYS_ADMIN from the get-go, starting by entering
	   the userns may restrict us from joining additional namespaces, so
	   we rearrange the order so that we setns into target nsfs files first. */
	if (capable(BST_CAP_SYS_ADMIN)) {
		qsort(namespaces, lengthof(namespaces), sizeof (namespaces[0]),
				cmp_nsids);
	}

	for (struct nsid *ns = &namespaces[0]; ns < namespaces + lengthof(namespaces); ++ns) {
		switch (ns->action) {
		case NSACTION_UNSHARE:
			if (unshare(flags[ns->ns].flag) == -1) {
				if (errno == EINVAL) {
					/* We realized that the namespace isn't supported -- remove it
					   from the unshare set. */
					nsactions[ns->ns] = NSACTION_SHARE_WITH_PARENT;
				} else {
					err(1, "unshare %s", flags[ns->ns].proc_ns_name);
				}
			}
			break;

		case NSACTION_SHARE_WITH_PARENT:
			break;

		default:
			if (setns(ns->action, flags[ns->ns].flag) == -1) {
				if (ns->ns == NS_USER && errno == EINVAL) {
					/* EINVAL is overloaded -- it might mean that the user
					   passed something that's not a userns file, or it might
					   mean that the user is trying to enter the current userns.

					   We want to ignore the latter case, and give semantics
					   that using --share-userns=/your/own/userns is the same
					   as --share-userns. */

					struct stat self;
					if (stat("/proc/self/ns/user", &self) == -1) {
						err(1, "stat /proc/self/ns/user");
					}

					struct stat stat;
					if (fstat(ns->action, &stat) == -1) {
						err(1, "fstat %s nsfs", flags[ns->ns].proc_ns_name);
					}

					if (self.st_ino == stat.st_ino) {
						nsactions[ns->ns] = NSACTION_SHARE_WITH_PARENT;
						continue;
					}
				}
				err(1, "setns %s", flags[ns->ns].proc_ns_name);
			}
			close(ns->action);
			break;
		}
	}
}
