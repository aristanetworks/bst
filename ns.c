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
#include "path.h"
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

bool is_nsfd_current(int nsfd, const char *name)
{
	const char *path = makepath("/proc/self/ns/%s", name);

	struct stat self;
	if (stat(path, &self) == -1) {
		if (errno == ENOENT) {
			/* This namespace is unsupported. */
			return false;
		}
		err(1, "stat %s", path);
	}

	struct stat stat;
	if (fstat(nsfd, &stat) == -1) {
		err(1, "fstat %s nsfs", name);
	}

	return self.st_ino == stat.st_ino;
}

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

static void ns_enter_one(struct nsid *ns)
{
	switch (ns->action) {
		case NSACTION_UNSHARE:
			if (unshare(flags[ns->ns].flag) == -1) {
				if (errno == EINVAL) {
					/* We realized that the namespace isn't supported -- remove it
					   from the unshare set. */
					//nsactions[ns->ns] = NSACTION_SHARE_WITH_PARENT;
					ns->action = NSACTION_SHARE_WITH_PARENT;
				} else {
					err(1, "unshare %s", flags[ns->ns].proc_ns_name);
				}
			}
			break;

		case NSACTION_SHARE_WITH_PARENT:
			break;

		default:
			if (setns(ns->action, flags[ns->ns].flag) == -1) {
				err(1, "setns %s", flags[ns->ns].proc_ns_name);
			}
			break;
	}
}

static bool is_postfork_ns(struct nsid *ns)
{
	/* For now, only the cgroup namespace needs to be unshared postfork */
	return ns->ns == NS_CGROUP;
}

void ns_enter_prefork(struct nsid *namespaces, size_t *len)
{
	/* Enter all relevant namespaces. It's hard to check in advance which
	   namespaces are supported, so we unshare them one by one in order. */

	/* If we have CAP_SYS_ADMIN from the get-go, starting by entering
	   the userns may restrict us from joining additional namespaces, so
	   we rearrange the order so that we setns into target nsfs files first. */
	if (capable(BST_CAP_SYS_ADMIN)) {
		qsort(namespaces, *len, sizeof (namespaces[0]),
				cmp_nsids);
	}

	struct nsid *first_postfork = NULL;
	struct nsid *ns = &namespaces[0];
	for (; ns < namespaces + *len; ++ns) {
		if (ns->action != NSACTION_SHARE_WITH_PARENT && is_postfork_ns(ns)) {
			first_postfork = ns;
			break;
		}
		ns_enter_one(ns);
	}

	size_t i = 0;
	for (; ns < namespaces + *len; ++ns, ++i) {
		if (first_postfork != NULL && !is_postfork_ns(ns)) {
			errx(1, "incompatible options: %s namespace must be entered before "
					"forking, but must be done after %s namespace is entered post-fork.",
					ns_name(ns->ns),
					ns_name(first_postfork->ns));
		}
		namespaces[i] = *ns;
	}
	*len = i;
}

void ns_enter_postfork(struct nsid *namespaces, size_t len)
{
	for (struct nsid *ns = &namespaces[0]; ns < namespaces + len; ++ns) {
		ns_enter_one(ns);
	}
}
