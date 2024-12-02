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

// Note that for namespaces that want to enter into a specific namespace,
// we actually setns those before forking.
static bool is_postfork_ns(struct nsid *ns)
{
	/* For now, only the cgroup namespace needs to be unshared postfork */
	return ns->ns == NS_CGROUP;
}

void ns_enter_prefork(struct nsid *namespaces, size_t *len)
{
	/* Enter all relevant namespaces. It's hard to check in advance which
	   namespaces are supported, so we unshare them one by one in order. */

	// First we setns the things that have a specific fd to share into.
	struct nsid *ns = &namespaces[0];
	for (; ns < namespaces + *len; ++ns) {
		if (ns->action < 0) {
			continue;
		}
		// Note that we also setns the postfork namespaces here. If they
		// have a specific namespace to share into then we must share into
		// that namespace while we are still in the user namespace of that
		// target namespace.
		ns_enter_one(ns);
	}

	// Then setns the things that just need a blanket unshare (postfork
	// namespaces with NSACTION_UNSHARE need to be shard post-fork).
	ns = &namespaces[0];
	for (; ns < namespaces + *len; ++ns) {
		if (is_postfork_ns(ns)) {
			continue;
		}
		if (ns->action >= 0) {
			continue;
		}
		ns_enter_one(ns);
	}
}

void ns_enter_postfork(struct nsid *namespaces, size_t len)
{
	for (struct nsid *ns = &namespaces[0]; ns < namespaces + len; ++ns) {
		if (!is_postfork_ns(ns)) {
			// Already handled in ns_enter_prefork.
			continue;
		}
		if (ns->action >= 0) {
			// If there is an fd action then we already did this prefork.
			continue;
		}
		ns_enter_one(ns);
	}
}
