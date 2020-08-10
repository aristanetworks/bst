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

#include "enter.h"
#include "ns.h"

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

void ns_enter(enum nsaction *nsactions)
{
	/* Enter all relevant namespaces. It's hard to check in advance which
	   namespaces are supported, so we unshare them one by one in order. */

	static int namespaces[] = {
		/* User namespace must be entered first and foremost. */
		NS_USER,
		NS_NET,
		NS_MNT,
		NS_IPC,
		NS_PID,
		NS_CGROUP,
		NS_UTS,
		NS_TIME,
		-1,
	};

	for (int *ns = &namespaces[0]; *ns != -1; ++ns) {
		enum nsaction action = nsactions[*ns];

		switch (action) {
		case NSACTION_UNSHARE:
			if (unshare(flags[*ns].flag) == -1) {
				if (errno == EINVAL) {
					/* We realized that the namespace isn't supported -- remove it
					   from the unshare set. */
					nsactions[*ns] = NSACTION_SHARE_WITH_PARENT;
				} else {
					err(1, "unshare %s", flags[*ns].proc_ns_name);
				}
			}
			break;

		case NSACTION_SHARE_WITH_PARENT:
			break;

		default:
			if (setns(action, flags[*ns].flag) == -1) {
				err(1, "setns %s", flags[*ns].proc_ns_name);
			}
			close(action);
			break;
		}
	}
}
