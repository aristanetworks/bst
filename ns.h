/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef NS_H_
# define NS_H_

struct cloneflag {
	int flag;
	const char *proc_ns_name;
};

enum {
	/* To ensure backward and forward compatibility for the ability of
	   unsharing the maximum of namespaces, we re-define these constants. */
	BST_CLONE_NEWNET    = 0x40000000,
	BST_CLONE_NEWUTS    = 0x04000000,
	BST_CLONE_NEWCGROUP = 0x02000000,
	BST_CLONE_NEWNS     = 0x00020000,
	BST_CLONE_NEWPID    = 0x20000000,
	BST_CLONE_NEWUSER   = 0x10000000,
	BST_CLONE_NEWIPC    = 0x08000000,
	BST_CLONE_NEWTIME   = 0x00000080,

	ALL_NAMESPACES = 0
		| BST_CLONE_NEWCGROUP
		| BST_CLONE_NEWIPC
		| BST_CLONE_NEWNS
		| BST_CLONE_NEWNET
		| BST_CLONE_NEWPID
		| BST_CLONE_NEWUSER
		| BST_CLONE_NEWUTS
		| BST_CLONE_NEWTIME
};

enum nstype {
	NS_CGROUP = 0,
	NS_IPC,
	NS_MNT,
	NS_NET,
	NS_PID,
	NS_TIME,
	NS_USER,
	NS_UTS,

	MAX_NS
};

enum nsaction {
	NSACTION_SHARE_WITH_PARENT = -1,
	NSACTION_UNSHARE = -2,
};

struct nsid {
	int ns;
	enum nsaction action;
};

const char *ns_name(enum nstype);
int ns_cloneflag(enum nstype);

bool is_nsfd_current(int nsfd, const char *name);
void ns_enter_prefork(struct nsid *namespaces, size_t *len);
void ns_enter_postfork(struct nsid *namespaces, size_t len);

#endif /* !NS_H_ */
