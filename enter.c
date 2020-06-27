/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "enter.h"
#include "init.h"
#include "mount.h"
#include "net.h"
#include "path.h"
#include "setarch.h"
#include "userns.h"

#define lengthof(Arr) (sizeof (Arr) / sizeof (*Arr))

struct cloneflag {
	const char *name;
	int flag;
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
		,
};

static int opts_to_unshareflags(const struct entry_settings *opts)
{
	static struct cloneflag flags[] = {
		{ "cgroup",  BST_CLONE_NEWCGROUP },
		{ "ipc",     BST_CLONE_NEWIPC },
		{ "mount",   BST_CLONE_NEWNS },
		{ "network", BST_CLONE_NEWNET },
		{ "pid",     BST_CLONE_NEWPID },
		{ "time",    BST_CLONE_NEWTIME },
		{ "user",    BST_CLONE_NEWUSER },
		{ "uts",     BST_CLONE_NEWUTS },
		{ "all",     ALL_NAMESPACES },
	};

	int unshareflags = ALL_NAMESPACES;
	for (const char *const *s = opts->shares; s < opts->shares + opts->nshares; ++s) {
		struct cloneflag *f;
		for (f = flags; f < flags + lengthof(flags); ++f) {
			if (strcmp(f->name, *s) == 0) {
				goto found;
			}
		}
		fprintf(stderr, "namespace `%s` does not exist.\n", *s);
		fprintf(stderr, "valid namespaces are: ");
		for (f = flags; f < flags + lengthof(flags) - 1; ++f) {
			fprintf(stderr, "%s, ", f->name);
		}
		fprintf(stderr, "%s.\n", f->name);
		exit(1);
found:
		unshareflags &= ~f->flag;
	}
	return unshareflags;
}

int enter(struct entry_settings *opts)
{
	const char *root = opts->root ? opts->root : "/";

	char resolved_root[PATH_MAX];
	if (realpath(root, resolved_root) == NULL) {
		err(1, "realpath(\"%s\")", root);
	}
	root = resolved_root;

	int unshareflags = opts_to_unshareflags(opts);

	struct userns_helper userns_helper;

	if (unshareflags & BST_CLONE_NEWUSER) {
		userns_helper = userns_helper_spawn();
	}

	int timens_offsets = -1;
	if (unshareflags & BST_CLONE_NEWTIME) {
		timens_offsets = open("/proc/self/timens_offsets", O_WRONLY);
		if (timens_offsets == -1) {
			if (errno != ENOENT) {
				err(1, "open(\"/proc/self/timens_offsets\")");
			}
			/* The kernel evidently don't support time namespaces yet. No need
			   to try below. */
			unshareflags &= ~BST_CLONE_NEWTIME;
		}
	}

	/* Drop all privileges, or none if we're real uid 0. */
	if (setuid(getuid()) == -1) {
		err(1, "setuid");
	}

	char cwd[PATH_MAX];
	char *workdir = opts->workdir;
	if ((!workdir || workdir[0] == '\0')) {
		if (getcwd(cwd, sizeof (cwd)) == NULL) {
			err(1, "getcwd");
		}

		assert(cwd[0] == '/' && "cwd must be an absolute path");
		assert(root[0] == '/' && "root must be an absolute path");

		/* Pure textual prefixing -- if the root is a prefix of the cwd, we remove
		   it. This must be done on two absolute paths.

		   As an exception, if root is /, the prefix is not removed. */
		size_t rootlen = strlen(root);
		if (strcmp(root, "/") == 0) {
			workdir = cwd;
		} else if (strncmp(root, cwd, rootlen) == 0) {
			workdir = cwd + rootlen;
		}
	}
	/* Our tentative to use the cwd failed, or it worked and the cwd _is_ the
	   new root. In both cases, the workdir must be /. */
	if (!workdir || workdir[0] == '\0') {
		workdir = "/";
	}

	/* Unshare all relevant namespaces. It's hard to check in advance which
	   namespaces are supported, so we unshare them one by one in order. */

	int unshareables[] = {
		/* User namespace must be unshared first and foremost. */
		BST_CLONE_NEWUSER,
		BST_CLONE_NEWNS,
		BST_CLONE_NEWUTS,
		BST_CLONE_NEWPID,
		BST_CLONE_NEWNET,
		BST_CLONE_NEWIPC,
		BST_CLONE_NEWCGROUP,
		BST_CLONE_NEWTIME,
		0,
	};

	for (int *flag = &unshareables[0]; *flag != 0; ++flag) {
		if (!(unshareflags & *flag)) {
			continue;
		}

		int rc = unshare(*flag);
		if (rc == -1 && errno == EINVAL) {
			/* We realized that the namespace isn't supported -- remove it
			   from the unshare set. */
			unshareflags &= ~*flag;
			continue;
		}
		if (rc == -1) {
			err(1, "unshare");
		}
	}

	/* Just unsharing the mount namespace is not sufficient -- if we don't make
	   every mount entry private, any change we make will be applied to the
	   parent mount namespace if it happens to have MS_SHARED propagation. We
	   don't like coin flips. */
	if (unshareflags & BST_CLONE_NEWNS && mount("none", "/", "", MS_REC | MS_PRIVATE, "") == -1) {
		err(1, "could not make / private: mount");
	}

	if (opts->arch && opts->arch[0] != 0) {
		setarch(opts->arch);
	}

	if (!opts->no_derandomize) {
		unsigned long persona = personality(0xffffffff) | ADDR_NO_RANDOMIZE;
		if (personality(persona) == -1) {
			err(1, "personality(%lu)", persona);
		}
	}

	if (unshareflags & BST_CLONE_NEWTIME) {
		init_clocks(timens_offsets, opts->clockspecs, lengthof(opts->clockspecs));
	}

	if (timens_offsets != -1 && close(timens_offsets) == -1) {
		err(1, "close(timens_offsets)");
	}

	/* You can't "really" unshare the PID namespace of a running process
	   without forking, since for process hierarchy reasons only the next
	   child process enters the namespace as init and subsequent calls to
	   clone(2) fails.

	   Since we set-up some things like the parent death signal, it's just
	   cleaner and easier to always fork, regardless of unsharing the PID
	   namespace. */

	pid_t pid = fork();
	if (pid == -1) {
		err(1, "fork");
	}

	if (pid) {
		int status;

		if (unshareflags & BST_CLONE_NEWUSER) {
			userns_helper_sendpid(&userns_helper, pid);
			userns_helper_close(&userns_helper);
		}

		if (waitpid(pid, &status, 0) == -1) {
			err(1, "waitpid");
		}

		if (WIFEXITED(status)) {
			return WEXITSTATUS(status);
		}
		return WTERMSIG(status) | 1 << 7;
	}

	/* We can't afford to leave the child alive in the background if bst
	   dies from uncatcheable signals. Or at least, we could, but this makes us
	   leaky by default which isn't great, and the obvious workaround to
	   daemonize the process tree is to just nohup bst. */
	if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1) {
		err(1, "prctl(PR_SET_PDEATHSIG)");
	}

	if (unshareflags & BST_CLONE_NEWUSER) {
		userns_helper_wait(&userns_helper);
		userns_helper_close(&userns_helper);
	}

	/* Check whether or not <root>/proc is a mountpoint. If so, and we're in a PID namespace,
	   mount a new /proc. */
	if (!opts->no_proc_remount && unshareflags & (BST_CLONE_NEWNS | BST_CLONE_NEWPID)) {
		int rootfd = open(root, O_PATH, 0);
		if (rootfd == -1) {
			err(1, "open(\"%s\")", root);
		}

		struct stat procst = { .st_dev = 0 };
		if (fstatat(rootfd, "proc", &procst, AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW) == -1 && errno != ENOENT) {
			err(1, "fstatat(\"%s/proc\")", root);
		}

		struct stat rootst;
		if (fstat(rootfd, &rootst) == -1) {
			err(1, "fstat(\"%s\")", root);
		}

		close(rootfd);

		/* <root>/proc is a mountpoint, remount it. And by remount, we mean mount over it,
		   since the original mount is probably more privileged than us, or might not be a
		   procfs one someone's oddball configuration. */
		if (procst.st_dev != 0 && procst.st_dev != rootst.st_dev) {
			const char *target = makepath("%s/proc", root);
			umount2(target, MNT_DETACH);

			if (mount("proc", target, "proc", 0, NULL) == -1) {
				err(1, "mount(\"proc\", \"%s\", \"proc\", 0)", target);
			}
		}
	}

	/* Set the host and domain names only when in an UTS namespace. */
	if ((opts->hostname || opts->domainname) && !(unshareflags & BST_CLONE_NEWUTS)) {
		errx(1, "attempted to set host or domain names on the host UTS namespace.");
	}

	const char *hostname = opts->hostname;
	if (!hostname && (unshareflags & BST_CLONE_NEWUTS)) {
		hostname = "localhost";
	}
	if (hostname && sethostname(hostname, strlen(hostname)) == -1) {
		err(1, "sethostname");
	}

	const char *domainname = opts->domainname;
	if (!domainname && (unshareflags & BST_CLONE_NEWUTS)) {
		domainname = "localdomain";
	}
	if (domainname && setdomainname(domainname, strlen(domainname)) == -1) {
		err(1, "setdomainname");
	}

	int rtnl = init_rtnetlink_socket();

	/* Setup localhost */
	if (unshareflags & BST_CLONE_NEWNET && !opts->no_localhost_setup) {
		net_if_up(rtnl, "lo");
	}

	/* The setuid will drop privileges. We ask to keep permitted capabilities
	   in order to restore them for the rest of the program. */
	prctl(PR_SET_KEEPCAPS, 1);

	if (opts->ngroups != 0 && setgroups(opts->ngroups, opts->groups) == -1) {
		err(1, "setgroups");
	}
	if (setregid(opts->gid, opts->gid) == -1) {
		err(1, "setregid");
	}
	if (setreuid(opts->uid, opts->uid) == -1) {
		err(1, "setreuid");
	}

	/* give ourselves back CAP_SYS_CHROOT if we need to chroot, and
	   CAP_SYS_ADMIN if we want to mount. */

	cap_value_t cap_list[2];

	size_t ncaps = 0;
	if (strcmp(root, "/") != 0) {
		cap_list[ncaps++] = CAP_SYS_CHROOT;
	}
	if (opts->nmounts > 0 || opts->nmutables > 0) {
		cap_list[ncaps++] = CAP_SYS_ADMIN;
	}

	cap_t caps = cap_get_proc();
	if (caps == NULL) {
		err(1, "cap_get_proc");
	}

	if (ncaps > 0 && cap_set_flag(caps, CAP_EFFECTIVE, ncaps, cap_list, CAP_SET) == -1) {
		err(1, "cap_set_flag");
	}

	if (cap_set_proc(caps) == -1) {
		err(1, "caps_set_proc");
	}

	if (cap_free(caps) == -1) {
		err(1, "cap_free");
	}

	/* We have a special case for pivot_root: the syscall wants the
	   new root to be a mount point, so we indulge. */
	if (unshareflags & BST_CLONE_NEWNS && strcmp(root, "/") != 0) {
		if (mount(root, root, "none", MS_BIND|MS_REC, "") == -1) {
			err(1, "mount(\"/\", \"/\", MS_BIND|MS_REC)");
		}
	}

	/* We have to do this after setuid/setgid/setgroups since mounting
	   tmpfses in user namespaces forces the options uid=<real-uid> and
	   gid=<real-gid>. */
	if (opts->nmounts > 0 || opts->nmutables > 0) {
		/* Don't shoot ourselves in the foot. It's technically possible to
		   let users mount things in the host mount namespace but in practice
		   it's a terrible idea due to the sheer amount of things that can go
		   wrong, like "what do I do if one of the mounts failed but the previous
		   ones didn't?", or "how do I clean up things that I've (re)mounted?". */
		if (!(unshareflags & BST_CLONE_NEWNS)) {
			errx(1, "attempted to mount things on the host mount namespace.");
		}

		if (!opts->no_fake_devtmpfs) {
			for (struct mount_entry *mnt = opts->mounts; mnt < opts->mounts + opts->nmounts; ++mnt) {
				if (strcmp(mnt->type, "devtmpfs") == 0) {
					mnt->type = "bst_devtmpfs";
				}
			}
		}

		mount_entries(root, opts->mounts, opts->nmounts, opts->no_derandomize);
		mount_mutables(root, opts->mutables, opts->nmutables);
	}

	/* Don't chroot if root is "/". This is a better default since it
	   allows us to run commands that unshare nothing unprivileged. */
	if (strcmp(root, "/") != 0) {

		/* The chroot-ing logic is a bit delicate. If we don't have a mount
		   namespace, we just use chroot. This has its limitations though,
		   namely, in that situation, you won't be able to nest user
		   namespaces, and you'll instead get baffling EPERMs when calling
		   unshare(CLONE_NEWUSER).

		   In order to remediate that, we pivot the root. Since this actively
		   changes the world for every running process, we *insist* that this
		   must be done in a mount namespace, because otherwise pivot_root
		   will burn your house, invoke dragons, and eat your children. */

		if (!(unshareflags & BST_CLONE_NEWNS)) {
			if (chroot(root) == -1) {
				err(1, "chroot");
			}
		} else {
			if (chdir(root) == -1) {
				err(1, "pivot_root: pre chdir");
			}
			/* Pivot the root to `root` (new_root) and mount the old root
			   (old_dir) on top of it. Then, unmount "." to get rid of the
			   old root.

			   The pivot_root manpage documents this approach: old_dir is
			   always layered on top of new_root, which means that we can
			   use this technique to avoid creating a mount point for the
			   old root under new_root, or assuming anything about the layout
			   of the new root. */
			if (syscall(SYS_pivot_root, ".", ".") == -1) {
				err(1, "pivot_root");
			}
			if (umount2(".", MNT_DETACH)) {
				err(1, "pivot_root: umount2");
			}
			if (chdir("/") == -1) {
				err(1, "pivot_root: post chdir");
			}
		}
	}
	if (chdir(workdir) == -1) {
		warn("chdir(\"%s\")", workdir);
		warnx("falling back work directory to /.");
		if (chdir("/") == -1) {
			err(1, "chdir(\"/\")");
		}
	}

	if (unshareflags & BST_CLONE_NEWPID && !opts->no_init) {
		pid_t child = fork();

		if (child == -1) {
			err(1, "fork");
		} else if (child) {
			init(child);
			__builtin_unreachable();
		}
	}

	execvpe(opts->pathname, opts->argv, opts->envp);
	err(1, "execvpe");
}
