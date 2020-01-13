/* Copyright (c) 2020 Arista Networks, Inc.  All rights reserved.
   Arista Networks, Inc. Confidential and Proprietary. */

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
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "enter.h"
#include "mount.h"
#include "setarch.h"
#include "userns.h"

static int opts_to_unshareflags(const struct entry_settings *opts)
{
	int flags = 0;
	if (opts->pid) {
		flags |= CLONE_NEWPID;
	}
	if (opts->mount) {
		flags |= CLONE_NEWNS;
	}
	if (opts->cgroup) {
		flags |= CLONE_NEWCGROUP;
	}
	if (opts->ipc) {
		flags |= CLONE_NEWIPC;
	}
	if (opts->net) {
		flags |= CLONE_NEWNET;
	}
	if (opts->uts) {
		flags |= CLONE_NEWUTS;
	}
	if (opts->user) {
		flags |= CLONE_NEWUSER;
	}
	return flags;
}

int enter(const struct entry_settings *opts)
{
	/* We can't afford to leave children alive in the background if b5-enter
	   dies from uncatcheable signals. Or at least, we could, but this makes us
	   leaky by default which isn't great, and the obvious workaround to
	   daemonize the process tree is to just nohup b5-enter. */
	if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1) {
		err(1, "prctl(PR_SET_PDEATHSIG)");
	}

	struct userns_helper userns_helper;

	if (opts->user) {
		userns_helper = userns_helper_spawn();
	}

	if (unshare(opts_to_unshareflags(opts)) == -1) {
		err(1, "unshare");
	}

	/* Just unsharing the mount namespace is not sufficient -- if we don't make
	   every mount entry private, any change we make will be applied to the
	   parent mount namespace if it happens to have MS_SHARED propagation. We
	   don't like coin flips. */
	if (opts->mount && mount("none", "/", "", MS_REC | MS_PRIVATE, "") == -1) {
		err(1, "could not make / private: mount");
	}

	if (opts->arch && opts->arch[0] != 0) {
		setarch(opts->arch);
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

		if (opts->user) {
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

	if (opts->user) {
		userns_helper_wait(&userns_helper);
		userns_helper_close(&userns_helper);
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
	if (strcmp(opts->root, "/") != 0) {
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
	if (opts->mount && strcmp(opts->root, "/") != 0) {
		if (mount(opts->root, opts->root, "none", MS_BIND, "") == -1) {
			err(1, "mount(\"/\", \"/\", MS_BIND)");
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
		if (!opts->mount) {
			errx(1, "attempted to mount things on the host mount namespace.");
		}

		mount_entries(opts->root, opts->mounts, opts->nmounts);
		mount_mutables(opts->root, opts->mutables, opts->nmutables);
	}

	/* Don't chroot if opts->root is "/". This is a better default since it
	   allows us to run commands that unshare nothing unprivileged. */
	if (strcmp(opts->root, "/") != 0) {

		/* The chroot-ing logic is a bit delicate. If we don't have a mount
		   namespace, we just use chroot. This has its limitations though,
		   namely, in that situation, you won't be able to nest user
		   namespaces, and you'll instead get baffling EPERMs when calling
		   unshare(CLONE_NEWUSER).

		   In order to remediate that, we pivot the root. Since this actively
		   changes the world for every running process, we *insist* that this
		   must be done in a mount namespace, because otherwise pivot_root
		   will burn your house, invoke dragons, and eat your children. */

		if (!opts->mount) {
			if (chroot(opts->root) == -1) {
				err(1, "chroot");
			}
		} else {
			if (chdir(opts->root) == -1) {
				err(1, "pivot_root: pre chdir");
			}
			/* Pivot the root to opts->root (new_root) and mount the old root
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
	if (chdir(opts->workdir) == -1) {
		err(1, "chdir");
	}

	execvpe(opts->pathname, opts->argv, opts->envp);
	err(1, "execvpe");
}
