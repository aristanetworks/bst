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
#include <sys/mount.h>
#include <sys/prctl.h>
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

		if (TEMP_FAILURE_RETRY(waitpid(pid, &status, 0)) == -1) {
			err(1, "waitpid");
		}
		return status;
	}

	if (opts->user) {
		userns_helper_wait(&userns_helper);
		userns_helper_close(&userns_helper);
	}

	if (opts->ngroups != 0 && setgroups(opts->ngroups, opts->groups) == -1) {
		err(1, "setgroups");
	}
	if (setregid(opts->gid, opts->gid) == -1) {
		err(1, "setregid");
	}
	if (setreuid(opts->uid, opts->uid) == -1) {
		err(1, "setreuid");
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

	if (chroot(opts->root) == -1) {
		err(1, "chroot");
	}
	if (chdir(opts->workdir) == -1) {
		err(1, "chdir");
	}

	execvpe(opts->pathname, opts->argv, opts->envp);
	err(1, "execvpe");
}
