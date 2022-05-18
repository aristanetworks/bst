/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <unistd.h>

#include "capable.h"
#include "cgroup.h"
#include "compat.h"
#include "config.h"
#include "enter.h"
#include "fd.h"
#include "outer.h"
#include "path.h"
#include "sig.h"
#include "userns.h"
#include "util.h"

#ifdef HAVE_SECCOMP_UNOTIFY
# include "sec.h"
#endif

enum {
	/* This should be enough for defining our mappings. If we assign
	   340 mappings, and since each line would contain at most
	   12 digits * 3 + 2 spaces + 1 newline, this would take about 13260
	   bytes. */
	ID_MAP_MAX = 4 * 4096,
};

/* burn opens the file pointed by path relative to dirfd, burns in it a
   null-terminated string using exactly one write syscall, then closes the file.

   This helper is useful for writing data in files that can only be written to
   exactly once (hence "burning" rather than "writing"). Such files
   include /proc/pid/uid_map, /proc/pid/gid_map, and /proc/pid/setgroups
   under some circumstances. */
ssize_t burn(int dirfd, char *path, char *data)
{
	int fd = openat(dirfd, path, O_WRONLY, 0);
	if (fd == -1) {
		return -1;
	}

	ssize_t written = write(fd, data, strlen(data));
	if (written == -1) {
		return -1;
	}

	if (close(fd) == -1) {
		return -1;
	}
	return written;
}

static void make_idmap(char *idmap, size_t size, const char *which,
		const char *subid_path,
		const char *procmap_path,
		const struct id *id, id_map desired)
{
	id_map cur_id_map;
	id_map_load_procids(cur_id_map, procmap_path);

	/* /proc/self/[ug]id_map files should be well-formed, but we might as well
	   enforce that rather than blindly trust. */
	id_map_normalize(cur_id_map, true, false);

	id_map subids;
	id_map_load_subids(subids, subid_path, id);
	id_map_normalize(subids, false, true);

	/* Project desired id maps onto permissible maps */
	if (!id_map_empty(desired)) {
		for (struct id_range *r = subids; r < subids + MAX_USER_MAPPINGS; ++r) {
			r->inner = r->outer;
		}

		id_map_normalize(desired, false, true);
		id_map_project(desired, subids, subids);

		uint32_t nids = id_map_count_ids(subids);
		uint32_t desired_ids = id_map_count_ids(desired);
		if (nids == UINT32_MAX || desired_ids == UINT32_MAX) {
			err(1, "too many %ss to map", which);
		}
		if (nids != desired_ids) {
			errx(1, "cannot map desired %s map: some %ss are not in the %ss "
				"allowed in %s", which, which, which, subid_path);
		}
	} else {
		id_map_generate(subids, subids, subid_path, id);
	}

	/* Slice up subid maps according to current id mappings. */
	id_map_project(subids, cur_id_map, subids);

	id_map_format(subids, idmap, size);
}

static void burn_uidmap_gidmap(pid_t child_pid, id_map uid_desired, id_map gid_desired)
{
	char procpath[PATH_MAX];
	if ((size_t) snprintf(procpath, PATH_MAX, "/proc/%d", child_pid) >= sizeof (procpath)) {
		errx(1, "/proc/%d takes more than PATH_MAX bytes.", child_pid);
	}

	int procfd = open(procpath, O_DIRECTORY | O_PATH);
	if (procfd == -1) {
		err(1, "open %s", procpath);
	}

	struct id uid = id_load_user(getuid());
	struct id gid = id_load_group(getgid());

	char uid_map[ID_MAP_MAX];
	make_idmap(uid_map, sizeof (uid_map), "uid", "/etc/subuid", "/proc/self/uid_map", &uid, uid_desired);

	char gid_map[ID_MAP_MAX];
	make_idmap(gid_map, sizeof (gid_map), "gid", "/etc/subgid", "/proc/self/gid_map", &gid, gid_desired);

	make_capable(BST_CAP_SETUID | BST_CAP_SETGID | BST_CAP_DAC_OVERRIDE);

	if (burn(procfd, "uid_map", uid_map) == -1) {
		err(1, "burn /proc/%d/uid_map", child_pid);
	}
	if (burn(procfd, "gid_map", gid_map) == -1) {
		err(1, "burn /proc/%d/gid_map", child_pid);
	}

	reset_capabilities();
}

static void create_nics(pid_t child_pid, struct nic_options *nics, size_t nnics)
{
	make_capable(BST_CAP_NET_ADMIN);

	int rtnl = init_rtnetlink_socket();

	for (size_t i = 0; i < nnics; ++i) {
		nics[i].netns_pid = child_pid;
		net_if_add(rtnl, &nics[i]);
	}

	reset_capabilities();
}

static void persist_ns_files(pid_t pid, const char **persist)
{
	for (enum nstype ns = 0; ns < MAX_NS; ++ns) {
		if (persist[ns] == NULL) {
			continue;
		}

		const char *name = ns_name(ns);

		if (mknod(persist[ns], S_IFREG, 0) == -1 && errno != EEXIST) {
			err(1, "create %s", persist[ns]);
		}

		char procpath[PATH_MAX];
		makepath_r(procpath, "/proc/%d/ns/%s", pid, name);

		make_capable(BST_CAP_SYS_ADMIN | BST_CAP_SYS_PTRACE);

		int rc = mount(procpath, persist[ns], "", MS_BIND, "");

		reset_capabilities();

		if (rc == -1) {
			unlink(persist[ns]);

			switch errno {
			case ENOENT:
				/* Kernel does not support this namespace type. */
				break;
			case EINVAL:
				errx(1, "bind-mount %s to %s: %s (is the destination on a private mount?)",
						procpath, persist[ns], strerror(EINVAL));
			default:
				err(1, "bind-mount %s to %s", procpath, persist[ns]);
			}
		}
	}
}

/* outer_helper_spawn spawns a new process whose only purpose is to modify
   the uid and gid mappings of our target process (TP).

   The outer helper thus runs as a sibling of the TP, and provides some basic
   synchronization routines to make sure the TP waits for its sibling to complete
   before calling setgroups/setgid/setuid.

   The reason why this helper is necessary is because once we enter the user
   namespace, we drop CAP_SET[UG]ID on the host namespace, which means we
   can't map arbitrary sub[ug]id ranges. We could setuid bst itself and
   do these mappings from a regular fork(), but this means that we can no
   longer do the right thing w.r.t unprivileged user namespaces, not to mention
   that I'm not happy with having a rootkit that everyone can use on my own
   machine.

   The canonical way to do all of this on a modern Linux distribution is to
   call the newuidmap and newgidmap utilities, which are generic interfaces
   that do exactly what bst--outer-helper does, which is writing to
   /proc/pid/[ug]id_map any id ranges that a user is allowed to map by looking
   allocated IDs for that user in /etc/sub[ug]id. We obviously don't want
   to rely on any external program that may or may not be installed on the
   host system, so we reimplement that functionality here. */
void outer_helper_spawn(struct outer_helper *helper)
{
	enum {
		SOCKET_PARENT,
		SOCKET_CHILD,
	};
	int fdpair[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fdpair) == -1) {
		err(1, "outer_helper: socketpair");
	}

	/* Set up a pipe that we do nothing with; we use the read end as the parent
	   handle in sig_setpdeathsig, and the write end will get closed on
	   process exit. This ensures that we are able to properly detect process
	   reparenting before we've called prctl(PR_SET_PDEATHSIG). */
	enum {
		LIVENESS_CHECK,
		LIVENESS_KEEP,
	};
	int liveness_fds[2];
	if (pipe2(liveness_fds, O_CLOEXEC | O_NONBLOCK) == -1) {
		err(1, "pipe2");
	}

	pid_t pid = fork();
	if (pid == -1) {
		err(1, "outer_helper: fork");
	}

	if (pid) {
		close(fdpair[SOCKET_CHILD]);
		close(liveness_fds[LIVENESS_CHECK]);
		helper->pid = pid;
		helper->fd  = fdpair[SOCKET_PARENT];
		return;
	}

	sig_setpdeathsig(SIGKILL, liveness_fds[LIVENESS_CHECK]);

	/* Make sure all file descriptors except for the ones we're actually using
	   get closed. This avoids keeping around file descriptors on which
	   the parent process might be waiting on. */
	rebind_fds_and_close_rest(3, &fdpair[SOCKET_CHILD], NULL);

	sigset_t mask;
	sigemptyset(&mask);

	if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
		err(1, "sigprocmask");
	}

	int fd = fdpair[SOCKET_CHILD];

	pid_t child_pid;
	ssize_t rdbytes = read(fd, &child_pid, sizeof (child_pid));
	if (rdbytes == -1) {
		err(1, "outer_helper: read child pid");
	}

	/* This typically happens when the parent dies, e.g. Ctrl-C. Not worth
	   warning against. */
	if (rdbytes != sizeof (child_pid)) {
		_exit(1);
	}

	int critical_limits = 0;
	for (size_t i = 0; i < helper->nclimits; ++i) {
		if (helper->climits[i].critical) {
			critical_limits++;
		}
	}

	int cgroup_driver_rc = cgroup_driver_init(helper->cgroup_driver, !!critical_limits);

	char cgroup_path[PATH_MAX];
	if (cgroup_driver_rc >= 0 && (helper->nclimits != 0 || helper->cgroup_path != NULL)) {
		if (helper->cgroup_path == NULL && cgroup_current_path(cgroup_path)) {
			helper->cgroup_path = cgroup_path;
		}
		if (helper->nclimits != 0 && helper->cgroup_path == NULL) {
			errx(1, "unable to apply limits without --cgroup specified");
		}
	}

	if (cgroup_driver_rc >= 0 && helper->cgroup_path != NULL) {
		uint64_t id[2];
		switch (getrandom(id, sizeof (id), 0)) {
		case -1:
			err(1, "outer_helper: getrandom");
		case sizeof (id):
			break;
		default:
			errx(1, "outer_helper: getrandom: did not return enough bytes");
		}

		char cgroupstr[PATH_MAX];
		makepath_r(cgroupstr, "bst-%" PRIx64 "%" PRIx64, id[0], id[1]);

		int cgroupfd = cgroup_join(helper->cgroup_path, cgroupstr);
		if (cgroupfd == -1) {
			err(1, "outer_helper: unable to open current cgroup");
		}

		/* Create two subcgroups; controller, which will contain this process,
		   and worker, which will contain the child process.

		   This is done to avoid the no-internal-process rule. */

		/* NOTE: this is fine, since we did some access checks earlier on putting
		   the current process into the parent cgroup */
		make_capable(BST_CAP_DAC_OVERRIDE);

		if (mkdirat(cgroupfd, "controller", 0777) == -1) {
			if (critical_limits > 0) {
				err(1, "outer_helper: unable to create controller sub-cgroup");
			} else {
				close(cgroupfd);
				goto unshare;
			}
		}
		if (mkdirat(cgroupfd, "worker", 0777) == -1) {
			if (critical_limits > 0) {
				err(1, "outer_helper: unable to create worker sub-cgroup");
			} else {
				close(cgroupfd);
				goto unshare;
			}
		}

		char pidstr[BUFSIZ];
		if (sprintf(pidstr, "%d", child_pid) == -1) {
			err(1, "outer_helper: unable to convert child_pid to string");
		}

		/* Put ourselves in the controller cgroup & the child in the worker cgroup */
		burn(cgroupfd, "controller/cgroup.procs", "0");
		burn(cgroupfd, "worker/cgroup.procs", pidstr);
		reset_capabilities();

		cgroup_enable_controllers(cgroupfd);

		/* Cgroup subhierarchy is created, now apply specified limits */
		int subcgroupfd = openat(cgroupfd, "worker", O_DIRECTORY);
		if (subcgroupfd == -1) {
			err(1, "outer_helper: unable to open worker cgroup");
		}

		for (size_t i = 0; i < helper->nclimits; ++i) {
			struct climit *lim = &helper->climits[i];
			if (burn(subcgroupfd, lim->fname, lim->limit) == -1) {
				switch (errno) {
				case ENOENT:
					if (lim->critical) {
						errx(1, "unknown cgroup limit %s", lim->fname);
					}
					break;
				default:
					err(1, "setting cgroup limit %s to %s", lim->fname, lim->limit);
				}
			}
		}

		if (close(subcgroupfd) == -1) {
			err(1, "outer_helper: close worker cgroup");
		}

		if (close(cgroupfd) == -1) {
			err(1, "outer_helper: close cgroup");
		}
	}

unshare:
	if (helper->unshare_user) {
		burn_uidmap_gidmap(child_pid, helper->uid_desired, helper->gid_desired);
	}

	persist_ns_files(child_pid, helper->persist);

	if (helper->unshare_net) {
		create_nics(child_pid, helper->nics, helper->nnics);
	}

	/* Notify sibling that we're done persisting their proc files
	   and/or changing their [ug]id map */
	int ok = 1;
	ssize_t count = write(fd, &ok, sizeof (ok));
	assert((ssize_t)(sizeof (ok)) == count);

#ifdef HAVE_SECCOMP_UNOTIFY
	int seccomp_fd = recv_fd(fd);
	sec_seccomp_supervisor(seccomp_fd);
	__builtin_unreachable();
#else
	_exit(0);
#endif
}

void outer_helper_sendpid(const struct outer_helper *helper, pid_t pid)
{
	/* Unblock the privileged helper to set our own [ug]id maps */
	if (write(helper->fd, &pid, sizeof (pid)) == -1) {
		err(1, "outer_helper_sendpid_and_wait: write");
	}
}

void outer_helper_sync(const struct outer_helper *helper)
{
	int ok;
	switch (read(helper->fd, &ok, sizeof (ok))) {
	case -1:
		err(1, "outer_helper_wait: read");
	case 0:
		/* Outer helper died before setting all of our attributes. */
		exit(1);
	}
}

void outer_helper_close(struct outer_helper *helper)
{
	close(helper->fd);
}
