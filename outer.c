/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "capable.h"
#include "enter.h"
#include "flags.h"
#include "outer.h"
#include "userns.h"

#define lengthof(Arr) (sizeof (Arr) / sizeof (*Arr))

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
static void burn(int dirfd, char *path, char *data)
{
	int fd = openat(dirfd, path, O_WRONLY, 0);
	if (fd == -1) {
		err(1, "burn %s: open", path);
	}

	if (write(fd, data, strlen(data)) == -1) {
		err(1, "burn %s: write", path);
	}

	if (close(fd) == -1) {
		err(1, "burn %s: close", path);
	}
}

static void burn_uidmap_gidmap(pid_t child_pid)
{
	char procpath[PATH_MAX];
	if ((size_t) snprintf(procpath, PATH_MAX, "/proc/%d", child_pid) >= sizeof (procpath)) {
		errx(1, "/proc/%d takes more than PATH_MAX bytes.", child_pid);
	}

	int procfd = open(procpath, O_DIRECTORY | O_PATH);
	if (procfd == -1) {
		err(1, "open %s", procpath);
	}

	id_map cur_uid_map;
	id_map_load_procids(cur_uid_map, "/proc/self/uid_map");
	id_map cur_gid_map;
	id_map_load_procids(cur_gid_map, "/proc/self/gid_map");

	/* /proc/self/[ug]id_map files should be well-formed, but we might as well
	   enforce that rather than blindly trust. */
	id_map_normalize(cur_uid_map, true, false);
	id_map_normalize(cur_gid_map, true, false);

	id_map subuids;
	uid_t uid = getuid();
	struct passwd *passwd = getpwuid(uid);
	id_map_load_subids(subuids, "/etc/subuid", uid, passwd ? passwd->pw_name : NULL);

	id_map subgids;
	gid_t gid = getgid();
	struct group *group = getgrgid(gid);
	id_map_load_subids(subgids, "/etc/subgid", gid, group ? group->gr_name : NULL);

	/* Slice up subid maps according to current id mappings. */
	id_map_normalize(subuids, false, true);
	id_map_project(subuids, cur_uid_map, subuids);
	id_map_normalize(subgids, false, true);
	id_map_project(subgids, cur_gid_map, subgids);

	char uid_map[ID_MAP_MAX];
	id_map_format(subuids, uid_map, sizeof (uid_map));

	char gid_map[ID_MAP_MAX];
	id_map_format(subgids, gid_map, sizeof (gid_map));

	make_capable(BST_CAP_SETUID | BST_CAP_SETGID | BST_CAP_DAC_OVERRIDE);

	burn(procfd, "uid_map", uid_map);
	burn(procfd, "gid_map", gid_map);

	reset_capabilities();
}

static void persist_ns_files(int pid, const char *persist);

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
	int pipefds_in[2];
	if (pipe(pipefds_in) == -1) {
		err(1, "outer_helper: pipe");
	}

	int pipefds_out[2];
	if (pipe(pipefds_out) == -1) {
		err(1, "outer_helper: pipe");
	}

	pid_t pid = fork();
	if (pid == -1) {
		err(1, "outer_helper: fork");
	}

	if (pid) {
		close(pipefds_in[1]);
		close(pipefds_out[0]);
		helper->pid = pid;
		helper->in = pipefds_in[0];
		helper->out = pipefds_out[1];
		return;
	}

	close(pipefds_in[0]);
	close(pipefds_out[1]);

	pid_t child_pid;
	ssize_t rdbytes = read(pipefds_out[0], &child_pid, sizeof (child_pid));
	if (rdbytes == -1) {
		err(1, "outer_helper: read child pid");
	}

	/* This typically happens when the parent dies, e.g. Ctrl-C. Not worth
	   warning against. */
	if (rdbytes != sizeof (child_pid)) {
		_exit(1);
	}

	if (helper->unshare_user) {
		burn_uidmap_gidmap(child_pid);
	}

	if (helper->persist) {
		persist_ns_files(child_pid, helper->persist);
	}
	
	/* Notify sibling that we're done persisting their proc files
	   and/or changing their [ug]id map */
	int ok = 1;
	write(pipefds_in[1], &ok, sizeof (ok));

	_exit(0);
}

struct persistflag {
	int flag;
	const char *proc_ns_name;
};

static struct persistflag pflags[] = {
	[ SHARE_CGROUP ]   = { BST_CLONE_NEWCGROUP,   "cgroup"   },
	[ SHARE_IPC ]      = { BST_CLONE_NEWIPC,      "ipc",     },
	[ SHARE_MNT ]      = { BST_CLONE_NEWNS,       "mnt"      },
	[ SHARE_NET ]      = { BST_CLONE_NEWNET,      "net"      },
	[ SHARE_PID ]      = { BST_CLONE_NEWPID,      "pid"      },
	[ SHARE_TIME ]     = { BST_CLONE_NEWTIME,     "time"     },
	[ SHARE_USER ]     = { BST_CLONE_NEWUSER,     "user"     },
	[ SHARE_UTS ]      = { BST_CLONE_NEWUTS,      "uts"      },
};

static void persist_ns_files(int pid, const char *persist) {
	char procname[PATH_MAX];
	snprintf(procname, sizeof(procname), "/proc/%d/ns", pid);
	int procnsdir = open(procname, O_DIRECTORY | O_PATH);
	if (procnsdir < 0) {
		err(1, "open %s", procname);
	}
	int persistdir = open(persist, O_DIRECTORY | O_PATH);
	if (persistdir < 0) {
		err(1, "open %s", persist);
	}
	for (struct persistflag *f = pflags; f < pflags + lengthof(pflags); f++) {
		int nsfd = openat(persistdir, f->proc_ns_name, O_CREAT | O_WRONLY | O_EXCL, 0666);
		if (nsfd < 0) {
			if (errno != EEXIST) {
				err(1, "creat %s/%s", persist, f->proc_ns_name);
			}
		} else {
			close(nsfd);
		}

		// Where is mountat()?  Thankfully, we can still name the persist directory.
		snprintf(procname, sizeof(procname), "/proc/%d/ns/%s", pid, f->proc_ns_name);
		procname[sizeof(procname) - 1] = 0;

		char persistname[PATH_MAX];
		snprintf(persistname, sizeof(persistname), "%s/%s", persist, f->proc_ns_name);
		persistname[sizeof(persistname) - 1] = 0;

		make_capable(BST_CAP_SYS_ADMIN | BST_CAP_SYS_PTRACE);

		int rc = mount(procname, persistname, "", MS_BIND, "");

		reset_capabilities();

		if (rc == -1) {
			if (errno == ENOENT) {
				/* Kernel does not support this namespace type.  Remove the mountpoint. */
				unlinkat(persistdir, f->proc_ns_name, 0);
			} else {
				err(1, "bind-mount %s to %s", procname, persistname);
			}
		}
	}
	close(persistdir);
	close(procnsdir);
}

void outer_helper_sendpid_and_wait(const struct outer_helper *helper, pid_t pid)
{
	/* Unblock the privileged helper to set our own [ug]id maps */
	if (write(helper->out, &pid, sizeof (pid)) == -1) {
		err(1, "outer_helper_sendpid_and_wait: write");
	}

	int status;
	if (waitpid(helper->pid, &status, 0) == -1) {
		err(1, "outer_helper_sendpid_and_wait: waitpid");
	}

	if (WIFSIGNALED(status)) {
		errx(1, "outer_helper_sendpid_and_wait: helper died with signal %d", WTERMSIG(status));
	}

	if (WIFEXITED(status) && WEXITSTATUS(status)) {
		errx(1, "outer_helper_sendpid_and_wait: helper exit status %d", WEXITSTATUS(status));
	}
}

void outer_helper_sync(const struct outer_helper *helper)
{
	int ok;
	int n = read(helper->in, &ok, sizeof (ok));
	switch (n) {
	case -1:
		err(1, "outer_helper_wait: read");
	case 0:
		/* Outer helper died before setting all of our attributes. */
		exit(1);
	}
}

void outer_helper_close(struct outer_helper *helper)
{
	close(helper->in);
	close(helper->out);
}
