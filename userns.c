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
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "userns.h"

enum {
	ID_MAX     = 65535,

	/* uid/gid values and user/group names are within 32 digits (man useradd) */
	ID_STR_MAX = 32,

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
		err(1, "burn(%s): open", path);
	}

	if (write(fd, data, strlen(data)) == -1) {
		err(1, "burn(%s): write", path);
	}

	if (close(fd) == -1) {
		err(1, "burn(%s): close", path);
	}
}

/* populate_id_map generates the contents of a [ug]id map.

   First, a mapping of `id` to 0 (root) is generated.

   Then, the function reads each entry in subid_path, which are of the form
   <name_or_id>:<start>:<length>\n, finds any of these allocated [ug]id ranges
   for which name_or_id matches either `name` or `id`, and grafts them
   together as a continuous [ug]id map. The function tries to map every uid
   from 0 to 65534 in the user namespace. If there are less IDs allocated in
   subid_path, the function fills up the available IDs starting from 0, then
   prints a warning and returns.

   The [ug]id map is written to `map`, which is a string bounded by `size`,
   and which follows the format described in man 7 user_namespaces,
   § "User and group ID mappings: uid_map and gid_map".

   For instance, given the following /etc/subuid:

       $ cat /etc/subuid
       barney:100000:65535

   Then, calling the function as such:

       populate_id_map(map, sizeof (map), "/etc/subuid", "1000", "barney");

   will populate the contents of `map` with the following data:

       0 1000 1
       1 100000 65534

   There is a special case for id 0 (root) if there are no allocated entries
   for it in subid_path. In that case, if the real uid of the program is 0,
   then populate_id_map maps 1:1 the host range 0-65534 into the user
   namespace. This is to provide a sane default while keeping some leeway for
   system configuration. */
static void populate_id_map(char *map, size_t size,
		const char *subid_path, const char *id, const char *name)
{

#define appendf(map, size, ...) \
	do { \
		int written = snprintf(map, size - 1, __VA_ARGS__); \
		if ((size_t) written >= size - 1) { \
			errx(1, "populate_id_map: could not append to id map: buffer too small."); \
		} \
		map += written; \
		size -= written; \
		*map = 0; \
	} while (0)

	/* Map our current uid to root.

	   This is pretty much the only sane thing to do -- keeping our current
	   user ID doesn't make sense unless we map it, and mapping it 1:1
	   then means that we can't setuid into anything else as soon as we
	   exec. */
	appendf(map, size, "0 %s 1\n", id);

	int cur_id = 1;

	FILE *subids = fopen(subid_path, "r");
	if (!subids) {
		goto no_subids;
	}

	/* Realistically speaking, each line can only contain a maximum of
	   3 * ID_STR_MAX + 2 characters. We are being very generous because
	   size assumptions tend to bite back, and pages are extremely cheap. */
	char line[4096];

	while (fgets(line, sizeof (line), subids)) {
		/* Note: entryname might not be null-terminated if the file
		   contains an username of 32 characters. */
		char entryname[ID_STR_MAX];
		int start;
		int length;

		_Static_assert(ID_STR_MAX == 32, "scanf width must be equal to ID_STR_MAX");
		int items = sscanf(line, "%32[^:]:%d:%d\n",
				entryname,
				&start,
				&length);

		if (items != 3) {
			continue;
		}

		if (strncmp(entryname, name, sizeof (entryname) != 0)
				&& strncmp(entryname, id, sizeof (entryname)) != 0) {
			continue;
		}

		if (cur_id + length >= ID_MAX) {
			length = ID_MAX - cur_id;
		}

		appendf(map, size, "%d %d %d\n", cur_id, start, length);
		cur_id += length;
	}

	fclose(subids);

no_subids:
	/* We're root. We don't care. Map the host range 1:1. */
	if (cur_id == 1 && strcmp(id, "0") == 0) {
		appendf(map, size, "1 1 %d\n", ID_MAX - 1);
		return;
	}

	/* Not enough subuids for a full mapping, but, well, it's not the end of
	   the world. Things might break, so let's at least tell the user. */

	if (!subids) {
		warnx("no range associated to %s in %s. Things may not work "
				"as expected, please allocate at least %d IDs for it.",
				name, subid_path, ID_MAX);
		return;
	}

	if (cur_id < ID_MAX) {
		warnx("not enough IDs allocated for %s in %s (currently %d allocated). "
				"Things may not work as expected, please allocate at least %d "
				"IDs for it.",
				name, subid_path, cur_id, ID_MAX);
	}
}

static char *itoa(int i) {
	static char buf[ID_STR_MAX + 1];

	if ((size_t) snprintf(buf, sizeof (buf), "%d", i) >= sizeof (buf)) {
		errx(1, "\"%d\" takes more than %zu bytes.", i, sizeof (buf));
	}

	return buf;
}

/* userns_helper_spawn spawns a new process whose only purpose is to modify
   the uid and gid mappings of our target process (TP).

   The userns helper thus runs as a sibling of the TP, and provides some basic
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
   that do exactly what bst--userns-helper does, which is writing to
   /proc/pid/[ug]id_map any id ranges that a user is allowed to map by looking
   allocated IDs for that user in /etc/sub[ug]id. We obviously don't want
   to rely on any external program that may or may not be installed on the
   host system, so we reimplement that functionality here. */
struct userns_helper userns_helper_spawn(void)
{
	int pipefds_in[2];
	if (pipe(pipefds_in) == -1) {
		err(1, "userns_helper: pipe");
	}

	int pipefds_out[2];
	if (pipe(pipefds_out) == -1) {
		err(1, "userns_helper: pipe");
	}

	pid_t pid = fork();
	if (pid == -1) {
		err(1, "userns_helper: fork");
	}

	if (pid) {
		close(pipefds_in[1]);
		close(pipefds_out[0]);
		return (struct userns_helper) {
			.pid = pid,
			.in = pipefds_in[0],
			.out = pipefds_out[1],
		};
	}

	close(pipefds_in[0]);
	close(pipefds_out[1]);

	pid_t child_pid;
	ssize_t rdbytes = read(pipefds_out[0], &child_pid, sizeof (child_pid));
	if (rdbytes == -1) {
		err(1, "userns_helper: read child pid");
	}

	/* This typically happens when the parent dies, e.g. Ctrl-C. Not worth
	   warning against. */
	if (rdbytes != sizeof (child_pid)) {
		_exit(1);
	}

	char procpath[PATH_MAX];
	if ((size_t) snprintf(procpath, PATH_MAX, "/proc/%d", child_pid) >= sizeof (procpath)) {
		errx(1, "/proc/%d takes more than PATH_MAX bytes.", child_pid);
	}

	int procfd = open(procpath, O_DIRECTORY);
	if (procfd == -1) {
		err(1, "open(\"%s\", O_DIRECTORY)", procpath);
	}

	char map[ID_MAP_MAX];
	const char *id_str;

	uid_t uid = getuid();
	struct passwd *passwd = getpwuid(uid);
	id_str = itoa(uid);
	populate_id_map(map, sizeof (map), "/etc/subuid", id_str, passwd ? passwd->pw_name : id_str);
	burn(procfd, "uid_map", map);

	gid_t gid = getgid();
	struct group *group = getgrgid(gid);
	id_str = itoa(gid);
	populate_id_map(map, sizeof (map), "/etc/subgid", id_str, group ? group->gr_name : id_str);
	burn(procfd, "gid_map", map);

	/* Notify sibling that we're done changing their [ug]id map */
	int ok = 1;
	write(pipefds_in[1], &ok, sizeof (ok));

	_exit(0);
}

void userns_helper_sendpid(const struct userns_helper *helper, pid_t pid)
{
	/* Unblock the privileged helper to set our own [ug]id maps */
	if (write(helper->out, &pid, sizeof (pid)) == -1) {
		err(1, "userns_helper_sendpid: write");
	}

	int status;
	if (waitpid(helper->pid, &status, 0) == -1) {
		err(1, "userns_helper_sendpid: waitpid");
	}

	if (WIFSIGNALED(status)) {
		errx(1, "userns_helper_sendpid: process died with signal %d.", WTERMSIG(status));
	}

	if (WIFEXITED(status) && WEXITSTATUS(status)) {
		errx(1, "userns_helper_sendpid: process exited with nonzero exit status %d.", WEXITSTATUS(status));
	}
}

void userns_helper_wait(const struct userns_helper *helper)
{
	int ok;
	if (read(helper->in, &ok, sizeof (ok)) == -1) {
		err(1, "userns_helper_wait: read");
	}
}

void userns_helper_close(struct userns_helper *helper)
{
	close(helper->in);
	close(helper->out);
}
