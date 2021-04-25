/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "mount.h"
#include "path.h"
#include "util.h"

struct mntflag {
	const char *name;
	unsigned long flag;
};

static int cmpflags(const void *lhs, const void *rhs)
{
	const char *flagname = lhs;
	const struct mntflag *flag = rhs;
	return strcmp(flagname, flag->name);
}

/* update_mount_flags_and_options updates in-place its own input by
   iterating through `opts`, updating `mountflags` when encountering any option
   defined in man mount(8) by its equivalent change in the bitfield, and
   removing the option from `opts`, leaving only fs-specific options.

   update_mount_flags_and_options is idempotent. */
static void update_mount_flags_and_options(unsigned long *mountflags, char *opts)
{
	/* Keep these two arrays ordered. We use bsearch on it. */

	static struct mntflag flags[] = {
		{ "bind",        MS_BIND },
		{ "dirsync",     MS_DIRSYNC },
		{ "mand",        MS_MANDLOCK },
		{ "noatime",     MS_NOATIME },
		{ "nodev",       MS_NODEV },
		{ "nodiratime",  MS_NODIRATIME },
		{ "noexec",      MS_NOEXEC },
		{ "nosuid",      MS_NOSUID },
		{ "private",     MS_PRIVATE },
		{ "rbind",       MS_BIND | MS_REC },
		{ "relatime",    MS_RELATIME },
		{ "remount",     MS_REMOUNT },
		{ "ro",          MS_RDONLY },
		{ "rprivate",    MS_PRIVATE | MS_REC },
		{ "rshared",     MS_SHARED | MS_REC },
		{ "rslave",      MS_SLAVE | MS_REC },
		{ "runbindable", MS_UNBINDABLE | MS_REC },
		{ "shared",      MS_SHARED },
		{ "silent",      MS_SILENT },
		{ "slave",       MS_SLAVE },
		{ "strictatime", MS_STRICTATIME },
		{ "sync",        MS_SYNCHRONOUS },
		{ "unbindable",  MS_UNBINDABLE },
	};

	static struct mntflag neg_flags[] = {
		{ "async",         MS_SYNCHRONOUS },
		{ "atime",         MS_NOATIME },
		{ "defaults",      MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_SYNCHRONOUS },
		{ "dev",           MS_NODEV },
		{ "diratime",      MS_NODIRATIME },
		{ "exec",          MS_NOEXEC },
		{ "loud",          MS_SILENT },
		{ "nomand",        MS_MANDLOCK },
		{ "norelatime",    MS_RELATIME },
		{ "nostrictatime", MS_STRICTATIME },
		{ "rw",            MS_RDONLY },
		{ "suid",          MS_NOSUID },
	};

	if (opts == NULL) {
		return;
	}

	char sentinel;
	char *newopts = opts;
	for (char *opt = opts, *delim = &sentinel; delim != NULL && *opt != '\0'; opt = delim + 1) {

		*delim = ',';
		delim = strchr(opt, ',');
		if (delim != NULL) {
			*delim = '\0';
		}

		struct mntflag *found;

		found = bsearch(opt, flags, lengthof(flags), sizeof (*flags), cmpflags);
		if (found != NULL) {
			*mountflags |= found->flag;
			continue;
		}

		found = bsearch(opt, neg_flags, lengthof(neg_flags), sizeof (*neg_flags), cmpflags);
		if (found != NULL) {
			*mountflags &= ~found->flag;
			continue;
		}

		if (newopts > opts) {
			*(newopts++) = ',';
		}
		for (char *s = opt; *s != '\0'; ++s, ++newopts) {
			*newopts = *s;
		}
	}
	*newopts = 0;
}

static void do_mount(const char *source, const char *target, const char *type, unsigned long flags, const char *options)
{
	if (mount(source, target, type, flags, options) == -1) {
		err(1, "mount_entries: mount(\"%s\", \"%s\", \"%s\", %lu, \"%s\")",
				source ? source : "null",
				target,
				type ? type : "null",
				flags,
				options ? options : "null");
	}

	/* Special case: we can't just do read-only bind mounts in a single step.
	   instead, we have to remount it with MS_RDONLY afterwards.
	   See mount(2) § "Remounting an existing mount". */

	int ro_bind = (flags & (MS_BIND | MS_RDONLY)) == (MS_BIND | MS_RDONLY)
			&& !(flags & MS_REMOUNT);
	if (ro_bind && mount("none", target, NULL, flags | MS_REMOUNT, NULL) == -1) {
		err(1, "mount_entries: read-only remount of %s", target);
	}
}

void mount_entries(const char *root, const struct mount_entry *mounts, size_t nmounts, int no_derandomize)
{
	mode_t old_mask = umask(0);

	for (const struct mount_entry *mnt = mounts; mnt < mounts + nmounts; ++mnt) {
		unsigned long flags = 0;
		update_mount_flags_and_options(&flags, mnt->options);

		if (mnt->target[0] != '/') {
			errx(1, "mount_entries: target \"%s\" must be an absolute path.", mnt->target);
		}
		const char *mnt_target = mnt->target;
		const char *target = makepath("%s%s", root, mnt_target);
		const char *type = mnt->type;

		/* --mount options always override whatever default mounts we might have
		   done prior to calling mount_entries. This is done to avoid EBUSY when
		   mounting something with the same source and target as one of our
		   default mounts. Right now, the only case where this applies is the
		   automatic /proc remount. */
		size_t targetlen = strlen(target);
		if (strcmp(mnt->source, "proc") == 0 && strcmp(target + targetlen - 5, "/proc") == 0) {
			umount2(target, MNT_DETACH);
		}

		/* Special case: we might want to construct a fake devtmpfs. We indicate that
		   through a special mount fstype that we recognize. */
		if (strcmp(mnt->type, "bst_devtmpfs") == 0) {
			type = "tmpfs";

			/* Use /tmp as temporary destination for our setup if our target
			   is /dev. This is because we might bind-mount devices from /dev. */
			if (strcmp(target, "/dev") == 0) {
				target = "/tmp";
				mnt_target = "/tmp";
			}
		}

		do_mount(mnt->source, target, type, flags, mnt->options);

		/* Construct the contents of our fake devtmpfs. */
		if (strcmp(mnt->type, "bst_devtmpfs") == 0) {

			static struct {
				const char *path;
				mode_t mode;
			} directories[] = {
				{ "net", 0755 },
				{ "shm", S_ISVTX | 0777 },
				{ "pts", 0755 },
			};

			for (size_t i = 0; i < lengthof(directories); ++i) {
				const char *path = makepath("%s%s/%s", root, mnt_target, directories[i].path);

				if (mkdir(path, directories[i].mode) == -1) {
					err(1, "mount_entries: bst_devtmpfs: mkdir %s", path);
				}
			}

			struct {
				const char *path;
				mode_t mode;
				dev_t dev;
			} devices[] = {
				{ "null",    S_IFCHR | 0666, makedev(1, 3) },
				{ "full",    S_IFCHR | 0666, makedev(1, 7) },
				{ "zero",    S_IFCHR | 0666, makedev(1, 5) },
				{ "tty",     S_IFCHR | 0666, makedev(5, 0) },
				{ "random",  S_IFCHR | 0666, makedev(1, 8) },
				{ "urandom", S_IFCHR | 0666, makedev(1, 9) },
			};

			for (size_t i = 0; i < lengthof(devices); ++i) {

				/* Skip random and urandom when derandomizing */
				if (!no_derandomize && major(devices[i].dev) == 1 && (minor(devices[i].dev) == 8 || minor(devices[i].dev) == 9)) {
					continue;
				}

				const char *path = makepath("%s%s/%s", root, mnt_target, devices[i].path);

				if (mknod(path, devices[i].mode, devices[i].dev) == 0) {
					continue;
				}

				/* Fallback: bind-mount device from host. */

				if (errno != EPERM) {
					err(1, "mount_entries: bst_devtmpfs: mknod %s mode 0%o dev {%d, %d})",
							path,
							devices[i].mode,
							major(devices[i].dev),
							minor(devices[i].dev));
				}

				char source[PATH_MAX];
				makepath_r(source, "/dev/%s", devices[i].path);

				if (mknod(path, S_IFREG | (devices[i].mode & 0777), 0) == -1) {
					err(1, "mount_entries: bst_devtmpfs: mknod %s mode 0%o",
							path,
							devices[i].mode);
				}

				if (mount(source, path, "", MS_BIND, "") == -1) {
					err(1, "mount_entries: bst_devtmpfs: bind-mount %s to %s",
							source, path);
				}
			}

			static const struct {
				const char *path;
				const char *target;
			} symlinks[] = {
				{ "fd", "/proc/self/fd" },
				{ "stdin", "/proc/self/fd/0" },
				{ "stdout", "/proc/self/fd/1" },
				{ "stderr", "/proc/self/fd/2" },
				{ "ptmx", "pts/ptmx" },
				{ "random", "zero" },
				{ "urandom", "zero" },
			};

			for (size_t i = 0; i < lengthof(symlinks); ++i) {
				const char *path = makepath("%s%s/%s", root, mnt_target, symlinks[i].path);

				if (symlink(symlinks[i].target, path) == -1 && errno != EEXIST) {
					err(1, "mount_entries: bst_devtmpfs: symlink %s -> %s",
							symlinks[i].target, path);
				}
			}

			const char *real_target = makepath("%s%s", root, mnt->target);
			if (strcmp(real_target, "/dev") == 0) {
				do_mount("/tmp", "/dev", NULL, MS_BIND | MS_REC, NULL);

				if (umount2("/tmp", MNT_DETACH) == -1) {
					err(1, "umount /tmp");
				}
			}
		}
	}

	umask(old_mask);
}
