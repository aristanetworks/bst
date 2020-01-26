/* Copyright (c) 2020 Arista Networks, Inc.  All rights reserved.
   Arista Networks, Inc. Confidential and Proprietary. */

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include "cp.h"
#include "mount.h"

#define lengthof(Arr) (sizeof (Arr) / sizeof (*Arr))

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

	if (!opts) {
		return;
	}

	char sentinel;
	char *newopts = opts;
	for (char *opt = opts, *delim = &sentinel; delim && *opt; opt = delim + 1) {

		*delim = ',';
		delim = strchr(opt, ',');
		if (delim) {
			*delim = 0;
		}

		struct mntflag *found;

		found = bsearch(opt, flags, lengthof(flags), sizeof (*flags), cmpflags);
		if (found) {
			*mountflags |= found->flag;
			continue;
		}

		found = bsearch(opt, neg_flags, lengthof(neg_flags), sizeof (*neg_flags), cmpflags);
		if (found) {
			*mountflags &= ~found->flag;
			continue;
		}

		if (newopts > opts) {
			*(newopts++) = ',';
		}
		for (char *s = opt; *s; ++s, ++newopts) {
			*newopts = *s;
		}
	}
	*newopts = 0;
}

/* This constructs a path in `out`, using a format string and arguments.
   `out` must be of size PATH_MAX. */
static void makepath_r(char *out, char *fmt, ...) {
	va_list vl;
	va_start(vl, fmt);
	if (vsnprintf(out, PATH_MAX, fmt, vl) >= PATH_MAX) {
		errx(1, "makepath: resulting path larger than PATH_MAX.");
	}
	va_end(vl);
}

static char *makepath(char *fmt, ...) {
	static char buf[PATH_MAX];

	va_list vl;
	va_start(vl, fmt);
	if (vsnprintf(buf, PATH_MAX, fmt, vl) >= PATH_MAX) {
		errx(1, "makepath: resulting path larger than PATH_MAX.");
	}
	va_end(vl);

	return buf;
}

void mount_entries(const char *root, const struct mount_entry *mounts, size_t nmounts)
{
	for (const struct mount_entry *mnt = mounts; mnt < mounts + nmounts; ++mnt) {
		unsigned long flags = 0;
		update_mount_flags_and_options(&flags, mnt->options);

		if (mnt->target[0] != '/') {
			errx(1, "mount_entries: target \"%s\" must be an absolute path.", mnt->target);
		}
		const char *target = makepath("%s%s", root, mnt->target);

		if (mount(mnt->source, target, mnt->type, flags, mnt->options) == -1) {
			err(1, "mount_entries: mount(\"%s\", \"%s\", \"%s\", %lu, \"%s\")",
					mnt->source,
					mnt->target,
					mnt->type,
					flags,
					mnt->options);
		}

		/* Special case: we can't just do read-only bind mounts in a single step.
		   instead, we have to remount it with MS_RDONLY afterwards. */

		int ro_bind = (flags & (MS_BIND | MS_RDONLY)) == (MS_BIND | MS_RDONLY)
				&& !(flags & MS_REMOUNT);
		if (ro_bind && mount("none", target, NULL, flags | MS_REMOUNT, NULL) == -1) {
			err(1, "mount_entries: mount(\"none\", \"%s\", NULL, %lu | MS_REMOUNT, NULL)",
					mnt->target,
					flags);
		}
	}
}

void mount_mutables(const char *root, const char *const *mutables, size_t nmutables)
{
	for (const char *const *mut = mutables; mut < mutables + nmutables; ++mut) {
		const char *mutpath = *mut;

		if (strcmp(mutpath, "/") == 0) {
			errx(1, "mount_mutables: cannot make / mutable (this would descend into /dev, /proc, /sys).");
		}
		if (mutpath[0] != '/') {
			errx(1, "mount_mutables: mutable \"%s\" must be an absolute path.", mutpath);
		}

		char fullpath[PATH_MAX];
		makepath_r(fullpath, "%s%s", root, mutpath);
		mutpath = fullpath;

		struct stat info;
		if (stat(mutpath, &info) == -1) {
			err(1, "mount_mutables: stat(\"%s\")", mutpath);
		}

		char tmpdir[PATH_MAX] = "/tmp/bst.XXXXXX";
		if (!mkdtemp(tmpdir)) {
			err(1, "mount_mutables: mkdtemp");
		}

		if (mount("none", tmpdir, "tmpfs", 0, "") == -1) {
			err(1, "mount_mutables: mount(\"none\", \"%s\", \"tmpfs\")", tmpdir);
		}

		const char *mnt_source = tmpdir;
		const char *mnt_target = mutpath;

		if ((info.st_mode & S_IFMT) != S_IFDIR) {
			mnt_source = makepath("%s/%s", tmpdir, basename(mutpath));
		}
		copy(mnt_source, mutpath, &info);

		if (mount(mnt_source, mnt_target, "", MS_BIND, "") == -1) {
			err(1, "mount_mutables: mount(\"%s\", \"%s\", MS_BIND)", mnt_source, mnt_target);
		}

		if (umount(tmpdir) == -1) {
			warn("mount_mutables: umount(\"%s\")", tmpdir);
		}

		if (rmdir(tmpdir) == -1) {
			warn("mount_mutables: rmdir(\"%s\")", tmpdir);
		}
	}
}
