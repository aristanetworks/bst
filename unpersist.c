/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define NSFS_DEV (makedev(0, 4))

static bool capable(cap_value_t cap)
{
	static cap_t caps;

	if (!caps) {
		caps = cap_get_proc();
	}

	cap_flag_value_t set;
	if (cap_get_flag(caps, cap, CAP_EFFECTIVE, &set) == -1) {
		err(1, "cap_get_flag");
	}
	return set;
}

static gid_t *get_groups(size_t *ngroups)
{
	static gid_t groups[NGROUPS_MAX];
	static size_t len;

	if (len == 0) {
		int rc = getgroups(NGROUPS_MAX, groups);
		if (rc == -1) {
			err(1, "getgroups");
		}
		len = (size_t) rc;
	}

	*ngroups = len;;
	return groups;
}

static int checkperm(const struct stat *stat)
{
	if (stat->st_mode & 0002) {
		return 1;
	}

	if (stat->st_uid == getuid() && stat->st_mode & 0200) {
		return 1;
	}

	if (!(stat->st_mode & 0020)) {
		return 0;
	}

	if (stat->st_gid == getgid()) {
		return 1;
	}

	size_t ngroups;
	gid_t *groups = get_groups(&ngroups);

	for (size_t i = 0; i < ngroups; ++i) {
		if (stat->st_gid == groups[i]) {
			return 1;
		}
	}

	return 0;
}

enum {
	UNPERSIST_KEEPFILE = 1,
};

static int unpersistat(int dirfd, const char *pathname, int flags)
{
	/* We are a privileged binary, with the ability to unmount arbitrary files.
	   We only allow ourselves to unmount something that fulfills two conditions:

	   1. The current uid or gids must have write permissions over the parent
	      directory.
	   2. The mount is an nsfs mount.

	   Everything else results from an access violation on our part. */

	int fd = openat(dirfd, pathname, O_PATH | O_NOFOLLOW);
	if (fd == -1) {
		goto error;
	}

	struct stat stat;
	if (fstat(fd, &stat) == -1) {
		goto error;
	}

	if (stat.st_dev != NSFS_DEV) {
		errno = EPERM;
		goto error;
	}

	char selfpath[PATH_MAX];
	snprintf(selfpath, PATH_MAX, "/proc/self/fd/%d", fd);

	if (dirfd == AT_FDCWD) {
		char resolved[PATH_MAX];
		if (readlink(selfpath, resolved, sizeof (resolved)) == -1) {
			goto error;
		}

		int dirfd = open(dirname(resolved), O_PATH | O_DIRECTORY);
		if (dirfd == -1) {
			goto error;
		}
		int rc = fstat(dirfd, &stat);
		close(dirfd);
		if (rc == -1) {
			goto error;
		}
	} else if (fstat(dirfd, &stat) == -1) {
		goto error;
	}

	if (!capable(CAP_DAC_OVERRIDE) && !checkperm(&stat)) {
		errno = EACCES;
		goto error;
	}

	/* This is subtle -- someone could race against us to swap out the mount
	   for a symlink to some arbitrary mount between the moment we open the
	   nsfs file and validate it, and the moment we call umount. Since we can't
	   trust the path itself, we have to rely on the kernel magic link resolution
	   to do this for us by unmounting /proc/self/fd/<fd>. */

	if (umount2(selfpath, MNT_DETACH) == -1) {
		goto error;
	}

	/* The file descriptor is now useless since it refers to our now-defunct
	   nsfs file. We have to use the original path for removal, but it's fine,
	   normal access rules apply here. */
	if (!(flags & UNPERSIST_KEEPFILE) && unlinkat(dirfd, pathname, 0) == -1) {
		goto error;
	}

	return 0;

error:
	if (fd != -1) {
		close(fd);
	}
	return -1;
}

static int usage(int error, char *argv0)
{
	FILE *out = error ? stderr : stdout;
	fprintf(out, "usage: %s [options] <path> [path...]\n", argv0);
	fprintf(out, "\n");
	fprintf(out, "Unpersist specified namespace files, or all namespace files\n");
	fprintf(out, "in specified directories.\n");
	fprintf(out, "\n");
	fprintf(out, "Options:\n");
	fprintf(out, "\t-h, --help:   print this message.\n");
	fprintf(out, "\t--no-unlink: do not attempt to remove nsfs mountpoints.\n");
	return error ? 2 : 0;
}

enum {
	OPTION_NO_UNLINK = 128,
};

int main(int argc, char *argv[])
{
	static struct option options[] = {
		{ "help",       no_argument,        NULL,   'h' },
		{ "no-unlink",  no_argument,        NULL,   OPTION_NO_UNLINK },
		{ 0, 0, 0, 0 }
	};

	static struct {
		int unpersistat_flags;
	} settings;

	int error = 0;
	int c;
	while ((c = getopt_long(argc, argv, "h", options, NULL)) != -1) {
		switch (c) {
			case 0:
				break;

			case OPTION_NO_UNLINK:
				settings.unpersistat_flags |= UNPERSIST_KEEPFILE;
				break;

			case '?':
				error = 1;
				/* fallthrough */
			case 'h':
				return usage(error, argv[0]);

			default:
				for (int i = 0; options[i].name != NULL; i++) {
					if (options[i].val == c) {
						if (options[i].flag != NULL) {
							*options[i].flag = c;
						}
						break;
					}
				}
		}
	}

	if (argc - optind < 1) {
		return usage(true, argv[0]);
	}

	const char *namespaces[] = {
		"cgroup",
		"ipc",
		"mnt",
		"net",
		"pid",
		"user",
		"uts",
		"time",
	};

	for (int arg = optind; arg < argc; ++arg) {
		char *name = argv[arg];

		int dirfd = open(name, O_PATH | O_DIRECTORY);
		if (dirfd == -1) {
			if (errno == ENOTDIR) {
				/* This is a normal filename -- treat it as if we got
				   passed an nsfs filename. */
				if (unpersistat(AT_FDCWD, name, settings.unpersistat_flags) == -1) {
					warn("unpersist \"%s\"", name);
				}
				continue;
			}
			err(1, "open \"%s\"", name);
		}

		for (size_t i = 0; i < sizeof (namespaces) / sizeof (*namespaces); ++i) {
			if (unpersistat(dirfd, namespaces[i], settings.unpersistat_flags) == -1) {
				switch (errno) {
				case ENOENT:
					continue;
				case EPERM:
					warnx("ignoring %s/%s: not an nsfs file", name, namespaces[i]);
					continue;
				}
				err(1, "unpersist \"%s/%s\"", name, namespaces[i]);
			}
		}

		close(dirfd);
	}

	return 0;
}
