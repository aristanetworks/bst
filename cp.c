/* Copyright (c) 2020 Arista Networks, Inc.  All rights reserved.
   Arista Networks, Inc. Confidential and Proprietary. */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>

static int copyfile(const char *target, const char *source, const struct stat *srcinfo)
{
	char realpath[PATH_MAX];
	ssize_t linksz;

	switch (srcinfo->st_mode & S_IFMT) {
	case S_IFLNK:
		linksz = readlink(source, realpath, PATH_MAX - 1);
		if (linksz == -1) {
			err(1, "copyfile: readlink(\"%s\")", source);
		}
		realpath[linksz] = 0;
		if (symlink(realpath, target) == -1) {
			err(1, "copyfile: symlink(\"%s\", \"%s\")", target, realpath);
		}
		return 0;
	case S_IFDIR:
		if (mkdir(target, srcinfo->st_mode & 07777) == -1 && errno != EEXIST) {
			err(1, "copyfile: mkdir(\"%s\", %o)", target, srcinfo->st_mode);
		}
		return 0;
	case S_IFREG:
		/* Handled below. */
		break;
	default:
		if (mknod(target, srcinfo->st_mode, srcinfo->st_dev) == -1) {
			err(1, "copyfile: mknod(\"%s\", %o, %lu)", target, srcinfo->st_mode, srcinfo->st_dev);
		}
		return 0;
	}

	int from, to;

	if ((from = open(source, O_RDONLY)) == -1) {
		err(1, "copyfile: open(\"%s\", O_RDONLY)", source);
	}

	if ((to = open(target, O_WRONLY | O_CREAT | O_EXCL, 0777)) == -1) {
		err(1, "copyfile: open(\"%s\", O_WRONLY | O_CREAT)", target);
	}

	size_t remain = srcinfo->st_size;
	do {
		ssize_t written = sendfile(to, from, NULL, remain);
		if (written == -1) {
			err(1, "copyfile: sendfile(\"%s\", \"%s\", \"%zu\")", target, source, remain);
		}
		remain -= (size_t) written;
	} while (remain > 0);

	if (close(to) == -1) {
		err(1, "copyfile: close(\"%s\")", target);
	}

	close(from);
	return 0;
}

/* Blergh. nftw doesn't let us pass some cookie, so we have to use a top-level
   variable. Good thing we're not calling copy in a multithreaded context... */
static const char *target_root;
static size_t source_prefix_len;

static int copydir(const char *fpath, const struct stat *sb,
		int typeflag, struct FTW *ftwbuf)
{
	char tpath[PATH_MAX];
	if ((size_t) snprintf(tpath, PATH_MAX, "%s/%s", target_root, fpath + source_prefix_len) >= PATH_MAX) {
		errx(1, "copydir: \"%s/%s\" is larger than PATH_MAX.", target_root, fpath + source_prefix_len);
	}
	return copyfile(tpath, fpath, sb);
}

int copy(const char *target, const char *source, const struct stat *srcinfo)
{
	if ((srcinfo->st_mode & S_IFMT) == S_IFDIR) {
		target_root = target;
		source_prefix_len = strlen(source);

		if (nftw(source, copydir, 512, FTW_PHYS) == -1) {
			err(1, "copy: nftw(\"%s\")", source);
		}
		return 0;
	} else {
		return copyfile(target, source, srcinfo);
	}
}
