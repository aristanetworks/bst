/* Copyright © 2021 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include "config.h"

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HAVE_close_range
# include <linux/close_range.h>
#endif

#include "compat.h"

size_t strlcpy(char *restrict dst, const char *restrict src, size_t size)
{
	size_t i = 0;
	for (; i < size - 1 && src[i] != '\0'; ++i) {
		dst[i] = src[i];
	}
	dst[i] = '\0';
	return i;
}

/* parse_fd parses a file descriptor in the range [0,~0). */
unsigned int parse_fd(char *optarg)
{
	errno = 0;
	long val = strtol(optarg, NULL, 10);
	if (errno == 0 && (val >= (long)UINT_MAX || val < 0)) {
		errno = ERANGE;
	}
	if (errno != 0) {
		return UINT_MAX;
	}
	return (unsigned int) val;
}

/* bst_close_range is like close_range(2), except that it works on linux
   versions that are too old for the system call. */
int bst_close_range(unsigned int from, unsigned int to, unsigned int flags)
{
	int rc = -1;
#ifdef HAVE_close_range
	rc = close_range(from, to, flags);
#else
	errno = ENOSYS;
#endif

	if (rc == -1 && errno == ENOSYS) {
		/* The system call is not implemented. Fall back to the good old
		   fashioned method.

		   Note that this isn't particularly efficient. bst_close_range is
		   itself called in a loop, which means traversing the list of fds
		   for each invocation. I'm not particularly motivated to optimize
		   this given that the easy answer is to just upgrade your kernel.

		   2023-03-28 -- Snaipe
		*/

		DIR *fdlist = opendir("/proc/self/fd");
		if (fdlist == NULL) {
			err(1, "bst_close_range: open /proc/self/fd");
		}

		struct dirent *dent;
		while ((dent = readdir(fdlist)) != NULL) {
			if (dent->d_name[0] == '.') {
				// Either . or ..
				continue;
			}
			unsigned int fd = parse_fd(dent->d_name);
			if (fd == UINT_MAX) {
				err(1, "bst_close_range: %s is not a valid file descriptor number", dent->d_name);
			}

			if (fd < from || fd > to) {
				continue;
			}

			/* Note: close takes a signed int, while close_range takes unsigned
			   ints. I'm not too sure how negative file descriptors are handled
			   (and I don't care much to be honest) so I'll just hope that the
			   system call just reads out an unsigned integer kernel-side. */

			if (close((int) fd) == -1) {
				err(1, "bst_close_range: close %d", fd);
			}
		}

		closedir(fdlist);
		rc = 0;
	}
	return rc;
}
