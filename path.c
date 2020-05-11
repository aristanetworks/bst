/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <limits.h>

/* cleanpath cleans the specified absolute filepath. It does the following:
   * removes duplicate slashes
   * removes . components
   * cancels inner .. components with preceding components */
static void cleanpath(char *path) {
	if (path[0] != '/') {
		errx(1, "cleanpath: must be called on absolute path, got \"%s\"", path);
	}
	++path;

	char *out = path;
	char *start = path;

	while (*path) {
		if (*path == '/') {
			// empty component
			++path;
		} else if (*path == '.' && (!*(path+1) || *(path+1) == '/')) {
			// . component
			++path;
		} else if (*path == '.' && *(path+1) == '.' && (!*(path+1) || *(path+1) == '/')) {
			// .. component
			path += 2;

			if (out > start) {
				--out;
				for (; out > start && *out != '/'; --out) {
					continue;
				}
			}
		} else {
			// normal component
			if (out != start) {
				*out = '/';
				++out;
			}
			for (; *path && *path != '/'; ++path, ++out) {
				*out = *path;
			}
		}
	}
	*out = '\0';
}

/* This constructs a path in `out`, using a format string and arguments.
   `out` must be of size PATH_MAX. */
void makepath_r(char *out, char *fmt, ...) {
	va_list vl;
	va_start(vl, fmt);
	if (vsnprintf(out, PATH_MAX, fmt, vl) >= PATH_MAX) {
		errx(1, "makepath: resulting path larger than PATH_MAX.");
	}
	va_end(vl);

	cleanpath(out);
}

char *makepath(char *fmt, ...) {
	static char buf[PATH_MAX];

	va_list vl;
	va_start(vl, fmt);
	if (vsnprintf(buf, PATH_MAX, fmt, vl) >= PATH_MAX) {
		errx(1, "makepath: resulting path larger than PATH_MAX.");
	}
	va_end(vl);

	cleanpath(buf);
	return buf;
}
