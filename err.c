/* Copyright © 2021 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "errutil.h"

/* The err(3) function family is generally not prepared to deal with error
   handling after the tty has been changed to raw mode. They do not call
   atexit handlers and the line endings are not configurable.

   To address this, we reimplement most of these functions here, so that
   they still behave correctly in our use-cases. */

void (*err_exit)(int) = exit;
const char *err_line_ending = "\n";
int err_flags = 0;

/* fdprintf and vfdprintf are fork-safe versions of fprintf and vfprintf. */

static void vfdprintf(int fd, const char *fmt, va_list vl)
{
	char buf[BUFSIZ];
	int written = vsnprintf(buf, sizeof (buf), fmt, vl);
	buf[sizeof (buf) - 1] = '\0';
	if ((size_t) written >= sizeof (buf)) {
		written = sizeof (buf);
	}
	write(fd, buf, (size_t) written);
}

static void fdprintf(int fd, const char *fmt, ...)
{
	va_list vl;
	va_start(vl, fmt);
	vfdprintf(fd, fmt, vl);
	va_end(vl);
}

extern const char *__progname;

static void vwarnsyslog(int errcode, const char *fmt, va_list vl)
{
	static const char suffix[] = ": %m";
	char newfmt[BUFSIZ];

	char *tail = stpncpy(newfmt, fmt, sizeof (newfmt) - sizeof (suffix));
	if (errcode != 0) {
		stpncpy(tail, suffix, sizeof (suffix));
	}

	vsyslog(LOG_ERR, fmt, vl);
}

void vwarn(const char *fmt, va_list vl)
{
	if (err_flags & ERR_USE_SYSLOG) {
		vwarnsyslog(errno, fmt, vl);
		return;
	}
	fdprintf(STDERR_FILENO, "%s: ", __progname);
	vfdprintf(STDERR_FILENO, fmt, vl);
	fdprintf(STDERR_FILENO, ": %s%s", strerror(errno), err_line_ending);
}

void vwarnx(const char *fmt, va_list vl)
{
	if (err_flags & ERR_USE_SYSLOG) {
		vwarnsyslog(0, fmt, vl);
		return;
	}
	fdprintf(STDERR_FILENO, "%s: ", __progname);
	vfdprintf(STDERR_FILENO, fmt, vl);
	write(STDERR_FILENO, err_line_ending, strlen(err_line_ending));
}

void warn(const char *fmt, ...)
{
	va_list vl;
	va_start(vl, fmt);
	vwarn(fmt, vl);
	va_end(vl);
}

void warnx(const char *fmt, ...)
{
	va_list vl;
	va_start(vl, fmt);
	vwarnx(fmt, vl);
	va_end(vl);
}

noreturn void err(int eval, const char *fmt, ...)
{
	va_list vl;
	va_start(vl, fmt);
	vwarn(fmt, vl);
	va_end(vl);

	err_exit(eval);
	__builtin_unreachable();
}

noreturn void errx(int eval, const char *fmt, ...)
{
	va_list vl;
	va_start(vl, fmt);
	vwarnx(fmt, vl);
	va_end(vl);

	err_exit(eval);
	__builtin_unreachable();
}
