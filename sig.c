/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include "signal.h"

static void ignoresig_handler(int signo, siginfo_t *info, void *context);

/* ignoresig ignores the signal, just like SIG_IGN but with two
   differences:

   1. when we exec(), our ignore-handler will not be inherited
      (whereas SIG_IGN is inherited across exec()), and

   2. if the kernel delivers us a SIGSEGV or SIGILL or SIGBUS,
      SIG_IGN would ignore it.  Our ignore-handler won't.
*/
void ignoresig(int signo)
{
	/* Block all signals when the ignore handler is executing. */
	sigset_t mask;
	sigfillset(&mask);

	struct sigaction act = {
		.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER | SA_RESETHAND,
		.sa_sigaction = ignoresig_handler,
		.sa_mask = mask,
	};
	/* Ignore EINVAL, because some signals in the range from 1 to SIGRTMAX
	   are either uncatcheable (SIGKILL, SIGSTOP) or don't actually exist. */
	if (sigaction(signo, &act, NULL) == -1 && errno != EINVAL) {
		err(1, "ignoresig: sigaction(%d)", signo);
	}
}

static void ignoresig_handler(int signo, siginfo_t *info, void *context)
{
	switch (signo) {
		/* These can be legitimately sent by the kernel, typically
		   when the controlling terminal gets a ^C or ^\. We want
		   to keep ignoring them, even if kernel-sent. */
		case SIGINT:
		case SIGHUP:
		case SIGQUIT:
		case SIGCHLD:
			ignoresig(signo);
			return;
	}

	/* Ignore user-sent signals. They want to send them to the child process
	   instead. */
	if (info->si_code == SI_USER || info->si_code == SI_TKILL) {
		ignoresig(signo);
	}
}
