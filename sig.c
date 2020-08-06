/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <sys/wait.h>

#include "sig.h"

void sig_wait(const sigset_t *set, siginfo_t *info)
{
retry:
	if (sigwaitinfo(set, info) == -1) {
		if (errno == EINTR) {
			goto retry;
		}
		err(1, "sigwaitinfo");
	}
}

void sig_reap_and_forward(const siginfo_t *info, pid_t pid)
{
	if (info->si_signo == SIGCHLD) {
		switch (info->si_code) {
		case CLD_EXITED:
		case CLD_KILLED:
		case CLD_DUMPED:
			if (waitpid(info->si_pid, NULL, WNOHANG) == -1) {
				err(1, "waitpid");
			}
		}
	}

	if (info->si_code != SI_USER) {
		return;
	}
	if (kill(pid, info->si_signo) == -1) {
		err(1, "kill");
	}
}
