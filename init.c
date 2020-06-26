/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "init.h"

noreturn void init(pid_t main_child_pid)
{
	for (int sig = 1; sig <= SIGRTMAX; ++sig) {
		signal(sig, SIG_DFL);
	}

	for (;;) {

		int status;
		pid_t pid = wait(&status);

		if (pid == -1) {
			// Should never happen. ECHILD in particular is bogus here, because
			// we explicitly handle it and forward the exit status.
			err(1, "wait");
		}
		if (pid == main_child_pid) {
			// the main child died -- rather that trying to collect the rest,
			// just abort init, and the kernel will sweep the rest.

			int exitcode;
			if (WIFEXITED(status)) {
				exitcode = WEXITSTATUS(status);
			} else {
				exitcode = WTERMSIG(status) | 1 << 7;
			}
			_exit(exitcode);
		}
	}
}
