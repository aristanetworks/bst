/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "init.h"

int main(int argc, char *argv[], char *envp[])
{
	if (argc == 1) {
		printf("usage: %s <program> [args...]\n", argv[0]);
		return 2;
	}

	if (prctl(PR_SET_NAME, "bst-init") == -1) {
		err(1, "prctl(PR_SET_NAME)");
	}

	pid_t main_child_pid = fork();
	if (main_child_pid == -1) {
		err(1, "fork");
	}

	if (!main_child_pid) {
		execvpe(argv[1], argv + 1, envp);
		err(1, "execvpe");
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
		if (WIFSTOPPED(status)) {
			/*
			 * Empirically, if a traced process's parent exits, the
			 * init process inherits the tracing of that process.
			 * If we notice an inherited child has stopped without
			 * explicitly asking for that notification, detach from
			 * it, forwarding WSTOPSIG.
			 */
			long rc = ptrace(PTRACE_DETACH, pid, 0, WSTOPSIG(status));
			if (rc != 0) {
				warn("failed to detach from traced child %d, "
					"status %d", pid, status);
			}
		}
	}
}
