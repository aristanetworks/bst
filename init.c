/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sig.h"

int main(int argc, char *argv[], char *envp[])
{
	if (argc == 1) {
		printf("usage: %s <program> [args...]\n", argv[0]);
		return 2;
	}

	if (prctl(PR_SET_NAME, "bst-init") == -1) {
		err(1, "prctl(PR_SET_NAME)");
	}

	sigset_t mask;
	sigfillset(&mask);

	if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
		err(1, "sigprocmask");
	}

	pid_t main_child_pid = fork();
	if (main_child_pid == -1) {
		err(1, "fork");
	}

	if (!main_child_pid) {
		if (setpgid(0, 0) == -1) {
			err(1, "setpgid");
		}
		if (tcsetpgrp(STDIN_FILENO, getpgrp()) == -1) {
			err(1, "tcsetpgrp");
		}

		sigemptyset(&mask);
		if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
			err(1, "sigprocmask");
		}

		execvpe(argv[1], argv + 1, envp);
		err(1, "execvpe");
	}

	for (;;) {
		siginfo_t info;
		sig_wait(&mask, &info);
		sig_reap_and_forward(&info, -main_child_pid);

		if (info.si_signo != SIGCHLD) {
			continue;
		}

		switch (info.si_code) {
		case CLD_EXITED:
		case CLD_KILLED:
		case CLD_DUMPED:

			if (info.si_pid == main_child_pid) {
				/* the main child died -- rather that trying to collect the rest,
				   just abort init, and the kernel will sweep the rest. */

				if (info.si_code == CLD_EXITED) {
					return info.si_status;
				} else {
					return info.si_status | 1 << 7;
				}
			}
			break;

		case CLD_TRAPPED:
			/*
			 * Empirically, if a traced process's parent exits, the
			 * init process inherits the tracing of that process.
			 * If we notice an inherited child has stopped without
			 * explicitly asking for that notification, detach from
			 * it, forwarding the stopping signal in the status.
			 */
			if (ptrace(PTRACE_DETACH, info.si_pid, 0, info.si_status) == -1) {
				warn("failed to detach from traced child %d, "
					"status %d", info.si_pid, info.si_status);
			}
			break;
		}
	}
}
