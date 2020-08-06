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

#include "init.h"

static pid_t main_child_pid = -1;

static void kill_pgrp_handler(int signo)
{
	if (main_child_pid != -1) {
		if (kill(-main_child_pid, signo) == -1) {
			err(1, "kill");
		}
		return;
	}
	_exit(signo | 1 << 7);
}

int main(int argc, char *argv[], char *envp[])
{
	if (argc == 1) {
		printf("usage: %s <program> [args...]\n", argv[0]);
		return 2;
	}

	if (prctl(PR_SET_NAME, "bst-init") == -1) {
		err(1, "prctl(PR_SET_NAME)");
	}

	void (*handlers[SIGRTMAX+1])(int);

	for (int sig = 1; sig <= SIGRTMAX; ++sig) {
		handlers[sig] = kill_pgrp_handler;
	}
	handlers[SIGCHLD] = SIG_DFL;
	handlers[SIGTTIN] = SIG_IGN;
	handlers[SIGTTOU] = SIG_IGN;

	for (int sig = 1; sig <= SIGRTMAX; ++sig) {
		if (signal(sig, handlers[sig]) == SIG_ERR && errno != EINVAL) {
			err(1, "signal %d", sig);
		}
	}

	main_child_pid = fork();
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

		signal(SIGTTIN, SIG_DFL);
		signal(SIGTTOU, SIG_DFL);

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
