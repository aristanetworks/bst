/* Copyright © 2025 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>

#include "path.h"
#include "pdeathsig.h"

void sig_pdeathsig_cookie_init(struct sig_pdeathsig_cookie *cookie)
{
	pid_t pid = getpid();
	int fds[2] = {-1, -1};

#ifdef SYS_pidfd_open
	fds[0] = syscall(SYS_pidfd_open, pid, 0);
	if (fds[0] == -1 && errno != ENOSYS) {
		err(1, "sig_pdeathsig_cookie_init: pidfd_open");
	}
#endif

	if (fds[0] == -1) {
		if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) == -1) {
			err(1, "sig_pdeathsig_cookie_init: pipe2");
		}
	}

	*cookie = (struct sig_pdeathsig_cookie) {
		.pid = pid,
		.rfd = fds[0],
		.wfd = fds[1],
	};
}

int sig_pdeathsig_cookie_check(struct sig_pdeathsig_cookie *cookie)
{
	pid_t pid = getppid();
	if (pid != 0 && pid != cookie->pid) {
		return 0;
	}

	/* The fd is either a pidfd, which becomes read-ready once the process
	   exits, or is a pipe file descriptor whose write end gets closed by
	   the parent once it dies. */
	struct pollfd fds[1] = {
		{
			.fd = cookie->rfd,
			.events = POLLIN,
		},
	};
	int rc = poll(fds, 1, 0);
	return rc == 0 || (fds[0].revents & (POLLIN | POLLHUP)) == 0;
}

void sig_pdeathsig_cookie_close_child(struct sig_pdeathsig_cookie *cookie)
{
	if (cookie->wfd != -1) {
		close(cookie->wfd);
	}
}

void sig_pdeathsig_cookie_close_parent(struct sig_pdeathsig_cookie *cookie)
{
	close(cookie->rfd);
}

void sig_setpdeathsig(int signo, struct sig_pdeathsig_cookie *cookie)
{
	if (prctl(PR_SET_PDEATHSIG, signo) == -1) {
		err(1, "sig_setpdeathsig: prctl PR_SET_PDEATHSIG");
	}

	if (!sig_pdeathsig_cookie_check(cookie)) {
		/* The parent process died unexpectedly and we got reparented to the
		   nearest subreaper. We won't get killed by the kernel anymore, because
		   our new parent might be long lived, so just do it ourselves. */
		kill(getpid(), signo);

		if (signo == SIGKILL) {
			/* Uh oh, we were not supposed to survive this. We might be init; exit. */
			_exit(128 + signo);
		}
	}
}
