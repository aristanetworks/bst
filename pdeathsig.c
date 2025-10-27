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
	int pid = getpid();
	int pidfd = -1;
	bool pollable = false;

#ifdef SYS_pidfd_open
	pidfd = syscall(SYS_pidfd_open, pid, 0);
	if (pidfd != -1) {
		pollable = 1;
	} else if (errno != ENOSYS) {
		err(1, "pidfd_open");
	}
#endif

	if (pidfd == -1) {
		char procpath[PATH_MAX];
		makepath_r(procpath, "/proc/%d", pid);

		pidfd = open(procpath, O_RDONLY | O_DIRECTORY);
		if (pidfd == -1) {
			err(1, "open %s", procpath);
		}
	}

	*cookie = (struct sig_pdeathsig_cookie) {
		.pid = pid,
		.pidfd = pidfd,
		.pollable = pollable,
	};
}

int sig_pdeathsig_cookie_check(struct sig_pdeathsig_cookie *cookie)
{
	int rc;

#ifdef SYS_pidfd_send_signal
	rc = syscall(SYS_pidfd_send_signal, cookie->pidfd, 0, NULL, 0);
	if (rc == 0) {
		return 1;
	} else {
		switch (errno) {
		/* Same case as ENOSYS; this happens when the cookie is created
		   outside of the current pid namespace, meaning the pidfd can't
		   be killed from this context. */
		case EINVAL:
			/* fallthrough */
		case ENOSYS:
			goto fallback;
		case ESRCH:
			return 0;
		default:
			err(1, "pidfd_send_signal");
		}
	}
fallback: {}
#endif

	pid_t pid = getppid();
	if (pid != cookie->pid) {
		return 0;
	}

	if (cookie->pollable) {
		/* if the pidfd is pollable, it will be read-ready once the process exits. */
		struct pollfd fds[1] = {
			{
				.fd = cookie->pidfd,
				.events = POLLIN,
			},
		};
		rc = poll(fds, 1, 0);
		return rc == 0 || (fds[0].revents & POLLIN) == 0;
	}

	/* Failing everything else, we can use the inode number to distinguish
	   between the pidfd of a dead process and the pidfd of a live process
	   with the same pid as the dead process. This is slower than the
	   rest and requires access to /proc, so the previous methods should
	   preferably be used, and will be so on any modern Kernel. */

	char procpath[PATH_MAX];
	makepath_r(procpath, "/proc/%d", pid);

	int pidfd = open(procpath, O_PATH | O_DIRECTORY);
	if (pidfd == -1) {
		err(1, "sig_pdeathsig_cookie_check: open %s", procpath);
	}

	struct stat buf1, buf2;
	rc = fstat(pidfd, &buf1);
	close(pidfd);

	if (rc == -1) {
		err(1, "sig_pdeathsig_cookie_check: fstat parent pidfd");
	}
	if (fstat(cookie->pidfd, &buf2) == -1) {
		err(1, "sig_pdeathsig_cookie_check: fstat cookie pidfd");
	}
	return buf1.st_ino == buf2.st_ino && buf1.st_dev == buf2.st_dev;
}

void sig_pdeathsig_cookie_close(struct sig_pdeathsig_cookie *cookie)
{
	close(cookie->pidfd);
}

void sig_setpdeathsig(int signo, struct sig_pdeathsig_cookie *cookie)
{
	if (prctl(PR_SET_PDEATHSIG, signo) == -1) {
		err(1, "prctl PR_SET_PDEATHSIG");
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
