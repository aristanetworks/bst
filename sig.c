/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <unistd.h>

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

void sig_forward(const siginfo_t *info, pid_t pid)
{
	if (info->si_code != SI_USER) {
		return;
	}
	if (kill(pid, info->si_signo) == -1) {
		err(1, "kill");
	}
}

void sig_read(int sigfd, siginfo_t *info)
{
	struct signalfd_siginfo sigfd_info;
	ssize_t rd = read(sigfd, &sigfd_info, sizeof (sigfd_info));
	if (rd == -1) {
		err(1, "read signalfd");
	}

	if (rd != sizeof(sigfd_info)) {
		errx(1, "read signalfd: expected reading size %zu, got %zu", sizeof (sigfd_info), (size_t) rd);
	}

	info->si_signo = (int) sigfd_info.ssi_signo;
	info->si_code = sigfd_info.ssi_code;
}

void sig_setup(int epollfd, const sigset_t *set, pid_t helper_pid, epoll_handler_fn *fn)
{
	int sigfd = signalfd(-1, set, SFD_CLOEXEC);
	if (sigfd == -1) {
		err(1, "signalfd");
	}

	static struct epoll_handler handler;
	handler.fn = fn;
	handler.fd = sigfd;
	handler.helper_pid = helper_pid;
	handler.priority = PRIORITY_LAST;

	struct epoll_event event = {
		.events = EPOLLIN,
		.data = {
			.ptr = &handler,
		},
	};

	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sigfd, &event) == -1) {
		err(1, "epoll_ctl_add signalfd");
	}
}
