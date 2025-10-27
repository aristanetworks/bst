/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef SIG_H_
# define SIG_H_

# include <limits.h>
# include <signal.h>
# include <sys/epoll.h>

typedef int epoll_handler_fn(int epollfd, const struct epoll_event *ev, int fd, pid_t pid);

enum io_readiness {
	READ_READY  = 1,
	WRITE_READY = 2,
	HANGUP      = 4,
};

enum {
	PRIORITY_FIRST = INT_MIN,
	PRIORITY_DEFAULT = 0,
	PRIORITY_LAST = INT_MAX,
};

# define EPOLL_HANDLER_CONTINUE (-1)

struct epoll_handler {
	epoll_handler_fn *fn;
	int fd;

	/* The priority defines the order in which this handler should be run. */
	int priority;

	/* The peer file descriptor represents the other side of the handler's
	   file descriptor, e.g. the file descriptor that must be written to
	   with the data from fd. */
	int peer_fd;

	/* The ready flag describes whether this handler is read-ready, write-ready,
	   or both. */
	enum io_readiness ready;

	/* The outer helper pid. */
	pid_t helper_pid;
};

void sig_wait(const sigset_t *set, siginfo_t *info);
void sig_forward(const siginfo_t *info, pid_t pid);
void sig_read(int sigfd, siginfo_t *info);
void sig_setup(int epollfd, const sigset_t *set, pid_t helper_pid, epoll_handler_fn *fn);

#endif /* !SIG_H_ */
