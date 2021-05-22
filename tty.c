/* Copyright © 2021 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>

#include "sig.h"
#include "tty.h"

void recv_fd(int socket, int *pFd) {
	char buf[1];
	struct iovec iov[1] = {
		[0] = {.iov_base = buf, .iov_len = 1 }
	};
	union {
		struct cmsghdr _align;
		char ctrl[CMSG_SPACE(sizeof(int))];
	} uCtrl;
	struct msghdr msg = {
		.msg_control = uCtrl.ctrl,
		.msg_controllen = sizeof(uCtrl.ctrl),
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = iov,
		.msg_iovlen = 1,
	};

	if ((recvmsg(socket, &msg, 0)) <= 0) {
		err(1, "recv_fd: recvmsg");
	}

	struct cmsghdr *pCm;
	if (((pCm = CMSG_FIRSTHDR(&msg)) != NULL) &&
		 pCm->cmsg_len == CMSG_LEN(sizeof(int))) {
		if (pCm->cmsg_level != SOL_SOCKET) {
			errx(1, "recv_fd: control level != SOL_SOCKET");
		}
		if (pCm->cmsg_type != SCM_RIGHTS) {
			errx(1, "recv_fd: control type != SCM_RIGHTS");
		}
		*pFd = *((int*) CMSG_DATA(pCm));
	} else {
		errx(1, "recv_fd: no descriptor passed");
	}
}

void send_fd(int socket, int fd) {
	char buf[1] = {0};
	struct iovec iov[1] = {
		[0] = {.iov_base = buf, .iov_len = 1 }
	};
	union {
		struct cmsghdr _align;
		char ctrl[CMSG_SPACE(sizeof(int))];
	} uCtrl;
	struct msghdr msg = {
		.msg_control = uCtrl.ctrl,
		.msg_controllen = sizeof(uCtrl.ctrl),
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = iov,
		.msg_iovlen = 1,
	};
	struct cmsghdr *pCm = CMSG_FIRSTHDR(&msg);
	pCm->cmsg_len = CMSG_LEN(sizeof(int));
	pCm->cmsg_level = SOL_SOCKET;
	pCm->cmsg_type = SCM_RIGHTS;
	*((int*) CMSG_DATA(pCm)) = fd;
	if (sendmsg(socket, &msg, 0) < 0) {
		err(1, "send_fd: sendmsg");
	}
}

struct buffer {
	char buf[BUFSIZ];
	size_t index;
	size_t size;
};

static struct tty_parent_info_s {
	int termfd;
	struct termios orig;
	bool stdinIsatty;
} info = {
	.termfd = -1,
};

void tty_setup_socketpair(int *pParentSock, int *pChildSock) {
	int socks[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, socks) < 0) {
		err(1, "tty_setup: socketpair");
	}
	*pParentSock = socks[0];
	*pChildSock = socks[1];
}

static ssize_t io_copy(int out_fd, int in_fd, struct buffer *buf)
{
	_Static_assert(sizeof (buf->buf) == BUFSIZ,
			"buf->buf must be of size BUFSIZ, check that sizeof (buf->buf) is still correct.");

	ssize_t copied = 0;
	ssize_t rd = sizeof (buf->buf);

	for (;;) {

		/* Write any leftover data from a previous read. This handles the case
		   where we cannot write all of the data we read from in_fd into
		   out_fd without having out_fd block.

		   This also serves as the main write syscall of the loop; the read
		   happens at the end, and simply loops back here when new data
		   is available in the buffer. */

		while (buf->size > 0) {
			ssize_t written = write(out_fd, buf->buf + buf->index, buf->size);
			if (written == -1) {
				switch (errno) {
				case EINTR:
					continue;
				case EAGAIN:
					if (copied != 0) {
						return copied;
					}
					break;
				}
				return -1;
			}
			buf->size -= written;
			buf->index += written;
			copied += written;
		}

		if ((size_t) rd < sizeof (buf->buf)) {
			return copied;
		}

		rd = read(in_fd, buf->buf, sizeof (buf->buf));
		if (rd == -1) {
			switch (errno) {
			case EAGAIN:
				if (copied != 0) {
					return copied;
				}
				break;
			case EINTR:
				continue;
			}
			return -1;
		}
		buf->size = (size_t) rd;
		buf->index = 0;
	}
}

static void set_nonblock(int fd, int nonblock)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		err(1, "fcntl %d F_GETFL", fd);
	}
	if (nonblock) {
		flags |= O_NONBLOCK;
	} else {
		flags &= ~O_NONBLOCK;
	}
	if (fcntl(fd, F_SETFL, flags) == -1) {
		err(1, "fcntl %d F_SETFL O_NONBLOCK", fd);
	}
}

void tty_parent_cleanup() {
	if (info.termfd >= 0) {
		/* Drain any remaining data in the terminal buffer */
		set_nonblock(STDOUT_FILENO, 0);
		set_nonblock(info.termfd, 0);
		struct buffer drain = {
			.size = 0,
		};

		if (io_copy(STDOUT_FILENO, info.termfd, &drain) == -1 && errno != EIO) {
			warn("copy tty -> stdout");
		}

		close(info.termfd);
		info.termfd = -1;
	}
	if (info.stdinIsatty) {
		tcsetattr(STDIN_FILENO, TCSADRAIN, &info.orig);
		info.stdinIsatty = false;
	}
}

void tty_set_winsize() {
	struct winsize wsize;
	if (info.stdinIsatty) {
		if (ioctl(STDIN_FILENO, TIOCGWINSZ, (char*) &wsize) < 0) {
			err(1, "reading window size");
		}
		if (ioctl(info.termfd, TIOCSWINSZ, (char*) &wsize) < 0) {
			err(1, "writing window size");
		}
	}
}

static int tty_handle_sig(int epollfd, const struct epoll_event *ev, int fd, pid_t pid)
{
	siginfo_t siginfo;
	sig_read(fd, &siginfo);

	assert(siginfo.si_signo == SIGWINCH && "tty_handle_sig can only handle SIGWINCH");
	tty_set_winsize();
	return EPOLL_HANDLER_CONTINUE;
}

static struct epoll_handler inbound_handler, outbound_handler, term_handler;

static struct buffer inbound_buffer, outbound_buffer;

static int tty_handle_io(int epollfd, const struct epoll_event *ev, int fd, pid_t pid)
{
	struct epoll_handler *handler = ev->data.ptr;

	if (fd == inbound_handler.fd) {
		if (ev->events & EPOLLIN) {
			handler->ready |= READ_READY;
		}
		if (ev->events & EPOLLHUP) {
			handler->ready |= HANGUP;
		}
	} else if (fd == outbound_handler.fd) {
		if (ev->events & EPOLLOUT) {
			handler->ready |= WRITE_READY;
		}
	} else {
		struct epoll_event newev = *ev;
		newev.events = EPOLLIN | EPOLLOUT | EPOLLONESHOT;

		if (ev->events & EPOLLOUT || inbound_handler.ready & WRITE_READY) {
			inbound_handler.ready |= WRITE_READY;
			newev.events &= ~EPOLLOUT;
		}
		if (ev->events & EPOLLIN || outbound_handler.ready & READ_READY) {
			outbound_handler.ready |= READ_READY;
			newev.events &= ~EPOLLIN;
		}
		if (!(ev->events & EPOLLHUP) && newev.events != EPOLLONESHOT) {
			if (epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &newev) == -1) {
				err(1, "epoll_ctl_mod termfd");
			}
		}
	}

	if ((inbound_handler.ready & (READ_READY | WRITE_READY)) == (READ_READY | WRITE_READY)) {
		int read_fd = inbound_handler.fd;
		int write_fd = inbound_handler.peer_fd;

		ssize_t copied = io_copy(write_fd, read_fd, &inbound_buffer);
		if (copied == -1) {
			err(1, "copy stdin -> tty");
		}

		inbound_handler.ready &= ~(READ_READY|WRITE_READY);

		struct epoll_event newev = {
			.events = EPOLLIN | EPOLLONESHOT,
			.data.ptr = &inbound_handler,
		};
		if (epoll_ctl(epollfd, EPOLL_CTL_MOD, inbound_handler.fd, &newev) == -1) {
			err(1, "epoll_ctl_mod stdin");
		}
	} else if ((inbound_handler.ready & (WRITE_READY | HANGUP)) == (WRITE_READY | HANGUP)) {
		if (write(inbound_handler.peer_fd, &(char){4}, 1) < 0) {
			err(1, "writing EOT to terminal");
		}
		inbound_handler.ready &= ~HANGUP;
	}

	if (outbound_handler.ready == (READ_READY | WRITE_READY)) {
		int read_fd = outbound_handler.peer_fd;
		int write_fd = outbound_handler.fd;

		if (io_copy(write_fd, read_fd, &outbound_buffer) == -1) {
			err(1, "copy tty -> stdout");
		}

		outbound_handler.ready = 0;

		struct epoll_event newev = {
			.events = EPOLLOUT | EPOLLONESHOT,
			.data.ptr = &outbound_handler,
		};
		if (epoll_ctl(epollfd, EPOLL_CTL_MOD, outbound_handler.fd, &newev) == -1) {
			err(1, "epoll_ctl_mod stdout");
		}
	}

	struct epoll_event termev = {
		.events = EPOLLIN | EPOLLOUT | EPOLLONESHOT,
		.data.ptr = &term_handler,
	};

	if (inbound_handler.ready & WRITE_READY) {
		termev.events &= ~EPOLLOUT;
	}
	if (outbound_handler.ready & READ_READY) {
		termev.events &= ~EPOLLIN;
	}
	if (termev.events != EPOLLONESHOT) {
		if (epoll_ctl(epollfd, EPOLL_CTL_MOD, info.termfd, &termev) == -1) {
			err(1, "epoll_ctl_mod termfd");
		}
	}

	return EPOLL_HANDLER_CONTINUE;
}

void tty_parent_setup(int epollfd, int socket)
{
	set_nonblock(STDIN_FILENO, 1);
	set_nonblock(STDOUT_FILENO, 1);

	struct termios tios;

	info.stdinIsatty = tcgetattr(STDIN_FILENO, &tios) == 0;
	if (!info.stdinIsatty && errno != ENOTTY) {
		err(1, "tty_parent: tcgetattr");
	}

	if (info.stdinIsatty) {
		info.orig = tios;
		cfmakeraw(&tios);
		if (tcsetattr(STDIN_FILENO, TCSANOW, &tios) == -1) {
			err(1, "tty_parent: tcsetattr");
		}
	}

	// Wait for the child to create the pty pair and pass the master back.
	recv_fd(socket, &info.termfd);

	if (info.stdinIsatty) {
		if (tcsetattr(info.termfd, TCSAFLUSH, &info.orig) == -1) {
			err(1, "tty_parent: tcsetattr");
		}
	}

	sigset_t sigmask;
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGWINCH);

	int sigfd = signalfd(-1, &sigmask, 0);
	if (sigfd == -1) {
		err(1, "tty_parent: signalfd");
	}

	static struct epoll_handler sighandler;
	sighandler.fn = tty_handle_sig;
	sighandler.fd = sigfd;

	struct epoll_event event = {
		.events = EPOLLIN,
		.data.ptr = &sighandler,
	};

	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sigfd, &event) == -1) {
		err(1, "epoll_ctl_add signalfd");
	}

	inbound_handler = (struct epoll_handler) {
		.fn = tty_handle_io,
		.fd = STDIN_FILENO,
		.peer_fd = info.termfd,
	};

	outbound_handler = (struct epoll_handler) {
		.fn = tty_handle_io,
		.fd = STDOUT_FILENO,
		.peer_fd = info.termfd,
	};

	term_handler = (struct epoll_handler) {
		.fn = tty_handle_io,
		.fd = info.termfd,
		.peer_fd = -1,
	};

	event.events = EPOLLOUT | EPOLLIN | EPOLLONESHOT;
	event.data.ptr = &term_handler;

	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, info.termfd, &event) == -1) {
		err(1, "epoll_ctl_add termfd");
	}

	event.events = EPOLLIN | EPOLLONESHOT;
	event.data.ptr = &inbound_handler;

	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, STDIN_FILENO, &event) == -1) {
		err(1, "epoll_ctl_add stdin");
	}

	event.events = EPOLLOUT | EPOLLONESHOT;
	event.data.ptr = &outbound_handler;

	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, STDOUT_FILENO, &event) == -1) {
		err(1, "epoll_ctl_add stdout");
	}

	if (info.stdinIsatty) {
		tty_set_winsize();
	}
}

void tty_child(int socket) {
	int mfd = open("/dev/pts/ptmx", O_RDWR | O_NONBLOCK);
	if (mfd < 0) {
		err(1, "tty_child: open ptmx");
	}
	int unlock = 0;
	if (ioctl(mfd, TIOCSPTLCK, &unlock) < 0) {
		err(1, "tty_child: ioctl(TIOCSPTLCK)");
	}
	int sfd = ioctl(mfd, TIOCGPTPEER, O_RDWR);
	if (sfd < 0) {
		err(1, "tty_child: ioctl(TIOCGPTPEER)");
	}
	send_fd(socket, mfd);
	close(mfd);

	setsid();
	if (ioctl(sfd, TIOCSCTTY, NULL) < 0) {
		err(1, "tty_child: ioctl(TIOCSCTTY)");
	}
	if (dup2(sfd, STDIN_FILENO) < 0) {
		err(1, "tty_child: dup2(stdin)");
	}
	if (dup2(sfd, STDOUT_FILENO) < 0) {
		err(1, "tty_child: dup2(stdout)");
	}
	if (dup2(sfd, STDERR_FILENO) < 0) {
		err(1, "tty_child: dup2(stderr)");
	}
	if (sfd > STDERR_FILENO) {
		close(sfd);
	}
}
