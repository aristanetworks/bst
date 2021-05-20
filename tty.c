/* Copyright © 2021 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/select.h>
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

static struct tty_parent_info_s {
	int termfd;
	int sigfd;
	fd_set rfds, wfds;
	int nfds;
	struct termios orig;
	bool stdinIsatty;
} info = {
	.termfd = -1,
	.sigfd = -1,
};

void tty_setup_socketpair(int *pParentSock, int *pChildSock) {
	int socks[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, socks) < 0) {
		err(1, "tty_setup: socketpair");
	}
	*pParentSock = socks[0];
	*pChildSock = socks[1];
}

void tty_parent_cleanup() {
	if (info.termfd >= 0) {
		close(info.termfd);
	}
	if (info.stdinIsatty) {
		tcsetattr(STDIN_FILENO, TCSADRAIN, &info.orig);
	}
}

void tty_set_winsize() {
	struct winsize wsize;
	if (ioctl(STDIN_FILENO, TIOCGWINSZ, (char*) &wsize) < 0) {
		err(1, "reading window size");
	}
	if (ioctl(info.termfd, TIOCSWINSZ, (char*) &wsize) < 0) {
		err(1, "writing window size");
	}
}

bool tty_handle_sig(siginfo_t *siginfo) {
	switch (siginfo->si_signo) {
	case SIGWINCH:
		if (!info.stdinIsatty) return false;
		tty_set_winsize();
		return true;
	}
	return false;
}

bool tty_parent_select(pid_t pid) {
	const size_t buflen = 1024;
	char buf[buflen];
	fd_set readFds = info.rfds, writeFds = info.wfds;
	bool rtn = false;

	int rc = select(info.nfds, &readFds, NULL, NULL, NULL);
	if (rc == 0) {
		return false;
	}
	if (rc < 0) {
		if (errno == EINTR) {
			return false;
		}
		err(1, "select");
	}
	struct timeval immediate = {0};
	if (select(info.nfds, NULL, &writeFds, NULL, &immediate) < 0) {
		return false;
	}
	if (FD_ISSET(STDIN_FILENO, &readFds) && FD_ISSET((unsigned long) info.termfd, &writeFds)) {
		ssize_t nread = read(STDIN_FILENO, buf, buflen);
		if (nread > 0) {
			if (write(info.termfd, buf, (size_t) nread) < 0) {
				warn("writing to terminal");
			}
		} else {
			if (nread < 0) {
				warn("reading from stdin");
			}
			FD_CLR(STDIN_FILENO, &info.rfds);
			if (write(info.termfd, &(char){4}, 1) < 0) {
				warn("writing EOT to terminal");
			}
		}
	}
	if (FD_ISSET((unsigned long) info.termfd, &readFds) && FD_ISSET(STDOUT_FILENO, &writeFds)) {
		ssize_t nread = read(info.termfd, buf, buflen);
		if (nread > 0) {
			if (write(STDOUT_FILENO, buf, (size_t) nread) < 0) {
				warn("writing to stdout");
			}
		} else {
			if (nread < 0 && errno != EIO) {
				warn("reading from terminal");
			}
			FD_CLR((unsigned long) info.termfd, &info.rfds);
		}
	}
	if (FD_ISSET((unsigned long) info.sigfd, &readFds)) {
		struct signalfd_siginfo sigfd_info;
		if (read(info.sigfd, &sigfd_info, sizeof(sigfd_info)) == sizeof(sigfd_info)) {
			siginfo_t siginfo;
			siginfo.si_signo = (int) sigfd_info.ssi_signo;
			siginfo.si_code = sigfd_info.ssi_code;
			if (!tty_handle_sig(&siginfo)) {
				sig_forward(&siginfo, pid);
			}
			rtn = (sigfd_info.ssi_signo == SIGCHLD);
		}
	}
	return rtn;
}

void tty_parent_setup(int socket) {
	// Put the parent's stdin in raw mode, except add CRLF handling.
	struct termios tios;

	info.stdinIsatty = tcgetattr(STDIN_FILENO, &tios) == 0;
	if (!info.stdinIsatty && errno != ENOTTY) {
		err(1, "tty_parent: tcgetattr");
	}

	if (info.stdinIsatty) {
		info.orig = tios;
		cfmakeraw(&tios);
		if (tcsetattr(STDIN_FILENO, TCSANOW, &tios) < 0) {
			err(1, "tty_parent: tcsetattr");
		}
	}
	atexit(tty_parent_cleanup);

	// Wait for the child to create the pty pair and pass the master back.
	recv_fd(socket, &info.termfd);

	if (info.stdinIsatty) {
		if (tcsetattr(info.termfd, TCSAFLUSH, &info.orig) < 0) {
			err(1, "tty_parent: tcsetattr");
		}
	}

	sigset_t sigmask;
	sigfillset(&sigmask);
	if (sigprocmask(SIG_BLOCK, &sigmask, NULL) < 0) {
		err(1, "tty_parent: sigprocmask");
	}
	if ((info.sigfd = signalfd(-1, &sigmask, 0)) < 0) {
		err(1, "tty_parent: signalfd");
	}
	FD_ZERO(&info.rfds);
	FD_ZERO(&info.wfds);
	FD_SET(STDIN_FILENO, &info.rfds);
	FD_SET((unsigned long) info.termfd, &info.rfds);
	FD_SET((unsigned long) info.sigfd, &info.rfds);
	FD_SET(STDOUT_FILENO, &info.wfds);
	FD_SET((unsigned long) info.termfd, &info.wfds);
	if (info.sigfd > info.termfd) {
		info.nfds = info.sigfd + 1;
	} else {
		info.nfds = info.termfd + 1;
	}
	if (info.stdinIsatty) {
		tty_set_winsize();
	}
}

void tty_child(int socket) {
	int mfd = open("/dev/pts/ptmx", O_RDWR);
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
