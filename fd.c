/* Copyright © 2021-2022 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/socket.h>
#include <unistd.h>

#include "compat.h"
#include "fd.h"

int recv_fd(int socket)
{
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

	ssize_t recv = recvmsg(socket, &msg, 0);
	if (recv == -1) {
		err(1, "recv_fd: recvmsg");
	}
	if (recv == 0) {
		errx(1, "recv_fd: child exited without sending file descriptor");
	}

	struct cmsghdr *pCm = CMSG_FIRSTHDR(&msg);
	if (pCm == NULL || pCm->cmsg_len != CMSG_LEN(sizeof (int))) {
		errx(1, "recv_fd: no descriptor passed");
	}
	if (pCm->cmsg_level != SOL_SOCKET) {
		errx(1, "recv_fd: control level != SOL_SOCKET");
	}
	if (pCm->cmsg_type != SCM_RIGHTS) {
		errx(1, "recv_fd: control type != SCM_RIGHTS");
	}
	return *((int*) CMSG_DATA(pCm));
}

void send_fd(int socket, int fd)
{
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

void rebind_fds_and_close_rest(int start_fd, ...)
{
	va_list vl;
	va_start(vl, start_fd);
	for (;;) {
		int *fd = va_arg(vl, int *);
		if (!fd) {
			break;
		}
		*fd = dup2(*fd, start_fd++);
		if (*fd == -1) {
			err(1, "dup2");
		}
	}
	va_end(vl);

	if (bst_close_range(start_fd, ~0U, 0) == -1) {
		err(1, "close_range");
	}
}
