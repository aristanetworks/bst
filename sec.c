/* Copyright © 2024 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <syscall.h>
#include <unistd.h>

#include "arch.h"
#include "capable.h"
#include "proc.h"
#include "sec.h"
#include "util.h"

typedef int syscall_handler_func(int, int, struct seccomp_notif *);

enum {
	SYSCALL_HANDLED,
	SYSCALL_CONTINUE,
};

static int self_mnt_nsfd(void) {

	static int fd = -1;

	if (fd == -1) {
		fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
		if (fd == -1) {
			err(1, "open /proc/self/ns/mnt");
		}
	}

	return fd;
}

static int check_seccomp_cookie(int seccomp_fd, __u64 *id)
{
	return ioctl(seccomp_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, id);
}

static int resolve_dirfd(int procfd, int dirfd)
{
	int realdirfd = -1;
	if (dirfd == AT_FDCWD) {
		make_capable(BST_CAP_SYS_PTRACE | BST_CAP_DAC_OVERRIDE);
		realdirfd = openat(procfd, "cwd", O_PATH | O_CLOEXEC);
		reset_capabilities();
	} else {
		char fdpath[PATH_MAX+1];
		if ((size_t) snprintf(fdpath, PATH_MAX, "fd/%d", dirfd) >= sizeof (fdpath)) {
			warnx("fd/%d takes more than PATH_MAX bytes.", dirfd);
			return -EINVAL;
		}

		make_capable(BST_CAP_SYS_PTRACE | BST_CAP_DAC_OVERRIDE);
		realdirfd = openat(procfd, fdpath, O_PATH | O_CLOEXEC);
		reset_capabilities();
	}
	if (realdirfd == -1) {
		warn("open");
		return -EINVAL;
	}
	return realdirfd;
}

struct arg_buf {
	uintptr_t addr;
	size_t size;
	void *buf;
};

typedef int runproc_func(int procfd, void *cookie);

static int run_in_process_context(int seccomp_fd, int procfd,
		struct seccomp_notif *req,
		struct arg_buf *in,
		struct arg_buf *out,
		void *cookie,
		runproc_func *fn)
{
	int rc = 0;

	make_capable(BST_CAP_SYS_PTRACE | BST_CAP_DAC_OVERRIDE);

	int selfmnt = self_mnt_nsfd();
	int memfd = openat(procfd, "mem", O_RDWR | O_CLOEXEC);
	int mntns = openat(procfd, "ns/mnt", O_RDONLY | O_CLOEXEC);

	reset_capabilities();

	if (memfd == -1) {
		warn("open /proc/<pid>/mem");
		rc = -EINVAL;
		goto error_close;
	}

	if (mntns == -1) {
		warn("open /proc/<pid>/ns/mnt");
		rc = -EINVAL;
		goto error_close;
	}

	for (struct arg_buf *a = in; a && a->addr; a++) {
		size_t total = 0;
		while (total < a->size) {
			ssize_t nread = pread(memfd, a->buf, a->size, a->addr);
			if (nread == -1) {
				warn("pread %lx:%zu", a->addr, a->size);
				rc = -EFAULT;
				goto error_close;
			}
			if (nread == 0) {
				break;
			}
			total += nread;
		}
		a->size = total;
	}

	/* Check again that the process is alive and blocked on the syscall. This
	   handles cases where the syscall got interrupted by a signal handler
	   and the program state changed before we read the pathname or other
	   information from proc. */

	if (check_seccomp_cookie(seccomp_fd, &req->id) == -1) {
		rc = -errno;
		goto error_close;
	}

	make_capable(BST_CAP_SYS_ADMIN | BST_CAP_SYS_CHROOT);
	int rc2 = setns(mntns, CLONE_NEWNS);
	reset_capabilities();

	if (rc2 == -1) {
		warn("setns");
		rc = -EOPNOTSUPP;
		goto error;
	}

	if ((rc = fn(procfd, cookie)) == -1) {
		goto error;
	}

	for (struct arg_buf *a = out; a && a->addr; a++) {
		while (a->size > 0) {
			ssize_t nwrite = pwrite(memfd, a->buf, a->size, a->addr);
			if (nwrite == -1) {
				warn("pwrite %lx:%zu", a->addr, a->size);
				rc = -EFAULT;
				goto error;
			}
			a->size -= nwrite;
			a->addr += nwrite;
		}
	}

error:
	make_capable(BST_CAP_SYS_ADMIN | BST_CAP_SYS_CHROOT);
	rc2 = setns(selfmnt, CLONE_NEWNS);
	reset_capabilities();

	if (rc2 == -1) {
		err(1, "setns");
	}

error_close:
	close(mntns);
	close(memfd);
	return rc;
}

struct mknodat_args {
	int dirfd;
	mode_t mode;
	dev_t dev;
	char pathname[PATH_MAX];
};

static int sec__mknodat_callback(int procfd, void *cookie)
{
	struct mknodat_args *args = cookie;

	struct proc_status status;
	if (proc_read_status(procfd, &status) == -1) {
		warn("proc_read_status /proc/<pid>/status");
		return -EINVAL;
	}

	mode_t old_umask = umask(status.umask);

	make_capable(BST_CAP_MKNOD);

	int rc = 0;
	if (mknodat(args->dirfd, args->pathname, args->mode, args->dev) == -1) {
		rc = -errno;
	}

	reset_capabilities();

	if (old_umask != (mode_t) -1) {
		umask(old_umask);
	}

	return rc;
}

static int sec__mknodat_impl(int seccomp_fd, int procfd,
		struct seccomp_notif *req,
		int dirfd,
		uintptr_t pathnameaddr,
		mode_t mode,
		dev_t dev)
{
	if ((mode & S_IFCHR) == 0 || (mode & S_IFBLK) == 0) {
		/* Fallthrough for non-privileged operations -- the caller already
		   has the rights to do this themselves. */
		return SYSCALL_CONTINUE;
	}

	/* Is this one of the safe devices? */

	struct devtype {
		mode_t type;
		dev_t  dev;
	};

	const struct devtype safe_devices[] = {
		{ .type = S_IFCHR, .dev = makedev(0, 0) }, // whiteout device
		{ .type = S_IFCHR, .dev = makedev(1, 3) }, // null device
		{ .type = S_IFCHR, .dev = makedev(1, 5) }, // zero device
		{ .type = S_IFCHR, .dev = makedev(1, 7) }, // full device
		{ .type = S_IFCHR, .dev = makedev(1, 8) }, // random device
		{ .type = S_IFCHR, .dev = makedev(1, 9) }, // urandom device
		{ .type = S_IFCHR, .dev = makedev(5, 0) }, // tty device
	};

	for (size_t i = 0; i < lengthof(safe_devices); i++) {
		if ((mode & S_IFMT) == safe_devices[i].type && dev == safe_devices[i].dev) {
			goto safe;
		}
	}
	return SYSCALL_CONTINUE;

safe: {}
	/* The device is safe to create -- perform shenanigans */

	int realdirfd = resolve_dirfd(procfd, dirfd);
	if (realdirfd < 0) {
		return realdirfd;
	}

	struct mknodat_args args = {
		.dirfd = realdirfd,
		.dev = dev,
		.mode = mode,
	};

	struct arg_buf in[] = {
		{
			.addr = pathnameaddr,
			.buf  = &args.pathname[0],
			.size = PATH_MAX-1,
		},
		{
			.addr = 0,
		},
	};

	int rc = run_in_process_context(seccomp_fd, procfd, req, in, NULL, &args, sec__mknodat_callback);

	close(realdirfd);
	return rc;
}

static int sec__mknod(int seccomp_fd, int procfd, struct seccomp_notif *req)
{
	uintptr_t pathnameaddr = req->data.args[0];
	mode_t mode = req->data.args[1];
	dev_t dev = req->data.args[2];

	return sec__mknodat_impl(seccomp_fd, procfd, req, AT_FDCWD, pathnameaddr, mode, dev);
}

static int sec__mknodat(int seccomp_fd, int procfd, struct seccomp_notif *req)
{
	int dirfd = req->data.args[0];
	uintptr_t pathnameaddr = req->data.args[1];
	mode_t mode = req->data.args[2];
	dev_t dev = req->data.args[3];

	return sec__mknodat_impl(seccomp_fd, procfd, req, dirfd, pathnameaddr, mode, dev);
}

static int seccomp(unsigned int op, unsigned int flags, void *args)
{
	return syscall(__NR_seccomp, op, flags, args);
}

int sec_seccomp_install_filter(void)
{
	struct sock_fprog prog = {
		.len    = syscall_filter_length,
		.filter = (struct sock_filter *)syscall_filter,
	};

	int fd = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
	if (fd == -1) {
		if (errno == EBUSY) {
			// We're likely running bst in bst; ignore the error, and return
			// a useless file descriptor to pass to the seccomp supervisor
			return epoll_create1(EPOLL_CLOEXEC);
		}
		err(1, "seccomp SECCOMP_SET_MODE_FILTER");
	}
	return fd;
}

static void sec_seccomp_dispatch_syscall(int seccomp_fd,
		struct seccomp_notif *req,
		struct seccomp_notif_resp *resp)
{
	static syscall_handler_func *const syscall_table[BST_NR_MAX+1] = {
#ifdef BST_NR_mknod
		[BST_NR_mknod]   = sec__mknod,
#endif
		[BST_NR_mknodat] = sec__mknodat,
	};

#ifdef BST_SECCOMP_32
	syscall_handler_func *syscall_table_32[BST_NR_MAX32+1] = {
#ifdef BST_NR_mknod_32
		[BST_NR_mknod_32]   = sec__mknod,
#endif
		[BST_NR_mknodat_32] = sec__mknodat,
	};
#endif

	resp->id = req->id;

	syscall_handler_func *const *table = syscall_table;
	size_t nr_syscall = lengthof(syscall_table);
#ifdef ARCH_X86_64
#ifdef BST_SECCOMP_32
	if (req->data.arch == AUDIT_ARCH_I386) {
		table = syscall_table_32;
		nr_syscall = lengthof(syscall_table_32);
	}
#endif
	if (req->data.arch == AUDIT_ARCH_X86_64) {
		/* x32 system calls are the same as x86_64, except they have bit 30
		 * set; we're not making any difference here, so reset it */
		req->data.nr &= ~0x40000000;
	}
#endif

	if (req->data.nr <= 0 || (size_t) req->data.nr >= nr_syscall) {
		goto fallthrough;
	}
	syscall_handler_func *fn = table[(size_t) req->data.nr];
	if (!fn) {
		goto fallthrough;
	}

	char procpath[PATH_MAX+1];
	if ((size_t) snprintf(procpath, PATH_MAX, "/proc/%d", req->pid) >= sizeof (procpath)) {
		errx(1, "/proc/%d takes more than PATH_MAX bytes.", req->pid);
	}

	int procfd = open(procpath, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (procfd == -1) {
		if (errno == ENOENT) {
			goto fallthrough;
		}
		err(1, "open");
	}

	int rc = fn(seccomp_fd, procfd, req);
	close(procfd);

	if (rc < 0) {
		resp->error = rc;
	} else if (rc == SYSCALL_CONTINUE) {
		goto fallthrough;
	}

send:
	if (ioctl(seccomp_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1) {
		// ENOENT is normal -- this means the syscall got interrupted by a
		// signal.
		if (errno != ENOENT) {
			warn("ioctl SECCOMP_IOCTL_NOTIF_SEND");
		}
	}
	return;

fallthrough:
	resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
	goto send;
}

noreturn void sec_seccomp_supervisor(int seccomp_fd)
{
	/* Run the seccomp supervisor. This supervisor is a privileged helper
	   that runs safe syscalls on behalf of the unprivileged child in a
	   user namespace.

	   Use-cases include:
	   * Allowing mknod on devices deemed "safe", like /dev/null, or the
	     overlayfs whiteout file.
	   * Allow devtmpfs mount with our custom bst_devtmpfs logic.
	
	   For now, this is intended to be a blocking loop -- if we need other
	   long-running agents down the line we might need to consider using
	   an epoll loop or forking these into other processes. */

	struct seccomp_notif_sizes sizes;

	if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == -1)
		err(1, "seccomp SECCOMP_GET_NOTIF_SIZES");

	struct seccomp_notif *req = malloc(sizes.seccomp_notif);
	if (req == NULL)
		err(1, "malloc");

	/* When allocating the response buffer, we must allow for the fact
	   that the user-space binary may have been built with user-space
	   headers where 'struct seccomp_notif_resp' is bigger than the
	   response buffer expected by the (older) kernel. Therefore, we
	   allocate a buffer that is the maximum of the two sizes. This
	   ensures that if the supervisor places bytes into the response
	   structure that are past the response size that the kernel expects,
	   then the supervisor is not touching an invalid memory location. */

	size_t resp_size = sizes.seccomp_notif_resp;
	if (sizeof (struct seccomp_notif_resp) > resp_size)
		resp_size = sizeof (struct seccomp_notif_resp);

	struct seccomp_notif_resp *resp = malloc(resp_size);
	if (resp == NULL)
		err(1, "malloc");

	for (;;) {
		memset(req,  0, sizes.seccomp_notif);
		memset(resp, 0, resp_size);

		if (ioctl(seccomp_fd, SECCOMP_IOCTL_NOTIF_RECV, req) == -1) {
			switch (errno) {
			case EINTR:
				continue;
			case ENOTTY:
				/* seccomp running in seccomp, which is not supported/needed */
				_exit(0);
			}
			err(1, "ioctl SECCOMP_IOCTL_NOTIF_RECV");
		}

		sec_seccomp_dispatch_syscall(seccomp_fd, req, resp);
	}
}

