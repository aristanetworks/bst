/* Copyright © 2024 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <assert.h>
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
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <syscall.h>
#include <unistd.h>

#include "arch.h"
#include "capable.h"
#include "mount.h"
#include "proc.h"
#include "sec.h"
#include "util.h"

int sec_seccomp_fix_stat_32bit = 0;
int sec_seccomp_emulate_mknod = 0;

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
		with_capable(BST_CAP_SYS_PTRACE | BST_CAP_DAC_OVERRIDE) {
			realdirfd = openat(procfd, "cwd", O_PATH | O_CLOEXEC);
		}
	} else {
		char fdpath[PATH_MAX+1];
		if ((size_t) snprintf(fdpath, PATH_MAX, "fd/%d", dirfd) >= sizeof (fdpath)) {
			warnx("fd/%d takes more than PATH_MAX bytes.", dirfd);
			return -EINVAL;
		}

		with_capable(BST_CAP_SYS_PTRACE | BST_CAP_DAC_OVERRIDE) {
			realdirfd = openat(procfd, fdpath, O_PATH | O_CLOEXEC);
		}
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
		runproc_func *init,
		runproc_func *fn)
{
	int rc = 0;

	int selfmnt, memfd, mntns;
	with_capable(BST_CAP_SYS_PTRACE | BST_CAP_DAC_OVERRIDE) {
		selfmnt = self_mnt_nsfd();
		memfd = openat(procfd, "mem", O_RDWR | O_CLOEXEC);
		mntns = openat(procfd, "ns/mnt", O_RDONLY | O_CLOEXEC);
	}

	if (memfd == -1) {
		warn("open /proc/%d/mem", req->pid);
		rc = -EINVAL;
		goto error_close;
	}

	if (mntns == -1) {
		warn("open /proc/%d/ns/mnt", req->pid);
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

	if (init && (rc = init(procfd, cookie)) == -1) {
		goto error_close;
	}

	/* Check again that the process is alive and blocked on the syscall. This
	   handles cases where the syscall got interrupted by a signal handler
	   and the program state changed before we read the pathname or other
	   information from proc. */

	if (check_seccomp_cookie(seccomp_fd, &req->id) == -1) {
		rc = -errno;
		goto error_close;
	}

	int rc2;
	with_capable(BST_CAP_SYS_ADMIN | BST_CAP_SYS_CHROOT) {
		rc2 = setns(mntns, CLONE_NEWNS);
	}

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
	with_capable(BST_CAP_SYS_ADMIN | BST_CAP_SYS_CHROOT) {
		rc2 = setns(selfmnt, CLONE_NEWNS);
	}

	if (rc2 == -1) {
		err(1, "setns");
	}

error_close:
	close(mntns);
	close(memfd);
	return rc;
}

struct mknodat_args {
	pid_t pid;
	int dirfd;
	mode_t mode;
	dev_t dev;
	char pathname[PATH_MAX];

	struct proc_status status;
	struct capabilities caps;
};

static int sec__mknodat_init(int procfd, void *cookie)
{
	struct mknodat_args *args = cookie;

	if (proc_read_status(procfd, &args->status) == -1) {
		warn("proc_read_status /proc/%d/status", args->pid);
		return -EINVAL;
	}

	if (tid_capget(args->pid, &args->caps) == -1) {
		int err = errno;
		warn("capget %d", args->pid);
		return -err;
	}

	return 0;
}

static int sec__mknodat_callback(int procfd, void *cookie)
{
	struct mknodat_args *args = cookie;

	/* It wouldn't technically matter for a user without CAP_MKNOD to be
	   able to create safe devices, but some programs handle EPERM with
	   fallback code to account for root and non-root execution. Deny
	   the syscall in order to be faithful to that behavior */
	if (!(args->caps.effective & BST_CAP_MKNOD)) {
		return -EPERM;
	}

	mode_t old_umask = umask(args->status.umask);

	uid_t uid = geteuid();
	uid_t gid = getegid();

	int rc = 0;
	with_capable(BST_CAP_MKNOD | BST_CAP_SETUID | BST_CAP_SETGID) {

		/* We must switch our effective {u,g}id because we need the owner IDs
		   to match mknodat's calling thread. We cannot switch the file
		   ownership after the fact because if the calling thread is in a user
		   namespace and operates with an effective ID outside of our own
		   0-65534 range, then mknod fails with a rather baffling EOVERFLOW. */
		if (seteuid(args->status.euid)) {
			rc = -errno;
			break;
		}
		if (setegid(args->status.egid)) {
			rc = -errno;
			goto error;
		}

		if (mknodat(args->dirfd, args->pathname, args->mode, args->dev) == -1) {
			rc = -errno;
			goto error;
		}

	error:
		if (seteuid(uid) == -1) {
			err(1, "seteuid");
		}
		if (setegid(gid) == -1) {
			err(1, "setegid");
		}
	}

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

	for (const struct devtmpfs_device *device = devtmpfs_safe_devices; device->path != NULL; device++) {
		if ((mode & S_IFMT) == (device->mode & S_IFMT) && dev == device->dev) {
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
		.pid = req->pid,
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

	int rc = run_in_process_context(seccomp_fd, procfd, req, in, NULL, &args, sec__mknodat_init, sec__mknodat_callback);

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

#ifdef BST_SECCOMP_32
struct sec32__statx_args {
	int dirfd;
	char pathname[PATH_MAX];
	int flags;
	unsigned int mask;
	struct statx statxbuf;
};

static int sec32__do_statx(int dirfd, char *pathname, int flags, unsigned int mask, struct statx *statxbuf)
{
	if (statx(dirfd, pathname, flags, mask, statxbuf) == -1) {
		return -errno;
	}

	/* Normalize the inode so that it fits in 32-bit space.
	   There's no good way to solve this perfectly, but a reasonable compromise
	   that keeps the (dev, ino) pair unique is to move the upper 32-bits into
	   st_dev. On the 32-bit stat struct however, st_dev is also 32-bit wide,
	   which means we have to split the upper and lower 16 bits of the upper
	   32-bits of stx_ino into the minor and major numbers of st_dev
	   respectively.
	  */
	const uint32_t prime32 = 3432918353;
	const uint16_t prime16 = 62533;

	if (statxbuf->stx_ino > UINT32_MAX) {
		uint32_t major, minor;
		minor  = (uint32_t)statxbuf->stx_dev_minor * prime32;
		minor ^= ((statxbuf->stx_ino >> 48) & 0xffff);
		statxbuf->stx_dev_minor = minor;
		major  = (uint32_t)statxbuf->stx_dev_major * prime32;
		major ^= ((statxbuf->stx_ino >> 32) & 0xffff);
		statxbuf->stx_dev_major = major;
		statxbuf->stx_ino &= 0xffffffff;
	}
	if (statxbuf->stx_dev_major > UINT16_MAX) {
		uint16_t major;
		major  = (uint16_t)statxbuf->stx_dev_major * prime16;
		major ^= (uint16_t)(statxbuf->stx_dev_major >> 16);
		statxbuf->stx_dev_major = major;
	}
	if (statxbuf->stx_dev_minor > UINT16_MAX) {
		uint16_t minor;
		minor  = (uint16_t)statxbuf->stx_dev_minor * prime16;
		minor ^= (uint16_t)(statxbuf->stx_dev_minor >> 16);
		statxbuf->stx_dev_minor = minor;
	}
	return 0;
}

static int sec32__statx_callback(int procfd, void *cookie)
{
	struct sec32__statx_args *args = cookie;
	return sec32__do_statx(args->dirfd, args->pathname, args->flags, args->mask, &args->statxbuf);
}

static int sec32__statx(int seccomp_fd, int procfd, struct seccomp_notif *req)
{
	int dirfd = req->data.args[0];
	uintptr_t pathnameaddr = req->data.args[1];
	int flags = req->data.args[2];
	unsigned int mask = req->data.args[3];
	uintptr_t statxbufaddr = req->data.args[4];

	int realdirfd = resolve_dirfd(procfd, dirfd);
	if (realdirfd < 0) {
		return realdirfd;
	}

	struct sec32__statx_args args = {
		.dirfd = realdirfd,
		.flags = flags,
		.mask = mask,
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

	struct arg_buf out[] = {
		{
			.addr = statxbufaddr,
			.buf  = (char *)&args.statxbuf,
			.size = sizeof (struct statx),
		},
		{
			.addr = 0,
		},
	};

	int rc = run_in_process_context(seccomp_fd, procfd, req, in, out, &args, NULL, sec32__statx_callback);

	close(realdirfd);
	return rc;
}

struct sec32__stat64 {
	uint64_t dev;
	uint64_t ino;
	uint64_t nlink;

	uint32_t mode;
	uint32_t uid;
	uint32_t gid;
	uint32_t __pad0;
	uint64_t rdev;
	int64_t size;
	int64_t blksize;
	int64_t blocks;

	uint64_t atime;
	uint64_t atime_nsec;
	uint64_t mtime;
	uint64_t mtime_nsec;
	uint64_t ctime;
	uint64_t ctime_nsec;
	int64_t __unused[3];
};

struct sec32__fstatat64_args {
	int dirfd;
	char pathname[PATH_MAX];
	int flags;
	unsigned int mask;
	struct sec32__stat64 statbuf;
};

static inline uint64_t makedev64(uint32_t major, uint32_t minor)
{
	/* We can't use makedev() since it's bit-dependent */
	uint64_t dev;
	dev  = (((dev_t) (major & 0x00000fffu)) <<  8);
	dev |= (((dev_t) (major & 0xfffff000u)) << 32);
	dev |= (((dev_t) (minor & 0x000000ffu)) <<  0);
	dev |= (((dev_t) (minor & 0xffffff00u)) << 12);
	return dev;
}

static int sec32__fstatat64_callback(int procfd, void *cookie)
{
	struct sec32__fstatat64_args *args = cookie;
	struct statx statxbuf;

	int rc = sec32__do_statx(args->dirfd, args->pathname, args->flags, STATX_BASIC_STATS, &statxbuf);
	if (rc < 0) {
		return rc;
	}

	args->statbuf.dev = makedev64(statxbuf.stx_dev_major, statxbuf.stx_dev_minor);
	args->statbuf.ino = statxbuf.stx_ino;
	args->statbuf._ino = statxbuf.stx_ino;
	args->statbuf.nlink = statxbuf.stx_nlink;
	args->statbuf.mode = statxbuf.stx_mode;
	args->statbuf.uid = statxbuf.stx_uid;
	args->statbuf.gid = statxbuf.stx_gid;
	args->statbuf.rdev = makedev64(statxbuf.stx_rdev_major, statxbuf.stx_rdev_minor);
	args->statbuf.size = statxbuf.stx_size;
	args->statbuf.blksize = statxbuf.stx_blksize;
	args->statbuf.blocks = statxbuf.stx_blocks;
	args->statbuf.atime = statxbuf.stx_atime.tv_sec;
	args->statbuf.atime_nsec = statxbuf.stx_atime.tv_nsec;
	args->statbuf.mtime = statxbuf.stx_mtime.tv_sec;
	args->statbuf.mtime_nsec = statxbuf.stx_mtime.tv_nsec;
	args->statbuf.ctime = statxbuf.stx_ctime.tv_sec;
	args->statbuf.ctime_nsec = statxbuf.stx_ctime.tv_nsec;

	return 0;
}

static int sec32__fstatat64_impl(int seccomp_fd, int procfd,
		struct seccomp_notif *req,
		int dirfd,
		uintptr_t pathnameaddr,
		uintptr_t statbufaddr,
		int flags)
{
	int realdirfd = resolve_dirfd(procfd, dirfd);
	if (realdirfd < 0) {
		return realdirfd;
	}

	struct sec32__fstatat64_args args = {
		.dirfd = realdirfd,
		.flags = flags,
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

	struct arg_buf out[] = {
		{
			.addr = statbufaddr,
			.buf  = (char *)&args.statbuf,
			.size = sizeof (struct sec32__stat64),
		},
		{
			.addr = 0,
		},
	};

	int rc = run_in_process_context(seccomp_fd, procfd, req, in, out, &args, NULL, sec32__fstatat64_callback);

	close(realdirfd);
	return rc;
}

static int sec32__stat64(int seccomp_fd, int procfd, struct seccomp_notif *req)
{
	return sec32__fstatat64_impl(seccomp_fd, procfd, req, AT_FDCWD, req->data.args[0], req->data.args[1], 0);
}

static int sec32__lstat64(int seccomp_fd, int procfd, struct seccomp_notif *req)
{
	return sec32__fstatat64_impl(seccomp_fd, procfd, req, AT_FDCWD, req->data.args[0], req->data.args[1], AT_SYMLINK_NOFOLLOW);
}

static int sec32__fstat64(int seccomp_fd, int procfd, struct seccomp_notif *req)
{
	return sec32__fstatat64_impl(seccomp_fd, procfd, req, req->data.args[0], 0, req->data.args[1], AT_EMPTY_PATH);
}

static int sec32__fstatat64(int seccomp_fd, int procfd, struct seccomp_notif *req)
{
	return sec32__fstatat64_impl(seccomp_fd, procfd, req, req->data.args[0], req->data.args[1], req->data.args[2], req->data.args[3]);
}
#endif /* !BST_SECCOMP_32 */

static int seccomp(unsigned int op, unsigned int flags, void *args)
{
	return syscall(__NR_seccomp, op, flags, args);
}

static syscall_handler_func *syscall_table[BST_NR_MAX+1];
#ifdef BST_SECCOMP_32
static syscall_handler_func *syscall_table_32[BST_NR_MAX32+1];
#endif

static void sec_seccomp_dispatch_syscall(int seccomp_fd,
		struct seccomp_notif *req,
		struct seccomp_notif_resp *resp)
{
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
		warnx("BUG: intercepted syscall %d on arch %x, but it was not in the supervisor's syscall table.", req->data.nr, req->data.arch);
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
	/* Populate any syscall handler tables prior to running the supervisor */

#ifdef BST_SECCOMP_32
	if (sec_seccomp_fix_stat_32bit) {
#ifdef BST_NR_stat64_32
		syscall_table_32[BST_NR_stat64_32] = sec32__stat64;
#endif
#ifdef BST_NR_lstat64_32
		syscall_table_32[BST_NR_lstat64_32] = sec32__lstat64;
#endif
#ifdef BST_NR_fstat64_32
		syscall_table_32[BST_NR_fstat64_32] = sec32__fstat64;
#endif
#ifdef BST_NR_fstatat64_32
		syscall_table_32[BST_NR_fstatat64_32] = sec32__fstatat64;
#endif
		syscall_table_32[BST_NR_statx_32] = sec32__statx;
	}
#endif

	if (sec_seccomp_emulate_mknod) {
#ifdef BST_NR_mknod
		syscall_table[BST_NR_mknod] = sec__mknod;
#endif
		syscall_table[BST_NR_mknodat] = sec__mknodat;

#ifdef BST_SECCOMP_32
#ifdef BST_NR_mknod_32
		syscall_table_32[BST_NR_mknod_32] = sec__mknod;
#endif
		syscall_table_32[BST_NR_mknodat_32] = sec__mknodat;
#endif
	}

	/* Some system call handlers expect to be able to run with the tid's
	   credentials, but still need to retain some capabilities. */
	if (prctl(PR_SET_KEEPCAPS, 1) == -1) {
		err(1, "prctl PR_SET_KEEPCAPS");
	}

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

	int epollfd = epoll_create1(0);
	if (epollfd == -1) {
		err(1, "epoll_create1");
	}

	struct epoll_event event = {
		.events = EPOLLIN,
	};
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, seccomp_fd, &event) == -1) {
		err(1, "epoll_ctl EPOLL_CTL_ADD");
	}

	for (;;) {

		int ready = epoll_wait(epollfd, &event, 1, -1);
		if (ready == -1) {
			if (errno == EINTR) {
				continue;
			}
			err(1, "epoll_wait");
		}

		/* We don't need to check for EPOLLERR -- it's not documented that
		   the seccomp fd can be in that condition, but even if it can,
		   the correct action is to let the ioctl clear the error condition.
		   Either the ioctl will return immediately and the error will be
		   handled correctly, or it will block until a syscall is received
		   or no users of the filter are left, both of which will cause
		   this code to loop back on itself and check for EPOLLHUP eventually. */

		if (ready != 1) {
			continue;
		}

		/* There are no users to the seccomp filter, meaning there
		   are no processes left. Exit. */
		if ((event.events & EPOLLHUP) != 0) {
			_exit(0);
		}

		memset(req,  0, sizes.seccomp_notif);
		memset(resp, 0, resp_size);

		if (ioctl(seccomp_fd, SECCOMP_IOCTL_NOTIF_RECV, req) == -1) {
			switch (errno) {
			case ENOENT:
				/* Target was killed during the syscall but before we have
				   the chance to handle it */
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

int sec_seccomp_install_filter(void)
{
	struct sock_fprog prog = {
		.len    = syscall_filter_length,
		.filter = (struct sock_filter *)syscall_filter,
	};

	int fd = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
	if (fd == -1) {
		if (errno == EBUSY) {
			// We're likely running bst in bst; this error is nonfatal.
			return -1;
		}
		err(1, "seccomp SECCOMP_SET_MODE_FILTER");
	}
	return fd;
}
