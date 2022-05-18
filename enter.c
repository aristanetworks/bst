/* Copyright © 2020-2022 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <syscall.h>

#include "bst_limits.h"
#include "capable.h"
#include "compat.h"
#include "config.h"
#include "enter.h"
#include "errutil.h"
#include "fd.h"
#include "mount.h"
#include "net.h"
#include "ns.h"
#include "outer.h"
#include "path.h"
#include "tty.h"
#include "setarch.h"
#include "sig.h"
#include "util.h"
#include "fd.h"

#ifdef HAVE_SECCOMP_UNOTIFY
# include "sec.h"
#endif

static inline size_t append_argv(char **argv, size_t argc, char *arg)
{
	if (argc >= ARG_MAX) {
		errx(1, "argv too large, a maximum of %zu arguments is supported", (size_t) ARG_MAX);
	}
	argv[argc] = arg;
	return argc + 1;
}

/* Applies the limit specified by `resource'.  If value is NULL, then copy the
   hard limit value to the soft limit and call `setrlimit'. */
static void apply_rlimit(int resource, struct rlimit const *value)
{
	struct rlimit new_limit;
	if (value == NULL) {
		if (getrlimit(resource, &new_limit)) {
			if (errno == EINVAL) {
				/* Skip this limit -- it is not supported. */
				return;
			}
			err(1, "getrlimit(%d) failed", resource);
		}
		new_limit.rlim_cur = new_limit.rlim_max;
		value = &new_limit;
	}

	if (setrlimit(resource, value)) {
		err(1, "setrlimit(%d) failed", resource);
	}
}

static int sig_handler(int epollfd, const struct epoll_event *ev, int fd, pid_t pid)
{
	siginfo_t info;
	sig_read(fd, &info);
	sig_forward(&info, pid);

	if (info.si_signo != SIGCHLD) {
		return EPOLL_HANDLER_CONTINUE;
	}

	struct epoll_handler *handler = ev->data.ptr;

	/* We might have been run as a process subreaper against our
	   will -- make sure we only exit when the main child pid
	   exited. */

	int rc;
	while ((rc = waitid(P_ALL, 0, &info, WEXITED | WNOHANG)) != -1) {
		if (info.si_signo != SIGCHLD) {
			break;
		}

		if (info.si_pid == pid) {
			switch (info.si_code) {
			case CLD_EXITED:
				return info.si_status;
			case CLD_KILLED:
			case CLD_DUMPED:
				return info.si_status | 1 << 7;
			}
		} else if (info.si_pid == handler->helper_pid) {
			switch (info.si_code) {
			case CLD_KILLED:
				errx(1, "helper got killed with signal %d", info.si_status);
			case CLD_DUMPED:
				errx(1, "helper crashed with signal %d", info.si_status);
			case CLD_EXITED:
				if (info.si_status > 1) {
					errx(1, "helper exit status %d", info.si_status);
				}
				break;
			}
		}
	}
	if (rc == -1) {
		err(1, "waitid");
	}

	return EPOLL_HANDLER_CONTINUE;
}

static int cmp_epoll_handler(const void *a, const void *b)
{
	struct epoll_handler *lhs = ((const struct epoll_event *)a)->data.ptr;
	struct epoll_handler *rhs = ((const struct epoll_event *)b)->data.ptr;
	return lhs->priority - rhs->priority;
}

int enter(struct entry_settings *opts)
{
	int timens_offsets = -1;
	if (opts->shares[NS_TIME] != SHARE_WITH_PARENT) {

		/* Because this process is privileged, /proc/self/timens_offsets
		   is unfortunately owned by root and not ourselves, so we have
		   to give ourselves the capability to read our own file. Geez. */

		make_capable(BST_CAP_DAC_OVERRIDE);

		timens_offsets = open("/proc/self/timens_offsets", O_WRONLY | O_CLOEXEC);
		if (timens_offsets == -1) {
			if (errno != ENOENT) {
				err(1, "open /proc/self/timens_offsets");
			}
			/* The kernel evidently doesn't support time namespaces yet.
			   Don't try to open the time namespace file with --share-all=<dir>,
			   or try to unshare or setns the time namespace below. */
			opts->shares[NS_TIME] = SHARE_WITH_PARENT;
		}

		reset_capabilities();
	}

	enum nsaction nsactions[MAX_NS];
	opts_to_nsactions(opts->shares, nsactions);

	if (nsactions[NS_NET] != NSACTION_UNSHARE && opts->nnics > 0) {
		errx(1, "cannot create NICs when not in a network namespace");
	}

	struct outer_helper outer_helper;
	outer_helper.persist = opts->persist;
	outer_helper.unshare_user = nsactions[NS_USER] == NSACTION_UNSHARE;
	memcpy(outer_helper.uid_desired, opts->uid_map, sizeof (outer_helper.uid_desired));
	memcpy(outer_helper.gid_desired, opts->gid_map, sizeof (outer_helper.gid_desired));
	outer_helper.unshare_net = nsactions[NS_NET] == NSACTION_UNSHARE;
	outer_helper.nics = opts->nics;
	outer_helper.nnics = opts->nnics;
	outer_helper.cgroup_driver = opts->cgroup_driver;
	outer_helper.cgroup_path = opts->cgroup_path;
	outer_helper.climits = opts->climits;
	outer_helper.nclimits = opts->nactiveclimits;
	outer_helper_spawn(&outer_helper);

	/* After this point, we must operate with the privilege set of the caller
	   -- no suid bit, no calling make_capable. */

	/* This drops capabilities if we're being run as a setuid binary. */
	if (setuid(getuid()) == -1) {
		err(1, "setuid");
	}
	deny_new_capabilities = 1;

	const char *root = (opts->root != NULL) ? opts->root : "/";

	char resolved_root[PATH_MAX];
	if (realpath(root, resolved_root) == NULL) {
		err(1, "realpath %s", root);
	}
	cleanpath(resolved_root);
	root = resolved_root;

	char cwd[PATH_MAX];
	char *workdir = opts->workdir;
	if ((workdir == NULL || workdir[0] == '\0')) {
		if (getcwd(cwd, sizeof (cwd)) == NULL) {
			err(1, "getcwd");
		}

		assert(cwd[0] == '/' && "cwd must be an absolute path");
		assert(root[0] == '/' && "root must be an absolute path");

		/* Pure textual prefixing -- if the root is a prefix of the cwd, we remove
		   it. This must be done on two absolute paths.

		   As an exception, if root is /, the prefix is not removed. */
		size_t rootlen = strlen(root);
		if (strcmp(root, "/") == 0) {
			workdir = cwd;
		} else if (strncmp(root, cwd, rootlen) == 0) {
			workdir = cwd + rootlen;
		}
	}
	/* Our tentative to use the cwd failed, or it worked and the cwd _is_ the
	   new root. In both cases, the workdir must be /. */
	if (workdir == NULL || workdir[0] == '\0') {
		workdir = "/";
	}

	// Only open by fd the target init if it resides outside of the target root.
	// If it resides inside the root, we need symlink resolution to be done
	// within the root itself.
	int initfd = -1;
	if (opts->init != NULL && opts->init[0] != '\0' && strncmp(opts->init, root, strlen(root)) != 0) {
		initfd = open(opts->init, O_PATH | O_CLOEXEC);
		if (initfd == -1) {
			err(1, "open %s", opts->init);
		}
	}

	struct nsid namespaces[] = {
		/* User namespace must be entered first and foremost if unprivileged */
		{ NS_USER,   nsactions[NS_USER] },
		{ NS_NET,    nsactions[NS_NET] },
		{ NS_MNT,    nsactions[NS_MNT] },
		{ NS_IPC,    nsactions[NS_IPC] },
		{ NS_PID,    nsactions[NS_PID] },
		{ NS_UTS,    nsactions[NS_UTS] },
		{ NS_TIME,   nsactions[NS_TIME] },
		{ NS_CGROUP, nsactions[NS_CGROUP] },
	};

	size_t ns_len = lengthof(namespaces);
	ns_enter_prefork(namespaces, &ns_len);

	/* Some convenience pre-checks */
	int mnt_unshare    = nsactions[NS_MNT]    == NSACTION_UNSHARE;
	int uts_unshare    = nsactions[NS_UTS]    == NSACTION_UNSHARE;
	int pid_unshare    = nsactions[NS_PID]    == NSACTION_UNSHARE;
	int net_unshare    = nsactions[NS_NET]    == NSACTION_UNSHARE;
	int time_unshare   = nsactions[NS_TIME]   == NSACTION_UNSHARE;
	int cgroup_unshare = nsactions[NS_CGROUP] == NSACTION_UNSHARE;

	/* Just unsharing the mount namespace is not sufficient -- if we don't make
	   every mount entry private, any change we make will be applied to the
	   parent mount namespace if it happens to have MS_SHARED propagation. We
	   don't like coin flips. */
	if (mnt_unshare && mount("none", "/", "", MS_REC | MS_PRIVATE, "") == -1) {
		err(1, "could not make / private: mount");
	}

	if (opts->arch != NULL && opts->arch[0] != '\0') {
		setarch(opts->arch);
	}

	if (!opts->no_derandomize) {
		unsigned long persona = (unsigned long) personality(0xffffffff) | ADDR_NO_RANDOMIZE;
		if (personality(persona) == -1) {
			err(1, "personality %lu", persona);
		}
	}

	if (time_unshare) {
		init_clocks(timens_offsets, opts->clockspecs, lengthof(opts->clockspecs));
	}

	if (timens_offsets != -1 && close(timens_offsets) == -1) {
		err(1, "close timens_offsets");
	}

	/* Setup a socket pair for file-descriptor passing. Used by pty allocation. */
	enum {
		SOCKET_PARENT,
		SOCKET_CHILD,
	};
	int socket_fdpass[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, socket_fdpass) < 0) {
		err(1, "socketpair");
	}

	/* Set up a pipe that we do nothing with; we use the read end as the parent
	   handle in sig_setpdeathsig, and the write end will get closed on
	   process exit. This ensures that we are able to properly detect process
	   reparenting before we've called prctl(PR_SET_PDEATHSIG). */
	enum {
		LIVENESS_CHECK,
		LIVENESS_KEEP,
	};
	int liveness_fds[2];
	if (pipe2(liveness_fds, O_CLOEXEC | O_NONBLOCK) == -1) {
		err(1, "pipe2");
	}

	/* You can't "really" unshare the PID namespace of a running process
	   without forking, since for process hierarchy reasons only the next
	   child process enters the namespace as init and subsequent calls to
	   clone(2) fails.

	   Since we set-up some things like the parent death signal, it's just
	   cleaner and easier to always fork, regardless of unsharing the PID
	   namespace. */

	pid_t pid = fork();
	if (pid == -1) {
		if (errno == ENOMEM && nsactions[NS_PID] >= 0) {
			errx(1, "fork: %s (is the target PID namespace dead?)", strerror(errno));
		}
		err(1, "fork");
	}

	if (pid) {

		/* Past this point, drop all capabilities. This promises that we do not
		   need to make any privileged adjustments past initialization, and
		   makes us debuggable unprivileged during the wait loop. */

		drop_capabilities();

		if (prctl(PR_SET_DUMPABLE, 1) == -1) {
			/* Not being debuggable is not the end of the world */
			warn("prctl PR_SET_DUMPABLE");
		}

		close(socket_fdpass[SOCKET_CHILD]);
		close(liveness_fds[LIVENESS_CHECK]);

		if (opts->pidfile != NULL) {
			int pidfile = open(opts->pidfile, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOCTTY , 0666);
			if (pidfile == -1) {
				err(1, "open %s", opts->pidfile);
			}

			struct stat stat;
			if (fstat(pidfile, &stat) == -1) {
				err(1, "stat %s", opts->pidfile);
			}

			if (S_ISREG(stat.st_mode)) {
				if (flock(pidfile, LOCK_EX | LOCK_NB) == -1) {
					err(1, "flock %s", opts->pidfile);
				}

				if (ftruncate(pidfile, 0) == -1) {
					err(1, "ftruncate %s, 0", opts->pidfile);
				}
			}

			char data[64];
			if ((size_t) snprintf(data, sizeof (data), "%d\n", pid) >= sizeof (data)) {
				errx(1, "'%d\n' takes more than %zu bytes.", pid, sizeof (data));
			}
			size_t remain = sizeof (data);
			char *ptr = data;
			while (remain > 0) {
				ssize_t written = write(pidfile, ptr, remain);
				if (written == -1) {
					err(1, "writing pid to %s", opts->pidfile);
				}
				remain -= written;
				ptr += written;
			}
		}

		outer_helper_sendpid(&outer_helper, pid);
		outer_helper_close(&outer_helper);

		int epollfd = epoll_create1(EPOLL_CLOEXEC);

		sigset_t mask;
		sigfillset(&mask);

		if (opts->tty) {
			/* tty_parent_setup handles SIGWINCH to resize the pty */
			sigdelset(&mask, SIGWINCH);
			tty_parent_setup(&opts->ttyopts, epollfd, socket_fdpass[SOCKET_PARENT]);
		}
		sig_setup(epollfd, &mask, outer_helper.pid, sig_handler);

		for (;;) {

			/* 16 events is good enough */
			struct epoll_event events[16];
			int ready;
			do {
				ready = epoll_wait(epollfd, events, lengthof(events), -1);
				if (ready == -1 && errno != EINTR) {
					err(1, "epoll_wait");
				}
			} while (ready == -1);

			/* Sort the handlers by priority */
			qsort(events, (size_t) ready, sizeof (*events), cmp_epoll_handler);

			for (int i = 0; i < ready; ++i) {
				struct epoll_handler *handler = events[i].data.ptr;
				int rc = handler->fn(epollfd, &events[i], handler->fd, pid);
				if (rc >= 0) {
					/* Cleanup and exit. We reset our proc mask to allow
					   ourselves to get killed during anything that blocks. */
					sigset_t mask;
					sigemptyset(&mask);

					if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
						err(1, "sigprocmask");
					}

					if (opts->tty) {
						tty_parent_cleanup();
					}
					return rc;
				}
			}
		}
	}

	close(liveness_fds[LIVENESS_KEEP]);

	/* err() and errx() cannot use exit(), since it's not fork-safe. */
	err_exit = _exit;

	close(socket_fdpass[SOCKET_PARENT]);

	sigset_t mask;
	sigemptyset(&mask);

	if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
		err(1, "sigprocmask");
	}

	/* We can't afford to leave the child alive in the background if bst
	   dies from uncatcheable signals. Or at least, we could, but this makes us
	   leaky by default which isn't great, and the obvious workaround to
	   daemonize the process tree is to just nohup bst. */
	sig_setpdeathsig(SIGKILL, liveness_fds[LIVENESS_CHECK]);

	outer_helper_sync(&outer_helper);

	/* Read the current cgroup before ns_enter_postfork; this allows us
	   to get the real path to the cgroup */
	char cgroup_path[PATH_MAX];
	if (!cgroup_read_current(cgroup_path)) {
		cgroup_path[0] = '\0';
	}
	ns_enter_postfork(namespaces, ns_len);

#ifdef HAVE_SECCOMP_UNOTIFY
		int seccomp_fd = sec_seccomp_install_filter();
		if (seccomp_fd != -1) {
			send_fd(outer_helper.fd, seccomp_fd);
			close(seccomp_fd);
		}
#endif

	outer_helper_close(&outer_helper);

	int rtnl = init_rtnetlink_socket();

	/* Rename interfaces according to their specifications */
	if (net_unshare) {
		for (size_t i = 0; i < opts->nnics; ++i) {
			if (i > (size_t) INT_MAX - 2) {
				errx(1, "cannot iterate over more than %d interfaces", INT_MAX - 2);
			}
			/* interface indices start from 1, and we want to ignore interface 1 (lo),
			   so we slide our indices by 2. */
			net_if_rename(rtnl, (int)i + 2, opts->nics[i].name);
		}
	}

	if (opts->setup_program != NULL) {
		pid_t pid = fork();
		if (pid == -1) {
			err(1, "setup: fork");
		}

		if (!pid) {
			char *default_argv[2];
			default_argv[0] = (char *) opts->setup_program;
			default_argv[1] = NULL;

			/* Set some extra useful environment */
			setenv("ROOT", root, 1);
			setenv("EXECUTABLE", opts->pathname, 1);
			if (cgroup_path[0] != '\0') {
				setenv("CGROUP_PATH", cgroup_path, 1);
			}

			extern char **environ;

			char *const *argv = default_argv;
			if (opts->setup_argv != NULL) {
				argv = opts->setup_argv;
			}

			if (dup2(STDERR_FILENO, STDOUT_FILENO) == -1) {
				err(1, "setup: dup2");
			}

			execvpe(opts->setup_program, argv, environ);
			err(1, "setup: execvpe %s", opts->setup_program);
		}

		int status;
		if (waitpid(pid, &status, 0) == -1) {
			err(1, "setup: waitpid");
		}

		if (WIFEXITED(status) && WEXITSTATUS(status)) {
			_exit(WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			_exit(WTERMSIG(status) | 1 << 7);
		}
	}

	for (const struct close_range *range = opts->close_fds; range < opts->close_fds + opts->nclose_fds; ++range) {
		if (bst_close_range(range->from, range->to, BST_CLOSE_RANGE_CLOEXEC) == -1) {
			err(1, "close_range %d %d", range->from, range->to);
		}
	}

	/*
	 * Only mount a a cgroup hierarchy over sys/fs/cgroup if:
	 *  1) The user has not specified --no_cgroup_remount
	 *  2) The mount namespaces are being unshared
	 *  3) The cgroup namespaces are being unshared
	 */
	if (!opts->no_cgroup_remount && mnt_unshare && cgroup_unshare) {
		int rootfd = open(root, O_PATH, 0);
		if (rootfd == -1) {
			err(1, "open %s", root);
		}

		struct stat cgroupst = { .st_dev = 0 };
		if (fstatat(rootfd, "sys/fs/cgroup", &cgroupst, AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW) == -1 && errno != ENOENT) {
			err(1, "fstatat %s/sys/fs/cgroup", root);
		}

		struct stat rootst;
		if (fstat(rootfd, &rootst) == -1) {
			err(1, "fstat %s", root);
		}

		close(rootfd);

		/*
		 * Check if sys/fs/cgroup is already a mount point
		 * If it is we need to mount the current cgroup root over it so procs have a
		 * coherent view of cgroup hierarchy. We cant just mount to sys/fs/cgroup
		 * (as we do with /proc remount), so we mount a tmpfs and mount cgroups to that.
		 */
		if (cgroupst.st_dev != 0 && cgroupst.st_dev != rootst.st_dev) {
			const char *target = makepath("%s/sys/fs/cgroup", root);

			if (mount("tmpfs", target, "tmpfs", 0, NULL) == -1) {
				err(1, "unable to mount tmpfs over %s", target);
			}

			if (mount("cgroup", target, "cgroup2", 0, NULL) == -1) {
				err(1, "unable to mount tmpfs over %s", target);
			}
		}
	}

	/* Check whether or not <root>/proc is a mountpoint. If so,
	   and we're in a PID + mount namespace, mount a new /proc. */
	if (!opts->no_proc_remount && mnt_unshare && pid_unshare) {
		int rootfd = open(root, O_PATH, 0);
		if (rootfd == -1) {
			err(1, "open %s", root);
		}

		struct stat procst = { .st_dev = 0 };
		if (fstatat(rootfd, "proc", &procst, AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW) == -1 && errno != ENOENT) {
			err(1, "fstatat %s/proc", root);
		}

		struct stat rootst;
		if (fstat(rootfd, &rootst) == -1) {
			err(1, "fstat %s", root);
		}

		close(rootfd);

		/* <root>/proc is a mountpoint, remount it. And by remount, we mean mount over it,
		   since the original mount is probably more privileged than us, or might not be a
		   procfs one someone's oddball configuration. */
		if (procst.st_dev != 0 && procst.st_dev != rootst.st_dev) {
			const char *target = makepath("%s/proc", root);

			int rc = mount("proc", target, "proc", 0, NULL);
			if (rc == -1 && errno == EBUSY) {
				/* This situation can arise on some kernels when we don't switch
				   roots, and the mount namespace already has an entry for /proc.
				   In this case, we have to unmount the original entry and
				   mount a new one over it. */
				if (umount2(target, MNT_DETACH) == -1) {
					warn("umount2 %s", target);
				}
				rc = mount("proc", target, "proc", 0, NULL);
			}
			if (rc == -1) {
				err(1, "mount: %s remount", target);
			}
		}
	}

	/* Set the host and domain names only when in an UTS namespace. */
	if ((opts->hostname != NULL || opts->domainname != NULL ) && !uts_unshare) {
		errx(1, "attempted to set host or domain names on the host UTS namespace.");
	}

	const char *hostname = opts->hostname;
	if (hostname == NULL && uts_unshare) {
		hostname = "localhost";
	}
	if (hostname != NULL && sethostname(hostname, strlen(hostname)) == -1) {
		err(1, "sethostname");
	}

	const char *domainname = opts->domainname;
	if (domainname == NULL && uts_unshare) {
		domainname = "localdomain";
	}
	if (domainname != NULL && setdomainname(domainname, strlen(domainname)) == -1) {
		err(1, "setdomainname");
	}

	if (net_unshare) {
		/* Setup localhost */
		if (!opts->no_loopback_setup) {
			net_if_up(rtnl, "lo");
		}

		/* Add addresses */
		for (size_t i = 0; i < opts->naddrs; ++i) {
			net_addr_add(rtnl, &opts->addrs[i]);
		}

		/* Bring up the rest of the nics */
		for (size_t i = 0; i < opts->nnics; ++i) {
			net_if_up(rtnl, opts->nics[i].name);
		}

		/* Add routes */
		for (size_t i = 0; i < opts->nroutes; ++i) {
			net_route_add(rtnl, &opts->routes[i]);
		}
	}

	/* We have a special case for pivot_root: the syscall wants the
	   new root to be a mount point, so we indulge. */
	if (mnt_unshare && strcmp(root, "/") != 0) {
		if (mount(root, root, "none", MS_BIND|MS_REC, "") == -1) {
			err(1, "mount(\"/\", \"/\", MS_BIND|MS_REC)");
		}
	}

	/* We have to do this after setuid/setgid/setgroups since mounting
	   tmpfses in user namespaces forces the options uid=<real-uid> and
	   gid=<real-gid>. */
	if (opts->nmounts > 0) {
		/* Don't shoot ourselves in the foot. It's technically possible to
		   let users mount things in the host mount namespace but in practice
		   it's a terrible idea due to the sheer amount of things that can go
		   wrong, like "what do I do if one of the mounts failed but the previous
		   ones didn't?", or "how do I clean up things that I've (re)mounted?". */
		if (!mnt_unshare) {
			errx(1, "attempted to mount things in an existing mount namespace.");
		}

		if (!opts->no_fake_devtmpfs) {
			for (struct mount_entry *mnt = opts->mounts; mnt < opts->mounts + opts->nmounts; ++mnt) {
				if (strcmp(mnt->type, "devtmpfs") == 0) {
					mnt->type = "bst_devtmpfs";
				}
			}
		}

		mount_entries(root, opts->mounts, opts->nmounts, opts->no_derandomize);
	}

	/* Don't chroot if root is "/". This is a better default since it
	   allows us to run commands that unshare nothing unprivileged. */
	if (strcmp(root, "/") != 0) {

		/* The chroot-ing logic is a bit delicate. If we don't have a mount
		   namespace, we just use chroot. This has its limitations though,
		   namely, in that situation, you won't be able to nest user
		   namespaces, and you'll instead get baffling EPERMs when calling
		   unshare(CLONE_NEWUSER).

		   In order to remediate that, we pivot the root. Since this actively
		   changes the world for every running process, we *insist* that this
		   must be done in a mount namespace, because otherwise pivot_root
		   will burn your house, invoke dragons, and eat your children. */

		if (!mnt_unshare) {
			if (chroot(root) == -1) {
				err(1, "chroot");
			}
		} else {
			if (chdir(root) == -1) {
				err(1, "pivot_root: pre chdir");
			}

			/* Pivot the root to `root` (new_root) and mount the old root
			   (old_dir) on top of it. Then, unmount "." to get rid of the
			   old root.

			   The pivot_root manpage documents this approach: old_dir is
			   always layered on top of new_root, which means that we can
			   use this technique to avoid creating a mount point for the
			   old root under new_root, or assuming anything about the layout
			   of the new root. */
			if (syscall(SYS_pivot_root, ".", ".") == -1) {
				err(1, "pivot_root");
			}
			if (umount2(".", MNT_DETACH)) {
				err(1, "pivot_root: umount2");
			}
			if (chdir("/") == -1) {
				err(1, "pivot_root: post chdir");
			}
		}
	}

	if (opts->umask != (mode_t) -1) {
		umask(opts->umask);
	}

	/* Beyond this point, all capabilities are dropped by the uid/gid change.
	   Only operations that make sense to be privileged in the context of
	   the specified credentials (and not the userns root) should be placed
	   below. */

	if (opts->ngroups != 0 && setgroups(opts->ngroups, opts->groups) == -1) {
		err(1, "setgroups");
	}
	if (setregid(opts->gid, opts->gid) == -1) {
		err(1, "setregid");
	}
	if (setreuid(opts->uid, opts->uid) == -1) {
		err(1, "setreuid");
	}

	if (chdir(workdir) == -1) {
		warn("chdir %s", workdir);
		warnx("falling back work directory to /.");
		if (chdir("/") == -1) {
			err(1, "chdir /");
		}
	}

	for (size_t resource = 0; resource < lengthof(opts->rlimits); ++resource) {
		struct rlimit const * value = NULL;
		if (opts->rlimits[resource].present) {
			value = &opts->rlimits[resource].rlim;
		}
		/* When no_copy_hard_rlimits is not set, we always want to call apply_rlimit, either
		   with the explicitly configured value (value != NULL), or by copying hard->soft
		   (value == NULL). */
		if (value || !opts->no_copy_hard_rlimits) {
			apply_rlimit(resource, value);
		}
	}

	if (opts->tty) {
		tty_child(&opts->ttyopts, socket_fdpass[SOCKET_CHILD]);
	}

	if (opts->init != NULL && opts->init[0] != '\0') {

		if (!pid_unshare && prctl(PR_SET_CHILD_SUBREAPER, 1) == -1) {
			err(1, "prctl: could not set init as child subreaper");
		}

		/* This size estimation is an overkill upper bound, but oh well... */
		char *argv[ARG_MAX];
		size_t argc = 0;

		argc = append_argv(argv, argc, opts->argv[0]);
		argc = append_argv(argv, argc, (char *) opts->pathname);
		char *const *arg = opts->argv + 1;
		for (; *arg != NULL; ++arg) {
			argc = append_argv(argv, argc, *arg);
		}
		argv[argc] = NULL;

		if (initfd != -1) {
#ifdef SYS_execveat
			syscall(SYS_execveat, initfd, "", argv, opts->envp, AT_EMPTY_PATH);
			if (errno != ENOSYS) {
				err(1, "execveat %s", opts->init);
			}
#endif
			char fdpath[PATH_MAX];
			if ((size_t) snprintf(fdpath, sizeof (fdpath), "/proc/self/fd/%d", initfd) >= sizeof (fdpath)) {
				errx(1, "/proc/self/fd/%d takes more than PATH_MAX bytes.", initfd);
			}
			execve(fdpath, argv, opts->envp);
			err(1, "execve %s", opts->init);
		} else {
			// If we hit this, it means the requested init is within the target root.
			// We need init resolution to be done relative to the target root.
			size_t rootlen = strlen(root);
			assert(strncmp(opts->init, root, rootlen) == 0);

			if (rootlen == 1 && root[0] == '/') {
				rootlen = 0;
			}
			const char *init = opts->init + rootlen;

			execve(init, argv, opts->envp);
			err(1, "execve %s", init);
		}
	} else {
		execvpe(opts->pathname, opts->argv, opts->envp);
		err(1, "execvpe %s", opts->pathname);
	}
}
