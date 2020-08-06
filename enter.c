/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "capable.h"
#include "enter.h"
#include "flags.h"
#include "mount.h"
#include "net.h"
#include "outer.h"
#include "path.h"
#include "setarch.h"
#include "sig.h"

#define lengthof(Arr) (sizeof (Arr) / sizeof (*Arr))

#ifndef ARG_MAX
/* ARG_MAX is typically a runtime constant that one can retrieve via sysconf,
   but we don't want to be using VLAs in sensitive code. */
# define ARG_MAX 4096
#endif

struct cloneflag {
	int flag;
	const char *proc_ns_name;
};

static struct cloneflag flags[] = {
	[ SHARE_CGROUP ] = { BST_CLONE_NEWCGROUP, "cgroup" },
	[ SHARE_IPC ]    = { BST_CLONE_NEWIPC,    "ipc",   },
	[ SHARE_MNT ]    = { BST_CLONE_NEWNS,     "mnt"    },
	[ SHARE_NET ]    = { BST_CLONE_NEWNET,    "net"    },
	[ SHARE_PID ]    = { BST_CLONE_NEWPID,    "pid"    },
	[ SHARE_TIME ]   = { BST_CLONE_NEWTIME,   "time"   },
	[ SHARE_USER ]   = { BST_CLONE_NEWUSER,   "user"   },
	[ SHARE_UTS ]    = { BST_CLONE_NEWUTS,    "uts"    },
};

const char *nsname(int ns)
{
	return flags[ns].proc_ns_name;
}
	

struct nsaction {
	/* Which namespace is being unshared or entered */
	int flag;

	/* Legal values for enter_fd are:
	     >= 0: a file descriptor for an existing namespace that we will enter;
	     NSACTION_SHARE_WITH_PARENT: inherit from parent (don't unshare or setns);
	     NSACTION_UNSHARE: unshare this namespace. */
	int enter_fd;
};

enum {
      NSACTION_SHARE_WITH_PARENT = -1,
      NSACTION_UNSHARE = -2,
};

static void opts_to_nsactions(const struct entry_settings *opts, int *nsactions)
{
	for (int i = 0; i < MAX_SHARES; i++) {
		const char *share = opts->shares[i];
		if (share == NULL) {
			nsactions[i] = NSACTION_UNSHARE;
		} else if (share == SHARE_WITH_PARENT) {
			nsactions[i] = NSACTION_SHARE_WITH_PARENT;
		} else {
			int fd = open(share, O_RDONLY | O_CLOEXEC);
			if (fd < 0) {
				err(1, "open %s", share);
			}
			nsactions[i] = fd;
		}
	}
}

static inline size_t append_argv(char **argv, size_t argc, char *arg)
{
	if (argc >= ARG_MAX) {
		errx(1, "argv too large, a maximum of %zu arguments is supported", (size_t) ARG_MAX);
	}
	argv[argc] = arg;
	return argc + 1;
}

int enter(struct entry_settings *opts)
{
	int timens_offsets = -1;
	if (opts->shares[SHARE_TIME] != SHARE_WITH_PARENT) {

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
			opts->shares[SHARE_TIME] = SHARE_WITH_PARENT;
		}

		reset_capabilities();
	}

	int nsactions[MAX_SHARES];
	opts_to_nsactions(opts, nsactions);

	struct outer_helper outer_helper;
	outer_helper.persist = opts->persist;
	outer_helper.unshare_user = nsactions[SHARE_USER] == NSACTION_UNSHARE;
	memcpy(outer_helper.uid_desired, opts->uid_map, sizeof (outer_helper.uid_desired));
	memcpy(outer_helper.gid_desired, opts->gid_map, sizeof (outer_helper.gid_desired));
	outer_helper_spawn(&outer_helper);

	/* After this point, we must operate with the privilege set of the caller
	   -- no suid bit, no calling make_capable. */

	/* This drops capabilities if we're being run as a setuid binary. */
	if (setuid(getuid()) == -1) {
		err(1, "setuid");
	}
	deny_new_capabilities = 1;

	const char *root = opts->root ? opts->root : "/";

	char resolved_root[PATH_MAX];
	if (realpath(root, resolved_root) == NULL) {
		err(1, "realpath %s", root);
	}
	root = resolved_root;

	char cwd[PATH_MAX];
	char *workdir = opts->workdir;
	if ((!workdir || workdir[0] == '\0')) {
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
	if (!workdir || workdir[0] == '\0') {
		workdir = "/";
	}

	int nsenterables[] = {
		SHARE_USER,
		SHARE_NET,
		SHARE_MNT,
		SHARE_IPC,
		SHARE_PID,
		SHARE_CGROUP,
		SHARE_UTS,
		SHARE_TIME,
		-1,
	};

	for (int *ns = &nsenterables[0]; *ns != -1; ++ns) {
		int action = nsactions[*ns];
		if (action < 0) {
			continue;
		}
		int rc = setns(action, flags[*ns].flag);
		if (rc == -1) {
			err(1, "setns %s", flags[*ns].proc_ns_name);
		}
		close(action);
	}

	/* Unshare all relevant namespaces. It's hard to check in advance which
	   namespaces are supported, so we unshare them one by one in order. */

	int unshareables[] = {
		/* User namespace must be unshared first and foremost. */
		SHARE_USER,
		SHARE_MNT,
		SHARE_UTS,
		SHARE_PID,
		SHARE_NET,
		SHARE_IPC,
		SHARE_CGROUP,
		SHARE_TIME,
		-1,
	};

	for (int *ns = &unshareables[0]; *ns != -1; ++ns) {
		int action = nsactions[*ns];
		if (action != NSACTION_UNSHARE) {
			continue;
		}
		int rc = unshare(flags[*ns].flag);
		if (rc == -1 && errno == EINVAL) {
			/* We realized that the namespace isn't supported -- remove it
			   from the unshare set. */
			nsactions[*ns] = NSACTION_SHARE_WITH_PARENT;
		} else if (rc == -1) {
			err(1, "unshare %s", flags[*ns].proc_ns_name);
		}
	}

	int mnt_unshare  = nsactions[SHARE_MNT]  == NSACTION_UNSHARE;
	int uts_unshare  = nsactions[SHARE_UTS]  == NSACTION_UNSHARE;
	int pid_unshare  = nsactions[SHARE_PID]  == NSACTION_UNSHARE;
	int net_unshare  = nsactions[SHARE_NET]  == NSACTION_UNSHARE;
	int time_unshare = nsactions[SHARE_TIME] == NSACTION_UNSHARE;

	/* Just unsharing the mount namespace is not sufficient -- if we don't make
	   every mount entry private, any change we make will be applied to the
	   parent mount namespace if it happens to have MS_SHARED propagation. We
	   don't like coin flips. */
	if (mnt_unshare && mount("none", "/", "", MS_REC | MS_PRIVATE, "") == -1) {
		err(1, "could not make / private: mount");
	}

	if (opts->arch && opts->arch[0] != 0) {
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

	/* You can't "really" unshare the PID namespace of a running process
	   without forking, since for process hierarchy reasons only the next
	   child process enters the namespace as init and subsequent calls to
	   clone(2) fails.

	   Since we set-up some things like the parent death signal, it's just
	   cleaner and easier to always fork, regardless of unsharing the PID
	   namespace. */

	pid_t pid = fork();
	if (pid == -1) {
		err(1, "fork");
	}

	if (pid) {
		outer_helper_sendpid(&outer_helper, pid);
		outer_helper_close(&outer_helper);

		sigset_t mask;
		sigfillset(&mask);

		for (;;) {

			siginfo_t info;
			sig_wait(&mask, &info);
			sig_reap_and_forward(&info, pid);

			if (info.si_signo != SIGCHLD) {
				continue;
			}

			/* We might have been run as a process subreaper against our
			   will -- make sure we only exit when the main child pid
			   exited. */

			if (info.si_pid == pid) {
				switch (info.si_code) {
				case CLD_EXITED:
					return info.si_status;
				case CLD_KILLED:
				case CLD_DUMPED:
					return info.si_status | 1 << 7;
				}
			} else if (info.si_pid == outer_helper.pid) {
				switch (info.si_code) {
				case CLD_KILLED:
					errx(1, "helper got killed with signal %d", info.si_status);
				case CLD_DUMPED:
					errx(1, "helper crashed with signal %d", info.si_status);
				case CLD_EXITED:
					if (info.si_status) {
						errx(1, "helper exit status %d", info.si_status);
					}
					break;
				}
			}
		}
	}

	sigset_t mask;
	sigemptyset(&mask);

	if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
		err(1, "sigprocmask");
	}

	/* We can't afford to leave the child alive in the background if bst
	   dies from uncatcheable signals. Or at least, we could, but this makes us
	   leaky by default which isn't great, and the obvious workaround to
	   daemonize the process tree is to just nohup bst. */
	if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1) {
		err(1, "prctl PR_SET_PDEATHSIG");
	}

	outer_helper_sync(&outer_helper);
	outer_helper_close(&outer_helper);

	if (opts->setup_program) {
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

			extern char **environ;

			char *const *argv = default_argv;
			if (opts->setup_argv) {
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
			umount2(target, MNT_DETACH);

			if (mount("proc", target, "proc", 0, NULL) == -1) {
				err(1, "mount: %s remount", target);
			}
		}
	}

	/* Set the host and domain names only when in an UTS namespace. */
	if ((opts->hostname || opts->domainname) && !uts_unshare) {
		errx(1, "attempted to set host or domain names on the host UTS namespace.");
	}

	const char *hostname = opts->hostname;
	if (!hostname && uts_unshare) {
		hostname = "localhost";
	}
	if (hostname && sethostname(hostname, strlen(hostname)) == -1) {
		err(1, "sethostname");
	}

	const char *domainname = opts->domainname;
	if (!domainname && uts_unshare) {
		domainname = "localdomain";
	}
	if (domainname && setdomainname(domainname, strlen(domainname)) == -1) {
		err(1, "setdomainname");
	}

	int rtnl = init_rtnetlink_socket();

	/* Setup localhost */
	if (net_unshare && !opts->no_loopback_setup) {
		net_if_up(rtnl, "lo");
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
	if (opts->nmounts > 0 || opts->nmutables > 0) {
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
		mount_mutables(root, opts->mutables, opts->nmutables);
	}

	int initfd = -1;
	if (opts->init != NULL && opts->init[0] != '\0') {
		initfd = open(opts->init, O_PATH | O_CLOEXEC);
		if (initfd == -1) {
			err(1, "open %s", opts->init);
		}
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

	if (initfd != -1) {

		if (!pid_unshare && prctl(PR_SET_CHILD_SUBREAPER, 1) == -1) {
			err(1, "prctl: could not set init as child subreaper");
		}

		/* This size estimation is an overkill upper bound, but oh well... */
		char *argv[ARG_MAX];
		size_t argc = 0;

		argc = append_argv(argv, argc, opts->argv[0]);
		argc = append_argv(argv, argc, (char *) opts->pathname);
		char *const *arg = opts->argv + 1;
		for (; *arg; ++arg) {
			argc = append_argv(argv, argc, *arg);
		}
		argv[argc] = NULL;

		fexecve(initfd, argv, opts->envp);
		err(1, "fexecve %s", opts->init);
	} else {
		execvpe(opts->pathname, opts->argv, opts->envp);
		err(1, "execvpe %s", opts->pathname);
	}
}
