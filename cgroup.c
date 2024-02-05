#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <syslog.h>
#include <unistd.h>

#include "cgroup.h"
#include "config.h"
#include "errutil.h"
#include "fd.h"
#include "path.h"
#include "util.h"

extern const struct cgroup_driver_funcs cgroup_driver_none;
extern const struct cgroup_driver_funcs cgroup_driver_native;
#ifdef HAVE_SYSTEMD
extern const struct cgroup_driver_funcs cgroup_driver_systemd;
#endif

static const struct cgroup_driver_funcs *cgroup_drivers[] = {
	[CGROUP_DRIVER_NONE]   = &cgroup_driver_none,
	[CGROUP_DRIVER_NATIVE] = &cgroup_driver_native,
#ifdef HAVE_SYSTEMD
	[CGROUP_DRIVER_SYSTEMD] = &cgroup_driver_systemd,
#endif
};

static enum cgroup_driver cgroup_detected_driver = -1;

int cgroup_driver_init(enum cgroup_driver driver, bool fatal)
{
	cgroup_detected_driver = driver;

	if (cgroup_detected_driver != (enum cgroup_driver)-1) {
		if (cgroup_detected_driver < 0 || cgroup_detected_driver >= lengthof(cgroup_drivers)) {
			errx(1, "unknown cgroup driver ID %d", cgroup_detected_driver);
		}
		int rc = cgroup_drivers[cgroup_detected_driver]->init(fatal);
		if (rc < 0 && fatal) {
			errx(1, "cgroup_driver_init: cgroup driver failed to initialize");
		}
		return rc;
	}

	static enum cgroup_driver attempts[] = {
#ifdef HAVE_SYSTEMD
		CGROUP_DRIVER_SYSTEMD,
#endif
		CGROUP_DRIVER_NATIVE,
	};

	for (size_t i = 0; i < lengthof(attempts); i++) {
		if (attempts[i] < 0 || attempts[i] >= lengthof(cgroup_drivers)) {
			errx(1, "cgroup_driver_init: programming error: unexpected cgroup driver ID %d", cgroup_detected_driver);
		}
		if (cgroup_drivers[attempts[i]]->init(false) >= 0) {
			cgroup_detected_driver = attempts[i];
			return 0;
		}
	}
	if (fatal) {
		errx(1, "cgroup_driver_init: no cgroup driver initialized successfully");
	}
	return -1;
}

int cgroup_join(const char *parent, const char *name)
{
	return cgroup_drivers[cgroup_detected_driver]->join_cgroup(parent, name);
}

bool cgroup_current_path(char *path)
{
	return cgroup_drivers[cgroup_detected_driver]->current_path(path);
}

bool cgroup_read_current(char *path)
{
	FILE *selfcgroupfd = fopen("/proc/self/cgroup", "r");
	if (selfcgroupfd == NULL) {
		err(1, "unable to derive current cgroup hierarchy from /proc/self/cgroup");
	}

	const char *selfcgroup = NULL;
	char line[BUFSIZ];
	while (fgets(line, sizeof (line), selfcgroupfd) != NULL) {
		if (strncmp(line, "0::/", sizeof ("0::/") - 1) == 0) {
			// Remove newline character read by fgets
			line[strcspn(line, "\n")] = '\0';
			selfcgroup = line + 3;
			break;
		}
	}
	fclose(selfcgroupfd);

	if (selfcgroup != NULL && path != NULL) {
		makepath_r(path, "/sys/fs/cgroup/%s", selfcgroup);
	}
	return selfcgroup != NULL;
}

static int rm_cgroup(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
	char path[PATH_MAX];
	strncpy(path, fpath, sizeof (path));

	if (tflag == FTW_D) {
		for (int level = ftwbuf->level; level >= 0; level--) {
			if (rmdir(path) == -1) {
				break;
			}
			dirname(path);
		}
	}
	return 0;
}

/* If bst has entered a cgroup this function will epoll the cgroup.events file
   to detect when all pids have exited the cgroup ("populated 0"). The cgroup is
   destroyed when this condition is met. */
static void run_cleaner_child(int lock, int parentfd, const char *name)
{
	/* Wait for the parent to die before proceeding */
	int ok;
	switch (read(lock, &ok, sizeof (ok))) {
	case -1:
		warn("run_cgroup_child: read on lock");
		goto lastDitchEffort;
	case 0:
		break;
	}

	int cgroupfd = openat(parentfd, name, O_RDONLY | O_DIRECTORY, 0);
	if (cgroupfd == -1) {
		switch (errno) {
		case ENOENT:
			/* Parent died before it made the cgroup; nothing to do */
			return;
		default:
			warn("run_cgroup_child: open %s", name);
			goto lastDitchEffort;
		}
	}

	char fdpath[PATH_MAX];
	makepath_r(fdpath, "/proc/self/fd/%d", cgroupfd);

	char cgroup_path[PATH_MAX];
	if (readlink(fdpath, cgroup_path, sizeof (cgroup_path)) == -1) {
		warn("run_cgroup_child: readlink");
		goto lastDitchEffort;
	}

	int eventfd = openat(cgroupfd, "cgroup.events", 0);
	if (eventfd == -1) {
		warn("run_cgroup_child: open cgroup.events");
		goto recursiveClean;
	}

	struct epoll_event event = {
		.events = EPOLLET,
	};

	int epollfd = epoll_create1(0);
	if (epollfd == -1) {
		warn("run_cgroup_child: epoll_create1");
		goto recursiveClean;
	}

	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, eventfd, &event) == -1) {
		warn("run_cgroup_child: epoll_ctl_add cgroupfd");
		goto recursiveClean;
	}

	/* The first event is the initial state of the file; skip it, because
	   at that point the cgroup is still empty, and we'll have populated 0 */
	epoll_wait(epollfd, &event, 1, -1);

	FILE *eventsfp = fdopen(eventfd, "r");
	if (eventsfp == NULL) {
		warn("run_cgroup_child: fdopen cgroup.events");
		goto recursiveClean;
	}

	char populated[BUFSIZ];
	for (;;) {
		int ready = epoll_wait(epollfd, &event, 1, -1);
		if (ready == -1) {
			warn("run_cgroup_child: epoll_wait cgroup.events");
			goto recursiveClean;
		}

		rewind(eventsfp);

		/* The order of elements in cgroup.events is not necessarily specified. */
		while (fgets(populated, BUFSIZ, eventsfp) != NULL) {
			if (strnlen(populated, sizeof(populated)) == sizeof(populated)) {
				warn("run_cgroup_child: exceeded cgroup.events line read buffer");
				goto recursiveClean;
			}
			if (strncmp(populated, "populated 0", 11) == 0) {
				goto recursiveClean;
			}
		}
	}

	/* Let the process exit; no need to clean up fds. We don't need to
	   set any exit code since no parent process cares about them. */

recursiveClean:
	nftw(cgroup_path, rm_cgroup, 128, 0);
	return;

lastDitchEffort:
	if (unlinkat(parentfd, name, AT_REMOVEDIR) == -1) {
		warn("run_cgroup_child: unlinkat");
	}
	return;
}

void cgroup_start_cleaner(int parentfd, const char *name)
{
	int fds[2];
	if (pipe2(fds, O_CLOEXEC) == -1) {
		err(1, "cgroup_start_cleaner: pipe2");
	}

	pid_t pid = fork();
	if (pid == -1) {
		err(1, "cgroup_start_cleaner: fork");
	}

	/* This process is intentionally left to leak as the bst root process must have exited
	   and thus been removed from bst's cgroup.procs for the cgroup hierarchy to be removed */
	if (pid == 0) {
		/* Create a new session in case current group leader is killed */
		if (setsid() == -1) {
			err(1, "cgroup_start_cleaner: setsid");
		}

		/* Make sure all file descriptors except for the ones we're actually using
		   get closed. This avoids keeping around file descriptors on which
		   the parent process might be waiting on. */
		rebind_fds_and_close_rest(3, &fds[0], &parentfd, NULL);

		/* From now on, use syslog to report error messages. This is necessary
		   since the parent bst process might be gone by the time there's an
		   error, and whatever started it might not be there to report the
		   error anymore. */
		openlog("bst", LOG_CONS | LOG_PID, LOG_USER);
		err_flags |= ERR_USE_SYSLOG;

		run_cleaner_child(fds[0], parentfd, name);
		_exit(0);
	}

	close(fds[0]);

	/* Deliberately leak fds[1]. This _is_ important. It will get closed
	   once this process dies, releasing the read(2) lock of the cgroup
	   cleaner. */
}

void cgroup_enable_controllers(int cgroupfd)
{
	char controllers[BUFSIZ];
	int cfd = openat(cgroupfd, "cgroup.controllers", O_RDONLY, 0);
	if (cfd == -1) {
		err(1, "cgroup_enable_controllers: open cgroup.controllers");
	}
	if (read(cfd, controllers, sizeof (controllers)) == sizeof (controllers)) {
		errx(1, "cgroup_enable_controllers: read cgroup.controllers: too many controllers");
	}
	if (close(cfd) == -1) {
		err(1, "cgroup_enable_controllers: close cgroup.controllers");
	}

	int scfd = openat(cgroupfd, "cgroup.subtree_control", O_WRONLY, 0);
	if (scfd == -1) {
		err(1, "cgroup_enable_controllers: open cgroup.subtree_control");
	}

	char buf[BUFSIZ];
	buf[0] = '+';

	for (char *controller = strtok(controllers, " "); controller != NULL; controller = strtok(NULL, " ")) {
		char *last = stpncpy(buf + 1, controller, sizeof (buf) - 1);
		size_t len = last - buf;
		if (write(scfd, buf, len) == (ssize_t)-1) {
			err(1, "cgroup_enable_controllers: write %s into cgroup.subtree_control", buf);
		}
	}
	if (close(scfd) == -1) {
		err(1, "cgroup_enable_controllers: close cgroup.subtree_control");
	}
}

static int cgroup_none_driver_init(bool fatal)
{
	return -1;
}

static bool cgroup_none_current_path(char *path)
{
	return false;
}

static int cgroup_none_join_cgroup(const char *parent, const char *name)
{
	return -1;
}

const struct cgroup_driver_funcs cgroup_driver_none = {
	.init         = cgroup_none_driver_init,
	.join_cgroup  = cgroup_none_join_cgroup,
	.current_path = cgroup_none_current_path,
};
