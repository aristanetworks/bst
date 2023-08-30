#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "capable.h"
#include "cgroup.h"
#include "path.h"

static int cgroup_native_driver_init(bool fatal)
{
	/* The native driver can only work with cgroup v2. Perform some sanity
	   checks to verify this. */
	if (!cgroup_read_current(NULL)) {
		return -1;
	}

	/* Attempting to open /sys/fs/cgroup/cgroup.procs privileged checks two
	   things: first, that the cgroup hierarchy is v2 by checking that the
	   file exists; and second, that the mounted cgroup hierarchy can be
	   operated on, which might not be the case if bst was left in its
	   original cgroup. */
	make_capable(BST_CAP_DAC_OVERRIDE);
	int fd = open("/sys/fs/cgroup/cgroup.procs", O_WRONLY, 0);
	reset_capabilities();

	if (fd == -1) {
		return -1;
	}
	close(fd);

	return 0;
}

static bool cgroup_native_current_path(char *path)
{
	return cgroup_read_current(path);
}

static int cgroup_native_join_cgroup(const char *parent, const char *name)
{
	int parentfd = open(parent, O_RDONLY | O_DIRECTORY, 0);
	if (parentfd == -1) {
		err(1, "cgroup_native_join_cgroup: open %s", parent);
	}

	if (mkdirat(parentfd, name, 0777) == -1) {
		err(1, "cgroup_native_join_cgroup: mkdir %s under %s", name, parent);
	}

	int cgroupfd = openat(parentfd, name, O_RDONLY | O_DIRECTORY, 0);
	if (cgroupfd == -1) {
		warn("cgroup_native_join_cgroup: open %s under %s", name, parent);
		goto unlink;
	}

	make_capable(BST_CAP_DAC_OVERRIDE);
	int procs = openat(cgroupfd, "cgroup.procs", O_WRONLY, 0);
	reset_capabilities();

	if (procs == -1) {
		warn("cgroup_native_join_cgroup: open cgroup.procs under %s", parent);
		goto unlink;
	}

	/* openat was done with full privileges, but we actually just need the ability
	   to write to cgroups we own */
	if (faccessat(cgroupfd, "cgroup.procs", W_OK, 0) == -1) {
		warn("cgroup_native_join_cgroup: access cgroup.procs under %s", parent);
		goto unlink;
	}

	/* Start cleaner daemon; it will remove the cgroup once this process dies. */
	cgroup_run_cleaner(cgroupfd, parentfd, name);

	if (write(procs, "0", 1) == (ssize_t)-1) {
		warn("cgroup_native_join_cgroup: write cgroup.procs");
		goto unlink;
	}

	if (close(procs) == -1) {
		err(1, "cgroup_native_join_cgroup: close cgroup.procs under %s", parent);
	}
	if (close(parentfd) == -1) {
		err(1, "cgroup_native_join_cgroup: close %s", parent);
	}

	return cgroupfd;

unlink:
	if (unlinkat(parentfd, name, AT_REMOVEDIR) == -1) {
		warn("cgroup_native_join_cgroup: unlink %s under %s", name, parent);
	}
	exit(1);
}

const struct cgroup_driver_funcs cgroup_driver_native = {
	.init         = cgroup_native_driver_init,
	.join_cgroup  = cgroup_native_join_cgroup,
	.current_path = cgroup_native_current_path,
};
