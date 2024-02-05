#ifndef CGROUP_H_
# define CGROUP_H_

# include <stdbool.h>

struct cgroup_driver_funcs {
	int (*init)(bool fatal);
	int (*join_cgroup)(const char *parent, const char *name);
	bool (*current_path)(char *out);
};

enum cgroup_driver {
	CGROUP_DRIVER_NONE,
	CGROUP_DRIVER_NATIVE,
	CGROUP_DRIVER_SYSTEMD,
};

int cgroup_driver_init(enum cgroup_driver driver, bool fatal);
bool cgroup_current_path(char *path);
int cgroup_join(const char *parent, const char *name);
bool cgroup_read_current(char *path);
void cgroup_enable_controllers(int cgroupfd);
void cgroup_start_cleaner(int parentfd, const char *name);

#endif /* !CGROUP_H_ */
