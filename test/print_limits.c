#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

static void print_limit(int resource, char const *tag)
{
	struct rlimit rlim;

	if (getrlimit(resource, &rlim)) {
		err(1, "getrlimit(%s)", tag);
	}

	char *hard;
	if (rlim.rlim_max == RLIM_INFINITY) {
		hard = "unlimited";
	} else {
		hard = malloc(100);
		if (snprintf(hard, 100, "%ju", (uintmax_t)rlim.rlim_max) >= 100) {
			errx(1, "buffer error");
		}
	}

	char *soft;
	if (rlim.rlim_cur == RLIM_INFINITY) {
		soft = "unlimited";
	} else {
		soft = malloc(100);
		if (snprintf(soft, 100, "%ju", (uintmax_t)rlim.rlim_cur) >= 100) {
			errx(1, "buffer error");
		}
	}
	printf("%s: hard=%s soft=%s\n", tag, hard, soft);
}

int main(int argc, char **argv)
{
	struct lim {
		int resource;
		char const *tag;
	};
	struct lim limits[] = {
		{ RLIMIT_CORE, "core"},
		{ RLIMIT_NOFILE, "nofile"},
		{ RLIMIT_NPROC, "nproc"},
	};

	for (size_t x = 0; x < sizeof(limits)/sizeof(*limits); ++x) {
		if (argc > 1 && strcmp(argv[1], limits[x].tag) ) {
			continue;
		}
		print_limit(limits[x].resource, limits[x].tag);
	}

	return 0;
}
