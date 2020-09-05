#include <err.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include <asm/resource.h>

static void print_limit(int resource, char const *tag, bool soft_only)
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

	if (soft_only) {
		if (!strcmp(soft, hard)) {
			printf("%s: soft=hard\n", tag);
		} else {
			printf("%s: soft=%s\n", tag, soft);
		}
	} else {
		printf("%s: hard=%s soft=%s\n", tag, hard, soft);
	}
}

int main(int argc, char **argv)
{
	struct {
		int resource;
		char const *tag;
	} limits[] = {
		{ RLIMIT_AS,         "as"         },
		{ RLIMIT_CORE,       "core"       },
		{ RLIMIT_CPU,        "cpu"        },
		{ RLIMIT_DATA,       "data"       },
		{ RLIMIT_FSIZE,      "fsize"      },
		{ RLIMIT_LOCKS,      "locks"      },
		{ RLIMIT_MEMLOCK,    "memlock"    },
		{ RLIMIT_MSGQUEUE,   "msgqueue"   },
		{ RLIMIT_NICE,       "nice"       },
		{ RLIMIT_NOFILE,     "nofile"     },
		{ RLIMIT_NPROC,      "nproc"      },
		{ RLIMIT_RSS,        "rss"        },
		{ RLIMIT_RTPRIO,     "rtprio"     },
		{ RLIMIT_RTTIME,     "rttime"     },
		{ RLIMIT_SIGPENDING, "sigpending" },
		{ RLIMIT_STACK,      "stack"      },
	};

	bool soft_only = false;

	int arg = 1;

	if (argc > arg && !strcmp(argv[arg], "--soft-only")) {
		++arg;
		soft_only = true;
	}

	for (size_t x = 0; x < sizeof(limits)/sizeof(*limits); ++x) {
		if (argc > arg && strcmp(argv[arg], limits[x].tag) ) {
			continue;
		}
		print_limit(limits[x].resource, limits[x].tag, soft_only);
	}

	return 0;
}
