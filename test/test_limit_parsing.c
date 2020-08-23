#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>

#include "../bst_limits.h"

static int const USE_CURRENT = -1;

#pragma GCC diagnostic ignored "-Wsign-conversion"
#define NUM_EQ(_x_arg, _y_arg) do {					\
	intmax_t _x = (_x_arg);						\
	intmax_t _y = (_y_arg);						\
	if (_x != _y) {							\
		printf("\tFAIL\t %ju (\"" #_x_arg "\") != "		\
		       " %ju (\"" #_y_arg "\")\n", _x, _y);		\
	}								\
	assert(_x == _y); 						\
} while(0);

static void run_test(intmax_t hard, intmax_t soft, int expect_errno, char const *arg)
{
	char buf[100];

	assert(snprintf(buf, sizeof (buf), "\"%s\"", arg) <= (ssize_t)(sizeof (buf)));
	printf("test case: %-10s", buf);
	fflush(stdout);

	struct rlimit limit_value;
	assert(snprintf(buf, sizeof (buf), "%s", arg) <= (ssize_t)(sizeof (buf)));
	int rc = parse_rlimit(RLIMIT_NOFILE, &limit_value, buf);
	if (expect_errno != 0) {
		NUM_EQ(expect_errno, errno);
		assert(rc);
	} else {
		NUM_EQ(0, rc);
		struct rlimit current;
		if (getrlimit(RLIMIT_NOFILE, &current)) {
			err(1, "getrlimit");
		}
		if (hard == USE_CURRENT) {
			NUM_EQ(limit_value.rlim_max, current.rlim_max);
		} else {
			NUM_EQ(limit_value.rlim_max, (rlim_t)hard);
		}
		if (soft == USE_CURRENT) {
			NUM_EQ(limit_value.rlim_cur, current.rlim_cur);
		} else {
			NUM_EQ(limit_value.rlim_cur, (rlim_t)soft);
		}
	}
	printf("\tPASS\n");
}

int main(int argc, char **argv)
{
	struct rlimit current;
	if (getrlimit(RLIMIT_NOFILE, &current)) {
		err(1, "getrlimit");
	}

	struct {
		intmax_t hard;
		intmax_t soft;
		int expect_errno;
		char const *arg;
	} test_cases[] =
	{
	 /* normal cases */
	 { .arg = "100:100", .hard = 100, .soft = 100 },
	 { .arg = ":100", .hard = USE_CURRENT, .soft = 100 },
	 { .arg = "100:", .hard = 100, .soft = USE_CURRENT },
	 { .arg = "100", .hard = 100, .soft = 100 },
	 { .arg = ":", .hard = USE_CURRENT, .soft = current.rlim_max },
	 { .arg = "0:100", .hard = 0, .soft = 100 },
	 { .arg = "100:0", .hard = 100, .soft = 0 },
	 { .arg = "0", .hard = 0, .soft = 0 },
	 /* error cases */
	 { .arg = "", .expect_errno = EINVAL },
	 { .arg = "-1:100", .expect_errno = EINVAL },
	 { .arg = "100:-1", .expect_errno = EINVAL },
	 { .arg = "-1", .expect_errno = EINVAL },
	 { .arg = "a:b", .expect_errno = EINVAL },
	 { .arg = "a", .expect_errno = EINVAL },
	 { .arg = "1.1:2", .expect_errno = EINVAL },
	 { .arg = ":1.1", .expect_errno = EINVAL },
	};
	for (size_t i = 0; i < sizeof (test_cases) / sizeof (*test_cases); ++i) {
		run_test(test_cases[i].hard,
			 test_cases[i].soft,
			 test_cases[i].expect_errno,
			 test_cases[i].arg);
	}
	return 0;
}
