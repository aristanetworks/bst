/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/resource.h>

#include "bst_limits.h"

/* parse_complete_rlim_t: parses an rlim_t value from `value_str`.  Return 0 on
   success, 1 otherwise. */
static int parse_complete_rlim_t(int resource, rlim_t *value, char const *value_str)
{
	assert(value_str);

	/* an empty string means to use the current value  */
	if (*value_str == '\0') {
		return 0;
	}

	char *endptr;
	intmax_t parse_val = strtoimax(value_str, &endptr, 0);
	if (parse_val == INTMAX_MIN || parse_val == INTMAX_MAX) {
		return 1;
	}

	if (parse_val < 0) {
		errno = EINVAL;
		return 1;
	}

	/* This indicates a parsing error - since value_string is non-empty, the end
	   of the value is not the end of the string, so the value is not entirely
	   numeric. */
	if (*endptr != '\0') {
		errno = EINVAL;
		return 1;
	}

	/* Before casting to rlim_t, check against the max possible rlim_t
	   value so that the (rlim_t) cast is guaranteed correct. */
	if ((uintmax_t)parse_val >= BST_RLIM_INFINITY) {
		errno = EOVERFLOW;
		return 1;
	}

	*value = (rlim_t)(parse_val);
	return 0;
}

/* parse_rlimit: parses a tuple using a ':' separator charcter as (rlim_max,
   [rlim_cur]).  If the optional rlim_cur is not specified, use the rlim_max
   value.  Return 0 on success, 1 otherwise.  

   Example:
   100 => (100, 100)
   100:30 => (100, 30)
   :30 => ("preserve current hard limit", 30)
   100: => (100, "preserve current soft limit")
   : => ("preserve current hard limit", "use current hard limit as soft limit")

   limit and arg must be non-NULL. */
int parse_rlimit(int resource, struct rlimit *limit, char *arg)
{
	assert(limit);
	assert(arg);

	if (arg[0] == '\0') {
		errno = EINVAL;
		return 1;
	}
	
	char const *hard_limit = arg;
	char *p;
	bool found_sep = false;
	for (p = arg; *p != '\0'; ++p) {
		if (*p == ':') {
			*p = '\0';
			found_sep = true;
			++p;
			break;
		}
	}
	/* Special case: no ":" separator, so set hard and soft to <value> */
	char const *soft_limit = found_sep ? p : hard_limit;

	if (getrlimit(resource, limit) == -1) {
		err(1, "getrlimit(%d) failed", resource);
	}

	if (!soft_limit[0] && !hard_limit[0]) {
		/* special case: preserve hard limit, use that value as new soft
		   limit value */
		limit->rlim_cur = limit->rlim_max;
		return 0;
	}

	if (parse_complete_rlim_t(resource, &limit->rlim_max, hard_limit)) {
		/* pass errno through to caller */
		return 1;
	}

	if (parse_complete_rlim_t(resource, &limit->rlim_cur, soft_limit)) {
		/* pass errno through to caller */
		return 1;
	}

	return 0;
}
