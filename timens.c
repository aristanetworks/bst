/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include "timens.h"

void init_clocks(int fd, const struct timespec *times, size_t nclocks)
{
	FILE *clocks = fdopen(fd, "w");
	if (!clocks) {
		err(1, "init_clocks: fdopen");
	}

	for (clockid_t clock = 0; clock < (clockid_t) nclocks; ++clock) {
		if (times[clock].tv_sec == -1) {
			continue;
		}

		struct timespec tp;
		if (clock_gettime(clock, &tp) == -1) {
			/* EINVAL pretty much indicates that this clock is not supported. */
			if (errno == EINVAL) {
				continue;
			}
			err(1, "init_clocks: clock_gettime(%d)", clock);
		}

		tp.tv_sec  = times[clock].tv_sec - tp.tv_sec - 1;
		tp.tv_nsec = SEC_IN_NS - tp.tv_nsec + times[clock].tv_nsec;
		while (tp.tv_nsec > SEC_IN_NS) {
			tp.tv_sec += 1;
			tp.tv_nsec -= SEC_IN_NS;
		}

		fprintf(clocks, "%d %ld %ld\n", clock, tp.tv_sec, tp.tv_nsec);
		if (fflush(clocks) == -1) {
			/* Same deal as above -- time namespaces do not support this clock for offsetting. */
			if (errno == EINVAL) {
				continue;
			}
			err(1, "init_clocks: write");
		}
	}
}
