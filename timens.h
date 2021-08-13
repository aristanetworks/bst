/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef TIME_H_
# define TIME_H_

# include <stddef.h>
# include <time.h>

enum {
	MAX_CLOCK = CLOCK_TAI + 1,

	SEC_IN_NS = 1000000000,
};

typedef long clockspecs[MAX_CLOCK];

void init_clocks(int fd, const struct timespec *times, size_t nclocks);

#endif /* !TIME_H_ */
