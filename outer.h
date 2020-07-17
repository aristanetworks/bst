/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef OUTER_H
# define OUTER_H

# include <unistd.h>

struct outer_helper {
	int unshareflags;
	const char *persist;

	pid_t pid;
	int in;
	int out;
};

void outer_helper_spawn(struct outer_helper *helper);
void outer_helper_sendpid_and_wait(const struct outer_helper *helper, pid_t pid);
void outer_helper_sync(const struct outer_helper *helper);
void outer_helper_close(struct outer_helper *helper);

#endif /* !OUTER_H */
