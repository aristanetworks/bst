/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef BST_LIMITS_H_
# define BST_LIMITS_H_

/* We apparently cannot trust the resource.h on the current system, because
   the values actually supported by the running kernel might be different. 
   Instead of guessing, use fixed values. */
enum {
	BST_RLIMIT_CPU,
	BST_RLIMIT_FSIZE,
	BST_RLIMIT_DATA,
	BST_RLIMIT_STACK,
	BST_RLIMIT_CORE,
	BST_RLIMIT_RSS,
	BST_RLIMIT_NPROC,
	BST_RLIMIT_NOFILE,
	BST_RLIMIT_MEMLOCK,
	BST_RLIMIT_AS,
	BST_RLIMIT_LOCKS,
	BST_RLIMIT_SIGPENDING,
	BST_RLIMIT_MSGQUEUE,
	BST_RLIMIT_NICE,
	BST_RLIMIT_RTPRIO,
	BST_RLIMIT_RTTIME,

	BST_NLIMIT
};

# define BST_RLIM_INFINITY (~0UL)

int parse_rlimit(int resource, struct rlimit *limit, char *arg);

#endif /* !BST_LIMITS_H_ */
