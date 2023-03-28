/* Copyright © 2021 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef COMPAT_H_
# define COMPAT_H_

# include <stddef.h>

/* From the kernel headers */
# define BST_CLOSE_RANGE_UNSHARE (1U << 1)

size_t strlcpy(char *restrict dst, const char *restrict src, size_t size);
unsigned int parse_fd(char *optarg);
int bst_close_range(unsigned int from, unsigned int to, unsigned int flags);

#endif /* !COMPAT_H_ */
