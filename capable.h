/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef CAPABLE_H_
# define CAPABLE_H_

# include <stdbool.h>
# include <stdint.h>
# include <linux/capability.h>

/* Define more useful capability constants */
# define BST_CAP_SYS_ADMIN      ((uint64_t) 1 << CAP_SYS_ADMIN)
# define BST_CAP_SYS_PTRACE     ((uint64_t) 1 << CAP_SYS_PTRACE)
# define BST_CAP_DAC_OVERRIDE   ((uint64_t) 1 << CAP_DAC_OVERRIDE)
# define BST_CAP_SYS_RESOURCE   ((uint64_t) 1 << CAP_SYS_RESOURCE)
# define BST_CAP_NET_ADMIN      ((uint64_t) 1 << CAP_NET_ADMIN)
# define BST_CAP_SETUID         ((uint64_t) 1 << CAP_SETUID)
# define BST_CAP_SETGID         ((uint64_t) 1 << CAP_SETGID)
# define BST_CAP_SYS_CHROOT     ((uint64_t) 1 << CAP_SYS_CHROOT)
# define BST_CAP_MKNOD          ((uint64_t) 1 << CAP_MKNOD)

extern int deny_new_capabilities;

void init_capabilities(void);
bool capable(uint64_t cap);
void make_capable(uint64_t cap);
void reset_capabilities(void);
void drop_capabilities(void);

#endif /* !CAPABLE_H_ */
