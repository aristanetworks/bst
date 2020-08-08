/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef MOUNT_H
# define MOUNT_H

# include <stddef.h>

struct mount_entry {
	char *source;
	char *target;
	char *type;
	char *options;
};

void mount_entries(const char *root, const struct mount_entry *mounts, size_t nmounts, int no_derandomize);
void mount_mutables(const char *root, const char *const *mutables, size_t nmutables);

#endif /* !MOUNT_H */
