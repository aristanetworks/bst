/* Copyright (c) 2020 Arista Networks, Inc.  All rights reserved.
   Arista Networks, Inc. Confidential and Proprietary. */

#ifndef MOUNT_H
# define MOUNT_H

struct mount_entry {
	char *source;
	char *target;
	char *type;
	char *options;
};

void mount_entries(const char *root, const struct mount_entry *mounts, size_t nmounts);
void mount_mutables(const char *root, const char *const *mutables, size_t nmutables);

#endif /* !MOUNT_H */
