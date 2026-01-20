/* Copyright © 2022 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef PROC_H_
# define PROC_H_

# include <unistd.h>

struct proc_status {
	mode_t umask;
	uid_t ruid;
	uid_t euid;
	uid_t suid;
	uid_t fsuid;
	gid_t rgid;
	gid_t egid;
	gid_t sgid;
	gid_t fsgid;
};

int proc_read_status(int procfd, struct proc_status *out);

#endif /* !PROC_H_ */
