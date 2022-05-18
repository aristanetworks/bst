/* Copyright © 2022 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef PROC_H_
# define PROC_H_

struct proc_status {
	mode_t umask;
};

int proc_read_status(int procfd, struct proc_status *out);

#endif /* !PROC_H_ */
