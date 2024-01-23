/* Copyright © 2021 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef ERRUTIL_H_
# define ERRUTIL_H_

enum {
	ERR_USE_SYSLOG = 1,
};

extern void (*err_exit)(int);
extern const char *err_line_ending;
extern int err_flags;

#endif /* !ERRUTIL_H */
