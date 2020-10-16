/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef UTIL_H_
# define UTIL_H_

# define lengthof(Arr) (sizeof (Arr) / sizeof (*Arr))

# ifndef ARG_MAX
/* ARG_MAX is typically a runtime constant that one can retrieve via sysconf,
   but we don't want to be using VLAs in sensitive code. */
#  define ARG_MAX 4096
# endif

#endif /* !UTIL_H_ */
