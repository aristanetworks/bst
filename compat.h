/* Copyright © 2021 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef COMPAT_H_
# define COMPAT_H_

# include <stddef.h>

size_t strlcpy(char *restrict dst, const char *restrict src, size_t size);

#endif /* !COMPAT_H_ */
