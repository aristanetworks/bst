/* Copyright © 2021 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include "compat.h"

size_t strlcpy(char *restrict dst, const char *restrict src, size_t size)
{
	size_t i = 0;
	for (; i < size - 1 && src[i] != '\0'; ++i) {
		dst[i] = src[i];
	}
	dst[i] = '\0';
	return i;
}
