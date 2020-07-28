/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <stdarg.h>
#include <stddef.h>

#include "capable.h"

static cap_t original;
static cap_t current;

void init_capabilities(void)
{
	if (current && cap_free(current) == -1) {
		err(1, "cap_free");
	}
	if ((current = cap_get_proc()) == NULL) {
		err(1, "cap_get_proc");
	}
	if (original && cap_free(original) == -1) {
		err(1, "cap_free");
	}
	if ((original = cap_dup(current)) == NULL) {
		err(1, "cap_dup");
	}
}

bool capable(cap_value_t cap)
{
	if (!original) {
		init_capabilities();
	}

	cap_flag_value_t set;
	if (cap_get_flag(current, cap, CAP_EFFECTIVE, &set) == -1) {
		err(1, "cap_get_flag");
	}
	return set;
}

void make_capable(cap_value_t cap)
{
	if (!original) {
		init_capabilities();
	}

	if (cap_set_flag(current, CAP_EFFECTIVE, 1, &cap, CAP_SET) == -1) {
		err(1, "cap_set_flag");
	}

	if (cap_set_proc(current) == -1) {
		err(1, "caps_set_proc");
	}
}

void reset_capabilities(void)
{
	if (cap_set_proc(original) == -1) {
		err(1, "caps_set_proc");
	}
	if (cap_free(current) == -1) {
		err(1, "cap_free");
	}
	if ((current = cap_dup(original)) == NULL) {
		err(1, "cap_dup");
	}
}
