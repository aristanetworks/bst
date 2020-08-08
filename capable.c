/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>

#include "capable.h"

static struct __user_cap_data_struct original[2];
static struct __user_cap_data_struct current[2];

static struct __user_cap_header_struct hdr = {
	.version = _LINUX_CAPABILITY_VERSION_3,
};

int deny_new_capabilities = 0;

/* Normally, using cap(get|set) isn't really advisable, as it's a linux-specific
   interface. But the matter of fact is that bst is already linux-specific, that
   libcap adds a lot of unneeded complexity, and that it operates on dynamic
   memory. What's the point of flagellating ourselves? */

static int bst_capset(cap_user_header_t header, const cap_user_data_t data)
{
	return (int) syscall(SYS_capset, header, data);
}

static int bst_capget(cap_user_header_t header, cap_user_data_t data)
{
	return (int) syscall(SYS_capget, header, data);
}

void init_capabilities(void)
{
	if (bst_capget(&hdr, current) == -1) {
		err(1, "capget");
	}
	memcpy(original, current, sizeof (original));
}

bool capable(uint64_t cap)
{
	uint64_t caps = (uint64_t) current[1].effective << 32 | current[0].effective;
	return caps & (1 << cap);
}

void make_capable(uint64_t cap)
{
	if (deny_new_capabilities) {
		errx(1, "called make_capable in no-new-capabilities code");
	}
	current[0].effective |= (__u32) (cap & (__u32) -1);
	current[1].effective |= (__u32) (cap >> 32);
	if (bst_capset(&hdr, current) == -1) {
		err(1, "capset");
	}
}

void reset_capabilities(void)
{
	if (bst_capset(&hdr, original) == -1) {
		err(1, "capset");
	}
	memcpy(current, original, sizeof (current));
}
