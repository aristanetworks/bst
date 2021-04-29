/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/personality.h>
#include "setarch.h"

enum {
	MACHINE_SIZE = sizeof (((struct utsname *) NULL)->machine),
};

struct exec_domain {
	char name[MACHINE_SIZE];
	unsigned long persona;
};

void setarch(const char *arch)
{
	static struct exec_domain domains[] = {
		{ "", 0 },                      /* Placeholder for host execution domain */
		{ "linux32", PER_LINUX32 },
		{ "linux64", PER_LINUX },
		{ "x86_64",  PER_LINUX },
		{ "i386",    PER_LINUX32 },
		{ "i486",    PER_LINUX32 },
		{ "i586",    PER_LINUX32 },
		{ "i686",    PER_LINUX32 },
		{ "", 0 }                       /* Entry to mark end of the list */
	};

	struct exec_domain *host_domain = &domains[0];

	struct utsname ubuf;
	if (uname(&ubuf) == -1) {
		err(1, "setarch: uname");
	}

	memcpy(host_domain->name, ubuf.machine, MACHINE_SIZE);
#ifdef __LP64__
	host_domain->persona = PER_LINUX;
#else
	host_domain->persona = PER_LINUX32;
#endif

	struct exec_domain *domain = domains;
	for (; *domain->name != '\0'; ++domain) {
		if (strncmp(domain->name, arch, MACHINE_SIZE) == 0) {
			break;
		}
	}

	if (*domain->name == '\0') {
		errx(1, "setarch: unknown arch %s.", arch);
	}

	if (personality(domain->persona) == -1) {
		err(1, "setarch: personality");
	}
}
