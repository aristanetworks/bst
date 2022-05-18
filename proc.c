/* Copyright © 2022 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include "proc.h"

int proc_read_status(int procfd, struct proc_status *out)
{
	memset(out, 0, sizeof (*out));

	int statusfd = openat(procfd, "status", O_RDONLY | O_CLOEXEC);
	if (statusfd == -1) {
		return -1;
	}

	FILE *f = fdopen(statusfd, "r");

	char line[4096];
	while (fgets(line, sizeof (line) - 1, f)) {
		sscanf(line, "Umask:\t%o\n", &out->umask);
	}

	fclose(f);
	return 0;
}
