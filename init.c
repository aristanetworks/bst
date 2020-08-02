/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "capable.h"
#include "init.h"

static void read_mm_offsets(struct prctl_mm_map *map)
{
	/* This is ridiculous. I honestly can't think of why I'm writing this, but
	   like a brain parasite, there is something in me that really wants to have
	   pgrep distinguish between the main bst process and the builtin init. */

	FILE *stat = fopen("/proc/self/stat", "r");

	/* See man 5 proc. */

	fscanf(stat,
			"%*d " /* pid */ "%*s " /* comm */ "%*c " /* state */
			"%*d " /* ppid */ "%*d " /* pgrp */ "%*d " /* session */
			"%*d " /* tty_nr */ "%*d " /* tpgid */ "%*u " /* flags */
			"%*u " /* minflt */ "%*u " /* cminflt */ "%*u " /* majflt */
			"%*u " /* cmajflt */ "%*u " /* utime */ "%*d " /* stime */
			"%*d " /* cutime */ "%*d " /* cstime */ "%*d " /* priority */
			"%*d " /* nice */ "%*d " /* num_threads */ "%*u " /* itrealvalue */
			"%*u " /* starttime */ "%*d " /* vsize */ "%*u " /* rss */
			"%*u " /* rsslim */

			"%llu " /* startcode * */
			"%llu " /* endcode * */
			"%llu " /* startstack * */

			"%*u " /* kstkesp */ "%*u " /* kstkeip */ "%*u " /* signal */
			"%*u " /* blocked */ "%*u " /* sigignore */ "%*u " /* sigcatch */
			"%*u " /* wchan */ "%*u " /* nswap */ "%*u " /* cnswap */
			"%*d " /* exit_signal */ "%*d " /* processor */ "%*u " /* rt_priority */
			"%*u " /* policy */ "%*u " /* delayacct_blkio_ticks */ "%*u " /* guest_time */
			"%*u " /* cguest_time */

			"%llu " /* start_data * */
			"%llu " /* end_data * */
			"%llu " /* start_brk * */
			"%llu " /* arg_start * */
			"%llu " /* arg_end * */
			"%llu " /* env_start * */
			"%llu ", /* env_end * */

			&map->start_code,
			&map->end_code,
			&map->start_stack,
			&map->start_data,
			&map->end_data,
			&map->start_brk,
			&map->arg_start,
			&map->arg_end,
			&map->env_start,
			&map->env_end);

	fclose(stat);
}

noreturn void init(pid_t main_child_pid)
{
	char init_progname[] = "bst-init";

	/* Override program name to something more sensible. Unfortunately, we
	   apparently can't use PR_SET_MM_ARG_END in a user namespace, because
	   it's not permissible unless we use PR_SET_MM_MAP. This means we need
	   to jump through some fairly ridiculous hoops... */

	struct prctl_mm_map mm;
	memset(&mm, 0, sizeof (mm));
	read_mm_offsets(&mm);

	mm.brk = (__u64) sbrk(0);

	/* This isn't documented, but this seems to be the magic value to say
	   "please keep /proc/self/exe as-is". */
	mm.exe_fd = -1;

	/* That's right, prctl wants the argv array to exist within the stack area.
	   If it's outside, it inexplicably makes /proc/pid/cmdline always empty. */
	mm.arg_start = (__u64) &init_progname;
	mm.arg_end = (__u64) &init_progname + sizeof (init_progname);

	if (prctl(PR_SET_MM, PR_SET_MM_MAP, &mm, sizeof (mm), 0) == -1) {
		warn("prctl(PR_SET_MM, PR_SET_MM_MAP)");
	}

	if (prctl(PR_SET_NAME, init_progname) == -1) {
		warn("prctl(PR_SET_NAME)");
	}

	for (int sig = 1; sig <= SIGRTMAX; ++sig) {
		signal(sig, SIG_DFL);
	}

	for (;;) {

		int status;
		pid_t pid = wait(&status);

		if (pid == -1) {
			// Should never happen. ECHILD in particular is bogus here, because
			// we explicitly handle it and forward the exit status.
			err(1, "wait");
		}
		if (pid == main_child_pid) {
			// the main child died -- rather that trying to collect the rest,
			// just abort init, and the kernel will sweep the rest.

			int exitcode;
			if (WIFEXITED(status)) {
				exitcode = WEXITSTATUS(status);
			} else {
				exitcode = WTERMSIG(status) | 1 << 7;
			}
			_exit(exitcode);
		}
	}
}
