/* Copyright (c) 2020 Arista Networks, Inc.  All rights reserved.
   Arista Networks, Inc. Confidential and Proprietary. */

#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>

#include "userns.h"

/* userns_helper_spawn invokes the privileged b5-enter--userns-helper executable
   whose only purpose is to modify the uid and gid mappings of our target
   process (TP).

   The userns helper thus runs as a sibling of the TP, and provides some basic
   synchronization routines to make sure the TP waits for its sibling to complete
   before calling setgroups/setgid/setuid.

   The reason why this helper is necessary is because once we enter the user
   namespace, we drop CAP_SET[UG]ID on the host namespace, which means we
   can't map arbitrary sub[ug]id ranges. We could setuid b5-enter itself and
   do these mappings from a regular fork(), but this means that we can no
   longer do the right thing w.r.t unprivileged user namespaces, not to mention
   that I'm not happy with having a rootkit that everyone can use on my own
   machine.

   The canonical way to do all of this on a modern Linux distribution is to
   call the newuidmap and newgidmap utilities, which are generic interfaces
   that do exactly what b5-enter--userns-helper does, which is writing to
   /proc/pid/[ug]id_map any id ranges that a user is allowed to map by looking
   allocated IDs for that user in /etc/sub[ug]id. We obviously don't want
   to rely on any external program that may or may not be installed on the
   host system, so we reimplement that functionality here. */
struct userns_helper userns_helper_spawn(void)
{
	int pipefds_in[2];
	if (pipe(pipefds_in) == -1) {
		err(1, "userns_helper: pipe");
	}

	int pipefds_out[2];
	if (pipe(pipefds_out) == -1) {
		err(1, "userns_helper: pipe");
	}

	pid_t pid = fork();
	if (pid == -1) {
		err(1, "userns_helper: fork");
	}

	if (pid) {
		close(pipefds_in[1]);
		close(pipefds_out[0]);
		return (struct userns_helper) {
			.pid = pid,
			.in = pipefds_in[0],
			.out = pipefds_out[1],
		};
	}

	close(pipefds_in[0]);
	close(pipefds_out[1]);

	pid_t child_pid;
	ssize_t rdbytes = read(pipefds_out[0], &child_pid, sizeof (child_pid));
	if (rdbytes == -1) {
		err(1, "userns_helper: read child pid");
	}

	/* This typically happens when the parent dies, e.g. Ctrl-C. Not worth
	   warning against. */
	if (rdbytes != sizeof (child_pid)) {
		_exit(1);
	}

	/* Forking twice isn't that great, but we need to notify the sibling after
	   the helper terminates. */
	pid_t helper_pid = fork();
	if (helper_pid == -1) {
		err(1, "userns_helper: fork");
	}

	if (!helper_pid) {
		char child_pid_str[16];
		if ((size_t) snprintf(child_pid_str, sizeof (child_pid_str), "%d", child_pid) >= sizeof (child_pid_str)) {
			err(1, "userns_helper: snprintf: not enough space to store \"%d\" in %zu bytes.",
					child_pid, sizeof (child_pid_str));
		}

		execlp("b5-enter--userns-helper", "b5-enter--userns-helper", child_pid_str, NULL);
		err(1, "userns_helper: execlp");
	}

	if (TEMP_FAILURE_RETRY(waitpid(helper_pid, NULL, 0)) == -1) {
		err(1, "userns_helper: waitpid");
	}

	/* Notify sibling that we're done changing their [ug]id map */
	int ok = 1;
	write(pipefds_in[1], &ok, sizeof (ok));

	_exit(0);
}

void userns_helper_sendpid(const struct userns_helper *helper, pid_t pid)
{
	/* Unblock the privileged helper to set our own [ug]id maps */
	if (write(helper->out, &pid, sizeof (pid)) == -1) {
		err(1, "userns_helper_sendpid: write");
	}

	int status;
	if (TEMP_FAILURE_RETRY(waitpid(helper->pid, &status, 0)) == -1) {
		err(1, "userns_helper_sendpid: waitpid");
	}

	if (WIFSIGNALED(status)) {
		errx(1, "userns_helper_sendpid: process died with signal %d.", WTERMSIG(status));
	}

	if (WIFEXITED(status) && WEXITSTATUS(status)) {
		errx(1, "userns_helper_sendpid: process exited with nonzero exit status %d.", WEXITSTATUS(status));
	}
}

void userns_helper_wait(const struct userns_helper *helper)
{
	int ok;
	if (read(helper->in, &ok, sizeof (ok)) == -1) {
		err(1, "userns_helper_wait: read");
	}
}

void userns_helper_close(struct userns_helper *helper)
{
	close(helper->in);
	close(helper->out);
}
