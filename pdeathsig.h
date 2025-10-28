/* Copyright © 2025 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef PDEATHSIG_H_
# define PDEATHSIG_H_

#include <stdbool.h>

struct sig_pdeathsig_cookie {
	int pid;
	int rfd;
	int wfd;
};

/* sig_pdeathsig_cookie initializes the pdeathsig cookie with the current
   process. */
void sig_pdeathsig_cookie_init(struct sig_pdeathsig_cookie *cookie);

/* sig_pdeathsig_cookie_close releases any resource associated with the
   pdeathsig cookie for the parent process. */
void sig_pdeathsig_cookie_close_parent(struct sig_pdeathsig_cookie *cookie);

/* sig_pdeathsig_cookie_close releases any resource associated with the
   pdeathsig cookie in the child process. */
void sig_pdeathsig_cookie_close_child(struct sig_pdeathsig_cookie *cookie);

/* sig_pdeathsig_cookie checks whether the parent process represented by the
   cookie is alive. The function is undefined if the cookie was not initialized
   in the parent of the current process. */
int sig_pdeathsig_cookie_check(struct sig_pdeathsig_cookie *cookie);

/* sig_setpdeathsig sets the parent death signal of the current process to
   signo. If the parent process of the passed pdeathsig cookie is already dead
   when the function is called, it raises the signal immediately. */
void sig_setpdeathsig(int signo, struct sig_pdeathsig_cookie *cookie);

#endif /* !PDEATHSIG_H_ */
