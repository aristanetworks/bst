/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef SIG_H_
# define SIG_H_

# include <signal.h>

void sig_wait(const sigset_t *set, siginfo_t *info);
void sig_reap_and_forward(const siginfo_t *info, pid_t pid);

#endif /* !SIG_H_ */
