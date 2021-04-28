/* Copyright © 2021 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef TTY_H_
# define TTY_H_

# include <signal.h>
# include <stdbool.h>

void tty_setup_socketpair(int *pParentSock, int *pChildSock);
void tty_parent_setup(int fd);
bool tty_parent_select(pid_t pid, int *pwaitflags);
void tty_child(int fd);

#endif /* !TTY_H */
