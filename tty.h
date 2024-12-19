/* Copyright © 2021 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef TTY_H_
# define TTY_H_

# include <signal.h>
# include <stdbool.h>
# include <termios.h>

struct tty_opts {
	const char *ptmx;
	struct termios termios;
	struct termios neg_termios;
	bool *drain;
};

extern const char *tty_default_ptmx;

void tty_setup_socketpair(int *pParentSock, int *pChildSock);
void tty_parent_setup(struct tty_opts *opts, int epollfd, int socket);
bool tty_parent_select(pid_t pid);
void tty_parent_cleanup(void);
void tty_child(struct tty_opts *opts, int fd);
void tty_opt_parse(struct tty_opts *opts, const char *key, const char *val);

#endif /* !TTY_H */
