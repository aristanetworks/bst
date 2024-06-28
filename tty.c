/* Copyright © 2021 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>

#include "errutil.h"
#include "fd.h"
#include "sig.h"
#include "tty.h"
#include "util.h"

struct buffer {
	char buf[BUFSIZ];
	size_t index;
	size_t size;
};

static struct tty_parent_info_s {
	int termfd;
	struct termios orig;
	bool stdinIsatty;
} info = {
	.termfd = -1,
};

static ssize_t io_copy(int out_fd, int in_fd, struct buffer *buf)
{
	_Static_assert(sizeof (buf->buf) == BUFSIZ,
			"buf->buf must be of size BUFSIZ, check that sizeof (buf->buf) is still correct.");

	ssize_t copied = 0;
	ssize_t rd = sizeof (buf->buf);

	for (;;) {

		/* Write any leftover data from a previous read. This handles the case
		   where we cannot write all of the data we read from in_fd into
		   out_fd without having out_fd block.

		   This also serves as the main write syscall of the loop; the read
		   happens at the end, and simply loops back here when new data
		   is available in the buffer. */

		while (buf->size > 0) {
			ssize_t written = write(out_fd, buf->buf + buf->index, buf->size);
			if (written == -1) {
				switch (errno) {
				case EINTR:
					continue;
				case EAGAIN:
					if (copied != 0) {
						return copied;
					}
					break;
				}
				return -1;
			}
			buf->size -= written;
			buf->index += written;
			copied += written;
		}

		if ((size_t) rd < sizeof (buf->buf)) {
			return copied;
		}

		rd = read(in_fd, buf->buf, sizeof (buf->buf));
		if (rd == -1) {
			switch (errno) {
			case EAGAIN:
				if (copied != 0) {
					return copied;
				}
				break;
			case EINTR:
				continue;
			}
			return -1;
		}
		buf->size = (size_t) rd;
		buf->index = 0;
	}
}

static void set_nonblock(int fd, int nonblock)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		err(1, "fcntl %d F_GETFL", fd);
	}
	if (nonblock) {
		flags |= O_NONBLOCK;
	} else {
		flags &= ~O_NONBLOCK;
	}
	if (fcntl(fd, F_SETFL, flags) == -1) {
		err(1, "fcntl %d F_SETFL O_NONBLOCK", fd);
	}
}

static int send_veof(int ptm)
{
	struct termios tios;
	if (tcgetattr(info.termfd, &tios) == -1) {
		err(1, "send_veof: tcgetattr");
	}

	/* The terminal is is noncanonical mode; VEOF won't be interpreted. */
	if (!(tios.c_lflag & ICANON)) {
		errno = ENOTSUP;
		return -1;
	}

	return write(ptm, &tios.c_cc[VEOF], 1);
}

void tty_parent_cleanup(void)
{
	if (info.termfd >= 0) {
		/* Drain any remaining data in the terminal buffer */
		set_nonblock(STDOUT_FILENO, 0);
		set_nonblock(info.termfd, 0);
		struct buffer drain = {
			.size = 0,
		};

		if (io_copy(STDOUT_FILENO, info.termfd, &drain) == -1 && errno != EIO) {
			warn("copy tty -> stdout");
		}

		close(info.termfd);
		info.termfd = -1;
	}
	if (info.stdinIsatty) {
		tcsetattr(STDIN_FILENO, TCSADRAIN, &info.orig);
		info.stdinIsatty = false;
	}
}

void tty_set_winsize(void)
{
	struct winsize wsize;
	if (info.stdinIsatty) {
		if (ioctl(STDIN_FILENO, TIOCGWINSZ, (char*) &wsize) < 0) {
			err(1, "reading window size");
		}
		if (ioctl(info.termfd, TIOCSWINSZ, (char*) &wsize) < 0) {
			err(1, "writing window size");
		}
	}
}

static int tty_handle_sig(int epollfd, const struct epoll_event *ev, int fd, pid_t pid)
{
	siginfo_t siginfo;
	sig_read(fd, &siginfo);

	assert(siginfo.si_signo == SIGWINCH && "tty_handle_sig can only handle SIGWINCH");
	tty_set_winsize();
	return EPOLL_HANDLER_CONTINUE;
}

static struct epoll_handler inbound_handler, outbound_handler, term_handler;

static struct buffer inbound_buffer, outbound_buffer;

static int tty_handle_io(int epollfd, const struct epoll_event *ev, int fd, pid_t pid)
{
	/* The terminal got closed -- don't try to handle I/O any further */
	if (info.termfd == -1) {
		return EPOLL_HANDLER_CONTINUE;
	}

	struct epoll_handler *handler = ev->data.ptr;

	if (fd == inbound_handler.fd) {
		if (ev->events & EPOLLIN) {
			handler->ready |= READ_READY;
		}
		if (ev->events & EPOLLHUP) {
			handler->ready |= HANGUP;
		}
	} else if (fd == outbound_handler.fd) {
		if (ev->events & EPOLLOUT) {
			handler->ready |= WRITE_READY;
		}
	} else {
		struct epoll_event newev = *ev;
		newev.events = EPOLLIN | EPOLLOUT | EPOLLONESHOT;

		if (ev->events & EPOLLOUT || inbound_handler.ready & WRITE_READY) {
			inbound_handler.ready |= WRITE_READY;
			newev.events &= ~EPOLLOUT;
		}
		if (ev->events & EPOLLIN || outbound_handler.ready & READ_READY) {
			outbound_handler.ready |= READ_READY;
			newev.events &= ~EPOLLIN;
		}
		if (!(ev->events & EPOLLHUP) && newev.events != EPOLLONESHOT) {
			if (epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &newev) == -1) {
				err(1, "epoll_ctl_mod termfd");
			}
		}
	}

	if ((inbound_handler.ready & (READ_READY | WRITE_READY)) == (READ_READY | WRITE_READY)) {
		/* inbound_handler.fd might contain our eventfd workaround */
		int read_fd = STDIN_FILENO;
		int write_fd = inbound_handler.peer_fd;

		ssize_t copied = io_copy(write_fd, read_fd, &inbound_buffer);
		if (copied == -1) {
			err(1, "copy stdin -> tty");
		}

		inbound_handler.ready &= ~(READ_READY|WRITE_READY);

		struct epoll_event newev = {
			.events = EPOLLIN | EPOLLONESHOT,
			.data.ptr = &inbound_handler,
		};
		if (epoll_ctl(epollfd, EPOLL_CTL_MOD, inbound_handler.fd, &newev) == -1) {
			err(1, "epoll_ctl_mod stdin");
		}
	} else if ((inbound_handler.ready & (WRITE_READY | HANGUP)) == (WRITE_READY | HANGUP)) {
		inbound_handler.ready &= ~HANGUP;

		if (send_veof(inbound_handler.peer_fd) == -1) {
			if (errno == ENOTSUP) {
				goto hangup;
			}
			err(1, "send_eof: write");
		}

		/* Send VEOF twice. This is necessary, because if there is pending input
		   on the tty, a VEOF will cause the input to be dropped rather than
		   signaling EOF. A second VEOF is then required to properly indicate
		   EOF. */
		if (send_veof(inbound_handler.peer_fd) == -1) {
			switch (errno) {
			case ENOTSUP:
				goto hangup;
			case EAGAIN:
				/* The pty device isn't ready for a second VEOF -- that's fine,
				   we'll just send it later, so re-set the hangup flag */
				inbound_handler.ready |= HANGUP;
				break;
			default:
				err(1, "send_eof: write");
			}
		}
	}

	if (outbound_handler.ready == (READ_READY | WRITE_READY)) {
		int read_fd = outbound_handler.peer_fd;
		/* outbound_handler.fd might contain our eventfd workaround */
		int write_fd = STDOUT_FILENO;

		if (io_copy(write_fd, read_fd, &outbound_buffer) == -1) {
			err(1, "copy tty -> stdout");
		}

		outbound_handler.ready = 0;

		struct epoll_event newev = {
			.events = EPOLLOUT | EPOLLONESHOT,
			.data.ptr = &outbound_handler,
		};
		if (epoll_ctl(epollfd, EPOLL_CTL_MOD, outbound_handler.fd, &newev) == -1) {
			err(1, "epoll_ctl_mod stdout");
		}
	}

	struct epoll_event termev = {
		.events = EPOLLIN | EPOLLOUT | EPOLLONESHOT,
		.data.ptr = &term_handler,
	};

	if (inbound_handler.ready & WRITE_READY) {
		termev.events &= ~EPOLLOUT;
	}
	if (outbound_handler.ready & READ_READY) {
		termev.events &= ~EPOLLIN;
	}
	if (termev.events != EPOLLONESHOT) {
		if (epoll_ctl(epollfd, EPOLL_CTL_MOD, info.termfd, &termev) == -1) {
			err(1, "epoll_ctl_mod termfd");
		}
	}

	return EPOLL_HANDLER_CONTINUE;

hangup:
	close(info.termfd);
	info.termfd = -1;
	return EPOLL_HANDLER_CONTINUE;
}

void tty_parent_setup(struct tty_opts *opts, int epollfd, int socket)
{
	set_nonblock(STDIN_FILENO, 1);
	set_nonblock(STDOUT_FILENO, 1);

	struct termios tios;

	info.stdinIsatty = tcgetattr(STDIN_FILENO, &tios) == 0;
	if (!info.stdinIsatty && errno != ENOTTY) {
		err(1, "tty_parent: tcgetattr");
	}

	if (info.stdinIsatty) {
		info.orig = tios;
		cfmakeraw(&tios);
		if (tcsetattr(STDIN_FILENO, TCSANOW, &tios) == -1) {
			err(1, "tty_parent: tcsetattr");
		}

		/* We changed the terminal to raw mode. Line-endings now need carriage
		   returns in order to be palatable. */
		err_line_ending = "\r\n";
	}
	atexit(tty_parent_cleanup);

	// Wait for the child to create the pty pair and pass the master back.
	info.termfd = recv_fd(socket);

	if (!info.stdinIsatty) {
		if (tcgetattr(info.termfd, &tios) == -1) {
			err(1, "tty_parent: tcgetattr");
		}
	} else {
		tios = info.orig;
	}
	tios.c_cflag |= opts->termios.c_cflag;
	tios.c_cflag &= ~opts->neg_termios.c_cflag;
	tios.c_lflag |= opts->termios.c_lflag;
	tios.c_lflag &= ~opts->neg_termios.c_lflag;
	tios.c_iflag |= opts->termios.c_iflag;
	tios.c_iflag &= ~opts->neg_termios.c_iflag;
	tios.c_oflag |= opts->termios.c_oflag;
	tios.c_oflag &= ~opts->neg_termios.c_oflag;
	for (size_t i = 0; i < NCCS; ++i) {
		if (opts->neg_termios.c_cc[i]) {
			tios.c_cc[i] = opts->termios.c_cc[i];
		}
	}

	if (tcsetattr(info.termfd, TCSAFLUSH, &tios) == -1) {
		err(1, "tty_parent: tcsetattr");
	}

	sigset_t sigmask;
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGWINCH);

	int sigfd = signalfd(-1, &sigmask, 0);
	if (sigfd == -1) {
		err(1, "tty_parent: signalfd");
	}

	static struct epoll_handler sighandler;
	sighandler.fn = tty_handle_sig;
	sighandler.fd = sigfd;

	struct epoll_event event = {
		.events = EPOLLIN,
		.data.ptr = &sighandler,
	};

	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sigfd, &event) == -1) {
		err(1, "epoll_ctl_add signalfd");
	}

	inbound_handler = (struct epoll_handler) {
		.fn = tty_handle_io,
		.fd = STDIN_FILENO,
		.peer_fd = info.termfd,
	};

	outbound_handler = (struct epoll_handler) {
		.fn = tty_handle_io,
		.fd = STDOUT_FILENO,
		.peer_fd = info.termfd,
	};

	term_handler = (struct epoll_handler) {
		.fn = tty_handle_io,
		.fd = info.termfd,
		.peer_fd = -1,
	};

	event.events = EPOLLOUT | EPOLLIN | EPOLLONESHOT;
	event.data.ptr = &term_handler;

	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, info.termfd, &event) == -1) {
		err(1, "epoll_ctl_add termfd");
	}

	event.events = EPOLLIN | EPOLLONESHOT;
	event.data.ptr = &inbound_handler;

	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, STDIN_FILENO, &event) == -1) {
		if (errno != EPERM && errno != EBADF) {
			err(1, "epoll_ctl_add stdin");
		}
		/* EPERM means the file descriptor does not support epoll. This can
		   happen if our caller closed stdin on us, which causes the libc to
		   open /dev/full O_WRONLY in its stead.

		   EBADF usually does not happen for the reason above, but I can
		   imagine that not all libcs might open /dev/full for us.

		   Devices and regular files never block and are always read-ready
		   (well, rather, it's not possible to know whether an IO operation
		   will wait on disk, and select() already reports regular files
		   as being always read-ready). Emulate that behaviour with an eventfd. */

		int fd = eventfd(1, EFD_CLOEXEC);
		if (fd == -1) {
			err(1, "eventfd");
		}

		inbound_handler.fd = fd;
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event) == -1) {
			err(1, "epoll_ctl_add stdout eventfd fallback");
		}
	}

	event.events = EPOLLOUT | EPOLLONESHOT;
	event.data.ptr = &outbound_handler;

	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, STDOUT_FILENO, &event) == -1) {
		if (errno != EPERM && errno != EBADF) {
			err(1, "epoll_ctl_add stdout");
		}
		/* We ignore EPERM for the same reasons as for stdin. The libc opens
		   /dev/null if our caller closed stdout.

		   EBADF has the same treatment as stdin, too.

		   Devices and regular files never block, and are always write-ready.
		   Emulate that behaviour with an eventfd. */

		int fd = eventfd(1, EFD_CLOEXEC);
		if (fd == -1) {
			err(1, "eventfd");
		}

		outbound_handler.fd = fd;
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event) == -1) {
			err(1, "epoll_ctl_add stdout eventfd fallback");
		}
	}

	if (info.stdinIsatty) {
		tty_set_winsize();
	}
}

const char *tty_default_ptmx = "/dev/pts/ptmx";

void tty_child(struct tty_opts *opts, int socket)
{
	int mfd = open(opts->ptmx, O_RDWR | O_NONBLOCK);
	if (mfd < 0) {
		if (errno == EACCES && opts->ptmx == tty_default_ptmx) {
			/* Special case: some distros configure /dev/pts/ptmx to be mode
			   0000 as a way to force the use of /dev/ptmx. Fallback to that
			   so that it works as expected when not changing roots.
			
			   The direct comparison against tty_default_ptmx is right -- we want
			   to fallback when /dev/pts/ptmx is the default, and *not* when
			   provided by the users via the argv array. */
			mfd = open("/dev/ptmx", O_RDWR | O_NONBLOCK);
		}
		if (mfd == -1) {
			err(1, "tty_child: open ptmx");
		}
	}
	int unlock = 0;
	if (ioctl(mfd, TIOCSPTLCK, &unlock) < 0) {
		err(1, "tty_child: ioctl(TIOCSPTLCK)");
	}
	int sfd = ioctl(mfd, TIOCGPTPEER, O_RDWR);
	if (sfd < 0) {
		err(1, "tty_child: ioctl(TIOCGPTPEER)");
	}
	send_fd(socket, mfd);
	close(mfd);

	setsid();
	if (ioctl(sfd, TIOCSCTTY, NULL) < 0) {
		err(1, "tty_child: ioctl(TIOCSCTTY)");
	}
	if (dup2(sfd, STDIN_FILENO) < 0) {
		err(1, "tty_child: dup2(stdin)");
	}
	if (dup2(sfd, STDOUT_FILENO) < 0) {
		err(1, "tty_child: dup2(stdout)");
	}
	if (dup2(sfd, STDERR_FILENO) < 0) {
		err(1, "tty_child: dup2(stderr)");
	}
	if (sfd > STDERR_FILENO) {
		close(sfd);
	}
}

struct valmap {
	const char *name;
	void (*fn)(struct tty_opts *, const char *, const char *, const void *);
	const void *cookie;
};

static void parse_flag(struct tty_opts *opts, const char *key, const char *val, const void *cookie)
{
	if (val != NULL) {
		errx(2, "tty option '%s' must have no value", key);
	}

	const struct termios *tios = cookie;
	struct termios *dest = &opts->termios;
	if (key[0] == '-') {
		dest = &opts->neg_termios;
	}

	dest->c_iflag |= tios->c_iflag;
	dest->c_oflag |= tios->c_oflag;
	dest->c_lflag |= tios->c_cflag;
	dest->c_lflag |= tios->c_lflag;
}

static void parse_cc(struct tty_opts *opts, const char *key, const char *val, const void *cookie)
{
	if (key[0] == '-') {
		errx(2, "tty option '%s' cannot be negated", key);
	}
	if (val == NULL) {
		errx(2, "tty option '%s' must have a value", key);
	}

	char *end = (char *) &val[0];
	cc_t cc = val[0];
	if (cc != 0) {
		end++;
	}

	/* Support the caret notation */
	if (val[0] == '^' && val[1] != '\0') {
		if ((val[1] < '@' || val[1] > '_') && val[1] != '?') {
			errx(2, "invalid control character '%s' for tty option '%s'", val, key);
		}
		cc = val[1] - 64;
		if (val[1] == '?') {
			cc = val[1] + 64;
		}
		end = (char *) &val[2];
	}
	/* Support the backslash escape notation */
	if (val[0] == '\\' && val[1] != '\0') {
		int base = 8;
		const char *parse = &val[1];
		if (val[1] == 'x') {
			base = 16;
			parse++;
		}

		errno = 0;
		long v = strtol(parse, &end, base);
		if (v < 0 || v >= 256) {
			errno = ERANGE;
		}
		if (errno != 0) {
			err(2, "invalid escape sequence '%s' for tty option '%s'", val, key);
		}
		cc = v;
	}

	if (*end != '\0') {
		errx(2, "there can be no more than one control character for tty option '%s'", key);
	}

	const size_t *idx = cookie;
	opts->termios.c_cc[*idx] = cc;

	/* neg_termios.c_cc is used as a mean to distinguish between "not changing"
	   and "setting to 0" */
	opts->neg_termios.c_cc[*idx] = 1;
}

static void parse_ptmx(struct tty_opts *opts, const char *key, const char *val, const void *cookie)
{
	if (key[0] == '-') {
		errx(2, "tty option '%s' cannot be negated", key);
	}
	if (val == NULL) {
		errx(2, "tty option '%s' must have a value", key);
	}
	opts->ptmx = val;
}

static int cmp_flag(const void *key, const void *elem)
{
	return strcmp(key, ((const struct valmap *)elem)->name);
}

void tty_opt_parse(struct tty_opts *opts, const char *key, const char *val)
{
	struct valmap valmap[] = {
		/* NOTE: this array must be kept sorted for bsearch */
		{ "brkint",     parse_flag,  .cookie = &(const struct termios) { .c_iflag = BRKINT   } },
		{ "clocal",     parse_flag,  .cookie = &(const struct termios) { .c_cflag = CLOCAL   } },
		{ "cmspar",     parse_flag,  .cookie = &(const struct termios) { .c_cflag = CMSPAR   } },
		{ "cr0",        parse_flag,  .cookie = &(const struct termios) { .c_oflag = CR0      } },
		{ "cr1",        parse_flag,  .cookie = &(const struct termios) { .c_oflag = CR1      } },
		{ "cr2",        parse_flag,  .cookie = &(const struct termios) { .c_oflag = CR2      } },
		{ "cr3",        parse_flag,  .cookie = &(const struct termios) { .c_oflag = CR3      } },
		{ "cread",      parse_flag,  .cookie = &(const struct termios) { .c_cflag = CREAD    } },
		{ "crtscts",    parse_flag,  .cookie = &(const struct termios) { .c_cflag = CRTSCTS  } },
		{ "cstopb",     parse_flag,  .cookie = &(const struct termios) { .c_cflag = CSTOPB   } },
		{ "echo",       parse_flag,  .cookie = &(const struct termios) { .c_lflag = ECHO     } },
		{ "echoctl",    parse_flag,  .cookie = &(const struct termios) { .c_lflag = ECHOCTL  } },
		{ "echoe",      parse_flag,  .cookie = &(const struct termios) { .c_lflag = ECHOE    } },
		{ "echok",      parse_flag,  .cookie = &(const struct termios) { .c_lflag = ECHOK    } },
		{ "echoke",     parse_flag,  .cookie = &(const struct termios) { .c_lflag = ECHOKE   } },
		{ "echonl",     parse_flag,  .cookie = &(const struct termios) { .c_lflag = ECHONL   } },
		{ "echoprt",    parse_flag,  .cookie = &(const struct termios) { .c_lflag = ECHOPRT  } },
		{ "extproc",    parse_flag,  .cookie = &(const struct termios) { .c_lflag = EXTPROC  } },
		{ "ff0",        parse_flag,  .cookie = &(const struct termios) { .c_oflag = FF0      } },
		{ "ff1",        parse_flag,  .cookie = &(const struct termios) { .c_oflag = FF1      } },
		{ "flusho",     parse_flag,  .cookie = &(const struct termios) { .c_lflag = FLUSHO   } },
		{ "hupcl",      parse_flag,  .cookie = &(const struct termios) { .c_cflag = HUPCL    } },
		{ "icanon",     parse_flag,  .cookie = &(const struct termios) { .c_lflag = ICANON   } },
		{ "icrnl",      parse_flag,  .cookie = &(const struct termios) { .c_iflag = ICRNL    } },
		{ "iexten",     parse_flag,  .cookie = &(const struct termios) { .c_lflag = IEXTEN   } },
		{ "ignbrk",     parse_flag,  .cookie = &(const struct termios) { .c_iflag = IGNBRK   } },
		{ "igncr",      parse_flag,  .cookie = &(const struct termios) { .c_iflag = IGNCR    } },
		{ "ignpar",     parse_flag,  .cookie = &(const struct termios) { .c_iflag = IGNPAR   } },
		{ "inlcr",      parse_flag,  .cookie = &(const struct termios) { .c_iflag = INLCR    } },
		{ "inpck",      parse_flag,  .cookie = &(const struct termios) { .c_iflag = INPCK    } },
		{ "isig",       parse_flag,  .cookie = &(const struct termios) { .c_lflag = ISIG     } },
		{ "istrip",     parse_flag,  .cookie = &(const struct termios) { .c_iflag = ISTRIP   } },
		{ "iuclc",      parse_flag,  .cookie = &(const struct termios) { .c_iflag = IUCLC    } },
		{ "iutf8",      parse_flag,  .cookie = &(const struct termios) { .c_iflag = IUTF8    } },
		{ "ixany",      parse_flag,  .cookie = &(const struct termios) { .c_iflag = IXANY    } },
		{ "ixoff",      parse_flag,  .cookie = &(const struct termios) { .c_iflag = IXOFF    } },
		{ "ixon",       parse_flag,  .cookie = &(const struct termios) { .c_iflag = IXON     } },
		{ "nl0",        parse_flag,  .cookie = &(const struct termios) { .c_oflag = NL0      } },
		{ "nl1",        parse_flag,  .cookie = &(const struct termios) { .c_oflag = NL1      } },
		{ "noflsh",     parse_flag,  .cookie = &(const struct termios) { .c_lflag = NOFLSH   } },
		{ "ocrnl",      parse_flag,  .cookie = &(const struct termios) { .c_oflag = OCRNL    } },
		{ "ofill",      parse_flag,  .cookie = &(const struct termios) { .c_oflag = OFILL    } },
		{ "olcuc",      parse_flag,  .cookie = &(const struct termios) { .c_oflag = OLCUC    } },
		{ "onlcr",      parse_flag,  .cookie = &(const struct termios) { .c_oflag = ONLCR    } },
		{ "onlret",     parse_flag,  .cookie = &(const struct termios) { .c_oflag = ONLRET   } },
		{ "onocr",      parse_flag,  .cookie = &(const struct termios) { .c_oflag = ONOCR    } },
		{ "opost",      parse_flag,  .cookie = &(const struct termios) { .c_oflag = OPOST    } },
		{ "parenb",     parse_flag,  .cookie = &(const struct termios) { .c_cflag = PARENB   } },
		{ "parmrk",     parse_flag,  .cookie = &(const struct termios) { .c_iflag = PARMRK   } },
		{ "parodd",     parse_flag,  .cookie = &(const struct termios) { .c_cflag = PARODD   } },
		{ "ptmx",       parse_ptmx,  .cookie = NULL                                            },
		{ "tab0",       parse_flag,  .cookie = &(const struct termios) { .c_oflag = TAB0     } },
		{ "tab1",       parse_flag,  .cookie = &(const struct termios) { .c_oflag = TAB1     } },
		{ "tab2",       parse_flag,  .cookie = &(const struct termios) { .c_oflag = TAB2     } },
		{ "tab3",       parse_flag,  .cookie = &(const struct termios) { .c_oflag = TAB3     } },
		{ "tostop",     parse_flag,  .cookie = &(const struct termios) { .c_lflag = TOSTOP   } },
		{ "veof",       parse_cc,    .cookie = &(const size_t) { VEOF     }                    },
		{ "veol",       parse_cc,    .cookie = &(const size_t) { VEOL     }                    },
		{ "veol2",      parse_cc,    .cookie = &(const size_t) { VEOL2    }                    },
		{ "verase",     parse_cc,    .cookie = &(const size_t) { VERASE   }                    },
		{ "vintr",      parse_cc,    .cookie = &(const size_t) { VINTR    }                    },
		{ "vkill",      parse_cc,    .cookie = &(const size_t) { VKILL    }                    },
		{ "vlnext",     parse_cc,    .cookie = &(const size_t) { VLNEXT   }                    },
		{ "vquit",      parse_cc,    .cookie = &(const size_t) { VQUIT    }                    },
		{ "vreprint",   parse_cc,    .cookie = &(const size_t) { VREPRINT }                    },
		{ "vstart",     parse_cc,    .cookie = &(const size_t) { VSTART   }                    },
		{ "vstop",      parse_cc,    .cookie = &(const size_t) { VSTOP    }                    },
		{ "vsusp",      parse_cc,    .cookie = &(const size_t) { VSUSP    }                    },
		{ "vt0",        parse_flag,  .cookie = &(const struct termios) { .c_oflag = VT0      } },
		{ "vt1",        parse_flag,  .cookie = &(const struct termios) { .c_oflag = VT1      } },
		{ "vwerase",    parse_cc,    .cookie = &(const size_t) { VWERASE  }                    },
	};

	const char *k = key;
	if (key[0] == '-') {
		k = &key[1];
	}

	struct valmap *found = bsearch(k, valmap, lengthof(valmap), sizeof (*valmap), cmp_flag);
	if (!found) {
		errx(2, "unrecognized tty option '%s'", key);
	}

	found->fn(opts, key, val, found->cookie);
}
