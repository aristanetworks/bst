/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "enter.h"
#include "sig.h"

enum {
	OPTION_MOUNT = 128,
	OPTION_MUTABLE,
	OPTION_UID,
	OPTION_GID,
	OPTION_GROUPS,
	OPTION_WORKDIR,
	OPTION_ARCH,
	OPTION_SHARE,
	OPTION_ARGV0,
	OPTION_HOSTNAME,
	OPTION_DOMAIN,
	OPTION_TIME,
	OPTION_NO_FAKE_DEVTMPFS,
	OPTION_NO_DERANDOMIZE,
	OPTION_NO_PROC_REMOUNT,
};

/* Usage is generated from usage.txt. Note that the array is not null-terminated,
   I couldn't find a way to convince xxd to do that for me, so instead
   I just replace the last newline with a NUL and print an extra newline
   from the usage function. */
extern unsigned char usage_txt[];
extern unsigned int usage_txt_len;

int usage(int error, char *argv0)
{
	usage_txt[usage_txt_len - 1] = 0;
	FILE *out = error ? stderr : stdout;
	fprintf(out, (char *) usage_txt, argv0);
	fprintf(out, "\n");
	return error ? 2 : 0;
}

int main(int argc, char *argv[], char *envp[])
{
	static struct entry_settings opts = {
		.uid = -1,
		.gid = -1,
	};

	static struct option options[] = {
		{ "help",       no_argument,        NULL,           'h' },
		{ "root",       required_argument,  NULL,           'r' },

		/* long options without shorthand */
		{ "workdir",    required_argument,  NULL,           OPTION_WORKDIR  },
		{ "mount",      required_argument,  NULL,           OPTION_MOUNT    },
		{ "mutable",    required_argument,  NULL,           OPTION_MUTABLE  },
		{ "uid",        required_argument,  NULL,           OPTION_UID      },
		{ "gid",        required_argument,  NULL,           OPTION_GID      },
		{ "groups",     required_argument,  NULL,           OPTION_GROUPS   },
		{ "arch",       required_argument,  NULL,           OPTION_ARCH     },
		{ "share",      required_argument,  NULL,           OPTION_SHARE    },
		{ "argv0",      required_argument,  NULL,           OPTION_ARGV0    },
		{ "hostname",   required_argument,  NULL,           OPTION_HOSTNAME },
		{ "domainname", required_argument,  NULL,           OPTION_DOMAIN   },
		{ "time",       required_argument,  NULL,           OPTION_TIME     },

		/* Opt-out feature flags */
		{ "no-fake-devtmpfs",   no_argument,    NULL,       OPTION_NO_FAKE_DEVTMPFS },
		{ "no-derandomize",     no_argument,    NULL,       OPTION_NO_DERANDOMIZE   },
		{ "no-proc-remount",    no_argument,    NULL,       OPTION_NO_PROC_REMOUNT  },

		{ 0, 0, 0, 0 }
	};

	static const char *clocknames[MAX_CLOCK + 1] = {
		[CLOCK_MONOTONIC] = "monotonic",
		[CLOCK_BOOTTIME]  = "boottime",
	};

	char *argv0 = NULL;

	int error = 0;
	int c;
	while ((c = getopt_long(argc, argv, "+hr:", options, NULL)) != -1) {
		switch (c) {
			case 0:
				break;

			case OPTION_WORKDIR:
				opts.workdir = optarg;
				break;

			case OPTION_MOUNT:
				if (opts.nmounts >= MAX_MOUNT) {
					err(1, "can only mount a maximum of %d entries", MAX_MOUNT);
				}
				opts.mounts[opts.nmounts].source  = strtok(optarg, ",");
				opts.mounts[opts.nmounts].target  = strtok(NULL, ",");
				opts.mounts[opts.nmounts].type    = strtok(NULL, ",");
				opts.mounts[opts.nmounts].options = strtok(NULL, "");
				opts.nmounts++;
				break;

			case OPTION_MUTABLE:
				if (opts.nmutables >= MAX_MOUNT) {
					err(1, "can only mount a maximum of %d mutables", MAX_MOUNT);
				}
				opts.mutables[opts.nmutables] = optarg;
				opts.nmutables++;
				break;

			case OPTION_UID:
				opts.uid = atoi(optarg);
				break;

			case OPTION_GID:
				opts.gid = atoi(optarg);
				break;

			case OPTION_GROUPS:
				for (char *grp = strtok(optarg, ","); grp; grp = strtok(NULL, ",")) {
					if (opts.ngroups >= NGROUPS_MAX) {
						err(1, "can only be part of a maximum of %d groups", NGROUPS_MAX);
					}
					opts.groups[opts.ngroups++] = atoi(grp);
				}
				break;

			case OPTION_ARCH:
				opts.arch = optarg;
				break;

			case OPTION_SHARE:
				for (char *share = strtok(optarg, ","); share; share = strtok(NULL, ",")) {
					if (opts.nshares >= MAX_SHARES) {
						err(1, "can only share a maximum of %d namespaces", MAX_SHARES);
					}
					opts.shares[opts.nshares++] = share;
				}
				break;

			case OPTION_ARGV0:
				argv0 = optarg;
				break;

			case OPTION_HOSTNAME:
				opts.hostname = optarg;
				break;

			case OPTION_DOMAIN:
				opts.domainname = optarg;
				break;

			case OPTION_TIME:
			{
				const char *name  = strtok(optarg, "=");
				const char *secs  = strtok(NULL, ".");
				const char *nsecs = strtok(NULL, "");

				clockid_t clock = -1;
				for (clockid_t id = 0; id < MAX_CLOCK + 1; ++id) {
					if (clocknames[id] && strcmp(clocknames[id], name) == 0) {
						clock = id;
						break;
					}
				}

				if (clock == -1 && isdigit(name[0])) {
					errno = 0;
					clock = strtol(name, NULL, 10);
					if (errno != 0) {
						clock = -1;
					}
				}

				if (clock < 0 || clock > MAX_CLOCK) {
					errx(2, "%s is not a valid clock ID or name", name);
				}

				struct timespec ts = {0, 0};
				errno = 0;
				ts.tv_sec  = strtol(secs, NULL, 10);
				if (errno != 0) {
					err(2, "%s is not a valid number of seconds", secs);
				}
				if (ts.tv_sec < 0) {
					errx(2, "%s must be a positive number of seconds", secs);
				}
				if (nsecs && nsecs[0] != '\0') {
					errno = 0;
					ts.tv_nsec = strtol(nsecs, NULL, 10);
					if (errno != 0) {
						err(2, "%s is not a valid number of nanoseconds", nsecs);
					}
					if (ts.tv_nsec < 0 || ts.tv_nsec >= SEC_IN_NS) {
						errx(2, "%s as nanoseconds is out of range (must be "
								"between 0 and 999.999.999)", nsecs);
					}
				}

				opts.clockspecs[clock] = ts;
				break;
			}

			case OPTION_NO_FAKE_DEVTMPFS:
				opts.no_fake_devtmpfs = 1;
				break;

			case OPTION_NO_DERANDOMIZE:
				opts.no_derandomize = 1;
				break;

			case OPTION_NO_PROC_REMOUNT:
				opts.no_proc_remount = 1;
				break;

			case 'r':
				opts.root = optarg;
				break;

			case '?':
				error = 1;
				/* fallthrough */
			case 'h':
				return usage(error, argv[0]);

			default:
				for (int i = 0; options[i].name != NULL; i++) {
					if (options[i].val == c) {
						if (options[i].flag != NULL) {
							*options[i].flag = c;
						}
						break;
					}
				}
		}
	}

	if (optind + 1 > argc) {
		return usage(1, argv[0]);
	}

	char *new_argv[argc - optind + 1];
	new_argv[0] = argv0 ? argv0 : argv[optind];
	for (int i = 1; i < argc - optind; ++i) {
		new_argv[i] = argv[optind + i];
	}
	new_argv[argc - optind] = NULL;

	opts.pathname = argv[optind];
	opts.argv = new_argv;
	opts.envp = envp;

	if (!opts.workdir || opts.workdir[0] == 0) {
		/* We don't want to remain outside the chroot. */
		opts.workdir = "/";
	}
	if (opts.workdir[0] != '/') {
		errx(1, "workdir must be an absolute path.");
	}

	/* Ignore all user-sent signals, and a few kernel-sent ones.
	
	   Some of these signals are typically sent to the foreground process group,
	   which includes us and our child process. We act on good faith that whatever
	   the child chooses to do (e.g. ignore SIGINT) we want to politely
	   leave them alone until completion. */

	for (int sig = 1; sig <= SIGRTMAX; ++sig) {
		ignoresig(sig);
	}

	return enter(&opts);
}
