/* Copyright (c) 2020 Arista Networks, Inc.  All rights reserved.
   Arista Networks, Inc. Confidential and Proprietary. */

#include <err.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "enter.h"

enum {
	OPTION_MOUNT = 128,
	OPTION_MUTABLE,
	OPTION_UID,
	OPTION_GID,
	OPTION_GROUPS,
	OPTION_WORKDIR,
	OPTION_ARCH,
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
	static struct entry_settings opts;

	static struct option options[] = {
		{ "help",       no_argument,        NULL,           'h' },
		{ "pidns",      no_argument,        &opts.pid,      'p' },
		{ "mountns",    no_argument,        &opts.mount,    'm' },
		{ "cgroupns",   no_argument,        &opts.cgroup,   'c' },
		{ "ipcns",      no_argument,        &opts.ipc,      'i' },
		{ "netns",      no_argument,        &opts.net,      'n' },
		{ "userns",     no_argument,        &opts.user,     'U' },
		{ "utsns",      no_argument,        &opts.uts,      'u' },

		/* long options without shorthand */
		{ "workdir",    required_argument,  NULL,           OPTION_WORKDIR  },
		{ "mount",      required_argument,  NULL,           OPTION_MOUNT    },
		{ "mutable",    required_argument,  NULL,           OPTION_MUTABLE  },
		{ "uid",        required_argument,  NULL,           OPTION_UID      },
		{ "gid",        required_argument,  NULL,           OPTION_GID      },
		{ "groups",     required_argument,  NULL,           OPTION_GROUPS   },
		{ "arch",       required_argument,  NULL,           OPTION_ARCH     },

		{ 0, 0, 0, 0 }
	};

	int error = 0;
	int c;
	while ((c = getopt_long(argc, argv, "+hpmcinUu", options, NULL)) != -1) {
		switch (c) {
			case 0:
				break;

			case OPTION_WORKDIR:
				opts.workdir = optarg;
				break;

			case OPTION_MOUNT:
				opts.mounts[opts.nmounts].source  = strtok(optarg, ",");
				opts.mounts[opts.nmounts].target  = strtok(NULL, ",");
				opts.mounts[opts.nmounts].type    = strtok(NULL, ",");
				opts.mounts[opts.nmounts].options = strtok(NULL, "");
				opts.nmounts++;
				break;

			case OPTION_MUTABLE:
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
					opts.groups[opts.ngroups++] = atoi(grp);
				}
				break;

			case OPTION_ARCH:
				opts.arch = optarg;
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

	if (optind + 3 > argc) {
		return usage(1, argv[0]);
	}
	opts.root = argv[optind++];
	opts.pathname = argv[optind++];
	opts.argv = argv + optind;
	opts.envp = envp;

	if (!opts.workdir || opts.workdir[0] == 0) {
		/* We don't want to remain outside the chroot. */
		opts.workdir = "/";
	}
	if (opts.workdir[0] != '/') {
		errx(1, "workdir must be an absolute path.");
	}

	/* These are typically sent to the foreground process group, which
	   includes us and our child process. We act on good faith that whatever
	   the child chooses to do (e.g. ignore SIGINT) we want to politely
	   leave them alone until completion. */
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGTERM, SIG_IGN);

	return enter(&opts);
}
