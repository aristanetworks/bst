/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <asm/resource.h>

#include "bst_limits.h"
#include "capable.h"
#include "enter.h"
#include "kvlist.h"

enum {
	OPTION_MOUNT = 128,
	OPTION_UID,
	OPTION_GID,
	OPTION_GROUPS,
	OPTION_WORKDIR,
	OPTION_ARCH,
	OPTION_LIMIT_AS,
	_OPTION_LIMIT_START = OPTION_LIMIT_AS,
	OPTION_LIMIT_CORE,
	OPTION_LIMIT_CPU,
	OPTION_LIMIT_DATA,
	OPTION_LIMIT_FSIZE,
	OPTION_LIMIT_LOCKS,
	OPTION_LIMIT_MEMLOCK,
	OPTION_LIMIT_MSGQUEUE,
	OPTION_LIMIT_NICE,
	OPTION_LIMIT_NOFILE,
	OPTION_LIMIT_NPROC,
	OPTION_LIMIT_RSS,
	OPTION_LIMIT_RTPRIO,
	OPTION_LIMIT_RTTIME,
	OPTION_LIMIT_SIGPENDING,
	OPTION_LIMIT_STACK,
	_OPTION_LIMIT_END = OPTION_LIMIT_STACK,
	OPTION_SHARE_CGROUP,
	OPTION_SHARE_IPC,
	OPTION_SHARE_MNT,
	OPTION_SHARE_NET,
	OPTION_SHARE_PID,
	OPTION_SHARE_TIME,
	OPTION_SHARE_USER,
	OPTION_SHARE_UTS,
	OPTION_SHARE_ALL,
	OPTION_ARGV0,
	OPTION_HOSTNAME,
	OPTION_DOMAIN,
	OPTION_TIME,
	OPTION_PERSIST,
	OPTION_UMASK,
	OPTION_INIT,
	OPTION_SETUP_EXE,
	OPTION_SETUP,
	OPTION_UIDMAP,
	OPTION_GIDMAP,
	OPTION_NIC,
	OPTION_NO_FAKE_DEVTMPFS,
	OPTION_NO_DERANDOMIZE,
	OPTION_NO_PROC_REMOUNT,
	OPTION_NO_LOOPBACK_SETUP,
	OPTION_NO_INIT,
	OPTION_SHARE_DEPRECATED,
	OPTION_MUTABLE_DEPRECATED,
};

/* Usage is generated from usage.txt. Note that the array is not null-terminated,
   I couldn't find a way to convince xxd to do that for me, so instead
   I just replace the last newline with a NUL and print an extra newline
   from the usage function. */
extern unsigned char usage_txt[];
extern unsigned int usage_txt_len;

static void process_share_deprecated(struct entry_settings *opts, const char *optarg) {
	for (const char *share = strtok((char *) optarg, ","); share; share = strtok(NULL, ",")) {
		int found = 0;
		if (!strcmp(share, "network")) {
			share = "net";
		}
		if (!strcmp(share, "mount")) {
			share = "mnt";
		}
		for (enum nstype ns = 0; ns < MAX_NS; ns++) {
			if (!strcmp(share, ns_name(ns))) {
				opts->shares[ns] = SHARE_WITH_PARENT;
				found = 1;
			}
		}
		if (!found) {
			fprintf(stderr, "namespace `%s` does not exist.\n", share);
			fprintf(stderr, "valid namespaces are: ");
			for (enum nstype ns = 0; ns < MAX_NS; ns++) {
				fprintf(stderr, "%s%s", ns == 0 ? "" : ", ", ns_name(ns));
			}
			fprintf(stderr, ".\n");
			exit(1);
		}
	}
}

static void handle_limit_arg(int option_num, struct entry_settings *opts, char *arg) {
	struct opt {
		int option_num;
		int resource;
		char const *name;
	};
	static const struct opt option_map[] = {
		{ OPTION_LIMIT_AS,         RLIMIT_AS,         "as"         },
		{ OPTION_LIMIT_CORE,       RLIMIT_CORE,       "core"       },
		{ OPTION_LIMIT_CPU,        RLIMIT_CPU,        "cpu"        },
		{ OPTION_LIMIT_DATA,       RLIMIT_DATA,       "data"       },
		{ OPTION_LIMIT_FSIZE,      RLIMIT_FSIZE,      "fsize"      },
		{ OPTION_LIMIT_LOCKS,      RLIMIT_LOCKS,      "locks"      },
		{ OPTION_LIMIT_MEMLOCK,    RLIMIT_MEMLOCK,    "memlock"    },
		{ OPTION_LIMIT_MSGQUEUE,   RLIMIT_MSGQUEUE,   "msgqueue"   },
		{ OPTION_LIMIT_NICE,       RLIMIT_NICE,       "nice"       },
		{ OPTION_LIMIT_NOFILE,     RLIMIT_NOFILE,     "nofile"     },
		{ OPTION_LIMIT_NPROC,      RLIMIT_NPROC,      "nproc"      },
		{ OPTION_LIMIT_RSS,        RLIMIT_RSS,        "rss"        },
		{ OPTION_LIMIT_RTPRIO,     RLIMIT_RTPRIO,     "rtprio"     },
		{ OPTION_LIMIT_RTTIME,     RLIMIT_RTTIME,     "rttime"     },
		{ OPTION_LIMIT_SIGPENDING, RLIMIT_SIGPENDING, "sigpending" },
		{ OPTION_LIMIT_STACK,      RLIMIT_STACK,      "stack"      },
	};

	assert(option_num >= _OPTION_LIMIT_START && option_num <= _OPTION_LIMIT_END);

	size_t index = (size_t)(option_num - _OPTION_LIMIT_START);
	assert(index < sizeof (option_map) / sizeof (*option_map));

	struct opt const * opt_ent = option_map + index;
	assert(opt_ent->option_num == option_num);

	if (parse_rlimit(opt_ent->resource, opts->limits_storage + opt_ent->resource, arg)) {
		err(1, "error in --limit-%s value", opt_ent->name);
	}
	*(opts->limits + opt_ent->resource) = opts->limits_storage + opt_ent->resource;
}

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
	init_capabilities();

	static struct entry_settings opts = {
		.uid   = (uid_t) -1,
		.gid   = (gid_t) -1,
		.umask = (mode_t) -1,
	};

	static struct option options[] = {
		{ "help",       no_argument,        NULL,           'h' },
		{ "root",       required_argument,  NULL,           'r' },

		/* long options without shorthand */
		{ "workdir",            required_argument, NULL, OPTION_WORKDIR         },
		{ "mount",              required_argument, NULL, OPTION_MOUNT           },
		{ "uid",                required_argument, NULL, OPTION_UID             },
		{ "gid",                required_argument, NULL, OPTION_GID             },
		{ "groups",             required_argument, NULL, OPTION_GROUPS          },
		{ "arch",               required_argument, NULL, OPTION_ARCH            },
		{ "limit-as",           required_argument, NULL, OPTION_LIMIT_AS        },
		{ "limit-core",         required_argument, NULL, OPTION_LIMIT_CORE      },
		{ "limit-cpu",          required_argument, NULL, OPTION_LIMIT_CPU       },
		{ "limit-data",         required_argument, NULL, OPTION_LIMIT_DATA      },
		{ "limit-fsize",        required_argument, NULL, OPTION_LIMIT_FSIZE     },
		{ "limit-locks",        required_argument, NULL, OPTION_LIMIT_LOCKS     },
		{ "limit-memlock",      required_argument, NULL, OPTION_LIMIT_MEMLOCK   },
		{ "limit-msgqueue",     required_argument, NULL, OPTION_LIMIT_MSGQUEUE  },
		{ "limit-nice",         required_argument, NULL, OPTION_LIMIT_NICE      },
		{ "limit-nofile",       required_argument, NULL, OPTION_LIMIT_NOFILE    },
		{ "limit-nproc",        required_argument, NULL, OPTION_LIMIT_NPROC     },
		{ "limit-rss",          required_argument, NULL, OPTION_LIMIT_RSS       },
		{ "limit-rtprio",       required_argument, NULL, OPTION_LIMIT_RTPRIO    },
		{ "limit-rttime",       required_argument, NULL, OPTION_LIMIT_RTTIME    },
		{ "limit-sigpending",   required_argument, NULL, OPTION_LIMIT_SIGPENDING},
		{ "limit-stack",        required_argument, NULL, OPTION_LIMIT_STACK     },
		{ "share-cgroup",       optional_argument, NULL, OPTION_SHARE_CGROUP    },
		{ "share-ipc",          optional_argument, NULL, OPTION_SHARE_IPC       },
		{ "share-mnt",          optional_argument, NULL, OPTION_SHARE_MNT       },
		{ "share-net",          optional_argument, NULL, OPTION_SHARE_NET       },
		{ "share-pid",          optional_argument, NULL, OPTION_SHARE_PID       },
		{ "share-time",         optional_argument, NULL, OPTION_SHARE_TIME      },
		{ "share-user",         optional_argument, NULL, OPTION_SHARE_USER      },
		{ "share-uts",          optional_argument, NULL, OPTION_SHARE_UTS       },
		{ "share-all",          optional_argument, NULL, OPTION_SHARE_ALL       },
		{ "argv0",              required_argument, NULL, OPTION_ARGV0           },
		{ "hostname",           required_argument, NULL, OPTION_HOSTNAME        },
		{ "domainname",         required_argument, NULL, OPTION_DOMAIN          },
		{ "time",               required_argument, NULL, OPTION_TIME            },
		{ "persist",            required_argument, NULL, OPTION_PERSIST         },
		{ "umask",              required_argument, NULL, OPTION_UMASK           },
		{ "init",               required_argument, NULL, OPTION_INIT            },
		{ "setup-exe",          required_argument, NULL, OPTION_SETUP_EXE       },
		{ "setup",              required_argument, NULL, OPTION_SETUP           },
		{ "uid-map",            required_argument, NULL, OPTION_UIDMAP          },
		{ "gid-map",            required_argument, NULL, OPTION_GIDMAP          },
		{ "nic",                required_argument, NULL, OPTION_NIC             },

		/* Opt-out feature flags */
		{ "no-fake-devtmpfs",   no_argument, NULL, OPTION_NO_FAKE_DEVTMPFS      },
		{ "no-derandomize",     no_argument, NULL, OPTION_NO_DERANDOMIZE        },
		{ "no-proc-remount",    no_argument, NULL, OPTION_NO_PROC_REMOUNT       },
		{ "no-loopback-setup",  no_argument, NULL, OPTION_NO_LOOPBACK_SETUP     },
		{ "no-init",            no_argument, NULL, OPTION_NO_INIT               },

		/* Deprecated flags */
		{ "share",      required_argument, NULL, OPTION_SHARE_DEPRECATED        },
		{ "mutable",    required_argument, NULL, OPTION_MUTABLE_DEPRECATED      },
		
		{ 0, 0, 0, 0 }
	};

	static const char *clocknames[MAX_CLOCK + 1] = {
		[CLOCK_MONOTONIC] = "monotonic",
		[CLOCK_BOOTTIME]  = "boottime",
	};

	char *setup_sh_argv[] = {
		"sh",
		"-euc",
		"false",
		NULL,
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
			{
				if (opts.nmounts >= MAX_MOUNT) {
					errx(1, "can only mount a maximum of %d entries", MAX_MOUNT);
				}
				struct kvlist kvlist[3];
				kvlist_parse(optarg, kvlist, 3, &opts.mounts[opts.nmounts].options);

				if (kvlist[0].value == NULL)
					opts.mounts[opts.nmounts].source = kvlist[0].key;
				if (kvlist[1].value == NULL)
					opts.mounts[opts.nmounts].target = kvlist[1].key;
				if (kvlist[2].value == NULL)
					opts.mounts[opts.nmounts].type = kvlist[2].key;

				for (size_t i = 0; i < 3; ++i) {
					if (kvlist[i].key == NULL) {
						errx(1, "missing argument(s) to --mount");
					}
					if (kvlist[i].value == NULL) {
						continue;
					}
					if (strcmp(kvlist[i].key, "source") == 0) {
						opts.mounts[opts.nmounts].source = kvlist[i].value;
					} else if (strcmp(kvlist[i].key, "target") == 0) {
						opts.mounts[opts.nmounts].target = kvlist[i].value;
					} else if (strcmp(kvlist[i].key, "type") == 0) {
						opts.mounts[opts.nmounts].type = kvlist[i].value;
					}
				}

				opts.nmounts++;
				break;
			}

			case OPTION_MUTABLE_DEPRECATED:
				warnx("--mutable is deprecated; use a setup program instead.");
				if (opts.nmutables >= MAX_MOUNT) {
					errx(1, "can only mount a maximum of %d mutables", MAX_MOUNT);
				}
				opts.mutables[opts.nmutables] = optarg;
				opts.nmutables++;
				break;

			case OPTION_UID:
				opts.uid = (uid_t) strtoul(optarg, NULL, 10);
				break;

			case OPTION_GID:
				opts.gid = (gid_t) strtoul(optarg, NULL, 10);
				break;

			case OPTION_GROUPS:
				for (char *grp = strtok(optarg, ","); grp; grp = strtok(NULL, ",")) {
					if (opts.ngroups >= NGROUPS_MAX) {
						errx(1, "can only be part of a maximum of %d groups", NGROUPS_MAX);
					}
					opts.groups[opts.ngroups++] = (gid_t) strtoul(grp, NULL, 10);
				}
				break;

			case OPTION_ARCH:
				opts.arch = optarg;
				break;

			case OPTION_LIMIT_AS:
			case OPTION_LIMIT_CORE:
			case OPTION_LIMIT_CPU:
			case OPTION_LIMIT_DATA:
			case OPTION_LIMIT_FSIZE:
			case OPTION_LIMIT_LOCKS:
			case OPTION_LIMIT_MEMLOCK:
			case OPTION_LIMIT_MSGQUEUE:
			case OPTION_LIMIT_NICE:
			case OPTION_LIMIT_NOFILE:
			case OPTION_LIMIT_NPROC:
			case OPTION_LIMIT_RSS:
			case OPTION_LIMIT_RTPRIO:
			case OPTION_LIMIT_RTTIME:
			case OPTION_LIMIT_SIGPENDING:
			case OPTION_LIMIT_STACK:
				handle_limit_arg(c, &opts, optarg);
				break;

			case OPTION_SHARE_CGROUP:
			case OPTION_SHARE_IPC:
			case OPTION_SHARE_MNT:
			case OPTION_SHARE_NET:
			case OPTION_SHARE_PID:
			case OPTION_SHARE_TIME:
			case OPTION_SHARE_USER:
			case OPTION_SHARE_UTS:
				opts.shares[c - OPTION_SHARE_CGROUP] = optarg ? optarg : SHARE_WITH_PARENT;
				break;

			case OPTION_SHARE_ALL:
				for (enum nstype ns = 0; ns < MAX_NS; ns++) {
					char buf[PATH_MAX];
					if (optarg) {
						snprintf(buf, sizeof(buf), "%s/%s", optarg, ns_name(ns));
						buf[sizeof(buf) - 1] = 0;
						opts.shares[ns] = strdup(buf);
					} else {
						opts.shares[ns] = SHARE_WITH_PARENT;
					}
				}
				break;

			case OPTION_SHARE_DEPRECATED:
				process_share_deprecated(&opts, optarg);
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
					clock = (clockid_t) strtol(name, NULL, 10);
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

			case OPTION_NIC:
			{
				if (opts.nnics >= MAX_NICS) {
					errx(1, "can only create a maximum of %d interfaces", MAX_NICS);
				}
				struct nic_options *nic = &opts.nics[opts.nnics];

				/* 16 is enough to support everything */
				struct kvlist kvlist[16];
				size_t nopts = sizeof (kvlist) / sizeof (*kvlist);
				kvlist_parse(optarg, kvlist, nopts, NULL);

				/* Only the first two argument need not be key-value pairs */
				size_t start = 0;
				if (kvlist[start].value == NULL)
					strncpy(nic->name, kvlist[start++].key, sizeof (nic->name));
				if (kvlist[start].value == NULL)
					strncpy(nic->type, kvlist[start++].key, sizeof (nic->type));

				/* Do a first pass to find name= and type= keys */
				for (size_t i = start; i < nopts; ++i) {
					if (kvlist[i].key == NULL) {
						continue;
					}
					if (strcmp(kvlist[i].key, "name") == 0) {
						strncpy(nic->name, kvlist[i].value, sizeof (nic->name));
					} else if (strcmp(kvlist[i].key, "type") == 0) {
						strncpy(nic->type, kvlist[i].value, sizeof (nic->type));
					} else {
						continue;
					}

					/* This was a name or type key, do not process it again. */
					kvlist[i].key = NULL;
				}

				if (nic->name[0] == '\0') {
					errx(1, "nic: must at least specify a name for anonymous interface");
				}
				if (nic->type[0] == '\0') {
					errx(1, "nic: must at least specify a type for '%.16s'", nic->name);
				}

				for (size_t i = start; i < nopts; ++i) {
					if (kvlist[i].key != NULL) {
						nic_parse(nic, kvlist[i].key, kvlist[i].value);
					}
				}

				opts.nnics++;
				break;
			}

			case OPTION_PERSIST:
				opts.persist = optarg;
				break;
				
			case OPTION_UMASK:
				if (sscanf(optarg, "%o", &opts.umask) != 1) {
					err(2, "%s is not a valid umask", optarg);
				}
				break;

			case OPTION_UIDMAP:
				id_map_parse(opts.uid_map, optarg);
				break;

			case OPTION_GIDMAP:
				id_map_parse(opts.gid_map, optarg);
				break;

			case OPTION_NO_FAKE_DEVTMPFS:
				opts.no_fake_devtmpfs = 1;
				break;

			case OPTION_NO_DERANDOMIZE:
				opts.no_derandomize = 1;
				break;

			case OPTION_NO_PROC_REMOUNT:
				opts.no_proc_remount = 1;
				break;

			case OPTION_INIT:
				opts.init = optarg;
				break;

			case OPTION_NO_INIT:
				opts.init = "";
				break;

			case OPTION_SETUP_EXE:
				opts.setup_program = optarg;
				break;

			case OPTION_SETUP:
				opts.setup_program = "/bin/sh";
				opts.setup_argv = setup_sh_argv;
				setup_sh_argv[2] = optarg;
				break;

			case OPTION_NO_LOOPBACK_SETUP:
				opts.no_loopback_setup = 1;
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

	/* Use our own default init if we unshare the pid namespace, and no
	   --init has been specified. */
	if (opts.shares[NS_PID] == NULL && opts.init == NULL) {
		opts.init = LIBEXECDIR "/bst-init";
	}

	char *default_argv[] = {
		"bst"
		"sh",
		NULL
	};

	if (optind + 1 > argc) {
		char *shell = getenv("SHELL");
		if (shell != NULL) {
			default_argv[1] = shell;
		}

		optind = 1;
		argc = 2;
		argv = default_argv;
	}
	char *new_argv[argc - optind + 1];

	if (!argv0 && opts.init && opts.init[0] != '\0') {
		argv0 = (char *) opts.init + strlen(opts.init) - 1;
		for (; argv0 != opts.init && *argv0 != '/'; --argv0) {
			continue;
		}
		++argv0;
	}

	new_argv[0] = argv0 ? argv0 : argv[optind];
	for (int i = 1; i < argc - optind; ++i) {
		new_argv[i] = argv[optind + i];
	}
	new_argv[argc - optind] = NULL;

	opts.pathname = argv[optind];
	opts.argv = new_argv;
	opts.envp = envp;

	if (opts.workdir && opts.workdir[0] != '\0' && opts.workdir[0] != '/') {
		errx(1, "workdir must be an absolute path.");
	}

	/* Block all signals. We use sigwaitinfo to probe for pending signals,
	   including SIGCHLD. */
	sigset_t mask;
	sigfillset(&mask);

	if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
		err(1, "sigprocmask");
	}

	return enter(&opts);
}
