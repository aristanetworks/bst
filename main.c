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

#include "config.h"

#include "bst_limits.h"
#include "capable.h"
#include "enter.h"
#include "kvlist.h"
#include "util.h"
#include "path.h"
#include "util.h"

enum {
	OPTION_VERSION = 128,
	OPTION_MOUNT,
	OPTION_UID,
	OPTION_GID,
	OPTION_GROUPS,
	OPTION_WORKDIR,
	OPTION_ARCH,
	OPTION_LIMIT,
	OPTION_SHARE,
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
	OPTION_NO_ENV,
	OPTION_NO_COPY_HARD_LIMITS,
};

static void process_nslist_entry(const char **out, const char *share, const char *path, int multiple)
{
	if (!strcmp(share, "network")) {
		share = "net";
	}
	if (!strcmp(share, "mount")) {
		share = "mnt";
	}
	for (enum nstype ns = 0; ns < MAX_NS; ns++) {
		if (!strcmp(share, ns_name(ns))) {
			if (path) {
				if (multiple) {
					out[ns] = strdup(makepath("%s/%s", path, ns_name(ns)));
				} else {
					out[ns] = path;
				}
			} else {
				out[ns] = SHARE_WITH_PARENT;
			}
			return;
		}
	}
	fprintf(stderr, "namespace `%s` does not exist.\n", share);
	fprintf(stderr, "valid namespaces are: ");
	for (enum nstype ns = 0; ns < MAX_NS; ns++) {
		fprintf(stderr, "%s%s", ns == 0 ? "" : ", ", ns_name(ns));
	}
	fprintf(stderr, ".\n");
	exit(2);
}

static void process_share(const char **out, const char *optarg)
{
	char *nsnames = strtok((char *) optarg, "=");
	char *path    = strtok(NULL, "");

	/* Specifying a standalone path means that all namespaces should be entered
	   from the nsfs files relative to that directory path. */
	char all_namespaces[] = "cgroup,ipc,mnt,net,pid,time,user,uts";
	if (nsnames[0] == '/' || nsnames[0] == '.') {
		path = nsnames;
		nsnames = all_namespaces;
	}
	if (strcmp(nsnames, "all") == 0) {
		nsnames = all_namespaces;
	}

	size_t nsnames_len = strlen(nsnames);
	const char *share = strtok(nsnames, ",");
	bool multiple = share + strlen(share) != nsnames + nsnames_len;

	for (; share; share = strtok(NULL, ",")) {
		process_nslist_entry(out, share, path, multiple);
	}
}

static void process_persist(const char **out, const char *optarg)
{
	/* Similar rules as for process_share, but refuse when no path is passed,
	   and treat long arguments as paths */

	char *nsnames = strtok((char *) optarg, "=");
	char *path    = strtok(NULL, "");

	/* Specifying a standalone path means that all namespaces should be persisted
	   into nsfs files relative to that directory path. */
	char all_namespaces[] = "cgroup,ipc,mnt,net,pid,time,user,uts";
	if (!path) {
		path = nsnames;
		nsnames = all_namespaces;
	}
	if (strcmp(nsnames, "all") == 0) {
		nsnames = all_namespaces;
	}

	size_t nsnames_len = strlen(nsnames);
	const char *share = strtok(nsnames, ",");
	bool multiple = share + strlen(share) != nsnames + nsnames_len;

	for (; share; share = strtok(NULL, ",")) {
		process_nslist_entry(out, share, path, multiple);
	}

	for (enum nstype ns = 0; ns < MAX_NS; ns++) {
		if (out[ns] == SHARE_WITH_PARENT) {
			err(2, "--persist must take a path to persist namespaces to");
		}
	}
}

static void handle_limit_arg(struct entry_settings *opts, char *optarg)
{
	struct opt {
		int resource;
		char const *name;
	};
	static const struct opt option_map[] = {
		{ BST_RLIMIT_AS,         "as"         },
		{ BST_RLIMIT_CORE,       "core"       },
		{ BST_RLIMIT_CPU,        "cpu"        },
		{ BST_RLIMIT_DATA,       "data"       },
		{ BST_RLIMIT_FSIZE,      "fsize"      },
		{ BST_RLIMIT_LOCKS,      "locks"      },
		{ BST_RLIMIT_MEMLOCK,    "memlock"    },
		{ BST_RLIMIT_MSGQUEUE,   "msgqueue"   },
		{ BST_RLIMIT_NICE,       "nice"       },
		{ BST_RLIMIT_NOFILE,     "nofile"     },
		{ BST_RLIMIT_NPROC,      "nproc"      },
		{ BST_RLIMIT_RSS,        "rss"        },
		{ BST_RLIMIT_RTPRIO,     "rtprio"     },
		{ BST_RLIMIT_RTTIME,     "rttime"     },
		{ BST_RLIMIT_SIGPENDING, "sigpending" },
		{ BST_RLIMIT_STACK,      "stack"      },
	};

	char *name = strtok(optarg, "=");
	char *arg = strtok(NULL, "");

	if (arg == NULL) {
		err(2, "--limit takes an argument in the form resource=value");
	}

	const struct opt *opt_ent = NULL;
	for (const struct opt *opt = option_map; opt < option_map + lengthof(option_map); ++opt) {
		if (strcmp(opt->name, name) == 0) {
			opt_ent = opt;
		}
	}

	if (opt_ent == NULL) {
		fprintf(stderr, "--limit: `%s` is not a valid resource name.\n", name);
		fprintf(stderr, "valid resources are: ");

		for (const struct opt *opt = option_map; opt < option_map + lengthof(option_map); ++opt) {
			fprintf(stderr, "%s%s", opt == option_map ? "" : ", ", opt->name);
		}
		fprintf(stderr, ".\n");
		exit(2);
	}

	if (parse_rlimit(opt_ent->resource, &opts->limits[opt_ent->resource].rlim, arg)) {
		err(1, "error in --limit %s value", opt_ent->name);
	}
	opts->limits[opt_ent->resource].present = true;
}

int usage(int error, char *argv0)
{
	/* Usage is generated from usage.txt. Note that the array is not null-terminated,
	   I couldn't find a way to convince xxd to do that for me, so instead
	   I just replace the last newline with a NUL and print an extra newline
	   from the usage function. */
	extern unsigned char usage_txt[];
	extern unsigned int usage_txt_len;

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
		{ "version",            no_argument,       NULL, OPTION_VERSION         },
		{ "workdir",            required_argument, NULL, OPTION_WORKDIR         },
		{ "mount",              required_argument, NULL, OPTION_MOUNT           },
		{ "uid",                required_argument, NULL, OPTION_UID             },
		{ "gid",                required_argument, NULL, OPTION_GID             },
		{ "groups",             required_argument, NULL, OPTION_GROUPS          },
		{ "arch",               required_argument, NULL, OPTION_ARCH            },
		{ "limit",              required_argument, NULL, OPTION_LIMIT           },
		{ "share",              required_argument, NULL, OPTION_SHARE           },
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
		{ "no-copy-hard-limits", no_argument, NULL, OPTION_NO_COPY_HARD_LIMITS  },
		{ "no-fake-devtmpfs",    no_argument, NULL, OPTION_NO_FAKE_DEVTMPFS     },
		{ "no-derandomize",      no_argument, NULL, OPTION_NO_DERANDOMIZE       },
		{ "no-proc-remount",     no_argument, NULL, OPTION_NO_PROC_REMOUNT      },
		{ "no-loopback-setup",   no_argument, NULL, OPTION_NO_LOOPBACK_SETUP    },
		{ "no-init",             no_argument, NULL, OPTION_NO_INIT              },
		{ "no-env",              no_argument, NULL, OPTION_NO_ENV               },

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

			case OPTION_VERSION:
				printf("%s\n", VERSION);
				return 0;

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

			case OPTION_LIMIT:
				handle_limit_arg(&opts, optarg);
				break;

			case OPTION_SHARE:
				process_share(opts.shares, optarg);
				break;

			case OPTION_PERSIST:
				process_persist(opts.persist, optarg);
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

			case OPTION_NO_COPY_HARD_LIMITS:
				opts.no_copy_hard_limits = 1;
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

			case OPTION_NO_ENV:
				opts.no_env = 1;
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

	/* ARG_MAX isn't really supposed to be the size of a pointer array, but
	   instead the size of the cmdline area... but this is a good enough upper
	   bound. */
	char *newenv[ARG_MAX];

	size_t i = 0;
	if (!opts.no_env) {
		for (char **e = envp; *e != NULL && i < ARG_MAX - 1; ++e, ++i) {
			newenv[i] = *e;
		}
	}

	/* Intepret any NAME=value at the start of the command line as environment
	   variable overrides. */
	for (; optind + 1 <= argc; ++optind) {
		char *c = argv[optind];
		for (; *c != '\0'; ++c) {
			if (*c == '=' && c != argv[optind]) {
				newenv[i++] = argv[optind];
				break;
			}
			if (!isalnum(*c) && *c != '_') {
				/* This is not a word, and thus not an environment variable
				   name, meaning this is the program name. */
				goto end;
			}
		}
		if (*c == '\0') {
			/* This was a word, but we didn't encounter an '='; this is also the
			   program name. */
			break;
		}
	}
end:
	newenv[i] = NULL;

	/* Use our own default init if we unshare the pid namespace, and no
	   --init has been specified. */
	if (opts.shares[NS_PID] == NULL && opts.init == NULL) {
		opts.init = BINDIR "/bst-init";
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
	opts.envp = newenv;

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
