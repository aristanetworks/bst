#include <assert.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../mock_syscall.h"

extern const struct sock_filter syscall_filter[];
extern const size_t syscall_filter_length;

static void parse(struct mock_syscall_rules *rules, const char *arg)
{
	char error[256];
	if (mock_syscall_parse(rules, arg, error, sizeof (error))) {
		fprintf(stderr, "%s\n", error);
		abort();
	}
}

static void build(struct mock_syscall_rules *rules, struct mock_syscall_program *prog)
{
	char error[256];
	if (mock_syscall_build(rules, syscall_filter_length, prog, error, sizeof (error))) {
		fprintf(stderr, "%s\n", error);
		abort();
	}
}

static void allow_filter_installation(void)
{
	assert(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
}

static void actual_results(void)
{
	struct mock_syscall_rules rules = { 0 };
	struct mock_syscall_program prog = { 0 };
	parse(&rules, "nr=getpid,ret=-5");
	parse(&rules, "nr=getppid,ret=0");
	build(&rules, &prog);
	allow_filter_installation();
	assert(mock_syscall_install(&prog) == 0);
	errno = 0;
	assert(syscall(SYS_getpid) == -1 && errno == EIO);
	assert(syscall(SYS_getppid) == 0);
	assert(syscall(SYS_gettid) > 0);
}

static void large_filter(void)
{
	struct mock_syscall_rules rules = { 0 };
	struct mock_syscall_program prog = { 0 };
	char arg[100];
	/* This is the maximum program size for either supported native arch. */
#if defined(__x86_64__)
	const char *abi = "x86_64";
	const size_t count = (BPF_MAXINSNS - 10) / 2;
#elif defined(__i386__)
	const char *abi = "i386";
	const size_t count = (BPF_MAXINSNS - 10) / 2;
#elif defined(__aarch64__)
	const char *abi = "aarch64";
	const size_t count = (BPF_MAXINSNS - 6) / 2;
#else
# error Unsupported native test architecture
#endif
	for (size_t i = 0; i < count; ++i) {
		snprintf(arg, sizeof (arg), "nr=%zu,arch=%s,ret=-5", 10000 + i, abi);
		parse(&rules, arg);
	}
	build(&rules, &prog);
	assert(prog.length == BPF_MAXINSNS);
	allow_filter_installation();
	assert(mock_syscall_install(&prog) == 0);
	errno = 0;
	assert(syscall(10000 + (long)count - 1) == -1 && errno == EIO);
	assert(syscall(SYS_getpid) > 0);
}

static void notification_precedence(void)
{
	struct mock_syscall_rules rules = { 0 };
	struct mock_syscall_program prog = { 0 };
	struct sock_fprog old = {
		.len = (unsigned short)syscall_filter_length,
		.filter = (struct sock_filter *)syscall_filter,
	};
	parse(&rules, "nr=mknodat,ret=-5");
	build(&rules, &prog);
	allow_filter_installation();
	int listener = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
				    SECCOMP_FILTER_FLAG_NEW_LISTENER, &old);
	if (listener == -1 && (errno == EBUSY || errno == ENOSYS || errno == EINVAL || errno == EACCES)) {
		fprintf(stderr, "notification listener unavailable: %d\n", errno);
		_exit(77);
	}
	assert(listener >= 0);
	/* Model nested bst's listener failure before installing its mock filter. */
	errno = 0;
	assert(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
		       SECCOMP_FILTER_FLAG_NEW_LISTENER, &old) == -1 && errno == EBUSY);
	assert(mock_syscall_install(&prog) == 0);
	/* Without ERRNO winning over USER_NOTIF this would block; the parent
	 * imposes an alarm so the test cannot hang. */
	errno = 0;
	assert(syscall(SYS_mknodat, -1, "unused", 0, 0) == -1 && errno == EIO);
	assert(close(listener) == 0);
}

static void install_failure(void)
{
	struct mock_syscall_rules rules = { 0 };
	struct mock_syscall_program prog = { 0 };
	struct sock_filter deny[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_seccomp, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog blocker = {
		.len = (unsigned short)(sizeof (deny) / sizeof (deny[0])),
		.filter = deny,
	};
	parse(&rules, "nr=getpid,ret=0");
	build(&rules, &prog);
	allow_filter_installation();
	assert(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &blocker) == 0);
	errno = 0;
	assert(mock_syscall_install(&prog) == -1 && errno == EACCES);
	assert(syscall(SYS_getpid) > 0);
}

static int child_test(void (*fn)(void), int may_skip)
{
	pid_t pid = fork();
	assert(pid >= 0);
	if (!pid) {
		alarm(5);
		fn();
		_exit(0);
	}
	int status;
	assert(waitpid(pid, &status, 0) == pid);
	assert(WIFEXITED(status));
	int rc = WEXITSTATUS(status);
	assert(rc == 0 || (may_skip && rc == 77));
	return rc;
}

int main(void)
{
	child_test(actual_results, 0);
	child_test(large_filter, 0);
	int skipped = child_test(notification_precedence, 1);
	child_test(install_failure, 0);
	if (skipped)
		fprintf(stderr, "notification precedence test skipped\n");
	return 0;
}
