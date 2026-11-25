/* Small static program for syscall mocking integration tests. */
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void show(const char *name, long number, long arg)
{
	errno = 0;
	long result = syscall(number, arg);
	printf("%s %ld %d\n", name, result, errno);
}

static int deny_mock_install(char **argv)
{
	struct sock_filter insns[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_seccomp, 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_SET_MODE_FILTER, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = { .len = sizeof (insns) / sizeof (insns[0]), .filter = insns };
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) {
		perror("deny mock install");
		return 1;
	}
	execvp(argv[0], argv);
	perror("execvp");
	return 1;
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return 2;
	if (!strcmp(argv[1], "syncs")) {
		show("fsync", SYS_fsync, -1);
		show("fdatasync", SYS_fdatasync, -1);
		show("syncfs", SYS_syncfs, -1);
	} else if (!strcmp(argv[1], "fork-exec")) {
		pid_t pid = fork();
		if (pid == 0) {
			execl("/proc/self/exe", "mock_probe", "syncs", (char *)NULL);
			_exit(1);
		}
		int status;
		if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
			return 1;
		return WEXITSTATUS(status);
	} else if (!strcmp(argv[1], "mkdir") && argc == 3) {
		errno = 0;
		long rc = syscall(SYS_mkdirat, AT_FDCWD, argv[2], 0700);
		printf("mkdirat %ld %d\n", rc, errno);
	} else if (!strcmp(argv[1], "mknod")) {
		errno = 0;
		long rc = syscall(SYS_mknodat, -1, "unused", S_IFCHR | 0600, 0x103);
		printf("mknodat %ld %d\n", rc, errno);
	} else if (!strcmp(argv[1], "number") && argc == 3) {
		char *end;
		long number = strtol(argv[2], &end, 10);
		if (!*argv[2] || *end || number < 0)
			return 2;
		show("syscall", number, -1);
	} else if (!strcmp(argv[1], "deny-install") && argc > 2) {
		return deny_mock_install(argv + 2);
	} else if (!strcmp(argv[1], "exec") && argc > 2) {
		execv(argv[2], argv + 2);
		if (errno == ENOEXEC)
			return 126;
		perror("execv");
		return 125;
	} else {
		return 2;
	}
	return 0;
}
