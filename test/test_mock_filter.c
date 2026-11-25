#include <assert.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../mock_syscall.h"

extern const struct sock_filter syscall_filter[];
extern const size_t syscall_filter_length;

static uint32_t evaluate(const struct sock_filter *insns, size_t len,
			 uint32_t arch, uint32_t nr)
{
	uint32_t a = 0;
	for (size_t pc = 0; pc < len; ++pc) {
		struct sock_filter insn = insns[pc];
		switch (insn.code) {
		case BPF_LD | BPF_W | BPF_ABS:
			if (insn.k == offsetof(struct seccomp_data, arch))
				a = arch;
			else {
				assert(insn.k == offsetof(struct seccomp_data, nr));
				a = nr;
			}
			break;
		case BPF_ALU | BPF_SUB | BPF_K:
			a -= insn.k;
			break;
		case BPF_JMP | BPF_JEQ | BPF_K:
			pc += a == insn.k ? insn.jt : insn.jf;
			break;
		case BPF_JMP | BPF_JGE | BPF_K:
			pc += a >= insn.k ? insn.jt : insn.jf;
			break;
		case BPF_JMP | BPF_JA:
			pc += insn.k;
			break;
		case BPF_RET | BPF_K:
			return insn.k;
		default:
			assert(!"unexpected filter instruction");
		}
	}
	assert(!"filter did not return");
	return 0;
}

static uint32_t action(const struct mock_syscall_program *prog, uint32_t arch, uint32_t nr)
{
	return evaluate(prog->insns, prog->length, arch, nr);
}

static void add(struct mock_syscall_rules *rules, const char *arg)
{
	char error[256];
	if (mock_syscall_parse(rules, arg, error, sizeof (error))) {
		fprintf(stderr, "%s\n", error);
		assert(0);
	}
}

int main(void)
{
	struct mock_syscall_rules rules = { 0 };
	struct mock_syscall_program prog = { 0 };
	char error[256];
	assert(!mock_syscall_build(&rules, syscall_filter_length, &prog, error, sizeof (error)));
	assert(!prog.length && !prog.insns);
	add(&rules, "nr=fsync,ret=-5");
	add(&rules, "nr=mknodat,ret=0");
	add(&rules, "nr=sync,ret=0");
#if defined(MOCK_SYSCALL_TEST_X86)
	add(&rules, "nr=execve,ret=-1,arch=x32");
	add(&rules, "nr=read,ret=-2,arch=x86_64");
	add(&rules, "nr=stat64,ret=-5,arch=i386");
	assert(!mock_syscall_build(&rules, syscall_filter_length, &prog, error, sizeof (error)));
	assert(action(&prog, AUDIT_ARCH_X86_64, 74) == (SECCOMP_RET_ERRNO | 5));
	assert(action(&prog, AUDIT_ARCH_I386, 118) == (SECCOMP_RET_ERRNO | 5));
	assert(action(&prog, AUDIT_ARCH_X86_64, 0x40000000U + 74) == (SECCOMP_RET_ERRNO | 5));
	assert(action(&prog, AUDIT_ARCH_X86_64, 0x40000000U + 520) == (SECCOMP_RET_ERRNO | 1));
	assert(action(&prog, AUDIT_ARCH_X86_64, 59) == SECCOMP_RET_ALLOW);
	assert(action(&prog, AUDIT_ARCH_X86_64, 520) == SECCOMP_RET_ALLOW);
	assert(action(&prog, AUDIT_ARCH_X86_64, 0) == (SECCOMP_RET_ERRNO | 2));
	assert(action(&prog, AUDIT_ARCH_X86_64, 0x40000000U) == SECCOMP_RET_ALLOW);
	assert(action(&prog, AUDIT_ARCH_I386, 0) == SECCOMP_RET_ALLOW);
	assert(evaluate(syscall_filter, syscall_filter_length, AUDIT_ARCH_X86_64, 259) == SECCOMP_RET_USER_NOTIF);
	assert(action(&prog, AUDIT_ARCH_X86_64, 259) == SECCOMP_RET_ERRNO);
	assert(evaluate(syscall_filter, syscall_filter_length, AUDIT_ARCH_I386, 195) == SECCOMP_RET_USER_NOTIF);
	assert(action(&prog, AUDIT_ARCH_I386, 195) == (SECCOMP_RET_ERRNO | 5));
	assert(evaluate(syscall_filter, syscall_filter_length, AUDIT_ARCH_I386, 196) == SECCOMP_RET_USER_NOTIF);
	assert(action(&prog, AUDIT_ARCH_I386, 196) == SECCOMP_RET_ALLOW);
	assert(evaluate(syscall_filter, syscall_filter_length, AUDIT_ARCH_X86_64, 162) == SECCOMP_RET_ALLOW);
	assert(action(&prog, AUDIT_ARCH_X86_64, 162) == SECCOMP_RET_ERRNO);
	assert(action(&prog, AUDIT_ARCH_I386, 36) == SECCOMP_RET_ERRNO);
	assert(action(&prog, AUDIT_ARCH_X86_64, 0x40000000U + 162) == SECCOMP_RET_ERRNO);
	assert(action(&prog, AUDIT_ARCH_AARCH64, 0) == SECCOMP_RET_KILL_PROCESS);
#elif defined(MOCK_SYSCALL_TEST_AARCH64)
	add(&rules, "nr=io_setup,ret=-2,arch=aarch64");
	assert(!mock_syscall_build(&rules, syscall_filter_length, &prog, error, sizeof (error)));
	assert(action(&prog, AUDIT_ARCH_AARCH64, 82) == (SECCOMP_RET_ERRNO | 5));
	assert(action(&prog, AUDIT_ARCH_AARCH64, 0) == (SECCOMP_RET_ERRNO | 2));
	assert(action(&prog, AUDIT_ARCH_AARCH64, 80) == SECCOMP_RET_ALLOW);
	assert(evaluate(syscall_filter, syscall_filter_length, AUDIT_ARCH_AARCH64, 33) == SECCOMP_RET_USER_NOTIF);
	assert(action(&prog, AUDIT_ARCH_AARCH64, 33) == SECCOMP_RET_ERRNO);
	assert(evaluate(syscall_filter, syscall_filter_length, AUDIT_ARCH_AARCH64, 81) == SECCOMP_RET_ALLOW);
	assert(action(&prog, AUDIT_ARCH_AARCH64, 81) == SECCOMP_RET_ERRNO);
	assert(action(&prog, AUDIT_ARCH_I386, 0) == SECCOMP_RET_KILL_PROCESS);
	assert(action(&prog, AUDIT_ARCH_X86_64, 0) == SECCOMP_RET_KILL_PROCESS);
	assert(action(&prog, AUDIT_ARCH_ARM, 0) == SECCOMP_RET_KILL_PROCESS);
#endif
	assert(action(&prog, 0, 0) == SECCOMP_RET_KILL_PROCESS);
	assert(evaluate(syscall_filter, syscall_filter_length, 0, 0) == SECCOMP_RET_KILL_PROCESS);
	mock_syscall_program_free(&prog);
	mock_syscall_rules_free(&rules);

	/* Fill the first architecture body so that the second branch has a JA
	 * target well beyond the 8-bit conditional jump range. */
#if defined(MOCK_SYSCALL_TEST_X86)
	const size_t overhead = 10;
	const uint32_t first_arch = AUDIT_ARCH_X86_64;
	const enum mock_syscall_abi first_abi = MOCK_ABI_X86_64;
#else
	const size_t overhead = 6;
	const uint32_t first_arch = AUDIT_ARCH_AARCH64;
	const enum mock_syscall_abi first_abi = MOCK_ABI_AARCH64;
#endif
	rules.count = (BPF_MAXINSNS - overhead) / 2;
	rules.rules = calloc(rules.count, sizeof (*rules.rules));
	assert(rules.rules);
	for (size_t i = 0; i < rules.count; ++i) {
		rules.rules[i] = (struct mock_syscall_rule){ first_arch, (uint32_t)(10000 + i), first_abi, -5 };
	}
	assert(!mock_syscall_build(&rules, syscall_filter_length, &prog, error, sizeof (error)));
	assert(prog.length == BPF_MAXINSNS);
	assert(action(&prog, first_arch, 10000) == (SECCOMP_RET_ERRNO | 5));
	assert(action(&prog, first_arch, (uint32_t)(9999 + rules.count)) == (SECCOMP_RET_ERRNO | 5));
	assert(action(&prog, first_arch, 9999) == SECCOMP_RET_ALLOW);
#if defined(MOCK_SYSCALL_TEST_X86)
	assert(action(&prog, AUDIT_ARCH_I386, 10000) == SECCOMP_RET_ALLOW);
#endif
	mock_syscall_program_free(&prog);
	assert(mock_syscall_build(&rules, 32768, &prog, error, sizeof (error)) == -1);
	++rules.count;
	assert(mock_syscall_build(&rules, syscall_filter_length, &prog, error, sizeof (error)) == -1);
	rules.count = SIZE_MAX;
	assert(mock_syscall_build(&rules, syscall_filter_length, &prog, error, sizeof (error)) == -1);
	mock_syscall_rules_free(&rules);
	return 0;
}
