/* Copyright © 2026 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "mock_syscall.h"

#if !defined(MOCK_SYSCALL_TEST_X86) && !defined(MOCK_SYSCALL_TEST_AARCH64)
# include "config.h"
#endif

#define X32_SYSCALL_BIT 0x40000000U
/* Linux counts four extra instructions for each earlier stacked filter. */
#define MAX_INSNS_PER_PATH 32768U

#if defined(MOCK_SYSCALL_TEST_X86) || defined(ARCH_X86_64) || defined(ARCH_X86)
static const uint32_t supported_arches[] = { AUDIT_ARCH_X86_64, AUDIT_ARCH_I386 };
#elif defined(MOCK_SYSCALL_TEST_AARCH64) || defined(ARCH_AARCH64)
static const uint32_t supported_arches[] = { AUDIT_ARCH_AARCH64 };
#else
# error Unsupported architecture for mock syscalls
#endif
#define NARCHES (sizeof (supported_arches) / sizeof (supported_arches[0]))

static int fail(char *error, size_t size, const char *reason)
{
	if (size)
		snprintf(error, size, "--mock-syscall: %s", reason);
	return -1;
}

static int valid_rule(const struct mock_syscall_rule *r)
{
	if (r->result > 0 || r->result < -4095)
		return 0;
	switch (r->abi) {
	case MOCK_ABI_X86_64:
		return r->audit_arch == AUDIT_ARCH_X86_64 && r->nr < X32_SYSCALL_BIT;
	case MOCK_ABI_X32:
		return r->audit_arch == AUDIT_ARCH_X86_64 &&
			(r->nr & 0xc0000000U) == X32_SYSCALL_BIT;
	case MOCK_ABI_I386:
		return r->audit_arch == AUDIT_ARCH_I386 && r->nr <= INT32_MAX;
	case MOCK_ABI_AARCH64:
		return r->audit_arch == AUDIT_ARCH_AARCH64 && r->nr <= INT32_MAX;
	}
	return 0;
}

int mock_syscall_build(const struct mock_syscall_rules *rules,
		       size_t previous_length, struct mock_syscall_program *program,
		       char *error, size_t error_size)
{
	/* Header: load arch, JEQ/JA per architecture, kill. Each architecture
	 * body loads nr, emits JEQ/RET per rule, and ends with ALLOW. */
	const size_t overhead = 2 + 4 * NARCHES;
	size_t counts[NARCHES], start[NARCHES];
	size_t length, pos;
	struct sock_filter *insns;

	if (!rules->count)
		return 0;
	if (rules->count > (BPF_MAXINSNS - overhead) / 2)
		return fail(error, error_size, "filter exceeds kernel instruction limit");
	length = overhead + rules->count * 2;
	if (previous_length > MAX_INSNS_PER_PATH - 4 ||
	    length > MAX_INSNS_PER_PATH - 4 - previous_length)
		return fail(error, error_size, "filters exceed kernel stacked instruction limit");
	if (length > SIZE_MAX / sizeof (*insns))
		return fail(error, error_size, "filter allocation is too large");
	for (size_t a = 0; a < NARCHES; ++a)
		counts[a] = 0;
	for (size_t i = 0; i < rules->count; ++i) {
		const struct mock_syscall_rule *rule = &rules->rules[i];
		size_t a;
		if (!valid_rule(rule))
			return fail(error, error_size, "invalid normalized rule");
		for (a = 0; a < NARCHES && rule->audit_arch != supported_arches[a]; ++a)
			;
		if (a == NARCHES)
			return fail(error, error_size, "unsupported rule architecture");
		++counts[a];
	}
	insns = calloc(length, sizeof (*insns));
	if (!insns)
		return fail(error, error_size, "out of memory building filter");
	pos = 2 + 2 * NARCHES;
	for (size_t a = 0; a < NARCHES; ++a) {
		start[a] = pos;
		pos += 2 + 2 * counts[a];
	}
	pos = 0;
	insns[pos++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
						     offsetof(struct seccomp_data, arch));
	for (size_t a = 0; a < NARCHES; ++a) {
		insns[pos++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
							     supported_arches[a], 0, 1);
		/* length <= BPF_MAXINSNS, so this offset fits the 32-bit JA. */
		insns[pos] = (struct sock_filter) BPF_STMT(BPF_JMP | BPF_JA,
							 (uint32_t)(start[a] - pos - 1));
		++pos;
	}
	insns[pos++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
	for (size_t a = 0; a < NARCHES; ++a) {
		insns[pos++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
							     offsetof(struct seccomp_data, nr));
		for (size_t i = 0; i < rules->count; ++i) {
			const struct mock_syscall_rule *rule = &rules->rules[i];
			if (rule->audit_arch != supported_arches[a])
				continue;
			insns[pos++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
								     rule->nr, 0, 1);
			insns[pos++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K,
								    SECCOMP_RET_ERRNO | (uint32_t)-rule->result);
		}
		insns[pos++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
	}
	program->insns = insns;
	program->length = length;
	return 0;
}

int mock_syscall_install(const struct mock_syscall_program *program)
{
	if (!program->length)
		return 0;
	if (program->length > BPF_MAXINSNS) {
		errno = EINVAL;
		return -1;
	}
	struct sock_fprog prog = {
		.len = (unsigned short)program->length,
		.filter = program->insns,
	};
	return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}

void mock_syscall_program_free(struct mock_syscall_program *program)
{
	free(program->insns);
	program->insns = NULL;
	program->length = 0;
}
