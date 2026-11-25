/* Copyright © 2026 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef MOCK_SYSCALL_H_
# define MOCK_SYSCALL_H_

# include <stddef.h>
# include <stdint.h>

enum mock_syscall_abi {
	MOCK_ABI_X86_64,
	MOCK_ABI_I386,
	MOCK_ABI_X32,
	MOCK_ABI_AARCH64,
};

/* nr is encoded exactly as it appears in seccomp_data, including x32's bit. */
struct mock_syscall_rule {
	uint32_t audit_arch;
	uint32_t nr;
	enum mock_syscall_abi abi;
	int result;
};

struct mock_syscall_rules {
	struct mock_syscall_rule *rules;
	size_t count;
};

/* On failure no rules are added; error contains an option-specific message. */
int mock_syscall_parse(struct mock_syscall_rules *rules, const char *arg,
		       char *error, size_t error_size);
void mock_syscall_rules_free(struct mock_syscall_rules *rules);

#endif /* !MOCK_SYSCALL_H_ */
