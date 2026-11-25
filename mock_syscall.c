/* Copyright © 2026 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <linux/audit.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mock_syscall.h"

#if !defined(MOCK_SYSCALL_TEST_X86) && !defined(MOCK_SYSCALL_TEST_AARCH64)
# include "config.h"
#endif

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))
#define X32_SYSCALL_BIT 0x40000000U

struct mock_syscall_name {
	const char *name;
	uint32_t nr;
};

struct mock_syscall_abi_info {
	const char *name;
	enum mock_syscall_abi abi;
	uint32_t audit_arch;
	uint32_t max_nr;
	uint32_t nr_bit;
	const struct mock_syscall_name *names;
	size_t name_count;
};

#if defined(MOCK_SYSCALL_TEST_X86) || defined(ARCH_X86_64) || defined(ARCH_X86)
# include "arch/x86/mock-syscalls.inc"
static const struct mock_syscall_abi_info abis[] = {
	{ "x86_64", MOCK_ABI_X86_64, AUDIT_ARCH_X86_64, 0x3fffffffU, 0,
	  names_x86_64, ARRAY_SIZE(names_x86_64) },
	{ "i386", MOCK_ABI_I386, AUDIT_ARCH_I386, INT32_MAX, 0,
	  names_i386, ARRAY_SIZE(names_i386) },
	{ "x32", MOCK_ABI_X32, AUDIT_ARCH_X86_64, 0x3fffffffU, X32_SYSCALL_BIT,
	  names_x32, ARRAY_SIZE(names_x32) },
};
#elif defined(MOCK_SYSCALL_TEST_AARCH64) || defined(ARCH_AARCH64)
# include "arch/aarch64/mock-syscalls.inc"
static const struct mock_syscall_abi_info abis[] = {
	{ "aarch64", MOCK_ABI_AARCH64, AUDIT_ARCH_AARCH64, INT32_MAX, 0,
	  names_aarch64, ARRAY_SIZE(names_aarch64) },
};
#else
# error Unsupported architecture for mock syscalls
#endif

static int fail(char *error, size_t size, const char *reason)
{
	if (size)
		snprintf(error, size, "--mock-syscall: %s", reason);
	return -1;
}

/* Decimal only, with no sign, whitespace, suffix, or overflow. */
static bool decimal(const char *s, uint32_t max, uint32_t *value)
{
	uint32_t n = 0;
	if (!*s)
		return false;
	for (; *s; ++s) {
		uint32_t digit;
		if (*s < '0' || *s > '9')
			return false;
		digit = (uint32_t)(*s - '0');
		if (n > (max - digit) / 10)
			return false;
		n = n * 10 + digit;
	}
	*value = n;
	return true;
}

static bool lookup(const struct mock_syscall_abi_info *abi, const char *name,
		   uint32_t *nr)
{
	size_t lo = 0, hi = abi->name_count;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		int cmp = strcmp(name, abi->names[mid].name);
		if (!cmp) {
			*nr = abi->names[mid].nr | abi->nr_bit;
			return true;
		}
		if (cmp < 0)
			hi = mid;
		else
			lo = mid + 1;
	}
	return false;
}

int mock_syscall_parse(struct mock_syscall_rules *rules, const char *arg,
		       char *error, size_t error_size)
{
	char *copy = strdup(arg), *p, *next;
	const char *nr = NULL, *ret = NULL, *arch = NULL;
	const struct mock_syscall_abi_info *selected = NULL;
	struct mock_syscall_rule pending[ARRAY_SIZE(abis)];
	size_t count = 0;
	uint32_t magnitude;
	int result, rc = -1;

	if (!copy)
		return fail(error, error_size, "out of memory");
	for (p = copy; p; p = next) {
		char *eq;
		const char **field;
		next = strchr(p, ',');
		if (next)
			*next++ = '\0';
		eq = strchr(p, '=');
		if (!eq || eq == p || !eq[1] || strchr(eq + 1, '=')) {
			fail(error, error_size, "expected nonempty key=value fields");
			goto out;
		}
		*eq++ = '\0';
		if (!strcmp(p, "nr"))
			field = &nr;
		else if (!strcmp(p, "ret"))
			field = &ret;
		else if (!strcmp(p, "arch"))
			field = &arch;
		else {
			fail(error, error_size, "unknown key");
			goto out;
		}
		if (*field) {
			fail(error, error_size, "duplicate key");
			goto out;
		}
		*field = eq;
	}
	if (!nr || !ret) {
		fail(error, error_size, "nr and ret are required");
		goto out;
	}
	if (ret[0] == '-') {
		if (!decimal(ret + 1, 4095, &magnitude) || !magnitude) {
			fail(error, error_size, "ret must be 0 or a decimal error from -1 to -4095");
			goto out;
		}
		result = -(int)magnitude;
	} else {
		if (!decimal(ret, 4095, &magnitude) || magnitude != 0) {
			fail(error, error_size, "ret must be 0 or a decimal error from -1 to -4095");
			goto out;
		}
		result = 0;
	}
	if (arch) {
		for (size_t i = 0; i < ARRAY_SIZE(abis); ++i)
			if (!strcmp(arch, abis[i].name))
				selected = &abis[i];
		if (!selected) {
			fail(error, error_size, "unsupported arch");
			goto out;
		}
	}
	if (*nr >= '0' && *nr <= '9') {
		if (!selected) {
			fail(error, error_size, "numeric nr requires arch");
			goto out;
		}
		if (!decimal(nr, selected->max_nr, &magnitude)) {
			fail(error, error_size, "invalid or out-of-range numeric nr");
			goto out;
		}
		pending[count++] = (struct mock_syscall_rule){ selected->audit_arch,
			magnitude | selected->nr_bit, selected->abi, result };
	} else {
		for (size_t i = 0; i < ARRAY_SIZE(abis); ++i) {
			uint32_t number;
			if ((!selected || selected == &abis[i]) && lookup(&abis[i], nr, &number))
				pending[count++] = (struct mock_syscall_rule){ abis[i].audit_arch,
					number, abis[i].abi, result };
		}
		if (!count) {
			fail(error, error_size, "unknown syscall name for selected arch");
			goto out;
		}
	}
	for (size_t i = 0; i < count; ++i)
		for (size_t j = 0; j < rules->count; ++j)
			if (pending[i].audit_arch == rules->rules[j].audit_arch &&
			    pending[i].nr == rules->rules[j].nr) {
				fail(error, error_size, "overlapping syscall rules");
				goto out;
			}
	if (rules->count > SIZE_MAX / sizeof (*rules->rules) - count) {
		fail(error, error_size, "too many rules");
		goto out;
	}
	struct mock_syscall_rule *grown = realloc(rules->rules,
			(rules->count + count) * sizeof (*rules->rules));
	if (!grown) {
		fail(error, error_size, "out of memory");
		goto out;
	}
	rules->rules = grown;
	memcpy(rules->rules + rules->count, pending, count * sizeof (*pending));
	rules->count += count;
	rc = 0;
out:
	free(copy);
	return rc;
}

void mock_syscall_rules_free(struct mock_syscall_rules *rules)
{
	free(rules->rules);
	rules->rules = NULL;
	rules->count = 0;
}
