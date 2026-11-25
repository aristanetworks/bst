#include <assert.h>
#include <linux/audit.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../mock_syscall.h"

static struct mock_syscall_rules rules;
static char error[256];

static void accepted(const char *arg)
{
	if (mock_syscall_parse(&rules, arg, error, sizeof (error))) {
		fprintf(stderr, "%s: %s\n", arg, error);
		assert(0);
	}
}

static void rejected(const char *arg, const char *message)
{
	size_t count = rules.count;
	assert(mock_syscall_parse(&rules, arg, error, sizeof (error)) == -1);
	assert(strstr(error, "--mock-syscall:") == error);
	assert(strstr(error, message));
	assert(rules.count == count);
}

static void check(size_t i, enum mock_syscall_abi abi, uint32_t arch,
		  uint32_t nr, int result)
{
	assert(i < rules.count);
	assert(rules.rules[i].abi == abi);
	assert(rules.rules[i].audit_arch == arch);
	assert(rules.rules[i].nr == nr);
	assert(rules.rules[i].result == result);
}

static void reset(void)
{
	mock_syscall_rules_free(&rules);
	assert(!rules.rules && !rules.count);
}

int main(void)
{
	const char *bad_fields[] = {
		"", ",", ",nr=read,ret=0", "nr=read,ret=0,",
		"nr=read,,ret=0", "nr=read,ret=0,,arch=x86_64",
		"nr=,ret=0", "nr=read,ret=", "nr=read,ret=0,arch=",
		"nr=read,ret=0=1", "nr=read,ret=0,=x", "nr=read,ret=0,arch",
	};
	const char *bad_returns[] = {
		"1", "+0", "-0", "-4096", "4096", "-1x", " 0", "0 ",
		"-999999999999999999999999999999", "0x0", "--1", "1.0",
	};
	for (size_t i = 0; i < sizeof (bad_fields) / sizeof (*bad_fields); ++i)
		rejected(bad_fields[i], "expected nonempty");
	for (size_t i = 0; i < sizeof (bad_returns) / sizeof (*bad_returns); ++i) {
		char arg[128];
		snprintf(arg, sizeof (arg), "nr=read,ret=%s", bad_returns[i]);
		rejected(arg, "ret must be 0 or");
	}
	rejected("nr=read", "required");
	rejected("ret=0", "required");
	rejected("nr=read,ret=0,foo=bar", "unknown key");
	rejected("nr=read,nr=write,ret=0", "duplicate key");
	rejected("ret=0,nr=read,ret=-1", "duplicate key");
	rejected("nr=read,ret=0,arch=x,arch=y", "duplicate key");
	rejected("nr=0,ret=0", "requires arch");
	rejected("nr=read,ret=0,arch=invalid", "unsupported arch");
	rejected("nr=no_such_syscall,ret=0", "unknown syscall");
	rejected("nr=SYS_read,ret=0", "unknown syscall");
	rejected("nr=__NR_read,ret=0", "unknown syscall");
	rejected("nr=-1,ret=0", "unknown syscall");
	rejected("nr= read,ret=0", "unknown syscall");
	rejected("nr=read ,ret=0", "unknown syscall");
	rejected("nr=READ,ret=0", "unknown syscall");

#if defined(MOCK_SYSCALL_TEST_X86)
	accepted("ret=-4095,nr=execve");
	assert(rules.count == 3);
	check(0, MOCK_ABI_X86_64, AUDIT_ARCH_X86_64, 59, -4095);
	check(1, MOCK_ABI_I386, AUDIT_ARCH_I386, 11, -4095);
	check(2, MOCK_ABI_X32, AUDIT_ARCH_X86_64, 0x40000000U + 520, -4095);
	rejected("arch=x32,ret=0,nr=520", "overlapping");
	rejected("arch=i386,ret=0,nr=11", "overlapping");
	rejected("nr=execve,ret=-4095", "overlapping");
	reset();
	accepted("nr=0,arch=x86_64,ret=0");
	accepted("arch=x32,nr=0,ret=-1");
	accepted("arch=i386,ret=0,nr=0");
	check(0, MOCK_ABI_X86_64, AUDIT_ARCH_X86_64, 0, 0);
	check(1, MOCK_ABI_X32, AUDIT_ARCH_X86_64, 0x40000000U, -1);
	check(2, MOCK_ABI_I386, AUDIT_ARCH_I386, 0, 0);
	rejected("nr=read,ret=0,arch=x86_64", "overlapping");
	reset();
	accepted("nr=11,ret=0,arch=i386");
	rejected("nr=execve,ret=0", "overlapping");
	assert(rules.count == 1);
	reset();
	accepted("nr=1073741823,ret=0,arch=x86_64");
	accepted("nr=1073741823,ret=0,arch=x32");
	accepted("nr=2147483647,ret=0,arch=i386");
	accepted("nr=10000,ret=000,arch=x86_64");
	check(1, MOCK_ABI_X32, AUDIT_ARCH_X86_64, 0x7fffffffU, 0);
	check(3, MOCK_ABI_X86_64, AUDIT_ARCH_X86_64, 10000, 0);
	rejected("nr=1073741824,ret=0,arch=x86_64", "out-of-range");
	rejected("nr=1073741824,ret=0,arch=x32", "out-of-range");
	rejected("nr=2147483648,ret=0,arch=i386", "out-of-range");
	rejected("nr=123junk,ret=0,arch=i386", "out-of-range");
	rejected("nr=9999999999999999999999999999999,ret=0,arch=i386", "out-of-range");
	rejected("nr=read,ret=0,arch=aarch64", "unsupported arch");
	reset();
	accepted("nr=map_shadow_stack,ret=0");
	assert(rules.count == 1);
	check(0, MOCK_ABI_X86_64, AUDIT_ARCH_X86_64, 453, 0);
	rejected("nr=map_shadow_stack,ret=0,arch=x32", "unknown syscall");
#elif defined(MOCK_SYSCALL_TEST_AARCH64)
	accepted("ret=-4095,nr=io_setup");
	assert(rules.count == 1);
	check(0, MOCK_ABI_AARCH64, AUDIT_ARCH_AARCH64, 0, -4095);
	rejected("nr=0,arch=aarch64,ret=0", "overlapping");
	reset();
	accepted("nr=2147483647,arch=aarch64,ret=0");
	check(0, MOCK_ABI_AARCH64, AUDIT_ARCH_AARCH64, 2147483647U, 0);
	accepted("nr=10000,arch=aarch64,ret=000");
	check(1, MOCK_ABI_AARCH64, AUDIT_ARCH_AARCH64, 10000, 0);
	rejected("nr=2147483648,ret=0,arch=aarch64", "out-of-range");
	rejected("nr=123junk,ret=0,arch=aarch64", "out-of-range");
	rejected("nr=99999999999999999999999999999,ret=0,arch=aarch64", "out-of-range");
	rejected("nr=read,ret=0,arch=i386", "unsupported arch");
	reset();
	accepted("arch=aarch64,nr=newfstatat,ret=-5");
	check(0, MOCK_ABI_AARCH64, AUDIT_ARCH_AARCH64, 79, -5);
	rejected("arch=aarch64,nr=arch_specific_syscall,ret=0", "unknown syscall");
#else
# error Select the metadata under test
#endif
	reset();
	return 0;
}
