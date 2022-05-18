/* Copyright © 2022 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <stddef.h>
#include <linux/audit.h>

/* The following is the x86-64-specific BPF boilerplate code for checking
   that the BPF program is running on the right architecture + ABI. At
   completion of these instructions, the accumulator contains the system
   call number. */

/* For the x32 ABI, all system call numbers have bit 30 set */

#define X32_SYSCALL_BIT         0x40000000

#define CHECK_ARCH_AND_LOAD_SYSCALL_NR \
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
			(offsetof(struct seccomp_data, arch))), \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2), \
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
			(offsetof(struct seccomp_data, nr))), \
	BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1), \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)
