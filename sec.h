/* Copyright © 2022 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef SEC_H_
# define SEC_H_

# include <stdnoreturn.h>

int sec_seccomp_install_filter(void);
noreturn void sec_seccomp_supervisor(int);

extern int sec_seccomp_fix_stat_32bit;
extern int sec_seccomp_emulate_mknod;

#endif /* !SEC_H_ */
