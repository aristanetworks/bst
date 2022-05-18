/* Copyright © 2024 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef ARCH_H_
# define ARCH_H_

# include "config.h"

# define ARCH_STR_(x) #x
# define ARCH_STR(x) ARCH_STR_(x)

/* *INDENT-OFF* - formatters try to add spaces here */
# define ARCH_HEADER_BASE arch/ARCH
/* *INDENT-ON* */

# include ARCH_STR(ARCH_HEADER_BASE/syscall.h)

#endif /* !ARCH_H_ */
