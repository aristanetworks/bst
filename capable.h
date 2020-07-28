/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef CAPABLE_H_
# define CAPABLE_H_

# include <stdbool.h>
# include <sys/capability.h>

void init_capabilities(void);
bool capable(cap_value_t cap);
void make_capable(cap_value_t cap);
void reset_capabilities(void);

#endif /* !CAPABLE_H_ */
