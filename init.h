/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef INIT_H_
# define INIT_H_

# include <stdnoreturn.h>
# include <sys/wait.h>

noreturn void init(pid_t main_child_pid);

#endif /* end of include guard: INIT_H_ */
