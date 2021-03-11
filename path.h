/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef PATH_H_
# define PATH_H_

void cleanpath(char *path);
void makepath_r(char *out, char *fmt, ...);
char *makepath(char *fmt, ...);

#endif /* !PATH_H_ */
