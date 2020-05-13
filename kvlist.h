/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef KVLIST_H_
# define KVLIST_H_

# include <stddef.h>

struct kvlist {
	char *key;
	char *value;
};

void kvlist_parse(char *in, struct kvlist *out, size_t len, char **rest);

#endif /* !KVLIST_H_ */
