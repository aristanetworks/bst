/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <string.h>
#include "kvlist.h"

void kvlist_parse(char *in, struct kvlist *out, size_t len, char **rest)
{
	char *end = in + strlen(in);
	char *save = NULL;
	char *tok = strtok_r(in, ",", &save);

	for (size_t i = 0; i < len; ++i) {
		if (tok == NULL) {
			out[i].key   = NULL;
			out[i].value = NULL;
			continue;
		}
		char *save2 = NULL;
		out[i].key   = strtok_r(tok, "=", &save2);
		out[i].value = strtok_r(NULL, "", &save2);
		tok = strtok_r(NULL, ",", &save);
	}

	if (rest != NULL) {
		/* There might be more tokens after that, but we don't have enough space
		   to store them. Re-join the last token with the tail if necessary, and
		   populate *rest with that. */
		if (tok != NULL) {
			size_t toklen = strlen(tok);
			if (tok + toklen != end) {
				tok[toklen] = ',';
			}
		}

		*rest = tok;
	}
}
