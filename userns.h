/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef USERNS_H_
# define USERNS_H_

# include <stdbool.h>
# include <stdint.h>

enum {
	MAX_USER_MAPPINGS = 340, /* as of linux 4.15, c.f. user_namespaces(7) */
};

struct id_range {
	uint32_t inner, outer, length;
};

typedef struct id_range id_map[MAX_USER_MAPPINGS];

void id_map_load_subids(id_map map, const char *subid_path, uint32_t id, const char *name);
void id_map_load_procids(id_map map, const char *procid_path);
void id_map_project(id_map map, id_map onto, id_map out);
void id_map_format(id_map map, char *out, size_t size);
void id_map_normalize(id_map map, bool inner, bool merge);

#endif /* !USERNS_H_ */
