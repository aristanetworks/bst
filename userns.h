/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef USERNS_H_
# define USERNS_H_

# include <stdbool.h>
# include <stddef.h>
# include <stdint.h>
# include <sys/types.h>

enum {
	MAX_USER_MAPPINGS = 340, /* as of linux 4.15, c.f. user_namespaces(7) */
};

struct id_range {
	uint32_t inner, outer, length;
};

typedef struct id_range id_map[MAX_USER_MAPPINGS];

struct id {
	uint32_t id;
	const char *name;
};

void id_map_parse(id_map map, char *opt);
void id_map_load_subids(id_map map, const char *subid_path, const struct id *id);
void id_map_generate(id_map allotted, id_map out, const char *subid_path, const struct id *id);
void id_map_load_procids(id_map map, const char *procid_path);
void id_map_project(id_map map, id_map onto, id_map out);
void id_map_format(id_map map, char *out, size_t size);
void id_map_normalize(id_map map, bool inner, bool merge);
bool id_map_empty(id_map map);
uint32_t id_map_count_ids(id_map map);

struct id id_load_user(uid_t uid);
struct id id_load_group(gid_t gid);

#endif /* !USERNS_H_ */
