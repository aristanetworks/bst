/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "userns.h"

enum {
	ID_MAX     = 65534,

	/* user/group names are within 32 digits (man useradd), and since
	   [UG]IDs are 32-bit, their stringified values will be at most 10-digits
	   long, so that also serves as an upper bound for stringified IDs. */
	ID_STR_MAX = 32,
};

static inline size_t id_map_append(id_map map, size_t nrange, uint32_t inner, uint32_t outer, uint32_t len)
{
	if (nrange >= MAX_USER_MAPPINGS) {
		errx(1, "load_subids: more than the max of %d mappings in use", MAX_USER_MAPPINGS);
	}
	map[nrange++] = (struct id_range) {
		.inner = inner,
		.outer = outer,
		.length = len
	};
	return nrange;
}

static char *itoa(int i)
{
	static char buf[ID_STR_MAX + 1];

	if ((size_t) snprintf(buf, sizeof (buf), "%d", i) >= sizeof (buf)) {
		errx(1, "\"%d\" takes more than %zu bytes.", i, sizeof (buf));
	}

	return buf;
}

/* id_map_load_subids generates the contents of a [ug]id map.

   First, a mapping of `id` to 0 (root) is generated.

   Then, the function reads each entry in subid_path, which are of the form
   <name_or_id>:<start>:<length>\n, finds any of these allocated [ug]id ranges
   for which name_or_id matches either `name` or `id`, and grafts them
   together as a continuous [ug]id map. The function tries to map every uid
   from 0 to 65534 in the user namespace. If there are less IDs allocated in
   subid_path, the function fills up the available IDs starting from 0, then
   prints a warning and returns.

   For instance, given the following /etc/subuid:

       $ cat /etc/subuid
       barney:100000:65535

   Then, calling the function as such:

       id_map_load_subids(map, "/etc/subuid", 1000, "barney");

   will populate the contents of `map` with the following data:

       0 1000 1
       1 100000 65534

   There is a special case for id 0 (root) if there are no allocated entries
   for it in subid_path. In that case, if the real uid of the program is 0,
   then load_subids maps 1:1 the host range 0-65534 into the user
   namespace. This is to provide a sane default while keeping some leeway for
   system configuration. */
void id_map_load_subids(id_map map, const char *subid_path, uint32_t id, const char *name)
{
	size_t range = 0;
	uint32_t cur_id = 1;

	FILE *subids = fopen(subid_path, "r");
	if (!subids) {
		goto no_subids;
	}

	char *id_str = itoa(id);
	if (name == NULL) {
		name = id_str;
	}

	memset(map, 0, sizeof (id_map));
	range = id_map_append(map, range, 0, id, 1);

	/* Realistically speaking, each line can only contain a maximum of
	   3 * ID_STR_MAX + 2 characters. We are being very generous because
	   size assumptions tend to bite back, and pages are extremely cheap. */
	char line[4096];

	while (fgets(line, sizeof (line), subids)) {
		char entryname[ID_STR_MAX + 1];
		entryname[ID_STR_MAX] = 0;

		int start;
		int length;

		_Static_assert(ID_STR_MAX == 32, "scanf width must be equal to ID_STR_MAX");
		int items = sscanf(line, "%32[^:]:%d:%d\n",
				entryname,
				&start,
				&length);

		if (items != 3) {
			continue;
		}

		if (strcmp(entryname, name) != 0 && strcmp(entryname, id_str) != 0) {
			continue;
		}

		range = id_map_append(map, range, cur_id, start, length);
		cur_id += length;
	}

	fclose(subids);

no_subids:
	/* We're root. We don't care. Map the host range 1:1. */
	if (cur_id == 1 && id == 0) {
		/* UINT32_MAX - 1 is explicitly left out because the kernel rejects it
		   (see user_namespaces(7)). */
		range = id_map_append(map, range, 1, 1, UINT32_MAX - 2);
		return;
	}

	/* Not enough subuids for a full mapping, but, well, it's not the end of
	   the world. Things might break, so let's at least tell the user. */

	if (!subids) {
		warnx("no range associated to %s in %s. Things may not work "
				"as expected, please allocate at least %d IDs for it.",
				name, subid_path, ID_MAX);
		return;
	}

	if (cur_id < ID_MAX) {
		warnx("not enough IDs allocated for %s in %s (currently %d allocated). "
				"Things may not work as expected, please allocate at least %d "
				"IDs for it.",
				name, subid_path, cur_id, ID_MAX);
	}
}

void id_map_load_procids(id_map map, const char *procid_path)
{
	size_t range = 0;

	FILE *subids = fopen(procid_path, "r");
	if (!subids) {
		err(1, "open %s", procid_path);
	}

	memset(map, 0, sizeof (id_map));

	char line[4096];
	while (fgets(line, sizeof (line), subids)) {
		uint32_t inner, outer, len;

		int items = sscanf(line, "%d%d%d\n", &inner, &outer, &len);
		if (items != 3) {
			err(1, "load_current_maps: invalid uid map format");
		}

		range = id_map_append(map, range, inner, outer, len);
	}

	fclose(subids);
}

/* id_map_project projects `map` onto `onto`, and stores the result in `out`.

   Projecting a map means splitting non-contiguous ranges in a manner that
   respects how `onto` is split, effectively following the same kind of
   id map layout.

   This kind of transformations are necessary due to how id map ranges are
   accepted by the kernel. If, for instance, your current ID map looks like:

       0        0        1
       1    10000      998
    1000     1000        1

   Then in order to map the range 0-1000 1:1, a newly created user namespace
   needs to produce the following uid map:

       0        0        1
       1        1      998
    1000     1000        1

   And in particular, it cannot just write "0 0 1000" in the uid_map file,
   because the range overlaps non-contiguous ranges in the parent uid map.

   Thus, if id_map_project is given an id_map with the "0 0 1000" range only,
   and gets the prior example uid_map as the map to projet onto, it will
   produce the example result, splitting the 1:1 mapping over 3 distinct
   ranges.

 */
void id_map_project(id_map map, id_map onto, id_map out)
{
	/* This is a fairly inefficient way to compute the intersection of
	   two interval maps. We should technically be using an interval tree
	   here, but these maps are fairly small, and doing this naive approach
	   is somewhat less complex to implement, although perhaps harder to
	   follow.

	   Here's what the transformation looks like:

	   onto:

	    *---------------------*         *-------*-------------*
	    |                     |         |       |             |
	    *---------------------*         *-------*-------------*

	   map:

	              *-*             *-----------------*
	              | |             |                 |
	              *-*             *-----------------*

	   out:
	              *-*                   *-------*---*
	              | |                   |       |   |
	              *-*                   *-------*---*

	 */

	id_map tmp;
	memset(tmp, 0, sizeof (tmp));

	size_t i = 0;
	size_t j = 0;
	size_t k = 0;

	struct id_range range = map[0];
	struct id_range onto_range = onto[0];

	while (i < MAX_USER_MAPPINGS && j < MAX_USER_MAPPINGS) {
		if (range.length == 0) {
			range = map[++i];
			continue;
		}

		if (onto_range.length == 0) {
			onto_range = onto[++j];
			continue;
		}

		if (onto_range.inner > range.outer) {
			size_t skip = onto_range.inner - range.outer;
			if (skip > range.length) {
				skip = range.length;
			}
			range.outer += skip;
			range.inner += skip;
			range.length -= skip;
			continue;
		}

		if (onto_range.inner < range.outer) {
			size_t skip = range.outer - onto_range.inner;
			if (skip > onto_range.length) {
				skip = onto_range.length;
			}
			onto_range.outer += skip;
			onto_range.inner += skip;
			onto_range.length -= skip;
			continue;
		}

		if (k == MAX_USER_MAPPINGS) {
			errx(1, "projecting guest map onto host id map would "
			        "result in more than %d mappings", MAX_USER_MAPPINGS);
		}

		uint32_t minlen = range.length < onto_range.length ? range.length : onto_range.length;

		k = id_map_append(tmp, k, range.inner, range.outer, minlen);

		onto_range.outer += minlen;
		onto_range.inner += minlen;
		onto_range.length -= minlen;
		range.outer += minlen;
		range.inner += minlen;
		range.length -= minlen;
	}

	memcpy(out, tmp, sizeof (tmp));
}

/* id_map_format writes the string representation of map into `out`.

   The [ug]id map is written to `out`, which is a string bounded by `size`,
   and which follows the format described in man 7 user_namespaces,
   § "User and group ID mappings: uid_map and gid_map". */
void id_map_format(id_map map, char *out, size_t size)
{
	for (struct id_range *r = map; r < map + MAX_USER_MAPPINGS; ++r) {
		if (r->length == 0) {
			continue;
		}

		int written = snprintf(out, size - 1, "%u %u %u\n", r->inner, r->outer, r->length);
		if ((size_t) written >= size - 1) {
			errx(1, "format_id_map: could not append to id map: buffer too small.");
		}
		out += written;
		size -= written;
		*out = 0;
	}
}

static int cmp_range(const struct id_range *lhs, const struct id_range *rhs, bool inner)
{
	if (lhs->length == 0) {
		return rhs->length != 0;
	}
	if (rhs->length == 0) {
		return -1;
	}

	if (inner) {
		return lhs->inner - rhs->inner;
	} else {
		return lhs->outer - rhs->outer;
	}
}

static int cmp_range_inner(const void *lhs, const void *rhs)
{
	return cmp_range(lhs, rhs, true);
}

static int cmp_range_outer(const void *lhs, const void *rhs)
{
	return cmp_range(lhs, rhs, false);
}

/* id_map_normalize ensures that the id_map follows a format suitable for
   other id_map operations, like id_map_project.

   A normalized map is sorted. If `inner` is true, the ranges are sorted in
   increasing order according to their `inner` field, and `outer` otherwise.

   If merge is true, contiguous ranges are also merged. */
void id_map_normalize(id_map map, bool inner, bool merge)
{
	qsort(map, MAX_USER_MAPPINGS, sizeof (map[0]), inner ? cmp_range_inner : cmp_range_outer);

	if (!merge) {
		return;
	}
	struct id_range *prev = map;
	for (struct id_range *r = map + 1; r < map + MAX_USER_MAPPINGS; ++r) {
		if (prev->inner + prev->length == r->inner && prev->outer + prev->length == r->outer) {
			prev->length += r->length;
		} else {
			*(++prev) = *r;
		}
	}
}
