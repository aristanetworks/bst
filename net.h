/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef NET_H
# define NET_H

# include <net/ethernet.h>
# include <net/if.h>
# include <stdint.h>

struct macvlan {
	uint32_t mode;
};

struct ipvlan {
	uint32_t mode;
};

struct nic_options {
	char type[16];
	char name[IF_NAMESIZE];
	unsigned link_idx;
	pid_t netns_pid;
	struct ether_addr address;
	struct ether_addr broadcast;
	union {
		struct macvlan macvlan;
		struct ipvlan ipvlan;
	};
};

int init_rtnetlink_socket();

void net_if_add(int sockfd, const struct nic_options *nicopts);
void net_if_rename(int sockfd, int link, const char *to);
void net_if_up(int sockfd, const char *name);

void nic_parse(struct nic_options *nic, const char *key, const char *val);

#endif /* !NET_H */
