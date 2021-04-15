/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#ifndef NET_H
# define NET_H

# include <net/ethernet.h>
# include <net/if.h>
# include <netinet/in.h>
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

struct ip {
	uint8_t type; // Either AF_INET or AF_INET6
	union {
		struct in_addr  v4;
		struct in6_addr v6;
	};
	uint8_t prefix_length;
};

struct addr_options {
	struct ip ip;
	char intf[IF_NAMESIZE];
};

struct route_options {
	uint8_t type; // Either AF_INET or AF_INET6
	struct ip src;
	struct ip dst;
	struct ip gateway;
	char intf[IF_NAMESIZE];
	uint32_t metric;
};

int init_rtnetlink_socket();

void net_addr_add(int sockfd, const struct addr_options *addropts);
void net_if_add(int sockfd, const struct nic_options *nicopts);
void net_if_rename(int sockfd, int link, const char *to);
void net_if_up(int sockfd, const char *name);
void net_route_add(int sockfd, const struct route_options *route);

void route_parse(struct route_options *route, const char *key, const char *val);
void addr_parse(struct addr_options *addr, const char *key, const char *val);
void nic_parse(struct nic_options *nic, const char *key, const char *val);

#endif /* !NET_H */
