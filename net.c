/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "compat.h"
#include "net.h"

// NLA_HDRLEN is defined with -Wsign-conversion errors, so just define our own here,
// making sure that the values match.
#define _NLA_HDRLEN ((int) NLA_ALIGN((int)(sizeof(struct nlattr))))
_Static_assert((_NLA_HDRLEN) == (NLA_HDRLEN), "NLA_HDRLEN mismatch");


int init_rtnetlink_socket()
{
	int sockfd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE);
	if (sockfd == -1) {
		err(1, "socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE");
	}
	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
	};
	if (bind(sockfd, (struct sockaddr *)&addr, sizeof (addr)) == -1) {
		err(1, "bind");
	}
	return sockfd;
}

static int nl_sendmsg(int sockfd, const struct iovec *iov, size_t iovlen)
{
	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
	};

	struct msghdr msg = {
		.msg_name = &addr,
		.msg_namelen = sizeof (addr),
		.msg_iov = (struct iovec *) iov,
		.msg_iovlen = iovlen,
	};

	if (sendmsg(sockfd, &msg, 0) == -1) {
		err(1, "nl_sendmsg: sendmsg");
	}

	struct {
		struct nlmsghdr hdr;
		struct nlmsgerr err;
	} resp;

	if (recv(sockfd, &resp, sizeof (resp), MSG_TRUNC) == -1) {
		err(1, "nl_sendmsg: recv");
	}

	if (resp.hdr.nlmsg_type == NLMSG_ERROR && resp.err.error != 0) {
		errno = -resp.err.error;
		return -1;
	}
	return 0;
}

struct nlpkt {
	struct {
		struct nlmsghdr nlhdr;
		union {
			struct ifinfomsg ifinfo;
			struct ifaddrmsg ifaddr;
			struct rtmsg rt;
		};
	} *hdr;
	char *data;
	size_t capacity;
};

static void nlpkt_init(struct nlpkt *pkt, size_t hdr_extra_size)
{
	pkt->data = calloc(1, 4096);
	pkt->capacity = 4096;
	pkt->hdr = (void *) pkt->data;
	pkt->hdr->nlhdr.nlmsg_len = NLMSG_HDRLEN + NLMSG_ALIGN(hdr_extra_size);
}

static void nlpkt_close(struct nlpkt *pkt)
{
	free(pkt->data);
}

static struct nlattr *nlpkt_append_attr(struct nlpkt *pkt, uint16_t type, size_t size)
{
	if (size > UINT16_MAX - _NLA_HDRLEN) {
		errx(1, "attribute size %zu overflows uint16_t", _NLA_HDRLEN + size);
	}

	uint32_t aligned = (uint32_t)(NLA_ALIGN(_NLA_HDRLEN + (int)size));
	uint32_t sz = pkt->hdr->nlhdr.nlmsg_len;

	if (sz > UINT32_MAX - aligned) {
		errno = EOVERFLOW;
		err(1, "could not reserve %" PRIu32 " more bytes for netlink packet buffer", aligned);
	}

	if (sz + aligned > pkt->capacity) {
		while (sz + aligned > pkt->capacity) {
			if (pkt->capacity > UINT32_MAX >> 1) {
				errno = EOVERFLOW;
				err(1, "could not resize netlink packet buffer");
			}
			pkt->capacity <<= 1;
		}
		pkt->data = realloc(pkt->data, pkt->capacity);
	}

	void *ptr = pkt->data + sz;
	memset(ptr, 0, aligned);

	struct nlattr *attr = ptr;
	attr->nla_len = (uint16_t) (_NLA_HDRLEN + size);
	attr->nla_type = type;

	pkt->hdr->nlhdr.nlmsg_len += aligned;
	return attr;
}

static inline uint16_t nlpkt_attr_sublen(uint32_t hi, uint32_t lo)
{
	assert(hi >= lo);
	if (hi - lo > UINT16_MAX) {
		errx(1, "nested attribute list size %" PRIu32 "overflows uint16_t", hi - lo);
	}
	return (uint16_t) (hi - lo);
}

static inline void nlpkt_add_attr_sz(struct nlpkt *pkt, uint16_t type, const void *ptr, size_t size, size_t padding)
{
	struct nlattr *attr = nlpkt_append_attr(pkt, type, size + padding);
	memcpy((char *) attr + _NLA_HDRLEN, ptr, size);
}

#define nlpkt_add_attr(Pkt, Type, Val) \
	nlpkt_add_attr_sz((Pkt), (Type), &(Val), sizeof (Val), 0)

#define nlpkt_add_attr_nstr(Pkt, Type, Val) \
	nlpkt_add_attr_sz((Pkt), (Type), &(Val), strnlen((Val), sizeof (Val)), 1)

/* This abuses a bit the C syntax for some syntactic sugar */

#define nlpkt_attrlist(Pkt, Type) \
	for (int __ok = 1; __ok;) \
	for (uint32_t __size = (Pkt)->hdr->nlhdr.nlmsg_len; __ok;) \
	for (struct nlattr *__attr = nlpkt_append_attr((Pkt), NLA_F_NESTED | (Type), 0); __ok; \
			__attr->nla_len = nlpkt_attr_sublen((Pkt)->hdr->nlhdr.nlmsg_len, __size), \
			__ok = 0)

static void add_macvlan_attrs(struct nlpkt *pkt, const struct nic_options *nicopts)
{
	nlpkt_add_attr(pkt, IFLA_LINK, nicopts->link_idx);

	nlpkt_attrlist(pkt, IFLA_LINKINFO) {
		nlpkt_add_attr_nstr(pkt, IFLA_INFO_KIND, nicopts->type);
		nlpkt_attrlist(pkt, IFLA_INFO_DATA) {
			uint32_t mode = nicopts->macvlan.mode;
			if (!mode) {
				mode = MACVLAN_MODE_PRIVATE;
			}
			nlpkt_add_attr(pkt, IFLA_MACVLAN_MODE, mode);
		}
	}
}

static void add_ipvlan_attrs(struct nlpkt *pkt, const struct nic_options *nicopts)
{
	nlpkt_add_attr(pkt, IFLA_LINK, nicopts->link_idx);

	nlpkt_attrlist(pkt, IFLA_LINKINFO) {
		nlpkt_add_attr_nstr(pkt, IFLA_INFO_KIND, nicopts->type);
		nlpkt_attrlist(pkt, IFLA_INFO_DATA) {
			nlpkt_add_attr(pkt, IFLA_IPVLAN_MODE, nicopts->ipvlan.mode);
			nlpkt_add_attr(pkt, IFLA_IPVLAN_FLAGS, nicopts->ipvlan.modeflags);
		}
	}
}

static void add_default_attrs(struct nlpkt *pkt, const struct nic_options *nicopts)
{
	nlpkt_attrlist(pkt, IFLA_LINKINFO) {
		nlpkt_add_attr_nstr(pkt, IFLA_INFO_KIND, nicopts->type);
	}
}

typedef void nic_handler_func(struct nlpkt *, const struct nic_options *);

struct nic_handler {
	const char *name;
	nic_handler_func *handler;
};

static struct nic_handler nic_handlers[] = {
	{ "macvlan", add_macvlan_attrs },
	{ "macvtap", add_macvlan_attrs },
	{ "ipvlan",  add_ipvlan_attrs },
	{ NULL, NULL },
};

void net_if_add(int sockfd, const struct nic_options *nicopts)
{
	struct nlpkt pkt;
	nlpkt_init(&pkt, sizeof (struct ifinfomsg));

	pkt.hdr->nlhdr.nlmsg_type = RTM_NEWLINK;
	pkt.hdr->nlhdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;

	nlpkt_add_attr(&pkt, IFLA_NET_NS_PID, nicopts->netns_pid);

	static struct ether_addr zeromac;
	if (memcmp(&nicopts->address, &zeromac, sizeof (nicopts->address)) != 0)
		nlpkt_add_attr(&pkt, IFLA_ADDRESS, nicopts->address);
	if (memcmp(&nicopts->broadcast, &zeromac, sizeof (nicopts->broadcast)) != 0)
		nlpkt_add_attr(&pkt, IFLA_BROADCAST, nicopts->broadcast);

	nic_handler_func *handler = add_default_attrs;
	for (struct nic_handler *h = nic_handlers; h->name; ++h) {
		if (strncmp(h->name, nicopts->type, sizeof (nicopts->type)) == 0) {
			handler = h->handler;
			break;
		}
	}
	handler(&pkt, nicopts);

	struct iovec iov = { .iov_base = pkt.data, .iov_len = pkt.hdr->nlhdr.nlmsg_len };

	if (nl_sendmsg(sockfd, &iov, 1) == -1) {
		err(1, "if_add %s %.*s", nicopts->type, IF_NAMESIZE, nicopts->name);
	}

	nlpkt_close(&pkt);
}

void net_if_rename(int sockfd, int link, const char *to)
{
	struct nlpkt pkt;
	nlpkt_init(&pkt, sizeof (struct ifinfomsg));

	pkt.hdr->nlhdr.nlmsg_type = RTM_NEWLINK;
	pkt.hdr->nlhdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	pkt.hdr->ifinfo.ifi_index = link;

	nlpkt_add_attr_sz(&pkt, IFLA_IFNAME, to, strlen(to), 1);

	struct iovec iov = { .iov_base = pkt.data, .iov_len = pkt.hdr->nlhdr.nlmsg_len };

	if (nl_sendmsg(sockfd, &iov, 1) == -1) {
		char name[IF_NAMESIZE];
		if_indextoname((unsigned int)link, name);
		err(1, "if_rename %.*s -> %.*s", IF_NAMESIZE, name, IF_NAMESIZE, to);
	}

	nlpkt_close(&pkt);
}

void net_if_up(int sockfd, const char *name)
{
	struct nlmsghdr hdr = {
		.nlmsg_type = RTM_NEWLINK,
		.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		.nlmsg_len = sizeof (hdr),
	};

	struct ifinfomsg ifinfo = {
		.ifi_index = (int)if_nametoindex(name),
		.ifi_flags = IFF_UP,
	};
	hdr.nlmsg_len += (unsigned int)(sizeof (ifinfo));

	if (ifinfo.ifi_index == 0) {
		err(1, "if_up %s: if_nametoindex", name);
	}

	struct iovec iov[] = {
		{ .iov_base = &hdr,    .iov_len = sizeof (hdr) },
		{ .iov_base = &ifinfo, .iov_len = sizeof (ifinfo) },
	};

	if (nl_sendmsg(sockfd, iov, sizeof (iov) / sizeof (struct iovec)) == -1) {
		err(1, "if_up %.*s", IF_NAMESIZE, name);
	}
}

void net_route_add(int sockfd, const struct route_options *route)
{
	struct nlpkt pkt;
	nlpkt_init(&pkt, sizeof (struct rtmsg));

	pkt.hdr->nlhdr.nlmsg_type = RTM_NEWROUTE;
	pkt.hdr->nlhdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;

	pkt.hdr->rt.rtm_family = route->family;
	pkt.hdr->rt.rtm_dst_len = route->dst.prefix_length;
	pkt.hdr->rt.rtm_src_len = route->src.prefix_length;
	pkt.hdr->rt.rtm_table = route->table;
	pkt.hdr->rt.rtm_protocol = route->protocol;
	pkt.hdr->rt.rtm_scope = (uint8_t) route->scope;
	pkt.hdr->rt.rtm_type = route->type;

	const void *dst_ptr, *src_ptr, *gateway_ptr;
	size_t ip_sz;

	switch (route->family) {
	case AF_INET6:
		ip_sz = sizeof (route->src.v6);
		gateway_ptr = &route->gateway.v6;
		dst_ptr = &route->dst.v6;
		src_ptr = &route->src.v6;
		break;
	case AF_INET:
		ip_sz = sizeof (route->src.v4);
		gateway_ptr = &route->gateway.v4;
		dst_ptr = &route->dst.v4;
		src_ptr = &route->src.v4;
		break;
	default:
		err(1, "route must either be ipv6 or ipv4");
	}

	if (route->gateway.type != 0) {
		nlpkt_add_attr_sz(&pkt, RTA_GATEWAY, gateway_ptr, ip_sz, 0);
	}
	if (route->src.type != 0) {
		nlpkt_add_attr_sz(&pkt, RTA_SRC, src_ptr, ip_sz, 0);
	}
	if (route->dst.type != 0) {
		nlpkt_add_attr_sz(&pkt, RTA_DST, dst_ptr, ip_sz, 0);
	}
	if (route->metric > 0) {
		nlpkt_add_attr(&pkt, RTA_PRIORITY, route->metric);
	}
	if (route->intf[0] != '\0') {
		uint32_t link_idx = if_nametoindex(route->intf);
		if (link_idx == 0) {
			err(1, "if_nametoindex %s", route->intf);
		}
		nlpkt_add_attr(&pkt, RTA_OIF, link_idx);
	}

	struct iovec iov = { .iov_base = pkt.data, .iov_len = pkt.hdr->nlhdr.nlmsg_len };

	if (nl_sendmsg(sockfd, &iov, 1) == -1) {
		char dst[INET6_ADDRSTRLEN+1];
		char src[INET6_ADDRSTRLEN+1];
		char gateway[INET6_ADDRSTRLEN+1];

		inet_ntop(route->family, dst_ptr, dst, sizeof (dst));
		dst[INET6_ADDRSTRLEN] = '\0';

		inet_ntop(route->family, src_ptr, src, sizeof (src));
		src[INET6_ADDRSTRLEN] = '\0';

		inet_ntop(route->family, gateway_ptr, gateway, sizeof (gateway));
		gateway[INET6_ADDRSTRLEN] = '\0';

		err(1, "route_add %s/%d via %s/%d src %s/%d dev %.*s metric %d",
				dst, route->dst.prefix_length,
				gateway, route->gateway.prefix_length,
				src, route->src.prefix_length,
				IF_NAMESIZE, route->intf,
				route->metric);
	}

	nlpkt_close(&pkt);
}

void net_addr_add(int sockfd, const struct addr_options *addr)
{
	struct nlpkt pkt;
	nlpkt_init(&pkt, sizeof (struct ifaddrmsg));

	pkt.hdr->nlhdr.nlmsg_type = RTM_NEWADDR;
	pkt.hdr->nlhdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;

	uint32_t link_idx = if_nametoindex(addr->intf);
	if (link_idx == 0) {
		err(1, "if_nametoindex %s", addr->intf);
	}

	pkt.hdr->ifaddr.ifa_family = addr->ip.type;
	pkt.hdr->ifaddr.ifa_prefixlen = addr->ip.prefix_length;
	pkt.hdr->ifaddr.ifa_scope = RT_SCOPE_UNIVERSE;
	pkt.hdr->ifaddr.ifa_index = link_idx;

	switch (addr->ip.type) {
	case AF_INET6:
		nlpkt_add_attr(&pkt, IFA_LOCAL, addr->ip.v6);
		nlpkt_add_attr(&pkt, IFA_ADDRESS, addr->ip.v6);
		break;
	case AF_INET:
		{
			nlpkt_add_attr(&pkt, IFA_LOCAL, addr->ip.v4);
			uint32_t broadcast = htonl(ntohl(*(uint32_t*)&addr->ip.v4) | (uint32_t) ((1 << (32 - addr->ip.prefix_length)) - 1));
			nlpkt_add_attr(&pkt, IFA_BROADCAST, broadcast);
			nlpkt_add_attr(&pkt, IFA_ADDRESS, addr->ip.v4);
		}
		break;
	}

	struct iovec iov = { .iov_base = pkt.data, .iov_len = pkt.hdr->nlhdr.nlmsg_len };

	if (nl_sendmsg(sockfd, &iov, 1) == -1) {
		char ip[INET6_ADDRSTRLEN+1];
		inet_ntop(addr->ip.type, &addr->ip.v6, ip, sizeof (ip));
		ip[INET6_ADDRSTRLEN] = '\0';
		err(1, "addr_add %s/%d %.*s", ip, addr->ip.prefix_length, IF_NAMESIZE, addr->intf);
	}

	nlpkt_close(&pkt);
}

struct valmap {
	const char *name;
	const void *val;
};

static int parse_val(void *dst, size_t size, const struct valmap *map, const char *name)
{
	if (name == NULL) {
		return -1;
	}
	for (const struct valmap *e = &map[0]; e->name != NULL; ++e) {
		if (strcmp(name, e->name) != 0) {
			continue;
		}
		memcpy(dst, e->val, size);
		return 0;
	}
	return -1;
}

static const struct valmap macvlan_mode_values[] = {
	{ "private",  &(const uint32_t) { MACVLAN_MODE_PRIVATE  } },
	{ "vepa",     &(const uint32_t) { MACVLAN_MODE_VEPA     } },
	{ "bridge",   &(const uint32_t) { MACVLAN_MODE_BRIDGE   } },
	{ "passthru", &(const uint32_t) { MACVLAN_MODE_PASSTHRU } },
	{ "source",   &(const uint32_t) { MACVLAN_MODE_SOURCE   } },
	{ NULL, NULL },
};

static void nic_parse_macvlan_mode(struct nic_options *nic, const char *v)
{
	if (parse_val(&nic->macvlan.mode, sizeof (nic->macvlan.mode), macvlan_mode_values, v) == -1) {
		errx(1, "invalid MACVLAN mode %s", v);
	}
}

static const struct valmap ipvlan_mode_values[] = {
	{ "l2",  &(const uint32_t) { IPVLAN_MODE_L2  } },
	{ "l3",  &(const uint32_t) { IPVLAN_MODE_L3  } },
	{ "l3s", &(const uint32_t) { IPVLAN_MODE_L3S } },
	{ NULL, NULL },
};

static const struct valmap ipvlan_modeflag_values[] = {
	{ "bridge",  &(const uint32_t) { 0                } },
	{ "private", &(const uint32_t) { IPVLAN_F_PRIVATE } },
	{ "vepa",    &(const uint32_t) { IPVLAN_F_VEPA    } },
	{ NULL, NULL },
};

static void nic_parse_ipvlan_mode(struct nic_options *nic, const char *v)
{
	char buf[1024];
	strncpy(buf, v, sizeof(buf)-1);
	if (strnlen(buf, sizeof(buf)-1) >= sizeof(buf)-1) {
		errx(1, "invalid IPVLAN mode %s: value too large", v);
	}
	char *saveptr;

	char *mode = strtok_r(buf, "+", &saveptr);
	if (parse_val(&nic->ipvlan.mode, sizeof (nic->ipvlan.mode), ipvlan_mode_values, mode) == -1) {
		errx(1, "invalid IPVLAN mode %s in %s", mode, v);
	}

	char *flag;
	while ((flag = strtok_r(NULL, "+", &saveptr)) != NULL) {
		uint32_t flagval;
		if (parse_val(&flagval, sizeof (flagval), ipvlan_modeflag_values, flag) == -1) {
			errx(1, "invalid IPVLAN mode flag %s in %s", flag, v);
		}

		nic->ipvlan.modeflags |= flagval;
	}
}

static void nic_parse_link(struct nic_options *nic, const char *v)
{
	nic->link_idx = if_nametoindex(v);
	if (nic->link_idx == 0) {
		err(1, "if_nametoindex %s", v);
	}
}

static void nic_parse_address(struct nic_options *nic, const char *v)
{
	if (ether_aton_r(v, &nic->address) == NULL) {
		errx(1, "%s is not a valid MAC address (must be in format aa:bb:cc:dd:ee:ff).", v);
	}
}

static void nic_parse_brd(struct nic_options *nic, const char *v)
{
	if (ether_aton_r(v, &nic->broadcast) == NULL) {
		errx(1, "%s is not a valid MAC address (must be in format aa:bb:cc:dd:ee:ff).", v);
	}
}

void nic_parse(struct nic_options *nic, const char *key, const char *val)
{
	struct optmap {
		const char *nictype;
		const char *opt;
		void (*fn)(struct nic_options *, const char *);
	};

	static struct optmap opts[] = {
		{ "macvlan", "mode",    nic_parse_macvlan_mode },
		{ "macvlan", "link",    nic_parse_link },
		{ "ipvlan",  "mode",    nic_parse_ipvlan_mode },
		{ "ipvlan",  "link",    nic_parse_link },
		{ "",        "address", nic_parse_address },
		{ "",        "brd",     nic_parse_brd },
		{ NULL, NULL, NULL },
	};

	for (struct optmap *e = &opts[0]; e->nictype != NULL; ++e) {
		if (e->nictype[0] != '\0' && strncmp(nic->type, e->nictype, sizeof (nic->type)) != 0) {
			continue;
		}
		if (strcmp(key, e->opt) != 0) {
			continue;
		}
		e->fn(nic, val);
		return;
	}
	errx(1, "unknown option '%s' for interface type '%s'", key, nic->type);
}

static void parse_ip(struct ip *ip, const char *data)
{
	char copy[64];
	if (strlcpy(copy, data, sizeof(copy)) != strlen(data)) {
		errx(1, "invalid IP address '%s': string too large", data);
	}

	/* Split the ip into its address and prefix length component */
	char *prefix_length = strchr(copy, '/');
	if (prefix_length != NULL) {
		*(prefix_length++) = 0;
	}

	void *buf;
	if (strchr(copy, ':') != NULL) {
		ip->type = AF_INET6;
		ip->prefix_length = 128;
		buf = &ip->v6;
	} else {
		ip->type = AF_INET;
		ip->prefix_length = 32;
		buf = &ip->v4;
	}

	if (inet_pton(ip->type, copy, buf) == -1) {
		err(1, "invalid IP address '%s'", copy);
	}

	if (prefix_length == NULL) {
		return;
	}

	errno = 0;
	long val = strtol(prefix_length, NULL, 10);
	if (val < 0 || (ip->type == AF_INET && val > 32) || (ip->type == AF_INET6 && val > 128)) {
		errno = ERANGE;
	}
	if (errno != 0) {
		err(1, "invalid prefix length '%s'", prefix_length);
	}
	ip->prefix_length = (uint8_t) val;
}

static void addr_parse_ip(struct addr_options *addr, const char *data)
{
	parse_ip(&addr->ip, data);
}

static void addr_parse_link(struct addr_options *addr, const char *v)
{
	strlcpy(addr->intf, v, IF_NAMESIZE);
}

void addr_parse(struct addr_options *addr, const char *key, const char *val)
{
	struct optmap {
		const char *opt;
		void (*fn)(struct addr_options *, const char *);
	};

	static struct optmap opts[] = {
		{ "ip",  addr_parse_ip },
		{ "dev", addr_parse_link },
		{ NULL, NULL },
	};

	for (struct optmap *e = &opts[0]; e->opt != NULL; ++e) {
		if (strcmp(key, e->opt) != 0) {
			continue;
		}
		e->fn(addr, val);
		return;
	}
	errx(1, "unknown option '%s' for address", key);
}

static void route_parse_ip(struct route_options *route, struct ip *ip, const char *data)
{
	parse_ip(ip, data);
	if (route->family == 0) {
		route->family = ip->type;
	}
	if (route->family != ip->type) {
		errx(1, "route IPs must either all be IPv4, or all be IPv6.");
	}
}

static void route_parse_src(struct route_options *route, const char *data)
{
	route_parse_ip(route, &route->src, data);
}

static void route_parse_dst(struct route_options *route, const char *data)
{
	if (strcmp(data, "default") == 0) {
		// Equivalent to parsing 0.0.0.0/0 or ::/128
		return;
	}
	route_parse_ip(route, &route->dst, data);
}

static void route_parse_gateway(struct route_options *route, const char *data)
{
	route_parse_ip(route, &route->gateway, data);
}

static void route_parse_dev(struct route_options *route, const char *data)
{
	strlcpy(route->intf, data, IF_NAMESIZE);
}

static void route_parse_metric(struct route_options *route, const char *data)
{
	errno = 0;
	long long val = strtoll(data, NULL, 10);
	if (val < 0) {
		errno = ERANGE;
	}
	if (errno != 0) {
		err(1, "invalid metric");
	}
	route->metric = (uint32_t) val;
}

static const struct valmap route_scope_values[] = {
	{ "universe",  &(const uint8_t) { RT_SCOPE_UNIVERSE } },
	{ "site",      &(const uint8_t) { RT_SCOPE_SITE     } },
	{ "link",      &(const uint8_t) { RT_SCOPE_LINK     } },
	{ "host",      &(const uint8_t) { RT_SCOPE_HOST     } },
	{ "nowhere",   &(const uint8_t) { RT_SCOPE_NOWHERE  } },
	{ NULL, NULL },
};

static void route_parse_scope(struct route_options *route, const char *v)
{
	if (parse_val(&route->scope, sizeof (route->scope), route_scope_values, v) == -1) {
		errno = 0;
		unsigned long long val = strtoull(v, NULL, 10);
		if (val == 0 || val >= RT_SCOPE_SITE) {
			errno = ERANGE;
		}
		if (errno != 0) {
			errx(1, "invalid scope %s: must be one of universe, site, link, host, nowhere, or a number in [1, 200).", v);
		}
		route->scope = (uint8_t) val;
	}
}

static const struct valmap route_proto_values[] = {
	{ "redirect",   &(const uint8_t) { RTPROT_REDIRECT   } },
	{ "kernel",     &(const uint8_t) { RTPROT_KERNEL     } },
	{ "boot",       &(const uint8_t) { RTPROT_BOOT       } },
	{ "static",     &(const uint8_t) { RTPROT_STATIC     } },
	{ NULL, NULL },
};

static void route_parse_proto(struct route_options *route, const char *v)
{
	if (parse_val(&route->protocol, sizeof (route->protocol), route_proto_values, v) == -1) {
		errno = 0;
		unsigned long long val = strtoull(v, NULL, 10);
		if (val < 5 || val >= 256) {
			errno = ERANGE;
		}
		if (errno != 0) {
			errx(1, "invalid protocol %s: must be one of redirect, kernel, boot, static, or a number in [5, 256).", v);
		}
		route->protocol = (uint8_t) val;
	}
}

static const struct valmap route_table_values[] = {
	{ "main",    &(const uint8_t) { RT_TABLE_MAIN    } },
	{ "local",   &(const uint8_t) { RT_TABLE_LOCAL   } },
	{ "default", &(const uint8_t) { RT_TABLE_DEFAULT } },
	{ NULL, NULL },
};

static void route_parse_table(struct route_options *route, const char *v)
{
	if (parse_val(&route->table, sizeof (route->table), route_table_values, v) == -1) {
		errno = 0;
		unsigned long long val = strtoull(v, NULL, 10);
		if (val == 0 || val >= 253) {
			errno = ERANGE;
		}
		if (errno != 0) {
			errx(1, "invalid table %s: must be one of main, local, default, or a number in [1, 253).", v);
		}
		route->table = (uint8_t) val;
	}
}

static const struct valmap route_type_values[] = {
	{ "unicast",     &(const uint8_t) { RTN_UNICAST     } },
	{ "local",       &(const uint8_t) { RTN_LOCAL       } },
	{ "broadcast",   &(const uint8_t) { RTN_BROADCAST   } },
	{ "anycast",     &(const uint8_t) { RTN_ANYCAST     } },
	{ "multicast",   &(const uint8_t) { RTN_MULTICAST   } },
	{ "blackhole",   &(const uint8_t) { RTN_BLACKHOLE   } },
	{ "unreachable", &(const uint8_t) { RTN_UNREACHABLE } },
	{ "prohibit",    &(const uint8_t) { RTN_PROHIBIT    } },
	{ "throw",       &(const uint8_t) { RTN_THROW       } },
	{ "nat",         &(const uint8_t) { RTN_NAT         } },
	{ "xresolve",    &(const uint8_t) { RTN_XRESOLVE    } },
	{ NULL, NULL },
};

static void route_parse_type(struct route_options *route, const char *v)
{
	if (parse_val(&route->type, sizeof (route->type), route_type_values, v) == -1) {
		errx(1, "invalid type %s: must be one of unicast, local, broadcast, anycast, multicast, blackhole, unreachable, prohibit, throw, nat or xresolve.", v);
	}
}

void route_parse(struct route_options *route, const char *key, const char *val)
{
	struct optmap {
		const char *opt;
		void (*fn)(struct route_options *, const char *);
	};

	static struct optmap opts[] = {
		{ "src",     route_parse_src },
		{ "dst",     route_parse_dst },
		{ "gateway", route_parse_gateway },
		{ "dev",     route_parse_dev },
		{ "metric",  route_parse_metric },
		{ "scope",   route_parse_scope },
		{ "proto",   route_parse_proto },
		{ "type",    route_parse_type },
		{ "table",   route_parse_table },
		{ NULL, NULL },
	};

	for (struct optmap *e = &opts[0]; e->opt != NULL; ++e) {
		if (strcmp(key, e->opt) != 0) {
			continue;
		}
		e->fn(route, val);
		return;
	}
	errx(1, "unknown option '%s' for route", key);
}

void route_set_defaults(struct route_options *route)
{
	route->protocol = RTPROT_BOOT;
	if (route->family == AF_INET) {
		route->scope = 0xffff;
	}
	route->type = RTN_UNICAST;
}

void route_set_defaults_post(struct route_options *route)
{
	if (route->table == 0) {
		switch (route->type) {
		case RTN_LOCAL:
		case RTN_BROADCAST:
		case RTN_ANYCAST:
		case RTN_NAT:
			route->table = RT_TABLE_LOCAL;
			break;
		default:
			route->table = RT_TABLE_MAIN;
			break;
		}
	}

	if (route->scope == 0xffff) {
		switch (route->type) {
		case RTN_UNICAST:
			if (route->gateway.type == 0) {
				route->scope = RT_SCOPE_LINK;
			} else {
				route->scope = RT_SCOPE_UNIVERSE;
			}
			break;
		case RTN_MULTICAST:
			route->scope = RT_SCOPE_UNIVERSE;
			break;
		case RTN_BROADCAST:
		case RTN_ANYCAST:
			route->scope = RT_SCOPE_LINK;
			break;
		case RTN_LOCAL:
		case RTN_NAT:
			route->scope = RT_SCOPE_HOST;
			break;
		}
	}
	if (route->scope == 0xffff) {
		errx(1, "route: must specify a scope");
	}

	if (route->family == 0) {
		route->family = AF_INET;
	}
}
