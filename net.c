/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

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
		struct ifinfomsg ifinfo;
	} *hdr;
	char *data;
	size_t capacity;
};

static void nlpkt_init(struct nlpkt *pkt)
{
	pkt->data = calloc(1, 4096);
	pkt->capacity = 4096;
	pkt->hdr = (void *) pkt->data;
	pkt->hdr->nlhdr.nlmsg_len = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof (struct ifinfomsg));
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
	nlpkt_init(&pkt);

	pkt.hdr->nlhdr.nlmsg_type = RTM_NEWLINK;
	pkt.hdr->nlhdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;

	nlpkt_add_attr(&pkt, IFLA_NET_NS_PID, nicopts->netns_pid);

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
	nlpkt_init(&pkt);

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

struct valmap {
	const char *name;
	void *val;
};

static int nic_parse_val(void *dst, size_t size, const struct valmap *map, const char *name)
{
	for (const struct valmap *e = &map[0]; e->name != NULL; ++e) {
		if (strcmp(name, e->name) != 0) {
			continue;
		}
		memcpy(dst, e->val, size);
		return 0;
	}
	return -1;
}

static void nic_parse_macvlan_mode(struct nic_options *nic, const char *v)
{
	struct valmap map[] = {
		{ "private",  &(uint32_t) { MACVLAN_MODE_PRIVATE  } },
		{ "vepa",     &(uint32_t) { MACVLAN_MODE_VEPA     } },
		{ "bridge",   &(uint32_t) { MACVLAN_MODE_BRIDGE   } },
		{ "passthru", &(uint32_t) { MACVLAN_MODE_PASSTHRU } },
		{ "source",   &(uint32_t) { MACVLAN_MODE_SOURCE   } },
		{ NULL, NULL },
	};
	if (nic_parse_val(&nic->macvlan.mode, sizeof (nic->macvlan.mode), map, v) == -1) {
		errx(1, "invalid MACVLAN mode %s", v);
	}
}

static void nic_parse_ipvlan_mode(struct nic_options *nic, const char *v)
{
	struct valmap map[] = {
		{ "l2",  &(uint32_t) { IPVLAN_MODE_L2  } },
		{ "l3",  &(uint32_t) { IPVLAN_MODE_L3  } },
		{ "l3s", &(uint32_t) { IPVLAN_MODE_L3S } },
		{ NULL, NULL },
	};
	if (nic_parse_val(&nic->ipvlan.mode, sizeof (nic->ipvlan.mode), map, v) == -1) {
		errx(1, "invalid IPVLAN mode %s", v);
	}
}

static void nic_parse_link(struct nic_options *nic, const char *v)
{
	nic->link_idx = if_nametoindex(v);
	if (nic->link_idx == 0) {
		err(1, "if_nametoindex %s", v);
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
		{ "macvlan", "mode", nic_parse_macvlan_mode },
		{ "macvlan", "link", nic_parse_link },
		{ "ipvlan",  "mode", nic_parse_ipvlan_mode  },
		{ "ipvlan",  "link", nic_parse_link },
		{ NULL, NULL, NULL },
	};

	for (struct optmap *e = &opts[0]; e->nictype != NULL; ++e) {
		if (strncmp(nic->type, e->nictype, sizeof (nic->type)) != 0) {
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
