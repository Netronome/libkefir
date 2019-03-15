// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libkefir_parse.h"
#include "libkefir_parse_tc.h"

#define NEXT_ARG()	do { *argv += 1; *argc -= 1; } while (0)

DEFINE_ERR_FUNCTIONS("tc flower")

enum ether_proto_type {
	TCFLOWER_ETH_PROTO_UNSPEC,
	TCFLOWER_ETH_PROTO_IPV4,
	TCFLOWER_ETH_PROTO_IPV6,
	TCFLOWER_ETH_PROTO_OTHER,
};

/*
enum l4_proto_type {
	TCFLOWER_L4_PROTO_UNSPEC,
	TCFLOWER_L4_PROTO_TCP,
	TCFLOWER_L4_PROTO_UDP,
	TCFLOWER_L4_PROTO_SCTP,
	TCFLOWER_L4_PROTO_OTHER,
};
*/

static int
tcflower_parse_ethproto(const char ***argv, unsigned int *argc,
			enum ether_proto_type *ethtype)
{
	if (!strcmp(**argv, "ip") || !strcmp(**argv, "ipv4")) {
		*ethtype = TCFLOWER_ETH_PROTO_IPV4;
	} else if (!strcmp(**argv, "ipv6")) {
		*ethtype = TCFLOWER_ETH_PROTO_IPV6;
	} else {
		err_fail("unsupported protocol %s", **argv);
		return -1;
	}

	NEXT_ARG();
	return 0;
}

static int
tcflower_parse_match(const char ***argv, unsigned int *argc,
		     enum ether_proto_type ethtype, struct kefir_match *match)
{
	uint32_t *data_ipv6_ptr = match->value.data.ipv6.__in6_u.__u6_addr32;
	uint32_t *data_ipv4_ptr = &match->value.data.ipv4.s_addr;

	if (*argc < 2) {
		err_fail("bad number of arguments for parsing match value");
		return -1;
	}

	match->comp_operator = OPER_EQUAL;

	if (!strcmp(**argv, "dst_mac")) {
		NEXT_ARG();
		if (parse_eth_addr_slash_mask(**argv, &match->value.data.eth,
					      match->mask))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_ETHER_DST;
		match->value.format = KEFIR_VAL_FMT_MAC_ADDR;
	} else if (!strcmp(**argv, "src_mac")) {
		NEXT_ARG();
		if (parse_eth_addr_slash_mask(**argv, &match->value.data.eth,
					      match->mask))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_ETHER_SRC;
		match->value.format = KEFIR_VAL_FMT_MAC_ADDR;
	} else if (!strcmp(**argv, "vlan_id")) {
		NEXT_ARG();
		if (parse_uint(**argv, &match->value.data.u16, 12))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_VLAN_ID;
		match->value.format = KEFIR_VAL_FMT_UINT12;
	} else if (!strcmp(**argv, "vlan_prio")) {
		NEXT_ARG();
		if (parse_uint(**argv, &match->value.data.u8, 3))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_VLAN_PRIO;
		match->value.format = KEFIR_VAL_FMT_UINT3;
	} else if (!strcmp(**argv, "vlan_ethtype")) {
		NEXT_ARG();
		if (parse_uint(**argv, &match->value.data.u16, 16))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_VLAN_ETHERTYPE;
		match->value.format = KEFIR_VAL_FMT_UINT16;
	} else if (!strcmp(**argv, "cvlan_id")) {
		NEXT_ARG();
		if (parse_uint(**argv, &match->value.data.u16, 12))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_CVLAN_ID;
		match->value.format = KEFIR_VAL_FMT_UINT12;
	} else if (!strcmp(**argv, "cvlan_prio")) {
		NEXT_ARG();
		if (parse_uint(**argv, &match->value.data.u8, 3))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_CVLAN_PRIO;
		match->value.format = KEFIR_VAL_FMT_UINT3;
	} else if (!strcmp(**argv, "cvlan_ethtype")) {
		NEXT_ARG();
		if (parse_uint(**argv, &match->value.data.u16, 16))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_CVLAN_ETHERTYPE;
		match->value.format = KEFIR_VAL_FMT_UINT16;
	} else if (!strcmp(**argv, "mpls_label")) {
		NEXT_ARG();
		if (parse_uint(**argv, &match->value.data.u32, 20))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_MPLS_LABEL;
		match->value.format = KEFIR_VAL_FMT_UINT20;
	} else if (!strcmp(**argv, "mpls_tc")) {
		NEXT_ARG();
		if (parse_uint(**argv, &match->value.data.u8, 3))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_MPLS_TC;
		match->value.format = KEFIR_VAL_FMT_UINT3;
	} else if (!strcmp(**argv, "mpls_bos")) {
		NEXT_ARG();
		if (parse_uint(**argv, &match->value.data.u8, 1))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_MPLS_BOS;
		match->value.format = KEFIR_VAL_FMT_BIT;
	} else if (!strcmp(**argv, "mpls_ttl")) {
		NEXT_ARG();
		if (parse_uint(**argv, &match->value.data.u8, 8))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_MPLS_TTL;
		match->value.format = KEFIR_VAL_FMT_UINT8;
	} else if (!strcmp(**argv, "ip_proto")) {
		NEXT_ARG();
		if (parse_uint(**argv, &match->value.data.u8, 8))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_IP_ANY_L4PROTO;
		match->value.format = KEFIR_VAL_FMT_UINT8;
	} else if (!strcmp(**argv, "ip_tos")) {
		NEXT_ARG();
		/* Note: For IPv4, should be 6 bits only */
		if (parse_uint_slash_mask(**argv, &match->value.data.u8, 8,
					  match->mask))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_IP_ANY_TOS;
		match->value.format = KEFIR_VAL_FMT_UINT8;
	} else if (!strcmp(**argv, "ip_ttl")) {
		NEXT_ARG();
		if (parse_uint_slash_mask(**argv, &match->value.data.u8, 8,
					  match->mask))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_IP_ANY_TTL;
		match->value.format = KEFIR_VAL_FMT_UINT8;
	} else if (!strcmp(**argv, "dst_ip")) {
		NEXT_ARG();
		switch (ethtype) {
		case TCFLOWER_ETH_PROTO_IPV4:
			if (parse_ipv4_addr_slash_mask(**argv, data_ipv4_ptr,
						       match->mask))
				return -1;
			match->match_type = KEFIR_MATCH_TYPE_IP_4_DST;
			match->value.format = KEFIR_VAL_FMT_IPV4_ADDR;
			break;
		case TCFLOWER_ETH_PROTO_IPV6:
			if (parse_ipv6_addr_slash_mask(**argv, data_ipv6_ptr,
						       match->mask))
				return -1;
			match->match_type = KEFIR_MATCH_TYPE_IP_6_DST;
			match->value.format = KEFIR_VAL_FMT_IPV6_ADDR;
			break;
		default:
			err_fail("unsupported match on dst_ip for protocol %s",
				 ethtype);
			return -1;
		}
	} else if (!strcmp(**argv, "src_ip")) {
		NEXT_ARG();
		switch (ethtype) {
		case TCFLOWER_ETH_PROTO_IPV4:
			if (parse_ipv4_addr_slash_mask(**argv, data_ipv4_ptr,
						       match->mask))
				return -1;
			match->match_type = KEFIR_MATCH_TYPE_IP_4_SRC;
			match->value.format = KEFIR_VAL_FMT_IPV4_ADDR;
			break;
		case TCFLOWER_ETH_PROTO_IPV6:
			if (parse_ipv6_addr_slash_mask(**argv, data_ipv6_ptr,
						       match->mask))
				return -1;
			match->match_type = KEFIR_MATCH_TYPE_IP_6_SRC;
			match->value.format = KEFIR_VAL_FMT_IPV6_ADDR;
			break;
		default:
			err_fail("unsupported match on src_ip for protocol %s",
				 ethtype);
			return -1;
		}
	} else if (!strcmp(**argv, "dst_port")) {
		NEXT_ARG();
		if (parse_uint(**argv, &match->value.data.u16, 16))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_L4_PORT_DST;
		match->value.format = KEFIR_VAL_FMT_UINT16;
	} else if (!strcmp(**argv, "src_port")) {
		NEXT_ARG();
		if (parse_uint(**argv, &match->value.data.u16, 16))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_L4_PORT_SRC;
		match->value.format = KEFIR_VAL_FMT_UINT16;
	} else if (!strcmp(**argv, "tcp_flags")) {
		NEXT_ARG();
		if (parse_uint_slash_mask(**argv, &match->value.data.u16, 12,
					  match->mask))
			return -1;
		match->match_type = KEFIR_MATCH_TYPE_TCP_FLAGS;
		match->value.format = KEFIR_VAL_FMT_UINT12;
	// } else if (!strcmp(**argv, "type")) {
	// } else if (!strcmp(**argv, "code")) {
	// } else if (!strcmp(**argv, "arp_tip")) {
	// } else if (!strcmp(**argv, "arp_sip")) {
	// } else if (!strcmp(**argv, "arp_op")) {
	// } else if (!strcmp(**argv, "arp_tha")) {
	// } else if (!strcmp(**argv, "arp_sha")) {
	// } else if (!strcmp(**argv, "enc_key_id")) {
	// } else if (!strcmp(**argv, "enc_dst_ip")) {
	// } else if (!strcmp(**argv, "enc_src_ip")) {
	// } else if (!strcmp(**argv, "enc_dst_port")) {
	// } else if (!strcmp(**argv, "enc_tos")) {
	// } else if (!strcmp(**argv, "enc_ttl")) {
	// } else if (!strcmp(**argv, "geneve_opts")) {
	// 	/* May have more than 1 arg */
	// } else if (!strcmp(**argv, "ip_flags")) {
	} else {
		err_fail("unsupported match keyword %s", **argv);
		return -1;
	}
	NEXT_ARG();

	if (*argc < 1) {
		err_fail("bad number of arguments for parsing match value");
		return -1;
	}

	return 0;
}

static int
tcflower_parse_action(const char ***argv, unsigned int *argc,
		      enum action_code *action_code)
{
	if (*argc != 2) {
		err_fail("bad number of arguments for parsing action");
		return -1;
	}

	if (strcmp(**argv, "action")) {
		err_fail("failed to parse action for the rule");
		return -1;
	}
	NEXT_ARG();

	if (!strcmp(**argv, "pass")) {
		*action_code = ACTION_CODE_PASS;
	} else if (!strcmp(**argv, "drop")) {
		*action_code = ACTION_CODE_DROP;
	} else {
		err_fail("unsupported action code %s");
		return -1;
	}

	return 0;
}

static struct kefir_rule *
tcflower_compose_rule(struct kefir_match *matches, enum action_code action_code)
{
	struct kefir_rule *rule;

	rule = malloc(sizeof(struct kefir_rule));
	if (!rule) {
		err_fail("failed to allocate memory for rule");
		return NULL;
	}

	memcpy(rule->matches, matches, sizeof(rule->matches));
	rule->action = action_code;

	return rule;
}

struct kefir_rule *
kefir_parse_rule_tcflower(const char **user_rule, size_t rule_size)
{
	enum ether_proto_type ethtype = TCFLOWER_ETH_PROTO_UNSPEC;
	struct kefir_match matches[KEFIR_MAX_MATCH_PER_RULE] = {{0}};
	enum action_code action_code;
	struct kefir_rule *rule;
	size_t match_index = 0;
	unsigned int argc;
	const char **argv;

	if (rule_size < 6) {
		err_fail("bad number of arguments");
		return NULL;
	}

	argc = rule_size;
	argv = user_rule;

	if (strcmp(*argv, "protocol")) {
		err_fail("failed to parse protocol");
		return NULL;
	}
	argv += 1;
	argc -= 1;
	if (tcflower_parse_ethproto(&argv, &argc, &ethtype))
		return NULL;

	/* Do not make "flower" keyword mandatory, just skip it if present */
	if (!strcmp(*argv, "flower")) {
		argv += 1;
		argc -= 1;
	}

	while (argc > 2 && match_index < KEFIR_MAX_MATCH_PER_RULE) {
		if (tcflower_parse_match(&argv, &argc, ethtype,
					 &matches[match_index++]))
			return NULL;
	}

	if (tcflower_parse_action(&argv, &argc, &action_code))
		return NULL;

	rule = tcflower_compose_rule(matches, action_code);

	return rule;
}
