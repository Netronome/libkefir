// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <bits/stdint-uintn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>

#include "libkefir_error.h"
#include "libkefir_internals.h"
#include "libkefir_parse.h"
#include "libkefir_parse_tc.h"

#define NEXT_ARG()		\
	do {			\
		*argv += 1;	\
		*argc -= 1;	\
	} while (0)

DEFINE_ERR_FUNCTIONS("tc flower parsing")

enum ether_proto_type {
	TCFLOWER_ETH_PROTO_UNSPEC,
	TCFLOWER_ETH_PROTO_IPV4,
	TCFLOWER_ETH_PROTO_IPV6,
	TCFLOWER_ETH_PROTO_OTHER,
};

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

static int tcflower_parse_ipproto(const char *input, void *output)
{
	int res = -1;

	if (!strcmp(input, "tcp"))
		res = parse_check_and_store_uint(IPPROTO_TCP, output, 8);
	else if (!strcmp(input, "udp"))
		res = parse_check_and_store_uint(IPPROTO_UDP, output, 8);
	else if (!strcmp(input, "sctp"))
		res = parse_check_and_store_uint(IPPROTO_SCTP, output, 8);
	else if (!strcmp(input, "icmp"))
		res = parse_check_and_store_uint(IPPROTO_ICMP, output, 8);
	else if (!strcmp(input, "icmpv6"))
		res = parse_check_and_store_uint(IPPROTO_ICMPV6, output, 8);
	else
		res = parse_uint(input, output, 8);

	if (res) {
		err_fail("unsupported protocol %s", input);
		return -1;
	}

	return 0;
}

static int
tcflower_parse_match(const char ***argv, unsigned int *argc,
		     enum ether_proto_type ethtype, struct kefir_match *match)
{
	uint32_t *data_ipv6_ptr = match->value.data.ipv6.__in6_u.__u6_addr32;
	uint32_t *data_ipv4_ptr = &match->value.data.ipv4.s_addr;
	bool ipv6_flow = (ethtype == TCFLOWER_ETH_PROTO_IPV6);

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
		/*
		 * Can be "tcp", "udp", "sctp", "icmp", "icmpv6", or an
		 * unsigned 8bit value in hexadecimal format
		 */
		NEXT_ARG();
		if (tcflower_parse_ipproto(**argv, &match->value.data.u8))
			return -1;
		if (ipv6_flow)
			match->match_type = KEFIR_MATCH_TYPE_IP_6_L4PROTO;
		else
			match->match_type = KEFIR_MATCH_TYPE_IP_4_L4PROTO;
		match->value.format = KEFIR_VAL_FMT_UINT8;
	} else if (!strcmp(**argv, "ip_tos")) {
		NEXT_ARG();
		/* Note: For IPv4, should be 6 bits only */
		if (parse_uint_slash_mask(**argv, &match->value.data.u8, 8,
					  match->mask))
			return -1;
		if (ipv6_flow)
			match->match_type = KEFIR_MATCH_TYPE_IP_6_TOS;
		else
			match->match_type = KEFIR_MATCH_TYPE_IP_4_TOS;
		match->value.format = KEFIR_VAL_FMT_UINT8;
	} else if (!strcmp(**argv, "ip_ttl")) {
		NEXT_ARG();
		if (parse_uint_slash_mask(**argv, &match->value.data.u8, 8,
					  match->mask))
			return -1;
		if (ipv6_flow)
			match->match_type = KEFIR_MATCH_TYPE_IP_6_TTL;
		else
			match->match_type = KEFIR_MATCH_TYPE_IP_4_TTL;
		match->value.format = KEFIR_VAL_FMT_UINT8;
	} else if (!strcmp(**argv, "dst_ip")) {
		NEXT_ARG();
		if (ipv6_flow) {
			if (parse_ipv6_addr_slash_mask(**argv, data_ipv6_ptr,
						       match->mask))
				return -1;
			match->match_type = KEFIR_MATCH_TYPE_IP_6_DST;
			match->value.format = KEFIR_VAL_FMT_IPV6_ADDR;
		} else {
			if (parse_ipv4_addr_slash_mask(**argv, data_ipv4_ptr,
						       match->mask))
				return -1;
			match->match_type = KEFIR_MATCH_TYPE_IP_4_DST;
			match->value.format = KEFIR_VAL_FMT_IPV4_ADDR;
		}
	} else if (!strcmp(**argv, "src_ip")) {
		NEXT_ARG();
		if (ipv6_flow) {
			if (parse_ipv6_addr_slash_mask(**argv, data_ipv6_ptr,
						       match->mask))
				return -1;
			match->match_type = KEFIR_MATCH_TYPE_IP_6_SRC;
			match->value.format = KEFIR_VAL_FMT_IPV6_ADDR;
		} else {
			if (parse_ipv4_addr_slash_mask(**argv, data_ipv4_ptr,
						       match->mask))
				return -1;
			match->match_type = KEFIR_MATCH_TYPE_IP_4_SRC;
			match->value.format = KEFIR_VAL_FMT_IPV4_ADDR;
		}
	} else if (!strcmp(**argv, "dst_port")) {
		NEXT_ARG();
		if (parse_uint(**argv, &match->value.data.u16, 16))
			return -1;
		if (ipv6_flow)
			match->match_type = KEFIR_MATCH_TYPE_IP_6_L4PORT_DST;
		else
			match->match_type = KEFIR_MATCH_TYPE_IP_4_L4PORT_DST;
		match->value.format = KEFIR_VAL_FMT_UINT16;
	} else if (!strcmp(**argv, "src_port")) {
		NEXT_ARG();
		if (parse_uint(**argv, &match->value.data.u16, 16))
			return -1;
		if (ipv6_flow)
			match->match_type = KEFIR_MATCH_TYPE_IP_6_L4PORT_SRC;
		else
			match->match_type = KEFIR_MATCH_TYPE_IP_4_L4PORT_SRC;
		match->value.format = KEFIR_VAL_FMT_UINT16;
	} else if (!strcmp(**argv, "tcp_flags")) {
		NEXT_ARG();
		if (parse_uint_slash_mask(**argv, &match->value.data.u16, 12,
					  match->mask))
			return -1;
		if (ipv6_flow)
			match->match_type = KEFIR_MATCH_TYPE_IP_6_TCP_FLAGS;
		else
			match->match_type = KEFIR_MATCH_TYPE_IP_4_TCP_FLAGS;
		match->value.format = KEFIR_VAL_FMT_UINT12;
	/*
	} else if (!strcmp(**argv, "type")) {
	} else if (!strcmp(**argv, "code")) {
	} else if (!strcmp(**argv, "arp_tip")) {
	} else if (!strcmp(**argv, "arp_sip")) {
	} else if (!strcmp(**argv, "arp_op")) {
	} else if (!strcmp(**argv, "arp_tha")) {
	} else if (!strcmp(**argv, "arp_sha")) {
	} else if (!strcmp(**argv, "enc_key_id")) {
	} else if (!strcmp(**argv, "enc_dst_ip")) {
	} else if (!strcmp(**argv, "enc_src_ip")) {
	} else if (!strcmp(**argv, "enc_dst_port")) {
	} else if (!strcmp(**argv, "enc_tos")) {
	} else if (!strcmp(**argv, "enc_ttl")) {
	} else if (!strcmp(**argv, "geneve_opts")) { // Possibly several args
	} else if (!strcmp(**argv, "ip_flags")) {
	*/
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

static int tcflower_check_matchlist(struct kefir_match *match_list)
{
	bool found_l4_port = false, found_ipproto = false;
	int i;

	for (i = 0; i < KEFIR_MAX_MATCH_PER_RULE; i++) {
		switch (match_list[i].match_type) {
		case KEFIR_MATCH_TYPE_UNSPEC:
			goto out;
		case KEFIR_MATCH_TYPE_IP_4_L4PROTO:
		case KEFIR_MATCH_TYPE_IP_6_L4PROTO:
		case KEFIR_MATCH_TYPE_IP_ANY_L4PROTO:
			found_ipproto = true;
			break;
		case KEFIR_MATCH_TYPE_IP_4_L4PORT_SRC:
		case KEFIR_MATCH_TYPE_IP_4_L4PORT_DST:
		case KEFIR_MATCH_TYPE_IP_4_L4PORT_ANY:
		case KEFIR_MATCH_TYPE_IP_6_L4PORT_SRC:
		case KEFIR_MATCH_TYPE_IP_6_L4PORT_DST:
		case KEFIR_MATCH_TYPE_IP_6_L4PORT_ANY:
		case KEFIR_MATCH_TYPE_IP_ANY_L4PORT_SRC:
		case KEFIR_MATCH_TYPE_IP_ANY_L4PORT_DST:
		case KEFIR_MATCH_TYPE_IP_ANY_L4PORT_ANY:
			found_l4_port = true;
			break;
		default:
			break;
		}
	}
out:
	if (found_l4_port && !found_ipproto) {
		err_fail("src_port/dst_port requires ip_proto");
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
		err_fail("unsupported action code %d", *action_code);
		return -1;
	}

	return 0;
}

static struct kefir_rule *
tcflower_compose_rule(struct kefir_match *matches, enum action_code action_code)
{
	struct kefir_rule *rule;

	rule = calloc(1, sizeof(struct kefir_rule));
	if (!rule) {
		err_fail("failed to allocate memory for rule");
		return NULL;
	}

	memcpy(rule->matches, matches, sizeof(rule->matches));
	rule->action = action_code;

	return rule;
}

struct kefir_rule *tcflower_parse_rule(const char **user_rule, size_t rule_size)
{
	struct kefir_match matches[KEFIR_MAX_MATCH_PER_RULE] = { {0} };
	enum ether_proto_type ethtype = TCFLOWER_ETH_PROTO_UNSPEC;
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
	if (tcflower_check_matchlist(matches))
		return NULL;

	if (tcflower_parse_action(&argv, &argc, &action_code))
		return NULL;

	rule = tcflower_compose_rule(matches, action_code);

	return rule;
}
