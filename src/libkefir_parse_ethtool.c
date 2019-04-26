// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/tcp.h>

#include "libkefir_error.h"
#include "libkefir_parse.h"
#include "libkefir_parse_ethtool.h"

DEFINE_ERR_FUNCTIONS("ethtool parsing")

enum ethtool_val_type {
	ETHTOOL_VAL_TYPE_ETHER_SRC,
	ETHTOOL_VAL_TYPE_ETHER_DST,
	ETHTOOL_VAL_TYPE_ETHER_PROTO,
	ETHTOOL_VAL_TYPE_IP_SRC,
	ETHTOOL_VAL_TYPE_IP_DST,
	ETHTOOL_VAL_TYPE_IPV4_TOS,
	ETHTOOL_VAL_TYPE_IPV6_TCLASS,
	ETHTOOL_VAL_TYPE_L4_PROTO,
	ETHTOOL_VAL_TYPE_L4_PORT_SRC,
	ETHTOOL_VAL_TYPE_L4_PORT_DST,
	ETHTOOL_VAL_TYPE_IP_SPI,
	ETHTOOL_VAL_TYPE_IP_L4DATA,
	ETHTOOL_VAL_TYPE_VLAN_ETYPE,
	ETHTOOL_VAL_TYPE_VLAN_ID,
};

struct ethtool_option {
	char			name[16];
	enum ethtool_val_type	type;
	enum value_format	format;
};

typedef const struct ethtool_option * const ethtool_opts_t;

static const struct ethtool_option opt_src = {
	.name		= "src",
	.type		= ETHTOOL_VAL_TYPE_ETHER_SRC,
	.format		= KEFIR_VAL_FMT_MAC_ADDR,
};

static const struct ethtool_option opt_dst = {
	.name		= "dst",
	.type		= ETHTOOL_VAL_TYPE_ETHER_DST,
	.format		= KEFIR_VAL_FMT_MAC_ADDR,
};

static const struct ethtool_option opt_proto = {
	.name		= "proto",
	.type		= ETHTOOL_VAL_TYPE_ETHER_PROTO,
	.format		= KEFIR_VAL_FMT_UINT16,
};

static const struct ethtool_option opt_src_ip4 = {
	.name		= "src-ip",
	.type		= ETHTOOL_VAL_TYPE_IP_SRC,
	.format		= KEFIR_VAL_FMT_IPV4_ADDR,
};

static const struct ethtool_option opt_dst_ip4 = {
	.name		= "dst-ip",
	.type		= ETHTOOL_VAL_TYPE_IP_DST,
	.format		= KEFIR_VAL_FMT_IPV4_ADDR,
};

static const struct ethtool_option opt_src_ip6 = {
	.name		= "src-ip",
	.type		= ETHTOOL_VAL_TYPE_IP_SRC,
	.format		= KEFIR_VAL_FMT_IPV6_ADDR,
};

static const struct ethtool_option opt_dst_ip6 = {
	.name		= "dst-ip",
	.type		= ETHTOOL_VAL_TYPE_IP_DST,
	.format		= KEFIR_VAL_FMT_IPV6_ADDR,
};

static const struct ethtool_option opt_tos = {
	.name		= "tos",
	.type		= ETHTOOL_VAL_TYPE_IPV4_TOS,
	.format		= KEFIR_VAL_FMT_UINT6,
};

static const struct ethtool_option opt_tclass = {
	.name		= "tclass",
	.type		= ETHTOOL_VAL_TYPE_IPV6_TCLASS,
	.format		= KEFIR_VAL_FMT_UINT8,
};

static const struct ethtool_option opt_l4proto = {
	.name		= "l4proto",
	.type		= ETHTOOL_VAL_TYPE_L4_PROTO,
	.format		= KEFIR_VAL_FMT_UINT8,
};

static const struct ethtool_option opt_src_port = {
	.name		= "src-port",
	.type		= ETHTOOL_VAL_TYPE_L4_PORT_SRC,
	.format		= KEFIR_VAL_FMT_UINT16,
};

static const struct ethtool_option opt_dst_port = {
	.name		= "dst-port",
	.type		= ETHTOOL_VAL_TYPE_L4_PORT_DST,
	.format		= KEFIR_VAL_FMT_UINT16,
};

static const struct ethtool_option opt_spi = {
	.name		= "spi",
	.type		= ETHTOOL_VAL_TYPE_IP_SPI,
	.format		= KEFIR_VAL_FMT_UINT32,
};

static const struct ethtool_option opt_l4data = {
	.name		= "l4data",
	.type		= ETHTOOL_VAL_TYPE_IP_L4DATA,
	.format		= KEFIR_VAL_FMT_UINT32,
};

static const struct ethtool_option opt_vlan_etype = {
	.name		= "vlan-etype",
	.type		= ETHTOOL_VAL_TYPE_VLAN_ETYPE,
	.format		= KEFIR_VAL_FMT_UINT16,
};

static const struct ethtool_option opt_vlan = {
	.name		= "vlan",
	.type		= ETHTOOL_VAL_TYPE_VLAN_ID,
	.format		= KEFIR_VAL_FMT_UINT16,
};

static const struct ethtool_option opt_dst_mac = {
	.name		= "dst-mac",
	.type		= ETHTOOL_VAL_TYPE_ETHER_DST,
	.format		= KEFIR_VAL_FMT_MAC_ADDR,
};

static ethtool_opts_t ethtool_ether_opts[] = {
	&opt_src,
	&opt_dst,
	&opt_proto,
	&opt_vlan_etype,
	&opt_vlan,
};

static ethtool_opts_t ethtool_ip4_opts[] = {
	&opt_src_ip4,
	&opt_dst_ip4,
	&opt_tos,
	&opt_l4proto,
	&opt_l4data,
	&opt_spi,
	&opt_src_port,
	&opt_dst_port,
	&opt_vlan_etype,
	&opt_vlan,
	&opt_dst_mac,
};

static ethtool_opts_t ethtool_tcp4_opts[] = {
	&opt_src_ip4,
	&opt_dst_ip4,
	&opt_tos,
	&opt_src_port,
	&opt_dst_port,
	&opt_vlan_etype,
	&opt_vlan,
	&opt_dst_mac,
};

static ethtool_opts_t ethtool_esp4_opts[] = {
	&opt_src_ip4,
	&opt_dst_ip4,
	&opt_tos,
	&opt_spi,
	&opt_vlan_etype,
	&opt_vlan,
	&opt_dst_mac,
};

static ethtool_opts_t ethtool_ip6_opts[] = {
	&opt_src_ip6,
	&opt_dst_ip6,
	&opt_tclass,
	&opt_l4proto,
	&opt_l4data,
	&opt_spi,
	&opt_src_port,
	&opt_dst_port,
	&opt_vlan_etype,
	&opt_vlan,
	&opt_dst_mac,
};

static ethtool_opts_t ethtool_tcp6_opts[] = {
	&opt_src_ip6,
	&opt_dst_ip6,
	&opt_tclass,
	&opt_src_port,
	&opt_dst_port,
	&opt_vlan_etype,
	&opt_vlan,
	&opt_dst_mac,
};

static ethtool_opts_t ethtool_esp6_opts[] = {
	&opt_src_ip6,
	&opt_dst_ip6,
	&opt_tclass,
	&opt_spi,
	&opt_vlan_etype,
	&opt_vlan,
	&opt_dst_mac,
};

static int
get_flow_opts(const char *input, ethtool_opts_t **opts_res,
	      size_t *opts_len_res)
{
	ethtool_opts_t *flow_opts;
	size_t flow_opts_len;

	if (!strcmp(input, "ether")) {
		flow_opts = ethtool_ether_opts;
		flow_opts_len = ARRAY_SIZE(ethtool_ether_opts);
	} else if (!strcmp(input, "ip4")) {
		flow_opts = ethtool_ip4_opts;
		flow_opts_len = ARRAY_SIZE(ethtool_ip4_opts);
	} else if (!strcmp(input, "tcp4") ||
		   !strcmp(input, "udp4") ||
		   !strcmp(input, "sctp4")) {
		flow_opts = ethtool_tcp4_opts;
		flow_opts_len = ARRAY_SIZE(ethtool_tcp4_opts);
	} else if (!strcmp(input, "ah4") ||
		   !strcmp(input, "exp4")) {
		flow_opts = ethtool_esp4_opts;
		flow_opts_len = ARRAY_SIZE(ethtool_esp4_opts);
	} else if (!strcmp(input, "ip6")) {
		flow_opts = ethtool_ip6_opts;
		flow_opts_len = ARRAY_SIZE(ethtool_ip6_opts);
	} else if (!strcmp(input, "tcp6") ||
		   !strcmp(input, "udp6") ||
		   !strcmp(input, "sctp6")) {
		flow_opts = ethtool_tcp6_opts;
		flow_opts_len = ARRAY_SIZE(ethtool_tcp6_opts);
	} else if (!strcmp(input, "ah4") ||
		   !strcmp(input, "exp4")) {
		flow_opts = ethtool_esp6_opts;
		flow_opts_len = ARRAY_SIZE(ethtool_esp6_opts);
	} else {
		err_fail("unsupported flow type: %s", input);
		return -1;
	}

	*opts_res = flow_opts;
	*opts_len_res = flow_opts_len;
	return 0;
}

static int
get_match_value(const char *input, struct kefir_value *val,
		enum value_format format)
{
	switch (format) {
	case KEFIR_VAL_FMT_UINT6:
		if (parse_uint(input, &val->data.u8, 6))
			return -1;
		break;
	case KEFIR_VAL_FMT_UINT8:
		if (parse_uint(input, &val->data.u8, 8))
			return -1;
		break;
	case KEFIR_VAL_FMT_UINT16:
		if (parse_uint(input, &val->data.u16, 16))
			return -1;
		break;
	case KEFIR_VAL_FMT_UINT32:
		if (parse_uint(input, &val->data.u32, 32))
			return -1;
		break;
	case KEFIR_VAL_FMT_MAC_ADDR:
		if (parse_eth_addr(input, &val->data.eth))
			return -1;
		break;
	case KEFIR_VAL_FMT_IPV4_ADDR:
		if (parse_ipv4_addr(input, &val->data.ipv4.s_addr))
			return -1;
		break;
	case KEFIR_VAL_FMT_IPV6_ADDR:
		if (parse_ipv6_addr(input, val->data.ipv6.__in6_u.__u6_addr32))
			return -1;
		break;
	default:
		err_bug("unknown enum value for value format: %d", format);
		return -1;
	}

	val->format = format;

	return 0;
}

static int get_action_code(const char *input, enum action_code *action)
{
	long int code;
	char *endptr;

	code = strtol(input, &endptr, 10);

	if (*endptr != '\0') {
		err_fail("could not parse %s as int", input);
		return -1;
	}
	
	switch (code) {
	case -1:
		*action = ACTION_CODE_DROP;
		break;
	case 0:
		*action = ACTION_CODE_PASS;
		break;
	default:
		err_fail("unsupported action code %s", input);
		return -1;
	}

	return 0;
}

static struct kefir_rule *
ethtool_compose_rule(enum ethtool_val_type val_type, struct kefir_value value,
		     enum action_code action_code)
{
	struct kefir_match match = {0};
	struct kefir_rule *rule;
	bool ipv6_flow = false;

	switch (val_type) {
	case ETHTOOL_VAL_TYPE_ETHER_SRC:
		match.match_type = KEFIR_MATCH_TYPE_ETHER_SRC;
		break;
	case ETHTOOL_VAL_TYPE_ETHER_DST:
		match.match_type = KEFIR_MATCH_TYPE_ETHER_DST;
		break;
	case ETHTOOL_VAL_TYPE_ETHER_PROTO:
		match.match_type = KEFIR_MATCH_TYPE_ETHER_PROTO;
		break;
	case ETHTOOL_VAL_TYPE_IP_SRC:
		if (ipv6_flow)
			match.match_type = KEFIR_MATCH_TYPE_IP_6_SRC;
		else
			match.match_type = KEFIR_MATCH_TYPE_IP_4_SRC;
		break;
	case ETHTOOL_VAL_TYPE_IP_DST:
		if (ipv6_flow)
			match.match_type = KEFIR_MATCH_TYPE_IP_6_DST;
		else
			match.match_type = KEFIR_MATCH_TYPE_IP_4_DST;
		break;
	case ETHTOOL_VAL_TYPE_IPV4_TOS:
		match.match_type = KEFIR_MATCH_TYPE_IP_4_TOS;
		break;
	case ETHTOOL_VAL_TYPE_IPV6_TCLASS:
		match.mask[1] &= 0x0f;
		match.mask[0] &= 0xf0;
		match.match_type = KEFIR_MATCH_TYPE_IP_6_TOS;
		break;
	case ETHTOOL_VAL_TYPE_L4_PROTO:
		if (ipv6_flow)
			match.match_type = KEFIR_MATCH_TYPE_IP_6_L4PROTO;
		else
			match.match_type = KEFIR_MATCH_TYPE_IP_4_L4PROTO;
		break;
	case ETHTOOL_VAL_TYPE_L4_PORT_SRC:
		if (ipv6_flow)
			match.match_type = KEFIR_MATCH_TYPE_IP_6_L4PORT_SRC;
		else
			match.match_type = KEFIR_MATCH_TYPE_IP_4_L4PORT_SRC;
		break;
	case ETHTOOL_VAL_TYPE_L4_PORT_DST:
		if (ipv6_flow)
			match.match_type = KEFIR_MATCH_TYPE_IP_6_L4PORT_DST;
		else
			match.match_type = KEFIR_MATCH_TYPE_IP_4_L4PORT_DST;
		break;
	case ETHTOOL_VAL_TYPE_IP_L4DATA:
		if (ipv6_flow)
			match.match_type = KEFIR_MATCH_TYPE_IP_6_L4DATA;
		else
			match.match_type = KEFIR_MATCH_TYPE_IP_4_L4DATA;
		break;
	case ETHTOOL_VAL_TYPE_VLAN_ETYPE:
		match.match_type = KEFIR_MATCH_TYPE_VLAN_ETHERTYPE;
		break;
	case ETHTOOL_VAL_TYPE_VLAN_ID:
		match.match_type = KEFIR_MATCH_TYPE_VLAN_ID;
		break;
	case ETHTOOL_VAL_TYPE_IP_SPI:
		// TODO: needs two matchs, one on SPI, one on flow type
	default:
		err_bug("unknown enum value for value type: %d", val_type);
		return NULL;
	}

	match.comp_operator = OPER_EQUAL;
	match.value = value;

	rule = calloc(1, sizeof(struct kefir_rule));
	if (!rule) {
		err_fail("failed to allocate memory for rule");
		return NULL;
	}

	rule->matches[0] = match;	/* ethtool allows for only 1 match */
	rule->action = action_code;

	return rule;
}

struct kefir_rule *ethtool_parse_rule(const char **user_rule, size_t rule_size)
{
	struct ethtool_option current_opt = { .name = "" };
	struct kefir_value match_val = {0};
	enum action_code action_code;
	ethtool_opts_t *flow_opts;
	struct kefir_rule *rule;
	size_t flow_opts_len, i;

	/*
	 * Shortest rules: "flow-type <type> <field> <value> action <value>"
	 * Longest rules: for now, same thing, in future we may have masks?
	 */
	if (rule_size < 6 || rule_size > 6) {
		err_fail("bad number of arguments");
		return NULL;
	}
	if (strcmp(*user_rule, "flow-type")) {
		err_fail("expected 'flow-type', got '%s'", *user_rule);
		return NULL;
	}
	user_rule++;

	if (get_flow_opts(*user_rule, &flow_opts, &flow_opts_len))
		return NULL;
	user_rule++;

	for (i = 0; i < flow_opts_len; i++) {
		if (strcmp(*user_rule, flow_opts[i]->name))
			continue;
		current_opt = *flow_opts[i];
		break;
	}
	if (!current_opt.name[0]) {
		err_fail("unsupported option %s", *user_rule);
		return NULL;
	}
	user_rule++;

	if (get_match_value(*user_rule, &match_val, current_opt.format))
		return NULL;
	user_rule++;

	if (strcmp(*user_rule, "action")) {
		err_fail("expected 'action', got '%s'", *user_rule);
		return NULL;
	}
	user_rule++;

	if (get_action_code(*user_rule, &action_code))
		return NULL;

	rule = ethtool_compose_rule(current_opt.type, match_val, action_code);

	return rule;
}
