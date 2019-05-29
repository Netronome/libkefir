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
#include "libkefir_parse_ethtool.h"

DEFINE_ERR_FUNCTIONS("ethtool parsing")

enum ethtool_flow_type {
	ETHTOOL_FLOW_TYPE_ETHER,
	ETHTOOL_FLOW_TYPE_IP4,
	ETHTOOL_FLOW_TYPE_TCP4,
	ETHTOOL_FLOW_TYPE_UDP4,
	ETHTOOL_FLOW_TYPE_SCTP4,
	ETHTOOL_FLOW_TYPE_AH4,
	ETHTOOL_FLOW_TYPE_ESP4,
	ETHTOOL_FLOW_TYPE_IP6,
	ETHTOOL_FLOW_TYPE_TCP6,
	ETHTOOL_FLOW_TYPE_UDP6,
	ETHTOOL_FLOW_TYPE_SCTP6,
	ETHTOOL_FLOW_TYPE_AH6,
	ETHTOOL_FLOW_TYPE_ESP6,
};

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

static int get_flow_type(const char *input)
{
	if (!strcmp(input, "ether"))
		return ETHTOOL_FLOW_TYPE_ETHER;
	else if (!strcmp(input, "ip4"))
		return ETHTOOL_FLOW_TYPE_IP4;
	else if (!strcmp(input, "tcp4"))
		return ETHTOOL_FLOW_TYPE_TCP4;
	else if (!strcmp(input, "udp4"))
		return ETHTOOL_FLOW_TYPE_UDP4;
	else if (!strcmp(input, "sctp4"))
		return ETHTOOL_FLOW_TYPE_SCTP4;
	else if (!strcmp(input, "ip6"))
		return ETHTOOL_FLOW_TYPE_IP6;
	else if (!strcmp(input, "tcp6"))
		return ETHTOOL_FLOW_TYPE_TCP6;
	else if (!strcmp(input, "udp6"))
		return ETHTOOL_FLOW_TYPE_UDP6;
	else if (!strcmp(input, "sctp6"))
		return ETHTOOL_FLOW_TYPE_SCTP6;
	/* TODO: Add support for ah4, esp4, ah6, esp6 */
	else
		err_fail("unsupported flow type: %s", input);

	return -1;
}

static int
get_flow_opts(enum ethtool_flow_type flow_type, ethtool_opts_t **opts_res,
	      size_t *opts_len_res)
{
	switch (flow_type) {
	case ETHTOOL_FLOW_TYPE_ETHER:
		*opts_res = ethtool_ether_opts;
		*opts_len_res = array_size(ethtool_ether_opts);
		break;
	case ETHTOOL_FLOW_TYPE_IP4:
		*opts_res = ethtool_ip4_opts;
		*opts_len_res = array_size(ethtool_ip4_opts);
		break;
	case ETHTOOL_FLOW_TYPE_TCP4:
	case ETHTOOL_FLOW_TYPE_UDP4:
	case ETHTOOL_FLOW_TYPE_SCTP4:
		*opts_res = ethtool_tcp4_opts;
		*opts_len_res = array_size(ethtool_tcp4_opts);
		break;
	case ETHTOOL_FLOW_TYPE_AH4:
	case ETHTOOL_FLOW_TYPE_ESP4:
		*opts_res = ethtool_esp4_opts;
		*opts_len_res = array_size(ethtool_esp4_opts);
		break;
	case ETHTOOL_FLOW_TYPE_IP6:
		*opts_res = ethtool_ip6_opts;
		*opts_len_res = array_size(ethtool_ip6_opts);
		break;
	case ETHTOOL_FLOW_TYPE_TCP6:
	case ETHTOOL_FLOW_TYPE_UDP6:
	case ETHTOOL_FLOW_TYPE_SCTP6:
		*opts_res = ethtool_tcp6_opts;
		*opts_len_res = array_size(ethtool_tcp6_opts);
		break;
	case ETHTOOL_FLOW_TYPE_AH6:
	case ETHTOOL_FLOW_TYPE_ESP6:
		*opts_res = ethtool_esp6_opts;
		*opts_len_res = array_size(ethtool_esp6_opts);
		break;
	default:
		err_bug("unknown flow type: %d", flow_type);
		return -1;
	}

	return 0;
}

static void
create_match_l4proto(struct kefir_match *match, bool ipv6_flow, uint8_t value)
{
	if (ipv6_flow)
		match->match_type = KEFIR_MATCH_TYPE_IP_6_L4PROTO;
	else
		match->match_type = KEFIR_MATCH_TYPE_IP_4_L4PROTO;
	match->comp_operator = OPER_EQUAL;
	match->value.data.u8 = value;
	match->value.format = KEFIR_VAL_FMT_UINT8;
}

static int
account_for_flow_type(struct kefir_match *match,
		      enum ethtool_flow_type flow_type, bool *ipv6_flow,
		      size_t *match_index)
{
	*ipv6_flow = false;

	switch (flow_type) {
	case ETHTOOL_FLOW_TYPE_TCP4:
		create_match_l4proto(match, *ipv6_flow, IPPROTO_TCP);
		*match_index += 1;
		break;
	case ETHTOOL_FLOW_TYPE_UDP4:
		create_match_l4proto(match, *ipv6_flow, IPPROTO_UDP);
		*match_index += 1;
		break;
	case ETHTOOL_FLOW_TYPE_SCTP4:
		create_match_l4proto(match, *ipv6_flow, IPPROTO_SCTP);
		*match_index += 1;
		break;
	case ETHTOOL_FLOW_TYPE_AH4:
	case ETHTOOL_FLOW_TYPE_ESP4:
		/* TODO: Complete here when adding support for ah4, esp4 */
		break;
	case ETHTOOL_FLOW_TYPE_IP6:
		*ipv6_flow = true;
		break;
	case ETHTOOL_FLOW_TYPE_TCP6:
		*ipv6_flow = true;
		create_match_l4proto(match, *ipv6_flow, IPPROTO_TCP);
		*match_index += 1;
		break;
	case ETHTOOL_FLOW_TYPE_UDP6:
		*ipv6_flow = true;
		create_match_l4proto(match, *ipv6_flow, IPPROTO_UDP);
		*match_index += 1;
		break;
	case ETHTOOL_FLOW_TYPE_SCTP6:
		*ipv6_flow = true;
		create_match_l4proto(match, *ipv6_flow, IPPROTO_SCTP);
		*match_index += 1;
		break;
	case ETHTOOL_FLOW_TYPE_AH6:
	case ETHTOOL_FLOW_TYPE_ESP6:
		/* TODO: Complete here when adding support for ah6, esp6 */
		*ipv6_flow = true;
		break;
	default:
		break;
	}

	return 0;
}

static int
set_match_type(struct kefir_match *match, bool ipv6_flow,
	       enum ethtool_val_type val_type)
{
	switch (val_type) {
	case ETHTOOL_VAL_TYPE_ETHER_SRC:
		match->match_type = KEFIR_MATCH_TYPE_ETHER_SRC;
		break;
	case ETHTOOL_VAL_TYPE_ETHER_DST:
		match->match_type = KEFIR_MATCH_TYPE_ETHER_DST;
		break;
	case ETHTOOL_VAL_TYPE_ETHER_PROTO:
		match->match_type = KEFIR_MATCH_TYPE_ETHER_PROTO;
		break;
	case ETHTOOL_VAL_TYPE_IP_SRC:
		if (ipv6_flow)
			match->match_type = KEFIR_MATCH_TYPE_IP_6_SRC;
		else
			match->match_type = KEFIR_MATCH_TYPE_IP_4_SRC;
		break;
	case ETHTOOL_VAL_TYPE_IP_DST:
		if (ipv6_flow)
			match->match_type = KEFIR_MATCH_TYPE_IP_6_DST;
		else
			match->match_type = KEFIR_MATCH_TYPE_IP_4_DST;
		break;
	case ETHTOOL_VAL_TYPE_IPV4_TOS:
		match->match_type = KEFIR_MATCH_TYPE_IP_4_TOS;
		break;
	case ETHTOOL_VAL_TYPE_IPV6_TCLASS:
		match->match_type = KEFIR_MATCH_TYPE_IP_6_TOS;
		break;
	case ETHTOOL_VAL_TYPE_L4_PROTO:
		if (ipv6_flow)
			match->match_type = KEFIR_MATCH_TYPE_IP_6_L4PROTO;
		else
			match->match_type = KEFIR_MATCH_TYPE_IP_4_L4PROTO;
		break;
	case ETHTOOL_VAL_TYPE_L4_PORT_SRC:
		if (ipv6_flow)
			match->match_type = KEFIR_MATCH_TYPE_IP_6_L4PORT_SRC;
		else
			match->match_type = KEFIR_MATCH_TYPE_IP_4_L4PORT_SRC;
		break;
	case ETHTOOL_VAL_TYPE_L4_PORT_DST:
		if (ipv6_flow)
			match->match_type = KEFIR_MATCH_TYPE_IP_6_L4PORT_DST;
		else
			match->match_type = KEFIR_MATCH_TYPE_IP_4_L4PORT_DST;
		break;
	case ETHTOOL_VAL_TYPE_IP_L4DATA:
		if (ipv6_flow)
			match->match_type = KEFIR_MATCH_TYPE_IP_6_L4DATA;
		else
			match->match_type = KEFIR_MATCH_TYPE_IP_4_L4DATA;
		break;
	case ETHTOOL_VAL_TYPE_VLAN_ETYPE:
		match->match_type = KEFIR_MATCH_TYPE_VLAN_ETHERTYPE;
		break;
	case ETHTOOL_VAL_TYPE_VLAN_ID:
		match->match_type = KEFIR_MATCH_TYPE_VLAN_ID;
		break;
	case ETHTOOL_VAL_TYPE_IP_SPI:
		/* TODO: Add support for spi. For now, fall through */
	default:
		err_bug("unknown enum value for value type: %d", val_type);
		return -1;
	}

	return 0;
}

static int
parse_value(const char *input, enum value_format format, void *output)
{
	struct kefir_value *val;

	val = container_of(output, struct kefir_value, data);

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
		err_bug("unknown enum value for match value format: %d",
			format);
		return -1;
	}

	return 0;
}

static int get_action_code(const char *input, enum action_code *action)
{
	char *endptr;
	long code;

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

struct kefir_rule *ethtool_parse_rule(const char **user_rule, size_t rule_size)
{
	struct ethtool_option current_opt = { .name = "" };
	size_t flow_opts_len, i, match_index = 0;
	enum ethtool_flow_type flow_type;
	enum action_code action_code;
	ethtool_opts_t *flow_opts;
	struct kefir_rule *rule;
	bool ipv6_flow;

	/*
	 * Shortest rules: "flow-type <type> <field> <value> action <value>"
	 * Longest rules: for now, same thing, in future we may have masks?
	 */
	if (rule_size < 6 || rule_size > 8) {
		err_fail("bad number of arguments");
		return NULL;
	}
	if (strcmp(*user_rule, "flow-type")) {
		err_fail("expected 'flow-type', got '%s'", *user_rule);
		return NULL;
	}
	user_rule++;

	rule = calloc(1, sizeof(struct kefir_rule));
	if (!rule) {
		err_fail("failed to allocate memory for rule");
		return NULL;
	}

	flow_type = get_flow_type(*user_rule);
	if (flow_type < 0)
		goto err_free_rule;
	if (get_flow_opts(flow_type, &flow_opts, &flow_opts_len))
		goto err_free_rule;
	if (account_for_flow_type(&rule->matches[match_index], flow_type,
				  &ipv6_flow, &match_index))
		goto err_free_rule;
	user_rule++;

	for (i = 0; i < flow_opts_len; i++) {
		if (strcmp(*user_rule, flow_opts[i]->name))
			continue;
		current_opt = *flow_opts[i];
		break;
	}
	if (!current_opt.name[0]) {
		err_fail("unsupported option %s", *user_rule);
		goto err_free_rule;
	}
	user_rule++;

	if (set_match_type(&rule->matches[match_index], ipv6_flow,
			   current_opt.type))
		goto err_free_rule;

	if (parse_value(*user_rule, current_opt.format,
			&rule->matches[match_index].value.data))
		goto err_free_rule;
	rule->matches[match_index].value.format = current_opt.format;
	user_rule++;

	if (!strcmp(*user_rule, "m")) {
		user_rule++;
		/*
		 * In parse_value() below, Mask will be cast as a struct
		 * kefir_value.data, this assumes that "data" attribute is the
		 * first attribute of struct kefir_value (null offset).
		 */
		if (offset_of(struct kefir_value, data) != 0) {
			err_bug("data offset in struct kefir_value should be null");
			goto err_free_rule;
		}
		if (parse_value(*user_rule,
				rule->matches[match_index].value.format,
				&rule->matches[match_index].mask))
			goto err_free_rule;
		user_rule++;
	}

	/*
	 * TODO: Support rules with two parameters. Some fields are considered
	 * as "extensions" by ethtool, and can be used in combination with
	 * regular fields. Extensions include vlan, vlan-etype and dst-mac.
	 */

	rule->matches[match_index].comp_operator = OPER_EQUAL;
	match_index++;

	if (strcmp(*user_rule, "action")) {
		err_fail("expected 'action', got '%s'", *user_rule);
		goto err_free_rule;
	}
	user_rule++;

	if (get_action_code(*user_rule, &action_code))
		goto err_free_rule;
	rule->action = action_code;

	return rule;

err_free_rule:
	free(rule);
	return NULL;
}
