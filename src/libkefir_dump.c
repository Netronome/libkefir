// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include "libkefir_dump.h"

static const char *comp_operator_str(enum comp_operator op)
{
	switch (op) {
	case OPER_EQUAL:
		return "==";
	case OPER_LT:
		return "< ";
	case OPER_LEQ:
		return "<=";
	case OPER_GT:
		return "> ";
	case OPER_GEQ:
		return ">=";
	default:
		return "";
	}
}

static void value_str(struct kefir_value val, char *buf, size_t buf_len)
{
	switch (val.format) {
	case KEFIR_VAL_FMT_BIT:
	case KEFIR_VAL_FMT_UINT3:
	case KEFIR_VAL_FMT_UINT6:
	case KEFIR_VAL_FMT_UINT8:
		snprintf(buf, buf_len, "%c", ntohs(val.data.u8));
		break;
	case KEFIR_VAL_FMT_UINT12:
	case KEFIR_VAL_FMT_UINT16:
		snprintf(buf, buf_len, "%hd", ntohs(val.data.u16));
		break;
	case KEFIR_VAL_FMT_UINT20:
	case KEFIR_VAL_FMT_UINT32:
		snprintf(buf, buf_len, "%d", ntohl(val.data.u32));
		break;
	case KEFIR_VAL_FMT_MAC_ADDR:
		snprintf(buf, buf_len, "%s", ether_ntoa(&val.data.eth));
		break;
	case KEFIR_VAL_FMT_IPV4_ADDR:
		inet_ntop(AF_INET, &val.data.ipv4, buf, buf_len);
		break;
	case KEFIR_VAL_FMT_IPV6_ADDR:
		inet_ntop(AF_INET6, &val.data.ipv6, buf, buf_len);
		break;
	default:
		return;
	}
}

static const char *action_str(enum action_code ac)
{
	switch (ac) {
	case ACTION_CODE_DROP:
		return "drop";
	case ACTION_CODE_PASS:
		return "pass";
	default:
		return "";
	}
}

__attribute__ ((format (printf, 3, 4)))
static void append(char **buf, size_t *buf_len, const char *fmt, ...)
{
	size_t len;
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(*buf, *buf_len, fmt, ap);
	va_end(ap);
	len = strlen(*buf);

	*buf += len;
	*buf_len += len;
}

static const char *match_type_str(enum match_type match_type)
{
	switch (match_type) {
	case KEFIR_MATCH_TYPE_ETHER_SRC:
		return "ether source address";
	case KEFIR_MATCH_TYPE_ETHER_DST:
		return "ether destination address";
	case KEFIR_MATCH_TYPE_ETHER_ANY:
		return "any ether address";
	case KEFIR_MATCH_TYPE_ETHER_PROTO:
		return "ether protocol";
	case KEFIR_MATCH_TYPE_IP_4_SRC:
		return "IPv4 source address";
	case KEFIR_MATCH_TYPE_IP_4_DST:
		return "IPv4 destination address";
	case KEFIR_MATCH_TYPE_IP_4_ANY:
		return "any IPv4 address";
	case KEFIR_MATCH_TYPE_IP_4_TOS:
		return "IPv4 ToS";
	case KEFIR_MATCH_TYPE_IP_4_TTL:
		return "IPv4 TTL";
	case KEFIR_MATCH_TYPE_IP_4_FLAGS:
		return "IPv4 flags";
	case KEFIR_MATCH_TYPE_IP_4_L4PROTO:
		return "IPv4, L4 protocol";
	case KEFIR_MATCH_TYPE_IP_4_L4DATA:
		return "IPv4, L4 first 4 bytes of data";
	case KEFIR_MATCH_TYPE_IP_4_SPI:
		return "IPv4, SPI";
	case KEFIR_MATCH_TYPE_IP_6_SRC:
		return "IPv6 source address";
	case KEFIR_MATCH_TYPE_IP_6_DST:
		return "IPv6 destination address";
	case KEFIR_MATCH_TYPE_IP_6_ANY:
		return "any IPv6 address";
	case KEFIR_MATCH_TYPE_IP_6_TOS:
		return "IPv6 traffic class";
	case KEFIR_MATCH_TYPE_IP_6_TTL:
		return "IPv6 TTL";
	case KEFIR_MATCH_TYPE_IP_6_FLAGS:
		return "IPv6 flags";
	case KEFIR_MATCH_TYPE_IP_6_L4PROTO:
		return "IPv6, L4 protocol";
	case KEFIR_MATCH_TYPE_IP_6_L4DATA:
		return "IPv6, L4 first 4 bytes of data";
	case KEFIR_MATCH_TYPE_IP_6_SPI:
		return "IPv6, SPI";
	case KEFIR_MATCH_TYPE_IP_ANY_SRC:
		return "IP source address";
	case KEFIR_MATCH_TYPE_IP_ANY_DST:
		return "IP destination address";
	case KEFIR_MATCH_TYPE_IP_ANY_ANY:
		return "any IP address";
	case KEFIR_MATCH_TYPE_IP_ANY_TOS:
		return "IP ToS (IPv4) or traffic class (IPv6)";
	case KEFIR_MATCH_TYPE_IP_ANY_TTL:
		return "IP TTL";
	case KEFIR_MATCH_TYPE_IP_ANY_FLAGS:
		return "IP flags";
	case KEFIR_MATCH_TYPE_IP_ANY_L4PROTO:
		return "IP, L4 protocol";
	case KEFIR_MATCH_TYPE_IP_ANY_L4DATA:
		return "IP, L4 first 4 bytes of data";
	case KEFIR_MATCH_TYPE_IP_ANY_SPI:
		return "IP, SPI";
	case KEFIR_MATCH_TYPE_L4_PORT_SRC:
		return "L4 source port";
	case KEFIR_MATCH_TYPE_L4_PORT_DST:
		return "L4 destination port";
	case KEFIR_MATCH_TYPE_L4_PORT_ANY:
		return "L4 any port";
	case KEFIR_MATCH_TYPE_TCP_FLAGS:
		return "TCP flags";
	case KEFIR_MATCH_TYPE_VLAN_ID:
		return "VLAN ID";
	case KEFIR_MATCH_TYPE_VLAN_PRIO:
		return "VLAN priority";
	case KEFIR_MATCH_TYPE_VLAN_ETHERTYPE:
		return "VLAN ethertype";
	case KEFIR_MATCH_TYPE_CVLAN_ID:
		return "CVLAN ID";
	case KEFIR_MATCH_TYPE_CVLAN_PRIO:
		return "CVLAN priority";
	case KEFIR_MATCH_TYPE_CVLAN_ETHERTYPE:
		return "CVLAN ethertype";
	case KEFIR_MATCH_TYPE_MPLS_LABEL:
		return "MPLS label";
	case KEFIR_MATCH_TYPE_MPLS_TC:
		return "MPLS traffic class";
	case KEFIR_MATCH_TYPE_MPLS_BOS:
		return "MPLS bottom-of-stack flag";
	case KEFIR_MATCH_TYPE_MPLS_TTL:
		return "MPLS TTL";
	case KEFIR_MATCH_TYPE_ICMP_TYPE:
		return "ICMP type";
	case KEFIR_MATCH_TYPE_ICMP_CODE:
		return "ICMP code";
	case KEFIR_MATCH_TYPE_ARP_TIP:
		return "ARP TIP";
	case KEFIR_MATCH_TYPE_ARP_SIP:
		return "ARP SIP";
	case KEFIR_MATCH_TYPE_ARP_OP:
		return "ARP OP";
	case KEFIR_MATCH_TYPE_ARP_THA:
		return "ARP THA";
	case KEFIR_MATCH_TYPE_ARP_SHA:
		return "ARP SHA";
	case KEFIR_MATCH_TYPE_ENC_KEY_ID:
		return "Encryption key ID";
	case KEFIR_MATCH_TYPE_ENC_DST_ID:
		return "Encryption destination ID";
	case KEFIR_MATCH_TYPE_ENC_SRC_ID:
		return "Encryption source ID";
	case KEFIR_MATCH_TYPE_ENC_DST_PORT:
		return "Encryption destination port";
	case KEFIR_MATCH_TYPE_ENC_TOS:
		return "Encryption ToS";
	case KEFIR_MATCH_TYPE_ENC_TTL:
		return "Encryption TTL";
	case KEFIR_MATCH_TYPE_GENEVE_OPTIONS:
		return "GENEVE options";
	default:
		return "";
	}
}

/*
 * Should be called as
 * int dump_rule(struct kefir_rule *rule_ptr, char **buf_ptr, size_t *buf_len)
 */
static int dump_rule(void *rule_ptr, va_list ap)
{
	struct kefir_rule *rule = (struct kefir_rule *)rule_ptr;
	size_t strval_len = 32;
	char strval[strval_len];
	size_t *buf_len;
	char **buf_ptr;

	buf_ptr = va_arg(ap, char **);
	buf_len = va_arg(ap, size_t *);

	append(buf_ptr, buf_len, "match: %s\t| ",
	       match_type_str(rule->match.match_type));
	append(buf_ptr, buf_len, "operator: %s | ",
	       comp_operator_str(rule->match.comp_operator));
	value_str(rule->match.value, strval, strval_len);
	append(buf_ptr, buf_len, "value: %s\t| ", strval);
	append(buf_ptr, buf_len, "action: %s | ",
	       action_str(rule->action));

	append(buf_ptr, buf_len, "\n");

	return 0;
}

void kefir_dump_filter_to_buf(const kefir_filter *filter, char *buf,
			      size_t buf_len)
{
	list_for_each((struct list *)filter->rules, dump_rule, &buf, &buf_len);
}
