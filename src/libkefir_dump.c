// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "list.h"
#include "libkefir.h"
#include "libkefir_buffer.h"
#include "libkefir_error.h"
#include "libkefir_dump.h"
#include "libkefir_internals.h"

DEFINE_ERR_FUNCTIONS("dump")

static const char *comp_operator_str(enum comp_operator op)
{
	switch (op) {
	case OPER_EQUAL:
		return "==";
	case OPER_LT:
		return "<";
	case OPER_LEQ:
		return "<=";
	case OPER_GT:
		return ">";
	case OPER_GEQ:
		return ">=";
	default:
		return "";
	}
}

static void
value_str(union kefir_value val, enum value_format format, char *buf,
	  size_t buf_len)
{
	switch (format) {
	case KEFIR_VAL_FMT_BIT:
	case KEFIR_VAL_FMT_UINT3:
	case KEFIR_VAL_FMT_UINT6:
	case KEFIR_VAL_FMT_UINT8:
		snprintf(buf, buf_len, "%hhd", val.u8);
		break;
	case KEFIR_VAL_FMT_UINT12:
	case KEFIR_VAL_FMT_UINT16:
		snprintf(buf, buf_len, "%hd", ntohs(val.u16));
		break;
	case KEFIR_VAL_FMT_UINT20:
	case KEFIR_VAL_FMT_UINT32:
		snprintf(buf, buf_len, "%d", ntohl(val.u32));
		break;
	case KEFIR_VAL_FMT_MAC_ADDR:
		snprintf(buf, buf_len, "%s", ether_ntoa(&val.eth));
		break;
	case KEFIR_VAL_FMT_IPV4_ADDR:
		inet_ntop(AF_INET, &val.ipv4, buf, buf_len);
		break;
	case KEFIR_VAL_FMT_IPV6_ADDR:
		inet_ntop(AF_INET6, &val.ipv6, buf, buf_len);
		break;
	default:
		return;
	}
}

static void mask_str(uint8_t *mask, size_t mask_len, char *buf, size_t buf_len)
{
	size_t i;

	for (i = 0; i < mask_len; i++)
		snprintf(buf + i * 3, buf_len - i * 3, "%02hhx ", mask[i]);

	for (i = strlen(buf) - 1; buf[i] == ' ' || buf[i] == '0'; i--) {
		/* Rewind */
	}
	buf[i + 1] = '\0';
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
	case KEFIR_MATCH_TYPE_IP_4_L4PORT_SRC:
		return "IPv4, L4 source port";
	case KEFIR_MATCH_TYPE_IP_4_L4PORT_DST:
		return "IPv4, L4 destination port";
	case KEFIR_MATCH_TYPE_IP_4_L4PORT_ANY:
		return "IPv4, L4 any port";
	case KEFIR_MATCH_TYPE_IP_4_SPI:
		return "IPv4, SPI";
	case KEFIR_MATCH_TYPE_IP_4_TCP_FLAGS:
		return "IPv4, TCP flags";
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
	case KEFIR_MATCH_TYPE_IP_6_L4PORT_SRC:
		return "IPv6, L4 source port";
	case KEFIR_MATCH_TYPE_IP_6_L4PORT_DST:
		return "IPv6, L4 destination port";
	case KEFIR_MATCH_TYPE_IP_6_L4PORT_ANY:
		return "IPv6, L4 any port";
	case KEFIR_MATCH_TYPE_IP_6_SPI:
		return "IPv6, SPI";
	case KEFIR_MATCH_TYPE_IP_6_TCP_FLAGS:
		return "IPv6, TCP flags";
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
	case KEFIR_MATCH_TYPE_IP_ANY_L4PORT_SRC:
		return "IP, L4 source port";
	case KEFIR_MATCH_TYPE_IP_ANY_L4PORT_DST:
		return "IP, L4 destination port";
	case KEFIR_MATCH_TYPE_IP_ANY_L4PORT_ANY:
		return "IP, L4 any port";
	case KEFIR_MATCH_TYPE_IP_ANY_TCP_FLAGS:
		return "IP, TCP flags";
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
 * Variadic list should contain:
 *     char **buf_ptr
 *     size_t *buf_len
 *     const char *prefix
 *     unsigned int *rule_nb
 */
static int dump_rule(void *rule_ptr, va_list ap)
{
	struct kefir_rule *rule = (struct kefir_rule *)rule_ptr;
	size_t strval_len = 128;
	char strval[strval_len];
	unsigned int *rule_nb;
	const char *prefix;
	size_t *buf_len;
	char **buf_ptr;
	size_t i;

	buf_ptr = va_arg(ap, char **);
	buf_len = va_arg(ap, size_t *);
	prefix = va_arg(ap, const char *);
	rule_nb = va_arg(ap, unsigned int *);

	if (buf_append(buf_ptr, buf_len, "%s - rule %2zd\n", prefix, *rule_nb))
		return -1;
	for (i = 0; i < KEFIR_MAX_MATCH_PER_RULE &&
	     rule->matches[i].match_type != KEFIR_MATCH_TYPE_UNSPEC; i++) {
		struct kefir_match *match = &rule->matches[i];

		if (buf_append(buf_ptr, buf_len, "%s\tmatch %2zd: %-32s",
			       prefix, i, match_type_str(match->match_type)))
			return -1;
		if (buf_append(buf_ptr, buf_len, " | operator %2zd: %2s", i,
			       comp_operator_str(match->comp_operator)))
			return -1;
		value_str(match->value, type_format[match->match_type], strval,
			  strval_len);
		if (buf_append(buf_ptr, buf_len, " | value %2zd: %-16s", i,
			       strval))
			return -1;
		if (match->flags & MATCH_FLAGS_USE_MASK) {
			mask_str(match->mask,
				 sizeof(match->mask), strval,
				 strval_len);
			if (buf_append(buf_ptr, buf_len, " | mask %2zd: %s",
				       i, strval))
				return -1;
		}
		if (buf_append(buf_ptr, buf_len, "\n"))
			return -1;
	}
	if (buf_append(buf_ptr, buf_len, "%s\taction: %s\n", prefix,
		       action_str(rule->action)))
		return -1;

	*rule_nb += 1;
	return 0;
}

int dump_filter_to_buf(const kefir_filter *filter, char **buf, size_t *buf_len,
		       const char *prefix)
{
	unsigned int count = 0;

	*buf_len = KEFIR_CPROG_INIT_BUFLEN;
	*buf = calloc(*buf_len, sizeof(*buf));
	if (!*buf) {
		err_fail("failed to allocate memory for dumping filter");
		return -1;
	}

	return list_for_each((struct list *)filter->rules, dump_rule, buf,
			     buf_len, prefix, &count);
}
