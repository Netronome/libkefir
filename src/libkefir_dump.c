// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include "libkefir_dump.h"

static const char *header_type_str(enum header_type ht)
{
	switch (ht) {
	case HDR_TYPE_ETHERNET:
		return "ethernet";
	case HDR_TYPE_VLAN:
		return "vlan";
	case HDR_TYPE_ARP:
		return "arp";
	case HDR_TYPE_IP:
		return "ip";
	case HDR_TYPE_TCP:
		return "tcp";
	case HDR_TYPE_UDP:
		return "udp";
	case HDR_TYPE_SCTP:
		return "sctp";
	case HDR_TYPE_IPSEC:
		return "ipsec";
	case HDR_TYPE_APPLI:
		return "application";
	default:
		return "";
	}
}

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

	append(buf_ptr, buf_len, "header: %s \t | ",
	       header_type_str(rule->match.header_type));
	append(buf_ptr, buf_len, "offset: %2d | ", rule->match.match_offset);
	append(buf_ptr, buf_len, "length: %2d | ", rule->match.match_length);
	append(buf_ptr, buf_len, "operator: %s | ",
	       comp_operator_str(rule->match.comp_operator));
	value_str(rule->match.value, strval, strval_len);
	append(buf_ptr, buf_len, "value: %s\t| ", strval);
	append(buf_ptr, buf_len, "flags: %#016lx | ", rule->match.flags);
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
