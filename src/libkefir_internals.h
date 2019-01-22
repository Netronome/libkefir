/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef LIBKEFIR_INTERNALS_H
#define LIBKEFIR_INTERNALS_H

#include <stdint.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "list.h"
#include "libkefir_error.h"

enum header_type {
	HDR_TYPE_ETHERNET,
	HDR_TYPE_VLAN,
	HDR_TYPE_ARP,
	HDR_TYPE_IP,
	HDR_TYPE_TCP,
	HDR_TYPE_UDP,
	HDR_TYPE_SCTP,
	HDR_TYPE_IPSEC,
	HDR_TYPE_APPLI,
};

enum comp_operator {
	OPER_EQUAL,
	OPER_LT,
	OPER_LEQ,
	OPER_GT,
	OPER_GEQ,
};

enum action_code {
	ACTION_CODE_DROP,
	ACTION_CODE_PASS,
};

#define KEFIR_MATCH_FLAG_IPV4	1 << 0
#define KEFIR_MATCH_FLAG_IPV6	1 << 1

enum value_format {
	KEFIR_VAL_FMT_UINT8,
	KEFIR_VAL_FMT_UINT16,
	KEFIR_VAL_FMT_UINT32,
	KEFIR_VAL_FMT_TOS,
	KEFIR_VAL_FMT_MAC_ADDR,
	KEFIR_VAL_FMT_IPV4_ADDR,
	KEFIR_VAL_FMT_IPV6_ADDR,
	KEFIR_VAL_FMT_VLAN_ID,
};

struct kefir_value {
	union {
		struct ether_addr	eth;
		struct in6_addr		ipv6;
		struct in_addr		ipv4;
		uint32_t		n; /* All other values <= uint32_t */
	}			data;
	enum value_format	format;
};

/*
 * - One protocol header type (Ethernet, ARP, IPv4, IPv6, TCP, UDP, application, etc.)
 * - One offset in this header (TODO: check if we have fields with non-fixed offsets)
 * - The length of the field to match.
 * - One mask to apply to the field.
 * - A value to match. If matching against a range of values, this should be the minimum value of the range.
 * - A maximum value to match, for ranges.
 * - An operator to indicate what type of comparison should be performed (equality, or other arithmetic or logic operator).
 * - Option flags, indicating for example that the match is against a range of values instead of a single value.
 */
struct kefir_match {
	enum header_type	header_type;
	uint16_t		match_offset;
	uint8_t			match_length;
	char			mask[16];
	struct kefir_value	value;
	char			max_value[16];
	enum comp_operator	comp_operator;
	uint64_t		flags;
};

/*
struct kefir_action {
	enum action_code	code;
	uint64_t		value;
};
*/

struct kefir_rule {
	struct kefir_match match;
//	struct kefir_action action;
	enum action_code action;
};

struct kefir_filter {
	struct list *rules;
};

#endif /* LIBKEFIR_INTERNALS_H */
