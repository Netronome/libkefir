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

enum match_type {
	KEFIR_MATCH_TYPE_ETHER_SRC,
	KEFIR_MATCH_TYPE_ETHER_DST,
	KEFIR_MATCH_TYPE_ETHER_ANY,	/* Either source or destination */
	KEFIR_MATCH_TYPE_ETHER_PROTO,

	KEFIR_MATCH_TYPE_IP_4_SRC,
	KEFIR_MATCH_TYPE_IP_4_DST,
	KEFIR_MATCH_TYPE_IP_4_ANY,	/* Either source or destination */
	KEFIR_MATCH_TYPE_IP_4_TOS,
	KEFIR_MATCH_TYPE_IP_4_TTL,
	KEFIR_MATCH_TYPE_IP_4_FLAGS,
	KEFIR_MATCH_TYPE_IP_4_L4PROTO,
	KEFIR_MATCH_TYPE_IP_4_L4DATA,
	KEFIR_MATCH_TYPE_IP_4_SPI,

	KEFIR_MATCH_TYPE_IP_6_SRC,
	KEFIR_MATCH_TYPE_IP_6_DST,
	KEFIR_MATCH_TYPE_IP_6_ANY,	/* Either source or destination */
	KEFIR_MATCH_TYPE_IP_6_TOS,	/* Actually TCLASS, traffic class */
	KEFIR_MATCH_TYPE_IP_6_TTL,
	KEFIR_MATCH_TYPE_IP_6_FLAGS,
	KEFIR_MATCH_TYPE_IP_6_L4PROTO,
	KEFIR_MATCH_TYPE_IP_6_L4DATA,
	KEFIR_MATCH_TYPE_IP_6_SPI,

	KEFIR_MATCH_TYPE_IP_ANY_SRC,
	KEFIR_MATCH_TYPE_IP_ANY_DST,
	KEFIR_MATCH_TYPE_IP_ANY_ANY,	/* Either source or destination */
	KEFIR_MATCH_TYPE_IP_ANY_TOS,
	KEFIR_MATCH_TYPE_IP_ANY_TTL,
	KEFIR_MATCH_TYPE_IP_ANY_FLAGS,
	KEFIR_MATCH_TYPE_IP_ANY_L4PROTO,
	KEFIR_MATCH_TYPE_IP_ANY_L4DATA,
	KEFIR_MATCH_TYPE_IP_ANY_SPI,

	KEFIR_MATCH_TYPE_L4_PORT_SRC,
	KEFIR_MATCH_TYPE_L4_PORT_DST,
	KEFIR_MATCH_TYPE_L4_PORT_ANY,	/* Either source or destination */

	KEFIR_MATCH_TYPE_TCP_FLAGS,

	KEFIR_MATCH_TYPE_VLAN_ID,
	KEFIR_MATCH_TYPE_VLAN_PRIO,
	KEFIR_MATCH_TYPE_VLAN_ETHERTYPE,

	KEFIR_MATCH_TYPE_CVLAN_ID,
	KEFIR_MATCH_TYPE_CVLAN_PRIO,
	KEFIR_MATCH_TYPE_CVLAN_ETHERTYPE,

	KEFIR_MATCH_TYPE_MPLS_LABEL,
	KEFIR_MATCH_TYPE_MPLS_TC,
	KEFIR_MATCH_TYPE_MPLS_BOS,
	KEFIR_MATCH_TYPE_MPLS_TTL,

	KEFIR_MATCH_TYPE_ICMP_TYPE,
	KEFIR_MATCH_TYPE_ICMP_CODE,

	KEFIR_MATCH_TYPE_ARP_TIP,
	KEFIR_MATCH_TYPE_ARP_SIP,
	KEFIR_MATCH_TYPE_ARP_OP,
	KEFIR_MATCH_TYPE_ARP_THA,
	KEFIR_MATCH_TYPE_ARP_SHA,

	KEFIR_MATCH_TYPE_ENC_KEY_ID,
	KEFIR_MATCH_TYPE_ENC_DST_ID,
	KEFIR_MATCH_TYPE_ENC_SRC_ID,
	KEFIR_MATCH_TYPE_ENC_DST_PORT,
	KEFIR_MATCH_TYPE_ENC_TOS,
	KEFIR_MATCH_TYPE_ENC_TTL,

	KEFIR_MATCH_TYPE_GENEVE_OPTIONS,
};

enum value_format {
	KEFIR_VAL_FMT_BIT,	/* MPLS BoS */
	KEFIR_VAL_FMT_UINT3,	/* VLAN prio, MPLS TC */
	KEFIR_VAL_FMT_UINT6,	/* IPv4 ToS */
	KEFIR_VAL_FMT_UINT8,
	KEFIR_VAL_FMT_UINT12,	/* VLAN ID, TCP flags */
	KEFIR_VAL_FMT_UINT16,
	KEFIR_VAL_FMT_UINT20,	/* MPLS label */
	KEFIR_VAL_FMT_UINT32,
	KEFIR_VAL_FMT_MAC_ADDR,
	KEFIR_VAL_FMT_IPV4_ADDR,
	KEFIR_VAL_FMT_IPV6_ADDR,
};

struct kefir_value {
	union {
		struct ether_addr	eth;
		struct in6_addr		ipv6;
		struct in_addr		ipv4;
		uint32_t		u32;
		uint16_t		u16;
		uint8_t			u8;
		uint8_t			raw[sizeof(struct in6_addr)];
	}			data;
	enum value_format	format;
};

/*
 * - A type for the match, indicating the semantics of the data to match (semantics needed for optimizations).
 * - A value to match. If matching against a range of values, this should be the minimum value of the range.
 * - An operator to indicate what type of comparison should be performed (equality, or other arithmetic or logic operator).
 * - One protocol header type (Ethernet, ARP, IPv4, IPv6, TCP, UDP, application, etc.)
 * - One mask to apply to the field.
 * - A maximum value to match, for ranges.
 * - Option flags, indicating for example that the match is against a range of values instead of a single value.
 */
struct kefir_match {
	enum match_type		match_type;
	struct kefir_value	value;
	enum comp_operator	comp_operator;

	enum header_type	header_type;
	char			mask[16];
	char			max_value[16];
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
