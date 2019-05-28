// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <linux/bpf.h>

#include "tester.h"

/* Ether */

static struct test_rule src_bitmask_match = {
	.rule = "protocol ip flower src_mac ff:00:ff:0d:0e:0f/00:00:00:ff:ff:ff action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule src_bitmask_nomatch = {
	.rule = "protocol ip flower src_mac 0a:0b:0c:ff:00:ff/00:00:00:ff:ff:ff action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule src_nbbits_match = {
	.rule = "protocol ip flower src_mac 0a:0b:0c:ff:00:ff/24 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule src_nbbits_nomatch = {
	.rule = "protocol ip flower src_mac 11:0b:0c:ff:00:ff/25 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dst_bitmask_match = {
	.rule = "protocol ip flower dst_mac 01:20:03:40:05:60/ff:00:ff:00:ff:00 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dst_bitmask_nomatch = {
	.rule = "protocol ip flower dst_mac 10:02:30:04:50:06/ff:00:ff:00:ff:00 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dst_nbbits_match = {
	.rule = "protocol ip flower dst_mac 01:02:03:04:05:ff/40 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dst_nbbits_nomatch = {
	.rule = "protocol ip flower dst_mac aa:02:03:04:05:ff/40 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

/* IPv4 */

static struct test_rule src_ipv4_nbbits_match = {
	.rule = "protocol ip flower src_ip 10.10.10.0/24 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule src_ipv4_nbbits_nomatch = {
	.rule = "protocol ip flower src_ip 10.10.99.99/24 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dst_ipv4_nbbits_match = {
	.rule = "protocol ip flower dst_ip 10.10.0.0/8 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dst_ipv4_nbbits_nomatch = {
	.rule = "protocol ip flower dst_ip 10.10.0.0/24 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule tos_ipv4_bitmask_match = {
	.rule = "protocol ip flower ip_tos 9/0x08 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule tos_ipv4_bitmask_nomatch = {
	.rule = "protocol ip flower ip_tos 9/0xff action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule ttl_ipv4_bitmask_match = {
	.rule = "protocol ip flower ip_ttl 255/0x40 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule ttl_ipv4_bitmask_nomatch = {
	.rule = "protocol ip flower ip_ttl 255/0x41 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

/* IPv6 */

static struct test_rule src_ipv6_nbbits_match = {
	.rule = "protocol ipv6 flower src_ip cafe:0004:0a11:f000::/48 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule src_ipv6_nbbits_nomatch = {
	.rule = "protocol ipv6 flower src_ip cafe:0004:0a11:f000::/49 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dst_ipv6_nbbits_match = {
	.rule = "protocol ipv6 flower dst_ip 0011:2233:4455:6677:8899:aabb:ccdd:eeff/128 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dst_ipv6_nbbits_nomatch = {
	.rule = "protocol ipv6 flower dst_ip 0011:2233:aaaa:6677:8899:aabb:ccdd:eeff/128 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule tclass_ipv6_bitmask_match = {
	.rule = "protocol ipv6 flower ip_tos 29/0x1c action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule tclass_ipv6_bitmask_nomatch = {
	.rule = "protocol ipv6 flower ip_tos 27/0x1c action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule hoplimit_ipv6_bitmask_match = {
	.rule = "protocol ipv6 flower ip_ttl 66/0x41 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule hoplimit_ipv6_bitmask_nomatch = {
	.rule = "protocol ipv6 flower ip_ttl 63/0x41 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

struct kefir_test tcflower_basic_tests_masks[] = {

	/* Ether */

	{
		.name = "tcflower_basic_masks_src_bitmask_match",
		.rule_set = { &src_bitmask_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_masks_src_bitmask_nomatch",
		.rule_set = { &src_bitmask_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_masks_src_nbbits_match",
		.rule_set = { &src_nbbits_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_masks_src_nbbits_nomatch",
		.rule_set = { &src_nbbits_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_masks_dst_bitmask_match",
		.rule_set = { &dst_bitmask_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_masks_dst_bitmask_nomatch",
		.rule_set = { &dst_bitmask_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_masks_dst_nbbits_match",
		.rule_set = { &dst_nbbits_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_masks_dst_nbbits_nomatch",
		.rule_set = { &dst_nbbits_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},

	/* IPv4 */

	{
		.name = "tcflower_basic_masks_src_ipv4_nbbits_match",
		.rule_set = { &src_ipv4_nbbits_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_masks_src_ipv4_nbbits_nomatch",
		.rule_set = { &src_ipv4_nbbits_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_masks_dst_ipv4_nbbits_match",
		.rule_set = { &dst_ipv4_nbbits_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_masks_dst_ipv4_nbbits_nomatch",
		.rule_set = { &dst_ipv4_nbbits_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_masks_tos_ipv4_bitmask_match",
		.rule_set = { &tos_ipv4_bitmask_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_masks_tos_ipv4_bitmask_nomatch",
		.rule_set = { &tos_ipv4_bitmask_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_masks_ttl_ipv4_bitmask_match",
		.rule_set = { &ttl_ipv4_bitmask_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_masks_ttl_ipv4_bitmask_nomatch",
		.rule_set = { &ttl_ipv4_bitmask_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},

	/* IPv6 */

	{
		.name = "tcflower_basic_masks_src_ipv6_nbbits_match",
		.rule_set = { &src_ipv6_nbbits_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_masks_src_ipv6_nbbits_nomatch",
		.rule_set = { &src_ipv6_nbbits_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_masks_dst_ipv6_nbbits_match",
		.rule_set = { &dst_ipv6_nbbits_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_masks_dst_ipv6_nbbits_nomatch",
		.rule_set = { &dst_ipv6_nbbits_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_masks_tclass_ipv6_bitmask_match",
		.rule_set = { &tclass_ipv6_bitmask_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_masks_tclass_ipv6_bitmask_nomatch",
		.rule_set = { &tclass_ipv6_bitmask_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_masks_hoplimit_ipv6_bitmask_match",
		.rule_set = { &hoplimit_ipv6_bitmask_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_masks_hoplimit_ipv6_bitmask_nomatch",
		.rule_set = { &hoplimit_ipv6_bitmask_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},

	/* Keep empty struct at the end */
	{
		.name = "",
	}
};
