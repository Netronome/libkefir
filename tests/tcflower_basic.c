// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <linux/bpf.h>

#include "tester.h"

static struct test_rule src_ipv4_match_pass = {
	.rule = "protocol ip flower src_ip 10.10.10.2 action pass",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

/* Ether */

static struct test_rule src_match = {
	.rule = "protocol ip flower src_mac 0a:0b:0c:0d:0e:0f action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule src_nomatch = {
	.rule = "protocol ip flower src_mac 11:0b:0c:0d:0e:0f action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dst_match = {
	.rule = "protocol ip flower dst_mac 01:02:03:04:05:06 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dst_nomatch = {
	.rule = "protocol ip flower dst_mac aa:02:03:04:05:06 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

/* IPv4 */

static struct test_rule src_ipv4_match = {
	.rule = "protocol ip flower src_ip 10.10.10.2 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule src_ipv4_nomatch = {
	.rule = "protocol ip flower src_ip 10.10.10.99 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dst_ipv4_match = {
	.rule = "protocol ip flower dst_ip 10.10.10.1 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dst_ipv4_nomatch = {
	.rule = "protocol ip flower dst_ip 10.10.10.99 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule tos_ipv4_match = {
	.rule = "protocol ip flower ip_tos 8 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule tos_ipv4_nomatch = {
	.rule = "protocol ip flower ip_tos 3 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule ttl_ipv4_match = {
	.rule = "protocol ip flower ip_ttl 64 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule ttl_ipv4_nomatch = {
	.rule = "protocol ip flower ip_ttl 48 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule l4proto_ipv4_match = {
	.rule = "protocol ip flower ip_proto 0x06 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule l4proto_ipv4_nomatch = {
	.rule = "protocol ip flower ip_proto 0x11 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule srcport_ipv4_match = {
	.rule = "protocol ip flower src_port 8888 ip_proto tcp action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule srcport_ipv4_nomatch = {
	.rule = "protocol ip flower src_port 8889 ip_proto tcp action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dstport_ipv4_match = {
	.rule = "protocol ip flower ip_proto tcp dst_port 2000 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dstport_ipv4_nomatch = {
	.rule = "protocol ip flower ip_proto tcp dst_port 2001 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

/* IPv6 */

static struct test_rule src_ipv6_match = {
	.rule = "protocol ipv6 flower src_ip cafe:0004:0a11::01 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule src_ipv6_nomatch = {
	.rule = "protocol ipv6 flower src_ip cafe:0004:0a11::02 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dst_ipv6_match = {
	.rule = "protocol ipv6 flower dst_ip 0011:2233:4455:6677:8899:aabb:ccdd:eeff action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dst_ipv6_nomatch = {
	.rule = "protocol ipv6 flower dst_ip ::1 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule tclass_ipv6_match = {
	.rule = "protocol ipv6 flower ip_tos 28 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule tclass_ipv6_nomatch = {
	.rule = "protocol ipv6 flower ip_tos 3 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule hoplimit_ipv6_match = {
	.rule = "protocol ipv6 flower ip_ttl 64 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule hoplimit_ipv6_nomatch = {
	.rule = "protocol ipv6 flower ip_ttl 48 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule l4proto_ipv6_match = {
	.rule = "protocol ipv6 flower ip_proto 0x06 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule l4proto_ipv6_nomatch = {
	.rule = "protocol ipv6 flower ip_proto 0x11 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule srcport_ipv6_match = {
	.rule = "protocol ipv6 flower src_port 8888 ip_proto tcp action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule srcport_ipv6_nomatch = {
	.rule = "protocol ipv6 flower src_port 8888 ip_proto udp action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dstport_ipv6_match = {
	.rule = "protocol ipv6 flower ip_proto tcp dst_port 2000 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule dstport_ipv6_nomatch = {
	.rule = "protocol ipv6 flower ip_proto tcp dst_port 2001 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

/* VLAN */

static struct test_rule vlan_id_match = {
	.rule = "protocol ip flower vlan_id 2748 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule vlan_id_nomatch = {
	.rule = "protocol ip flower vlan_id 3567 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule vlan_prio_match = {
	.rule = "protocol ip flower vlan_prio 5 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule vlan_prio_nomatch = {
	.rule = "protocol ip flower vlan_prio 7 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule vlan_etype_match = {
	.rule = "protocol ip flower vlan_ethtype 0x8100 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule vlan_etype_nomatch = {
	.rule = "protocol ip flower vlan_ethtype 0x8101 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

/* CVLAN */

static struct test_rule cvlan_id_match = {
	.rule = "protocol ip flower cvlan_id 3567 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule cvlan_id_nomatch = {
	.rule = "protocol ip flower cvlan_id 2748 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule cvlan_prio_match = {
	.rule = "protocol ip flower cvlan_prio 7 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule cvlan_prio_nomatch = {
	.rule = "protocol ip flower cvlan_prio 5 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule cvlan_etype_match = {
	.rule = "protocol ip flower cvlan_ethtype 0x86dd action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule cvlan_etype_nomatch = {
	.rule = "protocol ip flower cvlan_ethtype 0x8100 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

struct kefir_test tcflower_basic_tests[] = {

	{
		.name = "tcflower_basic_src_ipv4_match_pass",
		.rule_set = { &src_ipv4_match_pass },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},

	/* Ether */

	{
		.name = "tcflower_basic_src_match",
		.rule_set = { &src_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_src_nomatch",
		.rule_set = { &src_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_dst_match",
		.rule_set = { &dst_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_dst_nomatch",
		.rule_set = { &dst_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},

	/* IPv4 */

	{
		.name = "tcflower_basic_src_ipv4_match",
		.rule_set = { &src_ipv4_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_src_ipv4_nomatch",
		.rule_set = { &src_ipv4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_dst_ipv4_match",
		.rule_set = { &dst_ipv4_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_dst_ipv4_nomatch",
		.rule_set = { &dst_ipv4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_tos_ipv4_match",
		.rule_set = { &tos_ipv4_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_tos_ipv4_nomatch",
		.rule_set = { &tos_ipv4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_ttl_ipv4_match",
		.rule_set = { &ttl_ipv4_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_ttl_ipv4_nomatch",
		.rule_set = { &ttl_ipv4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_l4proto_ipv4_match",
		.rule_set = { &l4proto_ipv4_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_l4proto_ipv4_nomatch",
		.rule_set = { &l4proto_ipv4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_srcport_ipv4_match",
		.rule_set = { &srcport_ipv4_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_srcport_ipv4_nomatch",
		.rule_set = { &srcport_ipv4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_dstport_ipv4_match",
		.rule_set = { &dstport_ipv4_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_dstport_ipv4_nomatch",
		.rule_set = { &dstport_ipv4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},

	/* IPv6 */

	{
		.name = "tcflower_basic_src_ipv6_match",
		.rule_set = { &src_ipv6_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_src_ipv6_nomatch",
		.rule_set = { &src_ipv6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_dst_ipv6_match",
		.rule_set = { &dst_ipv6_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_dst_ipv6_nomatch",
		.rule_set = { &dst_ipv6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_tclass_ipv6_match",
		.rule_set = { &tclass_ipv6_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_tclass_ipv6_nomatch",
		.rule_set = { &tclass_ipv6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_hoplimit_ipv6_match",
		.rule_set = { &hoplimit_ipv6_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_hoplimit_ipv6_nomatch",
		.rule_set = { &hoplimit_ipv6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_l4proto_ipv6_match",
		.rule_set = { &l4proto_ipv6_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_l4proto_ipv6_nomatch",
		.rule_set = { &l4proto_ipv6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_srcport_ipv6_match",
		.rule_set = { &srcport_ipv6_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_srcport_ipv6_nomatch",
		.rule_set = { &srcport_ipv6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_dstport_ipv6_match",
		.rule_set = { &dstport_ipv6_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_dstport_ipv6_nomatch",
		.rule_set = { &dstport_ipv6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},

	/* VLAN */

	{
		.name = "tcflower_basic_vlan_id_match",
		.rule_set = { &vlan_id_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_vlan_id_nomatch",
		.rule_set = { &vlan_id_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_vlan_prio_match",
		.rule_set = { &vlan_prio_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_vlan_prio_nomatch",
		.rule_set = { &vlan_prio_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_vlan_etype_match",
		.rule_set = { &vlan_etype_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_vlan_etype_nomatch",
		.rule_set = { &vlan_etype_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},

	/* CVLAN */

	{
		.name = "tcflower_basic_cvlan_id_match",
		.rule_set = { &cvlan_id_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_cvlan_id_nomatch",
		.rule_set = { &cvlan_id_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_cvlan_prio_match",
		.rule_set = { &cvlan_prio_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_cvlan_prio_nomatch",
		.rule_set = { &cvlan_prio_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "tcflower_basic_cvlan_etype_match",
		.rule_set = { &cvlan_etype_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "tcflower_basic_cvlan_etype_nomatch",
		.rule_set = { &cvlan_etype_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},

	/* Keep empty struct at the end */
	{
		.name = "",
	}
};
