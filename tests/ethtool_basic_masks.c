// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <linux/bpf.h>

#include "tester.h"

/* Ether */

static struct test_rule proto_match_pass = {
	.rule = "flow-type ether proto 0x0800 m 0xff00 action 0",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule proto_match_drop = {
	.rule = "flow-type ether proto 0x0888 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule proto_nomatch = {
	.rule = "flow-type ether proto 0x0888 m 0xfff0 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule src_match = {
	.rule = "flow-type ether src 0a:0b:0c:fe:fe:fe m ff:ff:ff:00:00:00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule src_nomatch = {
	.rule = "flow-type ether src 0a:0b:fe:fe:fe:fe m ff:ff:ff:00:00:00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dst_match = {
	.rule = "flow-type ether dst 01:02:03:04:05:00 m ff:ff:ff:ff:ff:f0 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dst_nomatch = {
	.rule = "flow-type ether dst aa:02:03:04:05:00 m ff:ff:ff:ff:ff:f0 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dst_mac_match = {
	.rule = "flow-type ip4 dst-mac 01:02:03:04:05:06 m ff:00:00:00:00:00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dst_mac_nomatch = {
	.rule = "flow-type ip4 dst-mac a1:02:03:04:05:aa m ff:00:00:00:00:00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

/* IPv4 */

static struct test_rule src_ipv4_match = {
	.rule = "flow-type ip4 src-ip 10.10.10.0 m 255.255.255.192 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule src_ipv4_nomatch = {
	.rule = "flow-type ip4 src-ip 10.10.10.199 m 255.255.255.192 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dst_ipv4_match = {
	.rule = "flow-type ip4 dst-ip 10.10.10.1 m 255.255.255.255 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dst_ipv4_nomatch = {
	.rule = "flow-type ip4 dst-ip 10.10.10.99 m 255.255.255.255 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule tos_ipv4_match = {
	.rule = "flow-type ip4 tos 8 m 62 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule tos_ipv4_nomatch = {
	.rule = "flow-type ip4 tos 3 m 62 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule l4proto_ipv4_match = {
	.rule = "flow-type ip4 l4proto 6 m 0xf8 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule l4proto_ipv4_nomatch = {
	.rule = "flow-type ip4 l4proto 17 m 0xf8 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule l4data_ipv4_match = {
	.rule = "flow-type ip4 l4data 582485968 m 0xff000000 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule l4data_ipv4_nomatch = {
	.rule = "flow-type ip4 l4data 3490166818 m 0xff000000 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule srcport_ipv4_match = {
	.rule = "flow-type ip4 src-port 8800 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule srcport_ipv4_nomatch = {
	.rule = "flow-type ip4 src-port 8800 m 0xfffc action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule srcport_tcp4_match = {
	.rule = "flow-type tcp4 src-port 8800 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule srcport_udp4_nomatch = {
	.rule = "flow-type udp4 src-port 8800 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule srcport_sctp4_nomatch = {
	.rule = "flow-type sctp4 src-port 8800 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dstport_ipv4_match = {
	.rule = "flow-type ip4 dst-port 2019 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dstport_ipv4_nomatch = {
	.rule = "flow-type ip4 dst-port 2019 m 0xfffc action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dstport_tcp4_match = {
	.rule = "flow-type tcp4 dst-port 2019 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dstport_udp4_nomatch = {
	.rule = "flow-type udp4 dst-port 2019 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dstport_sctp4_nomatch = {
	.rule = "flow-type sctp4 dst-port 2019 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

/* IPv6 */

static struct test_rule src_ipv6_match = {
	.rule = "flow-type ip6 src-ip cafe:0004:0a11::01 m ffff:ffff:ffff:: action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule src_ipv6_nomatch = {
	.rule = "flow-type ip6 src-ip cafe:0004:0000::01 m ffff:ffff:ffff:: action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dst_ipv6_match = {
	.rule = "flow-type ip6 dst-ip 0011:2233:4455:6677:8899:aabb:ccdd:eeff m ffff:: action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dst_ipv6_nomatch = {
	.rule = "flow-type ip6 dst-ip ::1 m ffff:: action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule tclass_ipv6_match = {
	.rule = "flow-type ip6 tclass 28 m 0xff action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule tclass_ipv6_nomatch = {
	.rule = "flow-type ip6 tclass 3 m 0xff action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule l4proto_ipv6_match = {
	.rule = "flow-type ip6 l4proto 6 m 0xfc action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule l4proto_ipv6_nomatch = {
	.rule = "flow-type ip6 l4proto 17 m 0xfc action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule l4data_ipv6_match = {
	.rule = "flow-type ip6 l4data 582485968 m 0xf0000000 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule l4data_ipv6_nomatch = {
	.rule = "flow-type ip6 l4data 3490166818 m 0xf0000000 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule srcport_ipv6_match = {
	.rule = "flow-type ip6 src-port 8800 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule srcport_ipv6_nomatch = {
	.rule = "flow-type ip6 src-port 1800 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule srcport_tcp6_match = {
	.rule = "flow-type tcp6 src-port 8800 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule srcport_udp6_nomatch = {
	.rule = "flow-type udp6 src-port 8800 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule srcport_sctp6_nomatch = {
	.rule = "flow-type sctp6 src-port 8800 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dstport_ipv6_match = {
	.rule = "flow-type ip6 dst-port 2019 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dstport_ipv6_nomatch = {
	.rule = "flow-type ip6 dst-port 2019 m 0xfff0 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dstport_tcp6_match = {
	.rule = "flow-type tcp6 dst-port 2019 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dstport_udp6_nomatch = {
	.rule = "flow-type udp6 dst-port 2019 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule dstport_sctp6_nomatch = {
	.rule = "flow-type sctp6 dst-port 2019 m 0xff00 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

/* VLAN */

static struct test_rule vlan_id_match = {
	.rule = "flow-type ip4 vlan 2748 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule vlan_id_nomatch = {
	.rule = "flow-type ip4 vlan 2749 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule vlan_etype_match = {
	.rule = "flow-type ip4 vlan-etype 2048 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

static struct test_rule vlan_etype_nomatch = {
	.rule = "flow-type ip4 vlan-etype 2047 action -1",
	.type = KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
};

struct kefir_test ethtool_basic_tests_masks[] = {

	/* Ether */

	{
		.name = "ethtool_basic_masks_proto_match_pass",
		.rule_set = { &proto_match_pass },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_proto_match_drop",
		.rule_set = { &proto_match_drop },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_proto_nomatch",
		.rule_set = { &proto_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_src_match",
		.rule_set = { &src_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_src_nomatch",
		.rule_set = { &src_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_dst_match",
		.rule_set = { &dst_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_dst_nomatch",
		.rule_set = { &dst_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_dst_mac_match",
		.rule_set = { &dst_mac_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_dst_mac_nomatch",
		.rule_set = { &dst_mac_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},

	/* IPv4 */

	{
		.name = "ethtool_basic_masks_src_ipv4_match",
		.rule_set = { &src_ipv4_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_src_ipv4_nomatch",
		.rule_set = { &src_ipv4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_dst_ipv4_match",
		.rule_set = { &dst_ipv4_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_dst_ipv4_nomatch",
		.rule_set = { &dst_ipv4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_tos_ipv4_match",
		.rule_set = { &tos_ipv4_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_tos_ipv4_nomatch",
		.rule_set = { &tos_ipv4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_l4proto_ipv4_match",
		.rule_set = { &l4proto_ipv4_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_l4proto_ipv4_nomatch",
		.rule_set = { &l4proto_ipv4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_l4data_ipv4_match",
		.rule_set = { &l4data_ipv4_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_l4data_ipv4_nomatch",
		.rule_set = { &l4data_ipv4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_srcport_ipv4_match",
		.rule_set = { &srcport_ipv4_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_srcport_ipv4_nomatch",
		.rule_set = { &srcport_ipv4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_srcport_tcp4_match",
		.rule_set = { &srcport_tcp4_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_srcport_udp4_nomatch",
		.rule_set = { &srcport_udp4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_srcport_sctp4_nomatch",
		.rule_set = { &srcport_sctp4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_dstport_ipv4_match",
		.rule_set = { &dstport_ipv4_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_dstport_ipv4_nomatch",
		.rule_set = { &dstport_ipv4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_dstport_tcp4_match",
		.rule_set = { &dstport_tcp4_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_dstport_udp4_nomatch",
		.rule_set = { &dstport_udp4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_dstport_sctp4_nomatch",
		.rule_set = { &dstport_sctp4_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},

	/* IPv6 */

	{
		.name = "ethtool_basic_masks_src_ipv6_match",
		.rule_set = { &src_ipv6_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_src_ipv6_nomatch",
		.rule_set = { &src_ipv6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_dst_ipv6_match",
		.rule_set = { &dst_ipv6_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_dst_ipv6_nomatch",
		.rule_set = { &dst_ipv6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_tclass_ipv6_match",
		.rule_set = { &tclass_ipv6_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_tclass_ipv6_nomatch",
		.rule_set = { &tclass_ipv6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_l4proto_ipv6_match",
		.rule_set = { &l4proto_ipv6_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_l4proto_ipv6_nomatch",
		.rule_set = { &l4proto_ipv6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_l4data_ipv6_match",
		.rule_set = { &l4data_ipv6_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_l4data_ipv6_nomatch",
		.rule_set = { &l4data_ipv6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_srcport_ipv6_match",
		.rule_set = { &srcport_ipv6_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_srcport_ipv6_nomatch",
		.rule_set = { &srcport_ipv6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_srcport_tcp6_match",
		.rule_set = { &srcport_tcp6_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_srcport_udp6_nomatch",
		.rule_set = { &srcport_udp6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_srcport_sctp6_nomatch",
		.rule_set = { &srcport_sctp6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_dstport_ipv6_match",
		.rule_set = { &dstport_ipv6_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_dstport_ipv6_nomatch",
		.rule_set = { &dstport_ipv6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_dstport_tcp6_match",
		.rule_set = { &dstport_tcp6_match },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_dstport_udp6_nomatch",
		.rule_set = { &dstport_udp6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_dstport_sctp6_nomatch",
		.rule_set = { &dstport_sctp6_nomatch },
		.data_in = tcp6_packet,
		.data_size_in = sizeof(tcp6_packet),
		.expected_retval = XDP_PASS,
	},

	/* VLAN */

	{
		.name = "ethtool_basic_masks_vlan_id_match",
		.rule_set = { &vlan_id_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_vlan_id_nomatch",
		.rule_set = { &vlan_id_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "ethtool_basic_masks_vlan_etype_match",
		.rule_set = { &vlan_etype_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "ethtool_basic_masks_vlan_etype_nomatch",
		.rule_set = { &vlan_etype_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},

	/* Keep empty struct at the end */
	{
		.name = "",
	}
};
