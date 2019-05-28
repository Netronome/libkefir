// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <linux/bpf.h>

#include "tester.h"

/* Multiple patterns */

static struct test_rule patterns_3_mask_1_match = {
	.rule = "protocol ip flower src_ip 10.10.10.8/24 ip_proto tcp src_port 8888 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule patterns_3_mask_1_nomatch = {
	.rule = "protocol ip flower src_ip 10.10.10.8/24 ip_proto tcp src_port 8889 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

/* For filters with multiple rules */

static struct test_rule rule_1_match = {
	.rule = "protocol ip flower src_mac 0a:0b:0c:0d:0e:0f action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule rule_1_nomatch = {
	.rule = "protocol ip flower src_mac 11:11:11:11:11:11 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule rule_2 = {
	.rule = "protocol ip flower dst_mac 11:11:11:11:11:11 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule rule_3 = {
	.rule = "protocol ip flower src_ip 1.1.1.1 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule rule_4 = {
	.rule = "protocol ip flower dst_ip 1.1.1.1 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule rule_5_match = {
	.rule = "protocol ip flower ip_tos 8 action pass",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule rule_5_nomatch = {
	.rule = "protocol ip flower ip_tos 1 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule rule_6 = {
	.rule = "protocol ip flower ip_ttl 1 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule rule_7 = {
	.rule = "protocol ip flower ip_proto 1 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule rule_8 = {
	.rule = "protocol ip flower src_port 1 ip_proto 1 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule rule_9 = {
	.rule = "protocol ip flower ip_proto tcp dst_port 1 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule rule_10_match = {
	.rule = "protocol ip flower vlan_id 0x0abc action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

static struct test_rule rule_10_nomatch = {
	.rule = "protocol ip flower vlan_id 1 action drop",
	.type = KEFIR_RULE_TYPE_TC_FLOWER,
};

struct kefir_test advanced_tests[] = {
	{
		.name = "advanced_rules_1_patterns_3_mask_1_match",
		.rule_set = { &patterns_3_mask_1_match },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "advanced_rules_1_patterns_3_mask_1_nomatch",
		.rule_set = { &patterns_3_mask_1_nomatch },
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},

	{
		.name = "advanced_rules_10_rule-1-drops",
		.rule_set = {
			&rule_1_match,	// drop
			&rule_2,
			&rule_3,
			&rule_4,
			&rule_5_match,	// pass
			&rule_6,
			&rule_7,
			&rule_8,
			&rule_9,
			&rule_10_match, // drop
		},
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "advanced_rules_10_rule-5-passes",
		.rule_set = {
			&rule_1_nomatch,
			&rule_2,
			&rule_3,
			&rule_4,
			&rule_5_match,	// pass
			&rule_6,
			&rule_7,
			&rule_8,
			&rule_9,
			&rule_10_match, // drop
		},
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "advanced_rules_10_rule-10-drops",
		.rule_set = {
			&rule_1_nomatch,
			&rule_2,
			&rule_3,
			&rule_4,
			&rule_5_nomatch,
			&rule_6,
			&rule_7,
			&rule_8,
			&rule_9,
			&rule_10_match, // drop
		},
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},
	{
		.name = "advanced_rules_10_nomatch",
		.rule_set = {
			&rule_1_nomatch,
			&rule_2,
			&rule_3,
			&rule_4,
			&rule_5_nomatch,
			&rule_6,
			&rule_7,
			&rule_8,
			&rule_9,
			&rule_10_nomatch,
		},
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},
	{
		.name = "advanced_rules_81_rule-81-drops",
		.rule_set = {
			&rule_1_nomatch,
			&rule_2,
			&rule_3,
			&rule_4,
			&rule_5_nomatch,
			&rule_6,
			&rule_7,
			&rule_8,
			&rule_9,
			&rule_10_nomatch, // 10

			&rule_1_nomatch,
			&rule_2,
			&rule_3,
			&rule_4,
			&rule_5_nomatch,
			&rule_6,
			&rule_7,
			&rule_8,
			&rule_9,
			&rule_10_nomatch, // 20

			&rule_1_nomatch,
			&rule_2,
			&rule_3,
			&rule_4,
			&rule_5_nomatch,
			&rule_6,
			&rule_7,
			&rule_8,
			&rule_9,
			&rule_10_nomatch, // 30

			&rule_1_nomatch,
			&rule_2,
			&rule_3,
			&rule_4,
			&rule_5_nomatch,
			&rule_6,
			&rule_7,
			&rule_8,
			&rule_9,
			&rule_10_nomatch, // 40

			&rule_1_nomatch,
			&rule_2,
			&rule_3,
			&rule_4,
			&rule_5_nomatch,
			&rule_6,
			&rule_7,
			&rule_8,
			&rule_9,
			&rule_10_nomatch, // 50

			&rule_1_nomatch,
			&rule_2,
			&rule_3,
			&rule_4,
			&rule_5_nomatch,
			&rule_6,
			&rule_7,
			&rule_8,
			&rule_9,
			&rule_10_nomatch, // 60

			&rule_1_nomatch,
			&rule_2,
			&rule_3,
			&rule_4,
			&rule_5_nomatch,
			&rule_6,
			&rule_7,
			&rule_8,
			&rule_9,
			&rule_10_nomatch, // 70

			&rule_1_nomatch,
			&rule_2,
			&rule_3,
			&rule_4,
			&rule_5_nomatch,
			&rule_6,
			&rule_7,
			&rule_8,
			&rule_9,
			&rule_10_nomatch, // 80

			&rule_1_match,
		},
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_DROP,
	},

	/* Keep empty struct at the end */
	{
		.name = "",
	}
};
