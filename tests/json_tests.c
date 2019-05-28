// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <linux/bpf.h>

#include "tester.h"

/*
 * filters/test_filter.json should be loaded as:
 *
 *  - rule  0
 * 	match 0: IPv4 source address       | operator  0: == | value  0: 10.10.10.0 | mask 0: ff ff ff
 * 	match 1: IPv4, L4 protocol         | operator  1: == | value  1: 17
 * 	match 2: IPv4, L4 destination port | operator  2: == | value  2: 8888
 * 	action: pass
 *  - rule  1
 * 	match 0: IPv4, L4 protocol         | operator  0: == | value  0: 17
 * 	match 1: IPv4, L4 destination port | operator  1: == | value  1: 2000
 * 	action: pass
 *  - rule  2
 * 	match 0: IPv4 destination address  | operator  0: == | value  0: 10.99.1.1
 * 	action: drop
 */


struct kefir_test json_tests[] = {
	{
		.name = "json_load_and_run",
		.prog_file = "filters/test_filter.json",
		.data_in = tcp4_packet,
		.data_size_in = sizeof(tcp4_packet),
		.expected_retval = XDP_PASS,
	},

	/* Keep empty struct at the end */
	{
		.name = "",
	}
};
