// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_link.h>
#include <netinet/in.h>

#include <kefir/libkefir.h>

#include "cl_options.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

static int usage(const char *bin_name, int ret)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS] -i ifindex\n"
		"\n"
		"       OPTIONS:\n"
		"       -h, --help                      Display this help\n"
		"       -i, --ifname       <ifname>     Interface to attach the filter to\n"
		"", bin_name);

	return ret;
}

int main(int argc, char **argv)
{
	struct kefir_match matches[3] = { {0} };
	struct kefir_match *match_ptrs[3] = {
		&matches[0], &matches[1], &matches[2]
	};
	struct cl_options opts = {0};
	struct kefir_filter *filter;
	struct bpf_object *bpf_obj;
	struct kefir_rule *rule;
	struct in_addr src_ip;
	uint16_t src_port;
	uint8_t l4proto;
	int err = -1;

	/* Parse command line options */

	if (get_options(argc, argv, &opts))
		return usage(argv[0], -1);

	if (opts.help_req)
		return usage(argv[0], 0);

	if (!opts.ifindex)
		return usage(argv[0], -1);

	/* Initialize filter */

	filter = kefir_filter_init();

	if (!filter)
		return -1;

	/* Load rules */

	inet_pton(AF_INET, "10.10.10.1", &src_ip);
	l4proto = IPPROTO_TCP;
	src_port = 22;

	if (!kefir_match_create(&matches[0], KEFIR_MATCH_TYPE_IP_4_SRC,
				KEFIR_OPER_EQUAL, &src_ip, NULL, true))
		goto destroy_filter;

	if (!kefir_match_create(&matches[1], KEFIR_MATCH_TYPE_IP_4_L4PROTO,
				KEFIR_OPER_EQUAL, &l4proto, NULL, false))
		goto destroy_filter;

	if (!kefir_match_create(&matches[2], KEFIR_MATCH_TYPE_IP_4_L4PORT_SRC,
				KEFIR_OPER_EQUAL, &src_port, NULL, false))
		goto destroy_filter;

	rule = kefir_rule_create(match_ptrs, 3, KEFIR_ACTION_CODE_DROP);
	if (!rule)
		goto destroy_filter;

	if (kefir_filter_add_rule(filter, rule, 0)) {
		free(rule);
		goto destroy_filter;
	}

	/* Dump filter */

	kefir_filter_dump(filter);

	/* Convert filter to C then BPF, load and attach to interface */

	bpf_obj = kefir_filter_attach(filter, opts.ifindex);
	if (!bpf_obj)
		goto destroy_filter;

	err = 0;

	/* Clean up */

	kefir_bpfobj_destroy(bpf_obj);

destroy_filter:
	kefir_filter_destroy(filter);

	return err;
}
