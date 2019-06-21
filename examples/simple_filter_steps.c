// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/if_link.h>

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
		"       -o, --hw_offload                Attempt hardware offload for filter\n"
		"       -l, --log_level    <level>      Log level for kernel verifier\n"
		"       -c, --llvm_version <version>    LLVM version suffix (e.g. '-8')\n"
		"                                       to append to clang/llc binary names\n"
		"       --clang-bin        <path>       clang binary to use (overrides -l)\n"
		"       --llc-bin          <path>       llc binary to use (overrides -l)\n"
		"       --no_loops                      do not use BPF bounded loops, unroll\n"
		"", bin_name);

	return ret;
}

static const char *rule_eth_dstip[] = {
	"flow-type",
	"ip4",
	"dst-ip",
	"10.99.1.1",
	"action",
	"-1",
};

static const char *rule_tc_dstport[] = {
	"protocol",
	"ip",
	"flower",
	"ip_proto",
	"udp",
	"dst_port",
	"2000",
	"action",
	"pass",
};

static const char *rule_tc_twopatterns[] = {
	"protocol",
	"ip",
	"flower",
	"src_ip",
	"10.10.10.2/24",
	"ip_proto",
	"udp",
	"dst_port",
	"8888",
	"action",
	"pass",
};

int main(int argc, char **argv)
{
	struct kefir_compil_attr compil_attr = {0};
	struct kefir_cprog_attr cprog_attr = {0};
	struct kefir_load_attr load_attr = {0};
	struct cl_options opts = {0};
	struct kefir_filter *filter;
	struct bpf_object *bpf_obj;
	struct kefir_cprog *cprog;
	int err = -1;

	/* Parse command line options */

	if (get_options(argc, argv, &opts))
		return usage(argv[0], -1);

	if (opts.help_req)
		return usage(argv[0], 0);

	if (!opts.ifindex)
		return usage(argv[0], -1);

	select_llvm_binaries(&compil_attr, &opts);

	/* Initialize filter */

	filter = kefir_filter_init();

	if (!filter)
		return -1;

	/* Load rules */

	if (kefir_rule_load(filter, KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
			    rule_eth_dstip, ARRAY_SIZE(rule_eth_dstip), 0))
		goto destroy_filter;

	if (kefir_rule_load(filter, KEFIR_RULE_TYPE_TC_FLOWER,
			    rule_tc_dstport, ARRAY_SIZE(rule_tc_dstport), 0))
		goto destroy_filter;

	if (kefir_rule_load(filter, KEFIR_RULE_TYPE_TC_FLOWER,
			    rule_tc_twopatterns,
			    ARRAY_SIZE(rule_tc_twopatterns), 0))
		goto destroy_filter;

	/* Dump filter */

	kefir_filter_dump(filter);

	/* Convert to a C program */

	cprog_attr.target = KEFIR_CPROG_TARGET_XDP;
	cprog_attr.flags |= opts.no_loops ? KEFIR_CPROG_FLAG_NO_LOOPS : 0;
	cprog = kefir_filter_convert_to_cprog(filter, &cprog_attr);
	if (!cprog)
		goto destroy_filter;

	/* Save to file and compile */

	if (kefir_cprog_to_file(cprog, "/tmp/cprog.c"))
		goto destroy_cprog;
	if (kefir_cfile_compile_to_bpf("/tmp/cprog.c", &compil_attr))
		goto destroy_cprog;

	/* Load into kernel and attach to selected interface */

	load_attr.ifindex = opts.ifindex;
	load_attr.flags |= opts.hw_offload ? XDP_FLAGS_HW_MODE : 0;
	load_attr.log_level = opts.log_level;
	bpf_obj = kefir_cprog_load_attach_to_kernel(cprog, "/tmp/cprog.o",
						    &load_attr);
	if (!bpf_obj)
		goto destroy_cprog;
	kefir_bpfobj_destroy(bpf_obj);

	err = 0;

destroy_cprog:
	kefir_cprog_destroy(cprog);
destroy_filter:
	kefir_filter_destroy(filter);

	return err;
}
