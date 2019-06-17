// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>

#include <kefir/libkefir.h>

#include "cl_options.h"

int get_options(int argc, char **argv, struct cl_options *opts_ret)
{
	static const struct option options[] = {
		{ "help",		no_argument,		NULL,	'h' },
		{ "llvm_version",	required_argument,	NULL,	'c' },
		{ "clang_bin",		required_argument,	NULL,	'b' },
		{ "llc_bin",		required_argument,	NULL,	'B' },
		{ "ifname",		required_argument,	NULL,	'i' },
		{ "hw_offload",		no_argument,		NULL,	'o' },
		{ "log_level",		required_argument,	NULL,	'l' },
		{ "keep_files",		no_argument,		NULL,	'k' },
		{ "inline_fn",		no_argument,		NULL,	'I' },
		{ "no_vlan",		no_argument,		NULL,	'V' },
		{ "clone_filter",	no_argument,		NULL,	'C' },
		{ "use_printk",		no_argument,		NULL,	'P' },
		{ "test_list",		required_argument,	NULL,	't' },
		{ 0 }
	};
	int opt, ret = 0;

	while ((opt = getopt_long(argc, argv, "c:hi:kl:ot:",
				  options, NULL)) >= 0) {
		switch (opt) {
		case 'h':
			opts_ret->help_req = 1;
			break;
		case 'c':
			snprintf(opts_ret->llvm_version,
				 sizeof(opts_ret->llvm_version) - 1,
				 "%s", optarg);
			break;
		case 'b':
			snprintf(opts_ret->clang_bin,
				 sizeof(opts_ret->clang_bin) - 1,
				 "%s", optarg);
			break;
		case 'B':
			snprintf(opts_ret->llc_bin,
				 sizeof(opts_ret->llc_bin) - 1,
				 "%s", optarg);
			break;
		case 'i':
			opts_ret->ifindex = if_nametoindex(optarg);
			if (!opts_ret->ifindex)
				ret = -errno;
			break;
		case 'o':
			opts_ret->hw_offload = 1;
			break;
		case 'l':
			opts_ret->log_level = atoi(optarg);
			break;
		case 'k':
			opts_ret->keep_files = 1;
			break;
		case 'I':
			opts_ret->inline_fn = 1;
			break;
		case 'V':
			opts_ret->no_vlan = 1;
			break;
		case 'C':
			opts_ret->clone = 1;
			break;
		case 'P':
			opts_ret->use_printk = 1;
			break;
		case 't':
			opts_ret->test_list = optarg;
			break;
		default:
			ret = -1;
			break;
		}
	}
	return ret;
}

void select_llvm_binaries(struct kefir_compil_attr *attr,
			  struct cl_options *opts)
{
	if (!strlen(opts->clang_bin)) {
		strncat(opts->clang_bin, "/usr/bin/clang",
			sizeof(opts->clang_bin) - 1);
		if (strlen(opts->llvm_version))
			strncat(opts->clang_bin + 14, opts->llvm_version,
				sizeof(opts->clang_bin - 1 - 14));
	}
	attr->clang_bin = opts->clang_bin;

	if (!strlen(opts->llc_bin)) {
		strncat(opts->llc_bin, "/usr/bin/llc",
			sizeof(opts->llc_bin) - 1);
		if (strlen(opts->llvm_version))
			strncat(opts->llc_bin + 12, opts->llvm_version,
				sizeof(opts->llc_bin - 1 - 12));
	}
	attr->llc_bin = opts->llc_bin;
}
