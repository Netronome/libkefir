/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef OPTIONS_H
#define OPTIONS_H

struct cl_options {
	unsigned int help_req : 1;
	unsigned int version_req : 1;
	unsigned int hw_offload : 1;
	unsigned int keep_files : 1;
	unsigned int inline_fn : 1;
	unsigned int no_vlan : 1;
	unsigned int clone : 1;
	unsigned int use_printk : 1;
	char llvm_version[8];
	char clang_bin[64];
	char llc_bin[64];
	unsigned int ifindex;
	unsigned int log_level;
};

int get_options(int argc, char **argv, struct cl_options *opts_ret);

void select_llvm_binaries(struct kefir_compil_attr *attr,
			  struct cl_options *opts);

#endif /* OPTIONS_H */
