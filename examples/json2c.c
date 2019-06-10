// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

/*
 * Example:
 *	./tcflower2json protocol ip flower src_ip 10.10.10.1/24 \
 *		ip_proto udp dst_port 8888 action drop > out.json
 *	./json2c out.json
 */

#include <stdio.h>

#include <kefir/libkefir.h>

static int usage(const char *bin_name, int ret)
{
	fprintf(stderr,
		"Usage: %s filename\n"
		"", bin_name);

	return ret;
}

int main(int argc, const char **argv)
{
	struct kefir_cprog_attr cprog_attr = {0};
	struct kefir_filter *filter;
	struct kefir_cprog *cprog;
	int err = -1;

	if (argc != 2)
		return usage(argv[0], -1);

	/* Initialize filter */

	filter = kefir_filter_load_from_file(argv[1]);
	if (!filter)
		return -1;

	/* Convert to a C program */

	cprog_attr.target = KEFIR_CPROG_TARGET_XDP;
	cprog = kefir_filter_convert_to_cprog(filter, &cprog_attr);
	if (!cprog)
		goto destroy_filter;

	kefir_cprog_to_stdout(cprog);

	err = 0;

	kefir_cprog_destroy(cprog);
destroy_filter:
	kefir_filter_destroy(filter);

	return err;
}
