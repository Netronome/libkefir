// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <kefir/libkefir.h>

#include "cl_options.h"
#include "tester.h"

#define BUF_LEN 128

char tempdir[] = "/tmp/kefir_test_XXXXXXXXXX";

struct kefir_test_stats {
	unsigned int passed;
	unsigned int failed;
	unsigned int skipped;
	unsigned int insns;
};

static int usage(const char *bin_name, int ret)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS]\n"
		"\n"
		"       OPTIONS:\n"
		"\n"
		"       -h, --help                      Display this help\n"
		"       -i, --ifname       <ifname>     Interface to attach test programs to\n"
		"       -o, --hw_offload                Attempt hardware offload\n"
		"       -k, --keep_files                Keep produced test files\n"
		"       -t          <list of tests>     Run only given tests\n"
		"\n"
		"       -c, --llvm_version <version>    LLVM version suffix (e.g. '-8')\n"
		"                                       to append to clang/llc binary names\n"
		"       --clang-bin        <path>       clang binary to use (overrides -l)\n"
		"       --llc-bin          <path>       llc binary to use (overrides -l)\n"
		"\n"
		"       --inline_fn                     inline BPF functions (no BPF-to-BPF)\n"
		"       --no_loops                      do not use BPF bounded loops, unroll\n"
		"       --no_vlan                       do not generate VLAN parsing in BPF\n"
		"       --clone_filter                  clone filters before attaching to cprog\n"
		"       --use_prink                     use bpf_trace_printk() for debug in BPF\n"
		"", bin_name);

	return ret;
}

static bool
should_run_test(const char *name, const struct cl_options *opts)
{
	char *substr, sep;

	if (!opts->test_list)
		return true;

	substr = strstr(opts->test_list, name);
	if (!substr)
		return false;
	sep = *(substr + strlen(name));
	if (sep != ',' && sep != '\0')
		return false;

	return true;
}

static struct kefir_filter *fetch_filter(const struct kefir_test *test)
{
	struct kefir_filter *filter;

	if (strcmp(test->prog_file, "")) {
		filter = kefir_filter_load_from_file(test->prog_file);
		if (!filter)
			return NULL;
	} else if (strcmp(test->rule_set[0]->rule, "")) {
		int i;

		filter = kefir_filter_init();
		if (!filter)
			return NULL;

		for (i = 0; i < MAX_RULE_PER_TEST; i++) {
			if (!test->rule_set[i])
				break;
			if (kefir_rule_load_l(filter, test->rule_set[i]->type,
					      test->rule_set[i]->rule, -1))
				goto destroy_filter;
		}
	} else {
		printf("Error: malformed test object\n");
		return NULL;
	}

	return filter;

destroy_filter:
	kefir_filter_destroy(filter);
	return NULL;
}

static struct bpf_object *
inject_filter(struct kefir_filter *filter, const char *name,
	      struct cl_options *opts)
{
	char cprog_file[sizeof(tempdir) + MAX_NAME_LEN + 2];
	char obj_file[sizeof(tempdir) + MAX_NAME_LEN + 2];
	char ll_file[sizeof(tempdir) + MAX_NAME_LEN + 3];
	struct kefir_compil_attr compil_attr = {0};
	struct kefir_cprog_attr cprog_attr = {0};
	struct kefir_load_attr load_attr = {0};
	struct bpf_object *obj = NULL;
	struct kefir_cprog *cprog;

	sprintf(cprog_file, "%s/%s.c", tempdir, name);
	sprintf(obj_file, "%s/%s.o", tempdir, name);
	sprintf(ll_file, "%s/%s.ll", tempdir, name);

	cprog_attr.target = KEFIR_CPROG_TARGET_XDP;

	cprog_attr.flags |= opts->inline_fn ? KEFIR_CPROG_FLAG_INLINE_FUNC : 0;
	cprog_attr.flags |= opts->no_loops ? KEFIR_CPROG_FLAG_NO_LOOPS : 0;
	cprog_attr.flags |= opts->no_vlan ? KEFIR_CPROG_FLAG_NO_VLAN : 0;
	cprog_attr.flags |= opts->clone ? KEFIR_CPROG_FLAG_CLONE_FILTER : 0;
	cprog_attr.flags |= opts->use_printk ? KEFIR_CPROG_FLAG_USE_PRINTK : 0;

	cprog = kefir_filter_convert_to_cprog(filter, &cprog_attr);
	if (!cprog)
		goto rm_cfile;

	if (kefir_cprog_to_file(cprog, cprog_file))
		goto destroy_cprog;

	select_llvm_binaries(&compil_attr, opts);
	if (kefir_cfile_compile_to_bpf(cprog_file, &compil_attr))
		goto destroy_cprog;

	load_attr.ifindex = opts->ifindex;
	load_attr.flags |= opts->hw_offload ? XDP_FLAGS_HW_MODE : 0;

	obj = kefir_cprog_load_to_kernel(cprog, obj_file, &load_attr);
	if (!obj)
		goto rm_objfile;

	if (kefir_cprog_fill_map(cprog, obj)) {
		kefir_bpfobj_destroy(obj);
		obj = NULL;
	}

rm_objfile:
	if (!opts->keep_files) {
		if (unlink(obj_file))
			printf("Warning: failed to remove file %s: %s\n",
			       obj_file, strerror(errno));
		if (unlink(ll_file))
			printf("Warning: failed to remove file %s: %s\n",
			       obj_file, strerror(errno));
	}

destroy_cprog:
	kefir_cprog_destroy(cprog);

rm_cfile:
	if (!opts->keep_files)
		if (unlink(cprog_file))
			printf("Warning: failed to remove file %s: %s\n",
			       cprog_file, strerror(errno));

	return obj;
}

static int
run_test(struct kefir_test *test, struct cl_options *opts,
	 unsigned int *insn_count)
{
	struct bpf_prog_test_run_attr test_attr = {0};
	struct bpf_prog_info info = {0};
	uint8_t data_out[BUF_LEN] = {0};
	struct kefir_filter *filter;
	struct bpf_object *obj;
	unsigned int info_len;
	bool success = false;
	int fd;

	filter = fetch_filter(test);
	if (!filter)
		goto print_res;

	obj = inject_filter(filter, test->name, opts);
	if (!obj)
		goto destroy_filter;

	if (opts->hw_offload) {
		/* Test runs not supported on HW, succeed if load worked */
		success = true;
		goto destroy_object;
	}

	fd = kefir_bpfobj_get_prog_fd(obj);
	info_len = sizeof(info);
	if (bpf_obj_get_info_by_fd(fd, &info, &info_len))
		printf("Warning: could not get program info: %s\n",
		       strerror(errno));

	test_attr.prog_fd	= fd;
	test_attr.repeat	= 1;
	test_attr.data_in	= test->data_in;
	test_attr.data_size_in	= test->data_size_in;
	test_attr.data_out	= data_out;
	test_attr.data_size_out	= sizeof(data_out);

	if (bpf_prog_test_run_xattr(&test_attr)) {
		printf("Error: %s\n", strerror(errno));
		goto destroy_object;
	}

	success = (test_attr.retval == test->expected_retval);

destroy_object:
	kefir_bpfobj_destroy(obj);
destroy_filter:
	kefir_filter_destroy(filter);

print_res:
	info.xlated_prog_len /= 8;
	printf("%-64s\t", test->name);
	if (!opts->hw_offload)
		printf("%5u\t", info.xlated_prog_len);
	*insn_count += info.xlated_prog_len;

	if (success) {
		if (opts->hw_offload)
			printf("PASS\n");
		else
			printf("PASS (%dns)\n", test_attr.duration);
		return 0;
	}

	if (test_attr.duration)
		printf("FAIL (%dns): expected %u got %u\n", test_attr.duration,
		       test->expected_retval, test_attr.retval);
	else
		printf("FAIL\n");
	return -1;
}

static void
run_test_array(struct kefir_test *tests_array, struct cl_options *opts,
	       struct kefir_test_stats *stats)
{
	size_t i;

	for (i = 0; strcmp(tests_array[i].name, ""); i++) {
		if (!should_run_test(tests_array[i].name, opts)) {
			stats->skipped++;
			continue;
		}
		if (run_test(&tests_array[i], opts, &stats->insns))
			stats->failed++;
		else
			stats->passed++;
	}
}

int main(int argc, char **argv)
{
	struct kefir_test_stats stats = {0};
	time_t cur_time = time(NULL);
	struct cl_options opts = {0};

	if (get_options(argc, argv, &opts))
		return usage(argv[0], -1);

	if (opts.help_req)
		return usage(argv[0], 0);

	if (cur_time == (time_t)-1) {
		printf("Error: failed to get time: %s\n", strerror(errno));
		return -1;
	}
	snprintf(tempdir, sizeof(tempdir), "/tmp/kefir_test_%ld", cur_time);
	if (mkdir(tempdir, 0777)) {
		printf("Error: failed to create temp dir: %s\n",
		       strerror(errno));
	}

	printf("%-64s\t", "NAME");
	if (!opts.hw_offload)
		printf("INSNS\t");
	printf("RESULT\n\n");

	run_test_array(ethtool_basic_tests, &opts, &stats);
	run_test_array(ethtool_basic_tests_masks, &opts, &stats);
	run_test_array(tcflower_basic_tests, &opts, &stats);
	run_test_array(tcflower_basic_tests_masks, &opts, &stats);
	run_test_array(json_tests, &opts, &stats);
	run_test_array(advanced_tests, &opts, &stats);

	printf("\nTOTAL: %d passed, %d failed, %d skipped",
	       stats.passed, stats.failed, stats.skipped);
	if (!opts.hw_offload)
		printf(" (total insns: %d)", stats.insns);
	printf("\n");

	if (opts.keep_files)
		printf("Produced files were kept under %s\n", tempdir);
	else if (rmdir(tempdir))
		printf("Error: failed to remove temp dir: %s\n",
		       strerror(errno));

	return 0;
}
