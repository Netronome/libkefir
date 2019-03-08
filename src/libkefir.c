// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

// TODO check that
#include <stdio.h>
#include <string.h>

#include "libkefir.h"
#include "libkefir_compile.h"
#include "libkefir_dump.h"
#include "libkefir_internals.h"
#include "libkefir_parse_ethtool.h"
#include "libkefir_parse_tc.h"
#include "libkefir_proggen.h"

/*
 * Front end
 */

kefir_filter *kefir_init_filter(void)
{
	kefir_filter *filter;

	filter = calloc(1, sizeof(kefir_filter));
	return filter;
}

void kefir_destroy_filter(kefir_filter *filter)
{
	list_destroy(filter->rules, free);
	free(filter);
}

size_t kefir_sizeof_filter(const kefir_filter *filter) {
	return list_count(filter->rules);
}

static int
kefir_add_rule_to_filter(kefir_filter *filter, struct kefir_rule *rule,
			 unsigned int index)
{
	struct list *rule_list;

	if (!rule)
		return -1;

	rule_list = list_insert(filter->rules, rule, index);
	if (!rule_list)
		return -1;

	filter->rules = rule_list;
	return 0;
}

int kefir_load_rule(kefir_filter *filter, enum kefir_rule_type rule_type,
		    const char **user_rule, size_t rule_size, ssize_t index)
{
	struct kefir_rule *rule;

	switch (rule_type) {
	case RULE_TYPE_ETHTOOL_NTUPLE:
		rule = kefir_parse_rule_ethtool(user_rule, rule_size);
		break;
	case RULE_TYPE_TC_FLOWER:
		rule = kefir_parse_rule_tcflower(user_rule, rule_size);
		break;
	default:
		return -1;
	}

	return kefir_add_rule_to_filter(filter, rule, index);
}

/*
 * Data base
 */

void kefir_dump_filter(const kefir_filter *filter)
{
	size_t buf_len = 1024;
	char buf[buf_len];

	buf[0] = '\0';

	kefir_dump_filter_to_buf(filter, buf, buf_len);
	printf("%s", buf);
}

/*
 * Back end
 */

kefir_cprog *
kefir_convert_filter_to_cprog(const kefir_filter *filter,
			      enum kefir_cprog_target target)
{
	return proggen_make_cprog_from_filter(filter, target);
}

void kefir_destroy_cprog(kefir_cprog *cprog)
{
	proggen_cprog_destroy(cprog);
}

int kefir_cprog_to_buf(const kefir_cprog *cprog,
		       char **buf, size_t *buf_len)
{
	return proggen_cprog_to_buf(cprog, buf, buf_len);
}

void kefir_dump_cprog(const kefir_cprog *cprog)
{
	size_t buf_len = KEFIR_CPROG_INIT_BUFLEN;
	char *buf;

	buf = calloc(buf_len, sizeof(char));
	if (!buf)
		return;
	proggen_cprog_to_buf(cprog, &buf, &buf_len);
	printf("%s", buf);
}

int kefir_cprog_to_file(const kefir_cprog *cprog, const char *filename)
{
	size_t buf_len = KEFIR_CPROG_INIT_BUFLEN;
	size_t res;
	FILE *file;
	char *buf;

	if (!filename)
		return -1;

	buf = calloc(buf_len, sizeof(char));
	if (!buf)
		return -1;
	if (proggen_cprog_to_buf(cprog, &buf, &buf_len))
		return -1;

	file = fopen(filename, "w");
	if (!file)
		return -1;
	res = fprintf(file, "%s", buf);
	fclose(file);

	if (res != strlen(buf))
		return -1;

	return 0;
}

/*
 * Loader
 */

int kefir_compile_to_bpf(const char *c_file, const char *opt_object_file,
			 const char *opt_ll_file,
			 const char *opt_clang_bin, const char *opt_llc_bin)
{
	return compile_cfile_to_bpf(c_file, opt_object_file, opt_ll_file,
				    opt_clang_bin, opt_llc_bin);
}
