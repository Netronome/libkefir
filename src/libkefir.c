// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <bits/stdint-uintn.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "list.h"
#include "libkefir_compile.h"
#include "libkefir_dump.h"
#include "libkefir_error.h"
#include "libkefir_internals.h"
#include "libkefir_json_restore.h"
#include "libkefir_json_save.h"
#include "libkefir_parse_ethtool.h"
#include "libkefir_parse_tc.h"
#include "libkefir_proggen.h"

DEFINE_ERR_FUNCTIONS("core")

/*
 * Filter management
 */

kefir_filter *kefir_filter_init(void)
{
	kefir_filter *filter;

	filter = calloc(1, sizeof(kefir_filter));
	return filter;
}

static void destroy_rule(void *rule)
{
	free(rule);
}

void kefir_filter_destroy(kefir_filter *filter)
{
	if (!filter)
		return;

	list_destroy(filter->rules, destroy_rule);
	free(filter);
}

/*
 * Variadic list should contain:
 *     kefir_kefir *cpy_filter
 *     size_t *index
 */
static int clone_rule(void *rule_ptr, va_list ap)
{
	struct kefir_rule *ref_rule = (struct kefir_rule *)rule_ptr;
	struct kefir_rule *cpy_rule;
	kefir_filter *cpy_filter;
	size_t *index;

	cpy_filter = va_arg(ap, kefir_filter *);
	index = va_arg(ap, size_t *);

	cpy_rule = malloc(sizeof(struct kefir_rule));
	if (!cpy_rule) {
		err_fail("failed to allocate new rule");
		return -1;
	}

	memcpy(cpy_rule, ref_rule, sizeof(struct kefir_rule));

	if (kefir_add_rule_to_filter(cpy_filter, cpy_rule, *index)) {
		free(cpy_rule);
		return -1;
	}

	*index += 1;
	return 0;
}

kefir_filter *kefir_filter_clone(const kefir_filter *filter)
{
	kefir_filter *copy;
	size_t index = 0;

	if (!filter) {
		err_fail("filter object is NULL");
		return NULL;
	}

	copy = kefir_filter_init();
	if (!copy) {
		err_fail("failed to allocate memory for filter clone");
		return NULL;
	}

	if (list_for_each((struct list *)filter->rules, clone_rule, copy,
			  &index)) {
		kefir_filter_destroy(copy);
		return NULL;
	}

	return copy;
}

size_t kefir_filter_size(const kefir_filter *filter)
{
	return list_count(filter->rules);
}

/* Used in other files, but not UAPI */
int kefir_add_rule_to_filter(kefir_filter *filter, struct kefir_rule *rule,
			     ssize_t index)
{
	struct list *rule_list;
	ssize_t filter_len;

	filter_len = kefir_filter_size(filter);
	if (index < 0)
		index = kefir_filter_size(filter) + 1 + index;
	if (index < 0 || index > filter_len) {
		err_fail("index out of bounds (list has %zd filter%s)",
			 filter_len, filter_len > 1 ? "s" : "");
	}

	if (!rule) {
		err_fail("rule object is NULL");
		return -1;
	}

	rule_list = list_insert(filter->rules, rule, index);
	if (!rule_list) {
		err_fail("failed to insert rule into the list");
		return -1;
	}

	filter->rules = rule_list;
	return 0;
}

static void update_from_mask(struct kefir_rule *rule)
{
	size_t i, j;

	for (i = 0; i < KEFIR_MAX_MATCH_PER_RULE &&
	     rule->matches[i].match_type != KEFIR_MATCH_TYPE_UNSPEC; i++) {
		struct kefir_match *match = &rule->matches[i];

		for (j = 0; j < sizeof(match->mask); j++)
			if (match->mask[j]) {
				match->flags |= MATCH_FLAGS_USE_MASK;
				break;
			}

		if (match->flags & MATCH_FLAGS_USE_MASK)
			for (j = 0; j < sizeof(match->mask); j++)
				match->value.data.raw[j] &= match->mask[j];
	}
}

int kefir_rule_load(kefir_filter *filter, enum kefir_rule_type rule_type,
		    const char **user_rule, size_t rule_size, ssize_t index)
{
	struct kefir_rule *rule;

	switch (rule_type) {
	case RULE_TYPE_ETHTOOL_NTUPLE:
		rule = ethtool_parse_rule(user_rule, rule_size);
		break;
	case RULE_TYPE_TC_FLOWER:
		rule = tcflower_parse_rule(user_rule, rule_size);
		break;
	default:
		err_fail("unsupported rule type: %d", rule_type);
		return -1;
	}

	if (!rule)
		return -1;

	update_from_mask(rule);

	return kefir_add_rule_to_filter(filter, rule, index);
}

int kefir_rule_load_l(kefir_filter *filter, enum kefir_rule_type rule_type,
		      const char *user_rule, ssize_t index)
{
	size_t rule_size = 1, i = 0;
	const char **rule_words;
	char *rule_cpy, *word;
	int res = -1;

	/* Count words */
	rule_cpy = strdup(user_rule);
	if (!rule_cpy) {
		err_fail("failed to allocate buffer for splitting rule");
		return -1;
	}

	if (!strtok(rule_cpy, " \t\n")) {
		err_fail("rule is too short");
		goto free_rule_cpy;
	}
	while (strtok(NULL, " \t\n"))
		rule_size++;

	/* Split string */
	free(rule_cpy);
	rule_cpy = strdup(user_rule);
	if (!rule_cpy) {
		err_fail("failed to allocate buffer for splitting rule");
		return -1;
	}
	rule_words = calloc(rule_size, sizeof(char *));
	if (!rule_words) {
		err_fail("failed to allocate array for splitting rule");
		goto free_rule_cpy;
	}

	rule_words[0] = strtok(rule_cpy, " \t\n");
	while ((word = strtok(NULL, " \t\n")) != NULL) {
		i++;
		rule_words[i] = word;
	}

	res = kefir_rule_load(filter, rule_type, rule_words, rule_size, index);
	free(rule_words);

free_rule_cpy:
	free(rule_cpy);

	return res;
}

/*
 * TODO:
 * The id must be the index of the rule in the list as stored in the filter. In
 * case we process the list in the future and change the order after the user
 * loads a rule, this may NOT be the order in which the user loaded the rule
 * (e.g. if we removed duplicates in the list).
 *
 * Therefore, we will need a way in the future to make sure the user is aware
 * of the id of the list. We could make the loading function returning the id
 * of the whent it is loaded, but then it would be subject to change if
 * additional rules are loaded after that. We could dump all the filter and
 * print ids associated to the rules, but that will not be really helpful in
 * terms of programmability. One solution could be to add an attribute to each
 * rule to keep the order in which it was added, so we could instead match on
 * this user id in the future.
 */
int kefir_rule_delete_by_id(kefir_filter *filter, ssize_t index)
{
	return list_delete(filter->rules, index, destroy_rule);
}

/*
 * Dump, save and restore filter
 */

void kefir_filter_dump(const kefir_filter *filter)
{
	size_t buf_len;
	char *buf;

	if (dump_filter_to_buf(filter, &buf, &buf_len, ""))
		return;

	printf("%s", buf);
	free(buf);
}

int kefir_filter_save_to_file(const kefir_filter *filter, const char *filename)
{
	return json_save_filter_to_file(filter, filename);
}

kefir_filter *kefir_filter_load_from_file(const char *filename)
{
	return json_restore_filter_from_file(filename);
}

/*
 * Back end: Conversion to C
 */

void kefir_cprog_destroy(kefir_cprog *cprog)
{
	proggen_cprog_destroy(cprog);
}

kefir_cprog *
kefir_filter_convert_to_cprog(const kefir_filter *filter,
			      const struct kefir_cprog_attr *attr)
{
	return proggen_make_cprog_from_filter(filter, attr);
}

void kefir_cprog_to_stdout(const kefir_cprog *cprog)
{
	size_t buf_len;
	char *buf;

	if (proggen_cprog_to_buf(cprog, &buf, &buf_len))
		return;

	printf("%s", buf);
	free(buf);
}

int kefir_cprog_to_buf(const kefir_cprog *cprog, char **buf, size_t *buf_len)
{
	return proggen_cprog_to_buf(cprog, buf, buf_len);
}

int kefir_cprog_to_file(const kefir_cprog *cprog, const char *filename)
{
	size_t len, res;
	int ret = -1;
	FILE *file;
	char *buf;

	if (!filename) {
		err_fail("file name is NULL");
		return -1;
	}

	if (proggen_cprog_to_buf(cprog, &buf, &len))
		return -1;

	file = fopen(filename, "w");
	if (!file) {
		err_fail("fail to open file %s: %s", filename, strerror(errno));
		goto free_buf;
	}

	len = strlen(buf);
	res = fwrite(buf, 1, len, file);
	fclose(file);
	if (res != len) {
		err_fail("failed to write cprog to file %s", filename);
		goto free_buf;
	}

	ret = 0;

free_buf:
	free(buf);
	return ret;
}

/*
 * Compile to eBPF, load, attach programs
 */

int kefir_cfile_compile_to_bpf(const char *c_file,
			       const struct kefir_compil_attr *attr)
{
	return compile_cfile_to_bpf(c_file,
				    attr ? attr->object_file : NULL,
				    attr ? attr->ll_file : NULL,
				    attr ? attr->clang_bin : NULL,
				    attr ? attr->llc_bin : NULL);
}

void kefir_bpfobj_destroy(struct bpf_object *obj)
{
	bpf_object__close(obj);
}

int kefir_bpfobj_get_prog_fd(struct bpf_object *obj)
{
	struct bpf_program *prog;

	prog = bpf_program__next(NULL, obj);
	return bpf_program__fd(prog);
}

struct bpf_object *
kefir_cprog_load_to_kernel(const kefir_cprog *cprog, const char *objfile,
			   const struct kefir_load_attr *attr)
{
	struct bpf_object *bpf_obj;

	if (compile_load_from_objfile(cprog, objfile, &bpf_obj, attr) < 0)
		return NULL;

	return bpf_obj;
}

struct bpf_object *
kefir_cprog_load_attach_to_kernel(const kefir_cprog *cprog, const char *objfile,
				  const struct kefir_load_attr *attr)
{
	struct bpf_object *bpf_obj;
	int prog_fd;

	prog_fd = compile_load_from_objfile(cprog, objfile, &bpf_obj, attr);
	if (prog_fd < 0)
		return NULL;

	if (compile_attach_program(cprog, bpf_obj, prog_fd, attr))
		return NULL;

	return bpf_obj;
}

int kefir_cprog_fill_map(const kefir_cprog *cprog, struct bpf_object *bpf_obj)
{
	return compile_fill_map(cprog, bpf_obj);
}
