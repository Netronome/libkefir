// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <endian.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "list.h"
#include "libkefir.h"
#include "libkefir_compile.h"
#include "libkefir_dump.h"
#include "libkefir_error.h"
#include "libkefir_internals.h"
#include "libkefir_json_restore.h"
#include "libkefir_json_save.h"
#include "libkefir_parse.h"
#include "libkefir_parse_ethtool.h"
#include "libkefir_parse_tc.h"
#include "libkefir_proggen.h"

DEFINE_ERR_FUNCTIONS("core")

/*
 * Rule crafting
 */

size_t kefir_bytes_for_type(enum kefir_match_type type)
{
	return (format_size[type_format[type]] + 7) / 8;
}

struct kefir_match *
kefir_match_create(struct kefir_match *match, enum kefir_match_type type,
		   enum kefir_comp_operator oper, const void *value,
		   const uint8_t *mask, bool is_net_byte_order)
{
	size_t nb_bytes = kefir_bytes_for_type(type);
	size_t nb_bits = bits_for_type(type);
	bool match_alloc = false;
	size_t i;

	if (type >= __KEFIR_MAX_MATCH_TYPE) {
		err_fail("unknown match type %d", type);
		return NULL;
	}

	if (oper >= __KEFIR_MAX_OPER) {
		err_fail("unknown comparison operator %d", oper);
		return NULL;
	}

	if (!match) {
		match = calloc(1, sizeof(*match));
		match_alloc = true;
	}
	if (!match) {
		err_fail("failed to allocate memory for match");
		return NULL;
	}

	match->match_type = type;
	match->comp_operator = oper;

	if (!value)
		return match;

	if (nb_bytes <= 4) {
		unsigned int tmp = 0;

		memcpy(&tmp, value, nb_bytes);
		if (parse_check_and_store_uint(tmp, &match->value.raw,
					       nb_bits, is_net_byte_order))
			goto err_free;
		if (mask) {
			memcpy(&tmp, mask, nb_bytes);
			if (parse_check_and_store_uint(tmp, &match->mask,
						       nb_bits,
						       is_net_byte_order))
				goto err_free;
		}
	} else {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		if (is_net_byte_order) {
			memcpy(match->value.raw, value, nb_bytes);
		} else {
			for (i = 0; i < nb_bytes; i++) {
				match->value.raw[i] =
					*((uint8_t *)value + nb_bytes - 1 - i);
				if (!mask)
					continue;
				match->mask[i] =
					*((uint8_t *)mask + nb_bytes - 1 - i);
			}
		}
#else
		memcpy(match->value.raw, value, nb_bytes);
		if (mask)
			memcpy(match->mask, mask, nb_bytes);
#endif
	}

	return match;

err_free:
	if (match_alloc)
		free(match);
	return NULL;
}

struct kefir_rule *
kefir_rule_create(struct kefir_match **matches, unsigned int nb_matches,
		  enum kefir_action_code action)
{
	struct kefir_rule *rule;
	size_t i;

	if (nb_matches > KEFIR_MAX_MATCH_PER_RULE) {
		err_fail("too many match objects (got %d, max %d)", nb_matches,
			 KEFIR_MAX_MATCH_PER_RULE);
		return NULL;
	}

	if (action >= __KEFIR_MAX_ACTION_CODE) {
		err_fail("unknown action code %d", action);
		return NULL;
	}

	rule = calloc(1, sizeof(*rule));
	if (!rule) {
		err_fail("failed to allocate memory for rule");
		return NULL;
	}

	rule->action = action;
	for (i = 0; i < nb_matches; i++) {
		if (!matches || !matches[i])
			err_fail("null pointer to match object");
		memcpy(&rule->matches[i], matches[i], sizeof(rule->matches[0]));
	}

	return rule;
}

/*
 * Filter management
 */

kefir_filter *kefir_filter_init(void)
{
	kefir_filter *filter;

	filter = calloc(1, sizeof(*filter));
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

	if (kefir_filter_add_rule(cpy_filter, cpy_rule, *index)) {
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
	if (!filter)
		return 0;

	return list_count(filter->rules);
}

static void reset_flags(struct kefir_rule *rule)
{
	size_t i;

	for (i = 0; i < KEFIR_MAX_MATCH_PER_RULE &&
	     rule->matches[i].match_type != KEFIR_MATCH_TYPE_UNSPEC; i++) {
		struct kefir_match *match = &rule->matches[i];

		memset(&match->flags, 0, sizeof(match->flags));
	}
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
				match->value.raw[j] &= match->mask[j];
	}
}

int kefir_filter_add_rule(kefir_filter *filter, struct kefir_rule *rule,
			  ssize_t index)
{
	struct list *rule_list;
	ssize_t filter_len;

	if (!filter) {
		err_fail("filter object is NULL, cannot add rule");
		return -1;
	}
	if (!rule) {
		err_fail("rule object is NULL, cannot add to filter");
		return -1;
	}

	filter_len = kefir_filter_size(filter);
	if (index < 0)
		index = kefir_filter_size(filter) + 1 + index;
	if (index < 0 || index > filter_len) {
		err_fail("index out of bounds (list has %zd filter%s)",
			 filter_len, filter_len > 1 ? "s" : "");
	}

	reset_flags(rule);
	update_from_mask(rule);

	rule_list = list_insert(filter->rules, rule, index);
	if (!rule_list) {
		err_fail("failed to insert rule into the list");
		return -1;
	}

	filter->rules = rule_list;
	return 0;
}

int kefir_rule_load(kefir_filter *filter, enum kefir_rule_type rule_type,
		    const char **user_rule, size_t rule_size, ssize_t index)
{
	struct kefir_rule *rule;

	if (!user_rule) {
		err_fail("input string array for rule is NULL");
		return -1;
	}

	switch (rule_type) {
	case KEFIR_RULE_TYPE_ETHTOOL_NTUPLE:
		rule = ethtool_parse_rule(user_rule, rule_size);
		break;
	case KEFIR_RULE_TYPE_TC_FLOWER:
		rule = tcflower_parse_rule(user_rule, rule_size);
		break;
	default:
		err_fail("unsupported rule type: %d", rule_type);
		return -1;
	}

	if (!rule)
		return -1;

	return kefir_filter_add_rule(filter, rule, index);
}

int kefir_rule_load_l(kefir_filter *filter, enum kefir_rule_type rule_type,
		      const char *user_rule, ssize_t index)
{
	size_t rule_size = 1, i = 0;
	const char **rule_words;
	char *rule_cpy, *word;
	int res = -1;

	if (!user_rule) {
		err_fail("input string for rule is NULL");
		return -1;
	}

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
	rule_words = calloc(rule_size, sizeof(*rule_words));
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
	if (!filter) {
		err_fail("filter object is NULL, cannot delete rule");
		return -1;
	}
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
		err_fail("file name is NULL, cannot dump C prog object");
		return -1;
	}

	if (proggen_cprog_to_buf(cprog, &buf, &len))
		return -1;

	file = fopen(filename, "w");
	if (!file) {
		err_fail("failed to open file %s: %s", filename,
			 strerror(errno));
		goto free_buf;
	}

	len = strlen(buf);
	res = fwrite(buf, 1, len, file);
	fclose(file);
	if (res != len) {
		err_fail("failed to write C prog object to file %s", filename);
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
	if (!obj)
		return;

	bpf_object__close(obj);
}

int kefir_bpfobj_get_prog_fd(struct bpf_object *obj)
{
	struct bpf_program *prog;

	if (!obj)
		return -1;

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

int kefir_cprog_map_update_cmd(const kefir_cprog *cprog,
			       struct bpf_object *bpf_obj, char **buf,
			       size_t *buf_len)
{
	return dump_fillmap_cmd(cprog, bpf_obj, buf, buf_len);
}

struct bpf_object *kefir_filter_attach(const kefir_filter *filter, int ifindex)
{
	struct kefir_compil_attr compil_attr = {0};
	struct kefir_cprog_attr cprog_attr = {
		.target = KEFIR_CPROG_TARGET_XDP,
	};
	struct kefir_load_attr load_attr = {
		.ifindex = ifindex,
	};

	return kefir_filter_attach_attr(filter, &cprog_attr, &compil_attr,
					&load_attr);
}

struct bpf_object *
kefir_filter_attach_attr(const kefir_filter *filter,
			 const struct kefir_cprog_attr *cprog_attr,
			 const struct kefir_compil_attr *compil_attr,
			 const struct kefir_load_attr *load_attr)
{
	char tmpfile[] = "/tmp/kefir_filter_XXXXXXXXXX.YZ";
	struct bpf_object *obj = NULL;
	time_t cur_time = time(NULL);
	kefir_cprog *cprog;

	if (cur_time == (time_t) -1) {
		snprintf(tmpfile, sizeof(tmpfile),
			 "/tmp/kefir_filter_0000000000.c");
		errno = 0;
	} else {
		snprintf(tmpfile, sizeof(tmpfile),
			 "/tmp/kefir_filter_%ld.c", cur_time);
	}

	cprog = kefir_filter_convert_to_cprog(filter, cprog_attr);
	if (!cprog)
		return NULL;

	if (kefir_cprog_to_file(cprog, tmpfile))
		goto destroy_cprog;

	if (kefir_cfile_compile_to_bpf(tmpfile, compil_attr))
		goto delete_cfile;

	*(tmpfile + strlen(tmpfile) - 1) = 'o';
	obj = kefir_cprog_load_attach_to_kernel(cprog, tmpfile, load_attr);

	unlink(tmpfile);
	sprintf(tmpfile + strlen(tmpfile) - 1, "ll");
	unlink(tmpfile);
	sprintf(tmpfile + strlen(tmpfile) - 2, "c");
delete_cfile:
	unlink(tmpfile);
destroy_cprog:
	kefir_cprog_destroy(cprog);

	return obj;
}
