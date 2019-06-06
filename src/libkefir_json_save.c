// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "json_writer.h"
#include "list.h"
#include "libkefir.h"
#include "libkefir_error.h"
#include "libkefir_internals.h"
#include "libkefir_json_save.h"

DEFINE_ERR_FUNCTIONS("JSON_save")

static int
save_value(const union kefir_value *value, enum value_format format,
	   json_writer_t *jw)
{
	size_t i, nb_bytes;

	jsonw_start_array(jw);	/* value */

	nb_bytes = bytes_for_format(format);

	for (i = 0; i < nb_bytes; i++)
		jsonw_hhu(jw, value->raw[i]);

	jsonw_end_array(jw);	/* value */

	return 0;
}

static int save_match(const struct kefir_match *match, json_writer_t *jw)
{
	size_t i;

	jsonw_start_object(jw);	/* match */

	jsonw_uint_field(jw, "match_type", match->match_type);
	jsonw_uint_field(jw, "comp_operator", match->comp_operator);

	jsonw_name(jw, "value");
	if (save_value(&match->value, type_format[match->match_type], jw))
		return -1;

	jsonw_name(jw, "mask");
	if (match->flags & MATCH_FLAGS_USE_MASK) {
		jsonw_start_array(jw);	/* mask */
		for (i = 0; i < sizeof(match->mask); i++)
			jsonw_hhu(jw, match->mask[i]);
		jsonw_end_array(jw);	/* mask */
	} else {
		jsonw_uint(jw, 0);
	}

	jsonw_u64_field(jw, "flags", match->flags);

	jsonw_end_object(jw);	/* match */

	return 0;
}

/*
 * Variadic list should contain:
 *     json_writer_t *jw
 */
static int save_rule(void *rule_ptr, va_list ap)
{
	const struct kefir_rule *rule = (const struct kefir_rule *)rule_ptr;
	json_writer_t *jw;
	size_t i;

	jw = va_arg(ap, json_writer_t *);

	jsonw_start_object(jw);	/* rule */
	jsonw_name(jw, "matches");
	jsonw_start_array(jw);	/* matches */

	for (i = 0; i < KEFIR_MAX_MATCH_PER_RULE &&
	     rule->matches[i].match_type != KEFIR_MATCH_TYPE_UNSPEC; i++)
		if (save_match(&rule->matches[i], jw))
			return -1;

	jsonw_end_array(jw);	/* matches */
	jsonw_uint_field(jw, "action_code", rule->action);
	jsonw_end_object(jw);	/* rule */

	return 0;
}

static int save_filter_object(const kefir_filter *filter, json_writer_t *jw)
{
	int res;

	jsonw_start_object(jw);	/* filter */

	jsonw_name(jw, "rules");
	jsonw_start_array(jw);	/* rules */
	res = list_for_each((struct list *)filter->rules, save_rule, jw);
	jsonw_end_array(jw);	/* rules */

	jsonw_end_object(jw);	/* filter */

	return res;
}

int json_save_filter_to_file(const kefir_filter *filter, const char *filename)
{
	json_writer_t *jw;
	FILE *outfile;
	int err = -1;

	outfile = fopen(filename, "w");
	if (!outfile) {
		err_fail("failed to open file %s: %s", filename,
			 strerror(errno));
		return -1;
	}

	jw = jsonw_new(outfile);
	if (!jw) {
		err_fail("failed to allocate memory for JSON writer");
		goto close_file;
	}

	jsonw_pretty(jw, true);

	jsonw_start_object(jw);	/* root */

	jsonw_name(jw, "libkefir_version");
	jsonw_start_array(jw);	/* version number */
	jsonw_uint(jw, KEFIR_VERSION);
	jsonw_uint(jw, KEFIR_PATCHLEVEL);
	jsonw_uint(jw, KEFIR_EXTRAVERSION);
	jsonw_end_array(jw);	/* version number */
	jsonw_name(jw, "libkefir_filter");

	if (save_filter_object(filter, jw))
		goto close_file;

	jsonw_end_object(jw);	/* root */
	jsonw_destroy(&jw);

	err = 0;

close_file:
	fclose(outfile);
	return err;
}
