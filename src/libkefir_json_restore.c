// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <bits/stdint-uintn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "jsmn.h"
#include "libkefir.h"
#include "libkefir_error.h"
#include "libkefir_internals.h"
#include "libkefir_json_restore.h"

DEFINE_ERR_FUNCTIONS("JSON_load")

static bool
json_streq(const char *json_str, const jsmntok_t *token, const char *ref)
{
	size_t json_str_len;

	if (token->type != JSMN_STRING)
		return false;

	json_str_len = token->end - token->start;
	if (strncmp(json_str + token->start, ref, json_str_len))
		return false;

	if (strlen(ref) != json_str_len)
		return false;

	return true;
}

static bool json_isint(const char *str, const jsmntok_t *token)
{
	char c;

	if (token->type != JSMN_PRIMITIVE)
		return false;

	c = *(str + token->start);

	if (c == '-')
		return true;

	if (c >= '0' && c <= '9')
		return true;

	return false;
}

static int parse_int(const char *str, const jsmntok_t *token, int *dest)
{
	if (!json_isint(str, token)) {
		char buf[12] = {0};

		snprintf(buf, sizeof(buf) - 1, "%s", str + token->start);
		err_fail("failed to parse int at offset %d: %s", token->start,
			 buf);
		return -1;
	}

	errno = 0;
	*dest = strtol(str + token->start, NULL, 10);

	/*
	 * Do not check the end pointer (2nd argument to strtol) as the int to
	 * parse does not end with a nul character. Errno should be set in case
	 * of overflow or no digit found.
	 */
	if (errno) {
		char buf[12] = {0};

		snprintf(buf, sizeof(buf) - 1, "%s", str + token->start);
		err_fail("failed to convert to int at offset %d: %s",
			 token->start, buf);
		return -1;
	}

	return 0;
}

static int
parse_version(const char *str, const jsmntok_t *tokens, int nb_tokens)
{
	int version, patchlevel, extraversion;
	bool found = false;
	int i;

	/*
	 * Assume there is a "libkefir_version" string field as a direct child
	 * to the root object
	 */
	for (i = 0; i < nb_tokens - 1; i++) {
		if (tokens[i].parent != 0)
			continue;

		if (!json_streq(str, &tokens[i], "libkefir_version"))
			continue;

		if (tokens[i].size != 1)
			break;

		if (tokens[i + 1].type != JSMN_ARRAY)
			break;

		if (tokens[i + 1].size < 3)
			break;

		if (parse_int(str, &tokens[i + 1 + 1], &version) ||
		    parse_int(str, &tokens[i + 1 + 2], &patchlevel) ||
		    parse_int(str, &tokens[i + 1 + 3], &extraversion))
			return -1;

		found = true;
	}
	if (!found) {
		/* Not found or alloc error */
		err_fail("libkefir version number is missing from JSON");
		return -1;
	}

	/*
	 * TODO: We just checked version for consistency. In the future, we
	 * might actually check the number and see if support the file, or
	 * process some fields differently based on the version number.
	 */

	return 0;
}

static int count_nested_children(const jsmntok_t *tokens)
{
	int i, res = 1;

	for (i = 0; i < tokens[0].size; i++)
		res += count_nested_children(tokens + res);

	return res;
}

static int
parse_int_or_array(const char *str, const jsmntok_t *tokens, uint8_t *dest)
{
	int offset = 0, tmp;

	if (tokens[offset].type == JSMN_PRIMITIVE) {
		if (parse_int(str, &tokens[offset], &tmp))
			return -1;
		if (tmp != 0) {
			/* If != 0, should have been array of bytes */
			err_fail("expected 0 or array at offset %d, found %d",
				 tokens[offset].start, tmp);
			return -1;
		}
	} else if (tokens[offset].type == JSMN_ARRAY) {
		unsigned int i, nb_bytes;

		nb_bytes = tokens[offset].size;
		if (nb_bytes > sizeof_member(struct kefir_match, mask)) {
			err_fail("found %d bytes at offset %d, expected %ld or less",
				 nb_bytes, tokens[offset].start,
				 sizeof_member(struct kefir_match, mask));
			return -1;
		}
		for (i = 0; i < nb_bytes; i++) {
			offset++;
			if (parse_int(str, &tokens[offset], &tmp))
				return -1;
			dest[i] = tmp;
		}
	} else {
		err_fail("unexpected JSON token at offset %d",
			 tokens[offset].start);
		return -1;
	}

	return 0;
}

static int
parse_match(struct kefir_match *match, const char *str, const jsmntok_t *tokens)
{
	int i, offset = 0, tmp, nb_attr;

	nb_attr = tokens[offset].size;
	if (nb_attr < 5) {
		err_fail("missing elements in match starting at offset %d",
			 tokens[offset].start);
		return -1;
	}

	offset++;
	for (i = 0; i < nb_attr; i++) {
		if (json_streq(str, &tokens[offset], "match_type")) {
			offset++;
			if (parse_int(str, &tokens[offset], &tmp))
				return -1;
			match->match_type = tmp;
			offset++;
		} else if (json_streq(str, &tokens[offset], "comp_operator")) {
			offset++;
			if (parse_int(str, &tokens[offset], &tmp))
				return -1;
			match->comp_operator = tmp;
			offset++;
		} else if (json_streq(str, &tokens[offset], "flags")) {
			offset++;
			if (parse_int(str, &tokens[offset], &tmp))
				return -1;
			match->flags = tmp; /* Technically this one is a u64 */
			offset++;
		} else if (json_streq(str, &tokens[offset], "value")) {
			offset++;
			if (parse_int_or_array(str, &tokens[offset],
					       match->value.raw))
				return -1;
			offset += count_nested_children(&tokens[offset]);
		} else if (json_streq(str, &tokens[offset], "mask")) {
			offset++;
			if (parse_int_or_array(str, &tokens[offset],
					       match->mask))
				return -1;
			offset += count_nested_children(&tokens[offset]);
		} else {
			/* Ignore unknown token, just update offset */
			offset += count_nested_children(&tokens[offset]);
		}
	}

	return 0;
}

static int
parse_rule(kefir_filter *filter, int index, const char *str,
	   const jsmntok_t *tokens)
{
	int off_next, off_match, off_matches_array = -1, off_action = -1;
	int i, nb_matches, action;
	struct kefir_rule *rule;

	off_next = count_nested_children(&tokens[0]);

	/* Assume we have "matches", array of objects, and "action_code" */
	for (i = 1; i < off_next ; i++) {
		if (json_streq(str, &tokens[i], "matches")) {
			if (tokens[i].size != 1)
				break;
			if (tokens[i + 1].type != JSMN_ARRAY)
				break;
			off_matches_array = i + 1;
		} else if (json_streq(str, &tokens[i], "action_code")) {
			if (tokens[i].size != 1)
				break;
			if (tokens[i + 1].type != JSMN_PRIMITIVE)
				break;
			off_action = i + 1;
		}
		if (off_matches_array > 0 && off_action > 0)
			break;
	}
	if (off_matches_array < 0) {
		err_fail("failed to find a list of match objects for rule %d",
			 index);
		return -1;
	}
	if (off_action < 0) {
		err_fail("failed to find action code for rule %d", index);
		return -1;
	}

	if (parse_int(str, &tokens[off_action], &action))
		return -1;

	nb_matches = tokens[off_matches_array].size;
	if (nb_matches > KEFIR_MAX_MATCH_PER_RULE) {
		err_fail("found %d matches for rule %d, but max is %d",
			 nb_matches, index, KEFIR_MAX_MATCH_PER_RULE);
		return -1;
	}

	rule = calloc(1, sizeof(*rule));
	if (!rule) {
		err_fail("failed to allocate memory for rule");
		return -1;
	}

	off_match = off_matches_array + 1;
	for (i = 0; i < nb_matches; i++) {
		if (tokens[off_match].type != JSMN_OBJECT) {
			err_fail("match %d in rule %d is not an object", i,
				 index);
			goto err_free_rule;
		}
		if (parse_match(&rule->matches[i], str, &tokens[off_match]))
			goto err_free_rule;

		off_match += count_nested_children(&tokens[off_match]);
	}

	rule->action = action;
	if (kefir_add_rule_to_filter(filter, rule, index))
		goto err_free_rule;

	return 0;

err_free_rule:
	free(rule);
	return -1;
}

static int
parse_filter(kefir_filter *filter, const char *str, const jsmntok_t *tokens,
	     int nb_tokens)
{
	int i, rule_nb, off_rule, off_filter = -1, off_rules_array = -1;

	/*
	 * Assume there is a "libkefir_filter" object as a direct child to the
	 * root object
	 */
	for (i = 0; i < nb_tokens - 1; i++) {
		if (tokens[i].parent != 0)
			continue;
		if (!json_streq(str, &tokens[i], "libkefir_filter"))
			continue;
		if (tokens[i].size != 1)
			break;
		if (tokens[i + 1].type != JSMN_OBJECT)
			break;
		off_filter = i + 1;
		break;
	}
	if (off_filter < 0) {
		err_fail("could not find any libkefir_filter object in root");
		return -1;
	}

	/* Assume filter object contains an array named "rules" */
	for (i = off_filter + 1; i < off_filter + 1 + tokens[off_filter].size;
	     i++) {
		if (!json_streq(str, &tokens[i], "rules"))
			continue;
		if (tokens[i].size != 1)
			break;
		if (tokens[i + 1].type != JSMN_ARRAY)
			break;
		off_rules_array = i + 1;
		break;
	}
	if (off_rules_array < 0) {
		err_fail("could not find array of rules in libkefir_filter");
		return -1;
	}

	rule_nb = tokens[off_rules_array].size;

	off_rule = off_rules_array + 1;
	for (i = 0; i < rule_nb; i++) {
		/* Assume array contains only objects (representing rules) */
		if (tokens[off_rule].type != JSMN_OBJECT) {
			err_fail("rule %d is not a JSON object", i);
			return -1;
		}

		if (parse_rule(filter, i, str, &tokens[off_rule]))
			return -1;

		off_rule += count_nested_children(&tokens[off_rule]);
	}

	return 0;
}

static int
parse_json_as_filter(kefir_filter *filter, const char *str, jsmntok_t *tokens,
		     int nb_tokens)
{
	if (nb_tokens < 5) {
		err_fail("too few JSON tokens to represent a filter object");
		return -1;
	}

	if (tokens[0].type != JSMN_OBJECT) {
		err_fail("top-level JSON token should be an object");
		return -1;
	}

	if (parse_version(str, tokens, nb_tokens))
		return -1;

	if (parse_filter(filter, str, tokens, nb_tokens))
		return -1;

	return 0;
}

kefir_filter *json_restore_filter_from_file(const char *filename)
{
	kefir_filter *filter = NULL;
	size_t nb_read, input_len;
	struct stat statbuf;
	jsmntok_t *tokens;
	off_t input_size;
	FILE *input_file;
	char *input_str;
	jsmn_parser jp;
	int nb_tokens;

	input_file = fopen(filename, "r");
	if (!input_file) {
		err_fail("failed to open file %s: %s", filename,
			 strerror(errno));
		return NULL;
	}

	if (stat(filename, &statbuf)) {
		err_fail("failed to get size of file %s: %s", filename,
			 strerror(errno));
		goto close_file;
	}
	input_size = statbuf.st_size;

	input_str = calloc(input_size + 1, sizeof(*input_str));
	if (!input_str) {
		err_fail("failed to allocate memory for reading input file");
		goto close_file;
	}

	nb_read = fread(input_str, 1, input_size, input_file);
	if (nb_read < (size_t)input_size) {
		err_fail("failed to read file %s: %s", filename,
			 strerror(ferror(input_file)));
		goto free_input_str;
	}
	input_len = strlen(input_str);

	/* Retrieve number of tokens */
	jsmn_init(&jp);
	nb_tokens = jsmn_parse(&jp, input_str, input_len, NULL, 0);
	if (nb_tokens <= 0) {
		err_fail("failed to parse JSON in file %s", filename);
		goto free_input_str;
	}

	tokens = calloc(nb_tokens, sizeof(*tokens));
	if (!tokens) {
		err_fail("failed to allocate memory for JSON tokens in file %s",
			 filename);
		goto free_input_str;
	}

	/* Do parse JSON */
	jsmn_init(&jp);
	if (jsmn_parse(&jp, input_str, input_len,
		       tokens, nb_tokens) != nb_tokens) {
		/*
		 * This one is likely a bug, we already succeeded to parse JSON
		 * before. Or file has changed in between?
		 */
		err_bug("failed second JSON parsing in file %s", filename);
		goto free_tokens;
	}

	filter = kefir_filter_init();
	if (!filter) {
		err_fail("failed to allocate memory for filter object");
		goto free_tokens;
	}

	if (parse_json_as_filter(filter, input_str, tokens, nb_tokens)) {
		kefir_filter_destroy(filter);
		filter = NULL;
	}

	/*
	 * TODO: Apply here whatever optimisation of the set is added in the
	 * future when finilizing a filter object (e.g. removing duplicate
	 * rules), as we have no guarantee users have not been tinkering with
	 * the JSON file before reloading.
	 */

free_tokens:
	free(tokens);
free_input_str:
	free(input_str);
close_file:
	fclose(input_file);
	return filter;
}
