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
		if (nb_bytes > sizeof_member(struct kefir_match, max_value)) {
			err_fail("found %d bytes at offset %d, expected %ld or less",
				 nb_bytes, tokens[offset].start,
				 sizeof_member(struct kefir_match, max_value));
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
parse_value(struct kefir_value *value, const char *str, const jsmntok_t *tokens)
{
	int i, offset = 0, tmp, nb_attr;

	nb_attr = tokens[offset].size;
	if (nb_attr < 2) {
		err_fail("missing elements in value starting at offset %d",
			 tokens[offset].start);
		return -1;
	}

	offset++;
	for (i = 0; i < nb_attr; i++) {
		if (json_streq(str, &tokens[offset], "format")) {
			offset++;
			if (parse_int(str, &tokens[offset], &tmp))
				return -1;
			value->format = tmp;
			offset++;
		} else if (json_streq(str, &tokens[offset], "data")) {
			offset++;
			if (parse_int_or_array(str, &tokens[offset],
					       value->data.raw))
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
parse_match(struct kefir_match *match, const char *str, const jsmntok_t *tokens)
{
	int i, offset = 0, tmp, nb_attr;

	nb_attr = tokens[offset].size;
	if (nb_attr < 6) {
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
			if (parse_value(&match->value, str, &tokens[offset]))
				return -1;
			offset += count_nested_children(&tokens[offset]);
		} else if (json_streq(str, &tokens[offset], "max_value")) {
			offset++;
			if (parse_int_or_array(str, &tokens[offset],
					       match->max_value))
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
	int i, offset = 1, nb_matches, action;
	struct kefir_rule *rule;

	rule = calloc(1, sizeof(struct kefir_rule));
	if (!rule) {
		err_fail("failed to allocate memory for rule");
		return -1;
	}

	/* Assume we have "matches", array of objects, then "action_code" */
	if (!json_streq(str, &tokens[offset], "matches")) {
		err_fail("failed to find a list of match objects for rule %d",
			 index);
		return -1;
	}

	offset++;
	if (tokens[offset].type != JSMN_ARRAY) {
		err_fail("list of matches for rule %d should be an array",
			 index);
		return -1;
	}

	nb_matches = tokens[offset].size;
	if (nb_matches > KEFIR_MAX_MATCH_PER_RULE) {
		err_fail("found %d matches for rule %d, but max is %d",
			 nb_matches, index, KEFIR_MAX_MATCH_PER_RULE);
		return -1;
	}

	offset++;
	for (i = 0; i < nb_matches; i++) {
		if (tokens[offset].type != JSMN_OBJECT) {
			err_fail("match %d in rule %d is not an object", i,
				 index);
			return -1;
		}

		if (parse_match(&rule->matches[i], str, &tokens[offset]))
			return -1;

		offset += count_nested_children(&tokens[offset]);
	}

	// TODO: move action_code to an object in case more gets added later
	if (!json_streq(str, &tokens[offset], "action_code")) {
		err_fail("could not find action code for rule %d", index);
		return -1;
	}

	offset++;
	if (parse_int(str, &tokens[offset], &action))
		return -1;
	rule->action = action;

	if (kefir_add_rule_to_filter(filter, rule, index)) {
		free(rule);
		return -1;
	}

	return 0;
}

static int
parse_filter(kefir_filter *filter, const char *str, const jsmntok_t *tokens,
	     int nb_tokens)
{
	int i, rule_nb, offset = -1;

	/*
	 * Assume there is a "libkefir_filter" object as a direct child to the
	 * root object
	 */
	for (i = 0; i < nb_tokens - 1; i++) {
		if (tokens[i].parent != 0)
			continue;

		if (!json_streq(str, &tokens[i], "libkefir_filter"))
			continue;

		if (tokens[i + 1].parent != i)
			continue;

		if (tokens[i + 1].type != JSMN_OBJECT)
			continue;

		offset = i + 1;
		break;
	}
	if (offset < 0) {
		err_fail("could not find any libkefir_filter object in root");
		return -1;
	}

	/* Assume filter object contains a single array named "rules" */
	// TODO: we should make this more flexible for forward compatibility
	offset++;
	if (offset >= nb_tokens || !json_streq(str, &tokens[offset], "rules")) {
		err_fail("libkefir_filter object should contain one set of rules");
		return -1;
	}

	offset++;
	if (offset >= nb_tokens || tokens[offset].type != JSMN_ARRAY) {
		err_fail("set of rules should be a JSON array");
		return -1;
	}

	rule_nb = tokens[offset].size;

	offset++;
	for (i = 0; i < rule_nb; i++) {
		/* Assume array contains only objects (representing rules) */
		if (tokens[offset].type != JSMN_OBJECT) {
			err_fail("rule %d is not a JSON object", i);
			return -1;
		}

		if (parse_rule(filter, i, str, &tokens[offset]))
			return -1;

		offset += count_nested_children(&tokens[offset]);
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

	input_str = calloc(input_size + 1, sizeof(char));
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

	tokens = calloc(nb_tokens, sizeof(jsmntok_t));
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

	filter = kefir_init_filter();
	if (!filter) {
		err_fail("failed to allocate memory for filter object");
		goto free_tokens;
	}

	if (parse_json_as_filter(filter, input_str, tokens, nb_tokens)) {
		kefir_destroy_filter(filter);
		filter = NULL;
	}

free_tokens:
	free(tokens);
free_input_str:
	free(input_str);
close_file:
	fclose(input_file);
	return filter;
}
