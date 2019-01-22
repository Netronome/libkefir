// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

// TODO check that
#include <stdio.h>

#include "libkefir.h"
#include "libkefir_dump.h"
#include "libkefir_internals.h"
#include "libkefir_parse_ethtool.h"

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

static int
kefir_add_rule_to_filter(kefir_filter *filter, struct kefir_rule *rule,
			 unsigned int index)
{
	struct list *rule_list;

	rule_list = list_insert(filter->rules, rule, index);
	if (!rule_list)
		return -1;

	filter->rules = rule_list;
	return 0;
}

int kefir_load_rule(kefir_filter *filter, enum kefir_rule_type rule_type,
		    const char **user_rule, unsigned int rule_size,
		    unsigned int index)
{
	struct kefir_rule *rule;

	switch (rule_type) {
	case RULE_TYPE_ETHTOOL_NTUPLE:
		rule = kefir_parse_rule_ethtool(user_rule, rule_size);
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

/*
 * Loader
 */
