/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef LIBKEFIR_PARSE_TC_H
#define LIBKEFIR_PARSE_TC_H

#include <stddef.h>

struct kefir_rule *
tcflower_parse_rule(const char * const *user_rule, size_t rule_size);

#endif /* LIBKEFIR_PARSE_TC_H */
