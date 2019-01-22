/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef LIBKEFIR_PARSE_ETHTOOL_H
#define LIBKEFIR_PARSE_ETHTOOL_H

#include "libkefir_internals.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef sizeof_member
#define sizeof_member(TYPE, MEMBER) sizeof(*(&((TYPE *)0)->MEMBER))
#endif

struct kefir_rule *
kefir_parse_rule_ethtool(const char **user_rule, unsigned int rule_size);

#endif /* LIBKEFIR_PARSE_ETHTOOL_H */
