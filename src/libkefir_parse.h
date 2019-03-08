/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef LIBKEFIR_PARSE_H
#define LIBKEFIR_PARSE_H

#include "libkefir_internals.h"

#define __DO_ERR_FUNC(COMPONENT, NAME, CONTEXT)				\
	__attribute__((unused))						\
	static void err_ ## NAME(const char *format, ...)		\
	{								\
		va_list ap;						\
									\
		va_start(ap, format);					\
		kefir_vset_prefix_error(format,				\
					COMPONENT " " CONTEXT ": ", ap); \
		va_end(ap);						\
	}

#define DEFINE_ERR_FUNCTIONS(COMPONENT)					\
	__DO_ERR_FUNC(COMPONENT, fail, "parsing failed")		\
	__DO_ERR_FUNC(COMPONENT, bug, "parsing bug")

int parse_uint(const char *input, void *output, uint32_t nb_bits);
int parse_eth_addr(const char *input, struct ether_addr *output);
int parse_ipv4_addr(const char *input, uint32_t *output);
int parse_ipv6_addr(const char *input, uint8_t **output);

#endif /* LIBKEFIR_PARSE_H */
