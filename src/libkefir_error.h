/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef LIBKEFIR_ERROR_H
#define LIBKEFIR_ERROR_H

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "libkefir_internals.h"

__printf(2, 0)
static int default_print(const char *prefix, const char *format, va_list ap)
{
	if (prefix)
		fprintf(stderr, "%s", prefix);
	vfprintf(stderr, format, ap);
	if (format[strlen(format) - 1] != '\n')
		fprintf(stderr, "%c", '\n');

	return 0;
}

static int
(*__kefir_print)(const char *prefix,
		 const char *format,
		 va_list ap) = default_print;

#define __DO_ERR_FUNC(COMPONENT, NAME, CONTEXT)				\
	__attribute__((unused)) __printf(1, 2)	\
	static void err_ ## NAME(const char *format, ...)		\
	{								\
		va_list ap;						\
									\
		va_start(ap, format);					\
		__kefir_print(COMPONENT " " CONTEXT ": ", format, ap);	\
		va_end(ap);						\
	}

#define DEFINE_ERR_FUNCTIONS(COMPONENT)					\
	__DO_ERR_FUNC(COMPONENT, fail, "failed")			\
	__DO_ERR_FUNC(COMPONENT, bug, "bug")

#endif /* LIBKEFIR_ERROR_H */
