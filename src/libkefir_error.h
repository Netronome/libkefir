/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef LIBKEFIR_ERROR_H
#define LIBKEFIR_ERROR_H

#include <stdarg.h>

#define __DO_ERR_FUNC(COMPONENT, NAME, CONTEXT)				\
	__attribute__((unused)) __attribute__((format(printf, 1, 2)))	\
	static void err_ ## NAME(const char *format, ...)		\
	{								\
		va_list ap;						\
									\
		va_start(ap, format);					\
		error_vset_str(COMPONENT " " CONTEXT ": ", format, ap);	\
		va_end(ap);						\
	}

#define DEFINE_ERR_FUNCTIONS(COMPONENT)					\
	__DO_ERR_FUNC(COMPONENT, fail, "failed")		\
	__DO_ERR_FUNC(COMPONENT, bug, "bug")

#define KEFIR_ERROR_STR_SIZE 2048

char kefir_error_str[KEFIR_ERROR_STR_SIZE];

void error_set_str(const char *prefix, const char *format, ...);
void error_vset_str(const char *prefix, const char *format, va_list ap);

void error_append_str(const char *prefix, const char *format, ...);
void error_vappend_str(const char *prefix, const char *format, va_list ap);

#endif /* LIBKEFIR_ERROR_H */
