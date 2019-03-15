// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "libkefir.h"
#include "libkefir_error.h"

char *kefir_strerror()
{
	return kefir_error_str;
}

__attribute__((format(printf, 2, 0)))
void error_vset_str(const char *prefix, const char *format, va_list ap)
{
	size_t len;

	strncpy(kefir_error_str, prefix, KEFIR_ERROR_STR_SIZE);
	len = strlen(prefix);

	vsnprintf(kefir_error_str + len, KEFIR_ERROR_STR_SIZE - len - 1, format,
		  ap);
}

__attribute__((format(printf, 2, 3)))
void error_set_str(const char *prefix, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	error_vset_str(format, prefix, ap);
	va_end(ap);
}
