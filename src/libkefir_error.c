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

void kefir_set_error(const char* format, ...)
{
	va_list ap;

	va_start(ap, format);
	vsnprintf(kefir_error_str, KEFIR_ERROR_STR_SIZE - 1, format, ap);
	va_end(ap);
}

void kefir_vset_error(const char* format, va_list ap)
{
	vsnprintf(kefir_error_str, KEFIR_ERROR_STR_SIZE - 1, format, ap);
}

void kefir_vset_prefix_error(const char* format, const char* prefix,
			     va_list ap)
{
	size_t len;

	strncpy(kefir_error_str, prefix, KEFIR_ERROR_STR_SIZE);
	len = strlen(prefix);

	vsnprintf(kefir_error_str + len, KEFIR_ERROR_STR_SIZE - len - 1, format,
		  ap);
}
