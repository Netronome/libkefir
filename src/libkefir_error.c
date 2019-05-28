// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "libkefir.h"
#include "libkefir_error.h"

static size_t kefir_strerror_index;

const char *kefir_strerror()
{
	return kefir_error_str;
}

void kefir_strerror_reset()
{
	*kefir_error_str = '\0';
	kefir_strerror_index = 0;
}

__printf(2, 0)
void error_vset_str(const char *prefix, const char *format, va_list ap)
{
	size_t len;

	strncpy(kefir_error_str, prefix, KEFIR_ERROR_STR_SIZE);
	len = strlen(prefix);

	vsnprintf(kefir_error_str + len, KEFIR_ERROR_STR_SIZE - len - 1, format,
		  ap);
}

__printf(2, 3)
void error_set_str(const char *prefix, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	error_vset_str(format, prefix, ap);
	va_end(ap);
}

__printf(2, 0)
void error_vappend_str(const char *prefix, const char *format, va_list ap)
{
	if (kefir_strerror_index >= KEFIR_ERROR_STR_SIZE - strlen(prefix) - 1)
		return;

	strncpy(kefir_error_str + kefir_strerror_index, prefix,
		KEFIR_ERROR_STR_SIZE - kefir_strerror_index - 1);
	kefir_strerror_index += strlen(prefix);

	vsnprintf(kefir_error_str + kefir_strerror_index,
		  KEFIR_ERROR_STR_SIZE - kefir_strerror_index - 1,
		  format, ap);

	kefir_strerror_index += strlen(kefir_error_str + kefir_strerror_index);
}

__printf(2, 3)
void error_append_str(const char *prefix, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	error_vappend_str(prefix, format, ap);
	va_end(ap);
}
