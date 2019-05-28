// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "libkefir_buffer.h"
#include "libkefir_error.h"
#include "libkefir_internals.h"

DEFINE_ERR_FUNCTIONS("buffers")

__printf(3, 4)
int buf_append(char **buf, size_t *buf_len, const char *fmt, ...)
{
	size_t offset, maxlen, reqlen;
	va_list ap;

	offset = strlen(*buf);
	maxlen = *buf_len - offset;

	va_start(ap, fmt);
	reqlen = vsnprintf(*buf + offset, maxlen, fmt, ap);
	va_end(ap);

	while (reqlen >= maxlen) {
		/* Output was truncated. Reallocate buffer and retry. */
		char *new_buf;

		*buf_len *= 2;
		new_buf = realloc(*buf, *buf_len);
		if (!new_buf) {
			err_fail("failed to reallocate memory for C prog buffer");
			free(*buf);
			return -1;
		}
		*buf = new_buf;

		maxlen = *buf_len - offset;
		va_start(ap, fmt);
		reqlen = vsnprintf(*buf + offset, maxlen, fmt, ap);
		va_end(ap);
	}

	return 0;
}
