/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef LIBKEFIR_ERROR_H
#define LIBKEFIR_ERROR_H

#include <stdarg.h>
#include <stdio.h>

#include "libkefir.h"

#define KEFIR_ERROR_STR_SIZE 1024

char kefir_error_str[KEFIR_ERROR_STR_SIZE];

void kefir_set_error(const char* format, ...);
void kefir_vset_prefix_error(const char* format, const char* prefix,
			     va_list ap);

#endif /* LIBKEFIR_ERROR_H */
