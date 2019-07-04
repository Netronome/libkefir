/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef LIBKEFIR_DUMP_H
#define LIBKEFIR_DUMP_H

#include <stddef.h>

#include "libkefir.h"

int dump_filter_to_buf(const struct kefir_filter *filter, char **buf,
		       size_t *buf_len, const char *prefix);

#endif /* LIBKEFIR_DUMP_H */
