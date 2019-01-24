/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef LIBKEFIR_DUMP_H
#define LIBKEFIR_DUMP_H

#include "libkefir.h"
#include "libkefir_internals.h"

void kefir_dump_filter_to_buf(const kefir_filter *filter, char *buf,
			      size_t buf_len);

#endif /* LIBKEFIR_DUMP_H */
