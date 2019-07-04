/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef LIBKEFIR_JSON_SAVE_H
#define LIBKEFIR_JSON_SAVE_H

#include "libkefir.h"

int json_save_filter_to_file(const struct kefir_filter *filter,
			     const char *filename);

#endif /* LIBKEFIR_JSON_SAVE_H */
