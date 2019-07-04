/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef LIBKEFIR_PROGGEN_H
#define LIBKEFIR_PROGGEN_H

#include <stdlib.h>

#include "libkefir.h"

void proggen_cprog_destroy(struct kefir_cprog *cprog);
struct kefir_cprog *
proggen_make_cprog_from_filter(const struct kefir_filter *filter,
			       const struct kefir_cprog_attr *attr);
int proggen_cprog_to_buf(const struct kefir_cprog *cprog, char **buf,
			 size_t *buf_len);

#endif /* LIBKEFIR_PROGGEN_H */
