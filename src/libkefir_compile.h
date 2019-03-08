/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef LIBKEFIR_COMPILE_H
#define LIBKEFIR_COMPILE_H

int compile_cfile_to_bpf(const char *c_file, const char *opt_object_file,
			 const char *opt_ll_file,
			 const char *opt_clang_bin, const char *opt_llc_bin);

#endif /* LIBKEFIR_COMPILE_H */
