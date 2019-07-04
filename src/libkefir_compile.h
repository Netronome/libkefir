/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef LIBKEFIR_COMPILE_H
#define LIBKEFIR_COMPILE_H

#include "libkefir.h"

struct bpf_object;

int compile_cfile_to_bpf(const char *c_file, const char *opt_object_file,
			 const char *opt_ll_file, const char *opt_clang_bin,
			 const char *opt_llc_bin);
int compile_load_from_objfile(const struct kefir_cprog *cprog,
			      const char *objfile, struct bpf_object **bpf_obj,
			      const struct kefir_load_attr *attr);
int compile_fill_map(const struct kefir_cprog *cprog,
		     struct bpf_object *bpf_obj);
int dump_fillmap_cmd(const struct kefir_cprog *cprog,
		     struct bpf_object *bpf_obj, char **buf, size_t *buf_len);
int compile_attach_program(const struct kefir_cprog *cprog,
			   struct bpf_object *bpf_obj, int prog_fd,
			   const struct kefir_load_attr *attr);

#endif /* LIBKEFIR_COMPILE_H */
