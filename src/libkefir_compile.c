// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <bits/stdint-uintn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <sys/wait.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "list.h"
#include "libkefir.h"
#include "libkefir_compile.h"
#include "libkefir_error.h"
#include "libkefir_internals.h"

DEFINE_ERR_FUNCTIONS("compilation")

/* As used in the BPF program, see libkefir_proggen.c */
struct bpf_map_match {
	enum match_type		match_type;
	enum comp_operator	comp_operator;
	union {
		__u8	u8[16];
		__u64	u64[2];
	} value;
};

/* Must be identical to struct bpf_map_match, with additional flags and masks */
struct bpf_map_match_with_masks {
	enum match_type		match_type;
	enum comp_operator	comp_operator;
	union {
		__u8	u8[16];
		__u64	u64[2];
	} value;
	__u64	flags;
	__u8	mask[16];
};

/*
 * The action code and matches in use must correspond to the struct used in the
 * BPF program (see libkefir_proggen.c), where the number of matches is lower
 * or equal to KEFIR_MAX_MATCH_PER_RULE. So it is mandatory to keep "matches"
 * at the END of the current struct.
 */
struct bpf_map_filter_rule {
	enum action_code	action_code;
	struct bpf_map_match	matches[KEFIR_MAX_MATCH_PER_RULE];
};

struct bpf_map_filter_rule_with_masks {
	enum action_code		action_code;
	struct bpf_map_match_with_masks	matches[KEFIR_MAX_MATCH_PER_RULE];
};

__printf(2, 0)
static int
libbpf_output_to_buf(enum libbpf_print_level level, const char *format,
		     va_list ap)
{
	if (level == LIBBPF_DEBUG)
		return 0;

	error_vappend_str("attach fail: ", format, ap);
	return 0;
}

int compile_cfile_to_bpf(const char *c_file, const char *opt_object_file,
			 const char *opt_ll_file, const char *opt_clang_bin,
			 const char *opt_llc_bin)
{
	const char *clang = opt_clang_bin ? opt_clang_bin : "/usr/bin/clang";
	const char *llc = opt_llc_bin ? opt_llc_bin : "/usr/bin/llc";
	char *objfile, *llfile;
	int wstatus;
	size_t len;
	pid_t pid;

	if (!c_file) {
		err_fail("C input file name is NULL");
		return -1;
	}
	len = strlen(c_file);

	if (!opt_object_file || !opt_ll_file) {
		if (len < 3) {
			err_fail("no object or ll file name provided, and unable to derive it from C input file (name too short)");
			return -1;
		}
		if (strcmp(c_file + len - 2, ".c")) {
			err_fail("no object or ll file name provided, and unable to derive it from C input file (no .c extension)");
			return -1;
		}
	}

	if (!opt_object_file) {
		objfile = strdup(c_file);
		if (!objfile) {
			err_fail("failed to allocate memory for object file name");
			return -1;
		}
		*(objfile + len - 1) = 'o';
	} else {
		objfile = (char *)opt_object_file;
	}

	if (!opt_ll_file) {
		llfile = malloc(len + 2);
		if (!llfile) {
			err_fail("failed to allocate memory for ll file name");
			goto err_free_objfile;
		}
		strcpy(llfile, c_file);
		sprintf(llfile + len - 1, "ll");
	} else {
		llfile = (char *)opt_ll_file;
	}

	pid = fork();
	if (pid < 0) {
		err_fail("failed to fork for running clang: %s",
			 strerror(errno));
		goto err_free_filenames;
	}
	if (pid == 0) {
		if (execl(clang, clang, "-O2", "-g", "-emit-llvm", "-o", llfile,
			  "-c", c_file, (char *)NULL)) {
			err_fail("failed to exec clang: %s", strerror(errno));
			exit(-1);
		}
	}

	if (wait(&wstatus) < 0) {
		err_fail("cannot wait for clang, wait() syscall failed: %s",
			 strerror(errno));
		goto err_free_filenames;
	}
	if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus)) {
		err_fail("call to clang failed");
		goto err_free_filenames;
	}

	pid = fork();
	if (pid < 0) {
		err_fail("failed to fork for running llc: %s", strerror(errno));
		return -1;
	}
	if (pid == 0) {
		if (execl(llc, llc, "-march=bpf", "-mcpu=probe",
			  "-filetype=obj", "-o", objfile, llfile,
			  (char *)NULL)) {
			err_fail("failed to exec llc: %s", strerror(errno));
			exit(-1);
		}
	}

	if (wait(&wstatus) < 0) {
		err_fail("cannot wait for llc, wait() syscall failed: %s",
			 strerror(errno));
		goto err_free_filenames;
	}
	if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus)) {
		err_fail("call to llc failed");
		goto err_free_filenames;
	}

	if (!opt_ll_file)
		free(llfile);
	if (!opt_object_file)
		free(objfile);

	return 0;

err_free_filenames:
	if (!opt_ll_file)
		free(llfile);
err_free_objfile:
	if (!opt_object_file)
		free(objfile);

	return -1;
}

/*
 * Variadic list should contain:
 *     int map_fd
 *     int *index
 *     unsigned int nb_matches
 *     uint64_t flags
 */
static int fill_one_rule(void *rule_ptr, va_list ap)
{
	struct kefir_rule *rule = (struct kefir_rule *)rule_ptr;
	struct bpf_map_filter_rule_with_masks *map_entry;
	unsigned int nb_matches;
	int map_fd, *index;
	uint64_t flags;
	bool use_masks;
	size_t i;
	int res;

	map_fd = va_arg(ap, int);
	index = va_arg(ap, int *);
	nb_matches = va_arg(ap, unsigned int);
	flags = va_arg(ap, uint64_t);
	use_masks = flags & OPT_FLAGS_USE_MASKS;

	map_entry = calloc(1, sizeof(*map_entry));
	if (!map_entry) {
		err_fail("failed to allocate buffer for map entry");
		return -1;
	}

	for (i = 0; i < nb_matches; i++) {
		struct bpf_map_match_with_masks *map_match;
		struct kefir_match *rule_match = &rule->matches[i];

		if (use_masks) {
			map_match = &map_entry->matches[i];
		} else {
			struct bpf_map_filter_rule *r;
			struct bpf_map_match *m;

			/*
			 * Masks disabled, therefore the generated BPF program
			 * holds an array of struct bpf_map_match (with no
			 * masks), while here map_entry is declared as an array
			 * of structs with room for masks in each cell. Let's
			 * adjust it by casting map_entry to a struct
			 * bpf_map_filter_rule before pointing to, and filling,
			 * its i-th element. The struct will have empty room at
			 * its end but bpf_map_update_elem() does not care
			 * about that.
			 */
			r = (struct bpf_map_filter_rule *)map_entry;
			m = &r->matches[i];
			map_match = (struct bpf_map_match_with_masks *)m;
		}

		map_match->match_type = rule_match->match_type;
		map_match->comp_operator = rule_match->comp_operator;
		memcpy(map_match->value.u8, rule_match->value.data.raw,
		       sizeof(map_match->value));

		if (use_masks && rule_match->flags & MATCH_FLAGS_USE_MASK) {
			memcpy(map_match->mask, rule_match->mask,
			       sizeof(map_match->mask));
			map_match->flags |= MATCH_FLAGS_USE_MASK;
		}
	}
	map_entry->action_code = rule->action;

	res = bpf_map_update_elem(map_fd, index, map_entry, BPF_ANY);

	free(map_entry);

	if (res) {
		err_fail("map update failed: %s", strerror(errno));
		return -1;
	}

	*index += 1;

	return 0;
}

int compile_load_from_objfile(const kefir_cprog *cprog, const char *objfile,
			      struct bpf_object **bpf_obj,
			      const struct kefir_load_attr *attr)
{
	struct bpf_prog_load_attr load_attr = {0};
	int prog_fd;

	libbpf_set_print(libbpf_output_to_buf);

	load_attr.file = objfile;
	/* Ifindex must be 0 for loading if no hardware offload is required */
	load_attr.ifindex = attr->flags & XDP_FLAGS_HW_MODE ? attr->ifindex : 0;
	load_attr.log_level = attr->log_level;
	switch (cprog->options.target) {
	case KEFIR_CPROG_TARGET_XDP:
		load_attr.prog_type = BPF_PROG_TYPE_XDP;
		break;
	case KEFIR_CPROG_TARGET_TC:
		load_attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
		break;
	default:
		err_bug("unknown compilation target: %d",
			cprog->options.target);
		return -1;
	}

	/* Load BPF program */
	if (bpf_prog_load_xattr(&load_attr, bpf_obj, &prog_fd))
		return -1;
	/* Success, but bpf_prog_load_xattr often changes errno. Reset it */
	errno = 0;

	return prog_fd;
}

int compile_fill_map(const kefir_cprog *cprog, struct bpf_object *bpf_obj)
{
	struct bpf_map *rule_map;
	int rule_map_fd;
	int index = 0;

	/* Fill map */
	rule_map = bpf_object__find_map_by_name(bpf_obj, "rules");
	if (!rule_map) {
		err_fail("failed to retrieve map handler for loading rules");
		return -1;
	}
	rule_map_fd = bpf_map__fd(rule_map);
	if (rule_map_fd < 0) {
		err_fail("failed to retrieve file descriptor for the map");
		return -1;
	}
	if (list_for_each((struct list *)cprog->filter->rules, fill_one_rule,
			  rule_map_fd, &index, cprog->options.nb_matches,
			  cprog->options.flags))
		return -1;

	return 0;
}

int compile_attach_program(const kefir_cprog *cprog, struct bpf_object *bpf_obj,
			   int prog_fd, const struct kefir_load_attr *attr)
{
	switch (cprog->options.target) {
	case KEFIR_CPROG_TARGET_XDP:
		if (bpf_set_link_xdp_fd(attr->ifindex, prog_fd, attr->flags))
			/* libbpf should print extack messages on error */
			return -1;
		break;
	/* TODO: Add support for TC */
	default:
		err_bug("unknown attach target: %d", cprog->options.target);
		return -1;
	}

	return compile_fill_map(cprog, bpf_obj);
}
