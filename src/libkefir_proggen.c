// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <linux/bpf.h>

#include "libkefir_error.h"
#include "libkefir_internals.h"
#include "libkefir_proggen.h"

static void err_fail(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	kefir_vset_prefix_error(format, "C prog gen failed: ", ap);
	va_end(ap);
}

enum kefir_cprog_target {
	CPROG_TARGET_XDP,
	CPROG_TARGET_TC,
};

#define OPT_FLAGS_NEED_IPV4	1 << 0
#define OPT_FLAGS_NEED_IPV6	1 << 1
#define OPT_FLAGS_NEED_UDP	1 << 2
#define OPT_FLAGS_NEED_TCP	1 << 3
#define OPT_FLAGS_NEED_SCTP	1 << 4

struct kefir_cprog_options {
	enum kefir_cprog_target	target;
	uint64_t		flags;
	uint8_t	req_helpers[__BPF_FUNC_MAX_ID / 8 + 1];
};

struct kefir_cprog {
	kefir_filter		*filter;
	kefir_cprog_options	options;
};

static const char *cprog_header = ""
	"/*\n"
	" * This program was automatically generated with libkefir.\n"
	" */\n"
	"\n"
	"#include <stdint.h>\n"
	"\n"
	"#include <linux/bpf.h>\n"
	"#include <linux/if_ether.h>\n"
	"#include <linux/pkt_cls.h>\n"
	"#include <linux/swab.h>\n"
	"\n"
	"#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__\n"
	"#define bpf_ntohs(x) (__builtin_constant_p(x) ?\\\n"
	"	___constant_swab16(x) : __builtin_bswap16(x))\n"
	"#else\n"
	"#define bpf_ntohs(x) (x)\n"
	"#endif\n"
	"\n"
	"";

static const char * const cprog_prog_starts[] = {
	[CPROG_TARGET_XDP] =
		"#define RET_PASS XDP_PASS\n"
		"#define RET_DROP XDP_DROP\n"
		"\n"
		"__attribute__((section(\"xdp\"), used))\n"
		"int xdp_main(struct xdp_md *ctx)\n",
	[CPROG_TARGET_TC] =
		"#define RET_PASS TC_ACT_OK\n"
		"#define RET_DROP TC_ACT_SHOT\n"
		"\n"
		"__attribute__((section(\"classifier\"), used))\n"
		"int cls_main(struct __sk_buff *ctx)\n",
};

static const char *cprog_prog_body = ""
	"{\n"
	"	void *data_end = (void *)(long)ctx->data_end;\n"
	"	void *data = (void *)(long)ctx->data;\n"
	"	struct ethhdr *eth = data;\n"
	"	__u32 eth_proto;\n"
	"	__u32 nh_off;\n"
	"\n"
	"	if (extract_key(data, data_end))\n"
	"		return RET_DROP;\n"
	"\n"
	"	return RET_PASS;\n"
	"}\n"
	"\n"
	"";

static const char *cprog_license = ""
	"char _license[] __attribute__((section(\"license\"), used)) = \"Dual BSD/GPL\";\n"
	"";

static const char * const cprog_helpers[] = {
	[BPF_FUNC_map_lookup_elem] =
		"static void *(*bpf_map_lookup_elem)(void *map, void *key) =\n"
		"	(void *) BPF_FUNC_map_lookup_elem;\n",
	[BPF_FUNC_map_update_elem] =
		"static int (*bpf_map_update_elem)(void *map, void *key,\n"
		"				  void *value,\n"
		"				  unsigned long long flags) =\n"
		"	(void *) BPF_FUNC_map_update_elem;\n",
	[BPF_FUNC_map_delete_elem] =
		"static int (*bpf_map_delete_elem)(void *map, void *key) =\n"
		"	(void *) BPF_FUNC_map_delete_elem;\n",
	[BPF_FUNC_trace_printk] =
		"static int (*bpf_trace_printk)(const char *fmt,\n"
		"			       int fmt_size, ...) =\n"
		"	(void *) BPF_FUNC_trace_printk;\n",
};

 __attribute__ ((format (printf, 3, 4)))
static int buf_append(char **buf, size_t *buf_len, const char *fmt, ...)
{
	size_t offset, maxlen, reqlen;
	va_list ap;

	// Should not be required as long as we don't take buffer from caller,
	// in kefir_dump_cprog().
	//if (!*buf) {
	//	*buf = calloc(*buf_len ? *buf_len : 1024, sizeof(char));
	//	if (!*buf) {
	//		err_fail("failed to allocate memory for C prog buffer");
	//		return -1;
	//	}
	//}

	offset = strlen(*buf);
	maxlen = *buf_len - offset;

	va_start(ap, fmt);
	reqlen = vsnprintf(*buf + offset, maxlen, fmt, ap);
	va_end(ap);

	while (reqlen >= maxlen) {
		/* Output was truncated. Reallocate buffer and retry. */
		*buf_len *= 2;
		*buf = realloc(*buf, *buf_len);
		if (!*buf) {
			err_fail("failed to reallocate memory for C prog buffer");
			return -1;
		}

		maxlen = *buf_len - offset;
		va_start(ap, fmt);
		reqlen = vsnprintf(*buf + offset, maxlen, fmt, ap);
		va_end(ap);
	}

	return 0;
}

static kefir_cprog *create_cprog(void)
{
	kefir_cprog *prog;

	prog = calloc(1, sizeof(kefir_cprog));
	return prog;
}

void proggen_cprog_destroy(kefir_cprog *cprog)
{
	// TODO: If someday we copy the filter instead of just pointing to the
	// original, don't forget to free it here
	free(cprog);
}

static void add_req_helper(kefir_cprog *prog, size_t helper_id)
{
	uint8_t flag;
	size_t cell;

	cell = helper_id / 8;
	flag = 1 << (helper_id % 8);
	prog->options.req_helpers[cell] |= flag;
}

static bool need_helper(const kefir_cprog *prog, size_t helper_id)
{
	uint8_t flag;
	size_t cell;

	cell = helper_id / 8;
	flag = 1 << (helper_id % 8);
	return prog->options.req_helpers[cell] & flag;
}

#include <stdio.h>
static int
make_helpers_decl(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	size_t i;

	for (i = 0; i < __BPF_FUNC_MAX_ID; i++)
		if (need_helper(prog, i))
			if (buf_append(buf, buf_len, "%s", cprog_helpers[i]))
				return -1;

	if (buf_append(buf, buf_len, "\n"))
		return -1;

	return 0;
}

static int
cprog_func_extract_key(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	bool need_ipv4 = prog->options.flags & OPT_FLAGS_NEED_IPV4;
	bool need_ipv6 = prog->options.flags & OPT_FLAGS_NEED_IPV6;

	if (buf_append(buf, buf_len, ""
		       "static __attribute__((always_inline))\n"
		       "int extract_key(void *data, void *data_end)\n"
		       "{\n"
		       "	struct ethhdr *eth = data;\n"
		       "	__u32 eth_proto;\n"
		       "	__u32 nh_off;\n"
		       "\n"
		       "	if (data + nh_off > data_end)\n"
		       "		return -1;\n"
		       "	eth_proto = eth->h_proto;\n"
		       "\n"
		       ""))
		return -1;

	if (need_ipv4 || need_ipv6)
		if (buf_append(buf, buf_len, ""
			       "	switch (bpf_ntohs(eth_proto)) {\n"
			       ""))
			return -1;

	if (need_ipv4)
		if (buf_append(buf, buf_len, ""
			       "	case ETH_P_IP:\n"
			       "		//process_ipv4(ctx, nh_off)\n"
			       "		break;\n"
			       ""))
			return -1;

	if (need_ipv6)
		if (buf_append(buf, buf_len, ""
			       "	case ETH_P_IPV6:\n"
			       "		//process_ipv6(ctx, nh_off)\n"
			       "		break;\n"
			       ""))
			return -1;

	if (need_ipv4 || need_ipv6)
		if (buf_append(buf, buf_len, ""
			       "	default:\n"
			       "		return 0;\n"
			       "	}\n"
			       ""))
			return -1;

	if (buf_append(buf, buf_len, ""
		       "\n"
		       "	return 0;\n"
		       "}\n"
		       "\n"
		       ""))
		return -1;

	return 0;
}

static int
make_cprog_start(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	return buf_append(buf, buf_len, "%s",
			  cprog_prog_starts[prog->options.target]);
}

/*
 * Should be called as
 * void update_cprog_options(struct kefir_rule *rule_ptr, kefir_cprog *prog)
 */
static void update_cprog_options(void *rule_ptr, va_list ap)
{
	struct kefir_rule *rule = (struct kefir_rule *)rule_ptr;
	kefir_cprog *prog;

	prog = va_arg(ap, kefir_cprog *);

	switch (rule->match.header_type) {
	case HDR_TYPE_ETHERNET:
		break;
	case HDR_TYPE_VLAN:
		break;
	case HDR_TYPE_ARP:
		break;
	case HDR_TYPE_IP:
		if (rule->match.flags & KEFIR_MATCH_FLAG_IPV4)
			prog->options.flags |= OPT_FLAGS_NEED_IPV4;
		if (rule->match.flags & KEFIR_MATCH_FLAG_IPV6)
			prog->options.flags |= OPT_FLAGS_NEED_IPV6;
		break;
	case HDR_TYPE_TCP:
		break;
	case HDR_TYPE_UDP:
		break;
	case HDR_TYPE_SCTP:
		break;
	case HDR_TYPE_IPSEC:
		break;
	case HDR_TYPE_APPLI:
		break;
	default:
		return;
	}

	/************* for test */
	add_req_helper(prog, BPF_FUNC_map_lookup_elem);
	add_req_helper(prog, BPF_FUNC_trace_printk);
	/************* for test */
}

kefir_cprog *
proggen_make_cprog_from_filter(const kefir_filter *filter,
			       const kefir_cprog_options *opts)
{
	struct kefir_cprog_options default_opts = {0};
	kefir_cprog *prog;

	prog = create_cprog();
	if (!prog) {
		err_fail("failed to allocate memory for C prog object");
		return NULL;
	}

	if (!filter || !kefir_sizeof_filter(filter)) {
		err_fail("cannot convert empty filter");
		return NULL;
	}
	if (opts)
		memcpy(&prog->options, opts,
		       sizeof(struct kefir_cprog_options));
	else
		prog->options = default_opts;

	list_for_each((struct list *)filter->rules,
		      update_cprog_options, prog);

	return prog;
}

int proggen_cprog_to_buf(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	if (!prog) {
		err_fail("cannot dump empty C prog object");
		return -1;
	}

	if (buf_append(buf, buf_len, "%s", cprog_header))
		return -1;

	if (make_helpers_decl(prog, buf, buf_len))
		return -1;

	if (cprog_func_extract_key(prog, buf, buf_len))
		return -1;

	if (make_cprog_start(prog, buf, buf_len))
		return -1;

	if (buf_append(buf, buf_len, "%s", cprog_prog_body))
		return -1;

	if (buf_append(buf, buf_len, "%s", cprog_license))
		return -1;

	return 0;
}
