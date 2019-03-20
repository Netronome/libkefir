// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <linux/bpf.h>

#include "libkefir_error.h"
#include "libkefir_internals.h"
#include "libkefir_proggen.h"

// TODO just used for comments at bottom of file
#include "libkefir_dump.h"

#define max(a, b)	(a > b ? a : b)

static void err_fail(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	kefir_vset_prefix_error(format, "C prog gen failed: ", ap);
	va_end(ap);
}

static char cprog_attr_func_static_inline[] = ""
	"static __attribute__((always_inline))\n"
	"";

static const char *cprog_header = ""
	"/*\n"
	" * This program was automatically generated with libkefir.\n"
	" */\n"
	"\n"
	"#include <stdbool.h>\n"
	"#include <stdint.h>\n"
	"#include <string.h>\n"
	"\n"
	"#include <linux/bpf.h>\n"
	"#include <linux/if_ether.h>\n"
	"#include <linux/ip.h>\n"
	"#include <linux/ipv6.h>\n"
	"#include <linux/pkt_cls.h>\n"
	"#include <linux/swab.h>\n"
	"#include <linux/tcp.h>\n"
	"\n"
	"#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__\n"
	"#define bpf_ntohs(x) (__builtin_constant_p(x) ?\\\n"
	"	___constant_swab16(x) : __builtin_bswap16(x))\n"
	"#else\n"
	"#define bpf_ntohs(x) (x)\n"
	"#endif\n"
	"\n"
	"#define BPF_ANNOTATE_KV_PAIR(name, type_key, type_val)		\\\n"
	"	struct ____btf_map_##name {				\\\n"
	"		type_key key;					\\\n"
	"		type_val value;					\\\n"
	"	};							\\\n"
	"	struct ____btf_map_##name				\\\n"
	"	__attribute__ ((section(\".maps.\" #name), used))		\\\n"
	"		____btf_map_##name = { }\n"
	"\n"
	"";

static const char *cprog_license = ""
	"char _license[] __attribute__((section(\"license\"), used)) = \"Dual BSD/GPL\";\n"
	"";

static const char * const cprog_return_values[] = {
	[KEFIR_CPROG_TARGET_XDP] =
		"#define RET_PASS XDP_PASS\n"
		"#define RET_DROP XDP_DROP\n"
		"\n",
	[KEFIR_CPROG_TARGET_TC] =
		"#define RET_PASS TC_ACT_OK\n"
		"#define RET_DROP TC_ACT_SHOT\n"
		"\n",
};

static const char * const cprog_prog_starts[] = {
	[KEFIR_CPROG_TARGET_XDP] =
		"__attribute__((section(\"xdp\"), used))\n"
		"int xdp_main(struct xdp_md *ctx)\n",
	[KEFIR_CPROG_TARGET_TC] =
		"__attribute__((section(\"classifier\"), used))\n"
		"int cls_main(struct __sk_buff *ctx)\n",
};

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
		"static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =\n"
		"	(void *) BPF_FUNC_trace_printk;\n"
		"#define trace_printk(fmt, ...)	({			\\\n"
		"	char fmt_array[] = fmt;				\\\n"
		"	bpf_trace_printk(fmt_array, sizeof(fmt_array),	\\\n"
		"			 ##__VA_ARGS__);		\\\n"
		"})\n",
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

static kefir_cprog *cprog_create(void)
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
make_retval_decl(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	return buf_append(buf, buf_len, "%s",
			  cprog_return_values[prog->options.target]);
}

/*
 * Should be called as
 * int rule_has_matchtype(void *rule_ptr, enum match_type type);
 */
static int rule_has_matchtype(void *rule_ptr, va_list ap)
{
	struct kefir_rule *rule = (struct kefir_rule *)rule_ptr;
	enum match_type type;
	bool found = false;
	size_t i;

	type = va_arg(ap, enum match_type);
	for (i = 0; i < KEFIR_MAX_MATCH_PER_RULE &&
	     rule->matches[i].match_type != KEFIR_MATCH_TYPE_UNSPEC; i++) {
		found = type == rule->matches[i].match_type;
		if (found)
			break;
	}

	return found;
}

static bool
filter_has_matchtype(const kefir_filter* filter, enum match_type type)
{
	return !!list_for_each((struct list *)filter->rules,
			       rule_has_matchtype, type);
}

/*
 * Should be called as
 * int rule_has_matchtype(void *rule_ptr, enum comp_operator op, int expect_op);
 */
static int rule_has_comp_operator(void *rule_ptr, va_list ap)
{
	struct kefir_rule *rule = (struct kefir_rule *)rule_ptr;
	enum comp_operator op;
	bool found = false;
	int expect_op; /* bool, but va_arg promotes bools to ints */
	size_t i;

	op = va_arg(ap, enum comp_operator);
	expect_op = va_arg(ap, int);

	for (i = 0; i < KEFIR_MAX_MATCH_PER_RULE &&
	     rule->matches[i].match_type != KEFIR_MATCH_TYPE_UNSPEC; i++) {
		found = op == rule->matches[i].comp_operator;
		if (found)
			break;
	}

	return expect_op ? found : !found;
}

static int
filter_has_comp_oper(const kefir_filter *filter, enum comp_operator op)
{
	return list_for_each((struct list *)filter->rules,
			     rule_has_comp_operator, op, 1);
}

/*
static bool
filter_all_comp_equal(const kefir_filter *filter)
{
	return !list_for_each((struct list *)filter->rules,
			      rule_has_comp_operator, OPER_EQUAL, 0);
}
*/

static int
make_key_decl(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	const kefir_filter *filter = prog->filter;

	if (buf_append(buf, buf_len, "struct filter_key {\n"))
		return -1;

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_ANY))
		if (buf_append(buf, buf_len, "	uint32_t	ipv4_src;\n"))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_ANY))
		if (buf_append(buf, buf_len, "	uint32_t	ipv4_dst;\n"))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_TOS) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_TOS))
		if (buf_append(buf, buf_len, "	uint8_t		tos;\n"))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_TTL) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_TTL))
		if (buf_append(buf, buf_len, "	uint8_t		ttl;\n"))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_ANY))
		if (buf_append(buf, buf_len,
			       "	union {\n"
			       "		uint8_t		u8[16];\n"
			       "		uint32_t	u32[4];\n"
			       "		uint64_t	u64[2];\n"
			       "	} ipv6_src;\n"
			       ""))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_ANY))
		if (buf_append(buf, buf_len,
			       "	union {\n"
			       "		uint8_t		u8[16];\n"
			       "		uint32_t	u32[4];\n"
			       "		uint64_t	u64[2];\n"
			       "	} ipv6_dst;\n"
			       ""))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PROTO) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4PROTO))
		if (buf_append(buf, buf_len,
			       "	uint16_t	ipv4_l4proto;\n"))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PROTO) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4PROTO))
		if (buf_append(buf, buf_len,
			       "	uint16_t	ipv6_l4proto;\n"))
			return -1;

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_L4_PORT_SRC))
		if (buf_append(buf, buf_len,
			       "	uint16_t	l4port_src;\n"))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_L4_PORT_DST))
		if (buf_append(buf, buf_len,
			       "	uint16_t	l4port_dst;\n"))
			return -1;


	if (buf_append(buf, buf_len, "};\n\n"))
		return -1;

	return 0;
}

static int
make_rule_table_decl(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	const kefir_filter *filter = prog->filter;

	if (buf_append(buf, buf_len, "enum match_type {\n"))
		return -1;

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_SRC))
		if (buf_append(buf, buf_len,
			       "	MATCH_IPV4_SRC		= %d,\n",
			       KEFIR_MATCH_TYPE_IP_4_SRC))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_DST))
		if (buf_append(buf, buf_len,
			       "	MATCH_IPV4_DST		= %d,\n",
			       KEFIR_MATCH_TYPE_IP_4_DST))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_TOS))
		if (buf_append(buf, buf_len,
			       "	MATCH_IPV4_TOS		= %d,\n",
			       KEFIR_MATCH_TYPE_IP_4_TOS))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_TTL))
		if (buf_append(buf, buf_len,
			       "	MATCH_IPV4_TTL		= %d,\n",
			       KEFIR_MATCH_TYPE_IP_4_TTL))
			return -1;

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_SRC))
		if (buf_append(buf, buf_len,
			       "	MATCH_IPV6_SRC		= %d,\n",
			       KEFIR_MATCH_TYPE_IP_6_SRC))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_DST))
		if (buf_append(buf, buf_len,
			       "	MATCH_IPV6_DST		= %d,\n",
			       KEFIR_MATCH_TYPE_IP_6_DST))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_TOS))
		if (buf_append(buf, buf_len,
			       "	MATCH_IPV6_TOS		= %d,\n",
			       KEFIR_MATCH_TYPE_IP_6_TOS))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_TTL))
		if (buf_append(buf, buf_len,
			       "	MATCH_IPV6_TTL		= %d,\n",
			       KEFIR_MATCH_TYPE_IP_6_TTL))
			return -1;

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_SRC))
		if (buf_append(buf, buf_len,
			       "	MATCH_IP_ANY_SRC	= %d,\n",
			       KEFIR_MATCH_TYPE_IP_ANY_SRC))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_DST))
		if (buf_append(buf, buf_len,
			       "	MATCH_IP_ANY_DST	= %d,\n",
			       KEFIR_MATCH_TYPE_IP_ANY_DST))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_TOS))
		if (buf_append(buf, buf_len,
			       "	MATCH_IP_ANY_TOS	= %d,\n",
			       KEFIR_MATCH_TYPE_IP_ANY_TOS))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_TTL))
		if (buf_append(buf, buf_len,
			       "	MATCH_IP_ANY_TTL	= %d,\n",
			       KEFIR_MATCH_TYPE_IP_ANY_TTL))
			return -1;

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PROTO))
		if (buf_append(buf, buf_len,
			       "	MATCH_IPV4_L4PROTO	= %d,\n",
			       KEFIR_MATCH_TYPE_IP_4_L4PROTO))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_L4_PORT_SRC))
		if (buf_append(buf, buf_len,
			       "	MATCH_L4_PORT_SRC	= %d,\n",
			       KEFIR_MATCH_TYPE_L4_PORT_SRC))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_L4_PORT_DST))
		if (buf_append(buf, buf_len,
			       "	MATCH_L4_PORT_DST	= %d,\n",
			       KEFIR_MATCH_TYPE_L4_PORT_DST))
			return -1;

	if (buf_append(buf, buf_len, ""
		       "};\n"
		       "\n"
		       "enum comp_operator {\n"
		       "	OPER_EQUAL	= %d,\n"
		       "", OPER_EQUAL))
		return -1;

	if (filter_has_comp_oper(filter, OPER_LT))
		if (buf_append(buf, buf_len, "	OPER_LT		= %d,\n",
			       OPER_LT))
			return -1;
	if (filter_has_comp_oper(filter, OPER_LEQ))
		if (buf_append(buf, buf_len, "	OPER_LEQ	= %d,\n",
			       OPER_LEQ))
			return -1;
	if (filter_has_comp_oper(filter, OPER_GT))
		if (buf_append(buf, buf_len, "	OPER_GT		= %d,\n",
			       OPER_GT))
			return -1;
	if (filter_has_comp_oper(filter, OPER_GEQ))
		if (buf_append(buf, buf_len, "	OPER_GEQ	= %d,\n",
			       OPER_GEQ))
			return -1;
	if (buf_append(buf, buf_len, ""
		       "};\n"
		       "\n"
		       ""))
		return -1;

	if (buf_append(buf, buf_len, ""
		       "enum action_code {\n"
		       "	ACTION_CODE_DROP	= %d,\n"
		       "	ACTION_CODE_PASS	= %d,\n"
		       "};\n"
		       "\n"
		       "", ACTION_CODE_DROP, ACTION_CODE_PASS))
		return -1;

	if (prog->options.flags & OPT_FLAGS_USE_MASKS)
		if (buf_append(buf, buf_len, ""
			       "#define MATCH_FLAGS_USE_MASK	%d\n"
			       "\n"
			       "", MATCH_FLAGS_USE_MASK))
			return -1;

	/*
	 * Note that struct filter_rule must be identically defined in
	 * libkefir_compile.c
	 */
	if (buf_append(buf, buf_len, ""
		       "struct rule_match {\n"
		       "	enum match_type		match_type;\n"
		       "	enum comp_operator	comp_operator;\n"
		       "	union {\n"
		       "		__u8	u8[16];\n"
		       "		__u64	u64[2];\n"
		       "	} value;\n"
		       ""))
		return -1;

	if (prog->options.flags & OPT_FLAGS_USE_MASKS)
		if (buf_append(buf, buf_len, ""
			       "	__u64	flags;\n"
			       "	__u8	mask[16];\n"
			       ""))
			return -1;

	if (buf_append(buf, buf_len, ""
		       "};\n"
		       "\n"
		       "struct filter_rule {\n"
		       "	enum action_code	action_code;\n"
		       "	struct rule_match	matches[%d];\n"
		       "};\n"
		       "\n"
		       "struct bpf_elf_map {\n"
		       "	__u32 type;\n"
		       "	__u32 size_key;\n"
		       "	__u32 size_value;\n"
		       "	__u32 max_elem;\n"
		       "	__u32 flags;\n"
		       "	__u32 id;\n"
		       "	__u32 pinning;\n"
		       "	__u32 inner_id;\n"
		       "	__u32 inner_idx;\n"
		       "};\n"
		       "\n"
		       "struct bpf_elf_map __attribute__((section(\"maps\"), used)) rules = {\n"
		       "	.type		= BPF_MAP_TYPE_ARRAY,\n"
		       "	.size_key	= sizeof(__u32),\n"
		       "	.size_value	= sizeof(struct filter_rule),\n"
		       "	.max_elem	= %zd\n"
		       "};\n"
		       "BPF_ANNOTATE_KV_PAIR(rules, __u32, struct filter_rule);\n"
		       "\n"
		       "", prog->options.nb_matches,
		       list_count(prog->filter->rules)))
		return -1;

	return 0;
}

static int
cprog_func_process_l4(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	if (!(prog->options.flags & OPT_FLAGS_NEED_L4))
		return 0;

	if (buf_append(buf, buf_len, ""
		       "%sint process_l4(void *data, void *data_end, __u32 l4_off, struct filter_key *key)\n"
		       "{\n"
		       "	struct tcphdr *tcph = data + l4_off;\n"
		       "\n"
		       "	if ((void *)tcph + sizeof(tcph) > data_end)\n"
		       "		return -1;\n"
		       "\n"
		       "", cprog_attr_func_static_inline))
		return -1;

	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_L4_PORT_SRC) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_L4_PORT_ANY))
		if (buf_append(buf, buf_len,
			       "	key->l4port_src = tcph->source;\n"))
			       return -1;
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_L4_PORT_DST) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_L4_PORT_ANY))
		if (buf_append(buf, buf_len,
			       "	key->l4port_dst = tcph->dest;\n"))
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
cprog_func_process_ipv4(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	if (!(prog->options.flags & OPT_FLAGS_NEED_IPV4))
		return 0;

	if (buf_append(buf, buf_len, ""
		       "%sint process_ipv4(void *data, void *data_end, __u32 nh_off,\n"
		       "		 struct filter_key *key)\n"
		       "{\n"
		       "	struct iphdr *iph = data + nh_off;\n"
		       "\n"
		       "	if ((void *)(iph + 1) > data_end)\n"
		       "		return -1;\n"
		       "	if ((void *)iph + 4 * iph->ihl > data_end)\n"
		       "		return -1;\n"
		       "\n"
		       "", cprog_attr_func_static_inline))
		return -1;

	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_4_SRC) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_SRC))
		if (buf_append(buf, buf_len, "	key->ipv4_src = iph->saddr;\n"))
			return -1;
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_4_DST) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_DST))
		if (buf_append(buf, buf_len, "	key->ipv4_dst = iph->daddr;\n"))
			return -1;
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_4_L4PROTO) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_L4PROTO))
		if (buf_append(buf, buf_len,
			       "	key->ipv4_l4proto = iph->protocol;\n"))
			return -1;
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_4_TOS) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_TOS))
		if (buf_append(buf, buf_len, "	key->ipv4_tos = iph->tos;\n"))
			return -1;
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_4_TTL) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_TTL))
		if (buf_append(buf, buf_len, "	key->ipv4_ttl = iph->ttl;\n"))
			return -1;

	if (prog->options.flags & OPT_FLAGS_NEED_L4)
		if (buf_append(buf, buf_len, ""
			       "\n"
			       "	if (process_l4(data, data_end, nh_off + 4 * iph->ihl, key))\n"
			       "		return -1;\n"
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
cprog_func_process_ipv6(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	if (!(prog->options.flags & OPT_FLAGS_NEED_IPV4))
		return 0;

	if (buf_append(buf, buf_len, ""
		       "%sint process_ipv6(void *data, void *data_end, __u32 nh_off,\n"
		       "		 struct filter_key *key)\n"
		       "{\n"
		       "	struct ipv6hdr *ip6h = data + nh_off;\n"
		       "\n"
		       "	if ((void *)(ip6h + 1) > data_end)\n"
		       "		return -1;\n"
		       "\n"
		       "", cprog_attr_func_static_inline))
		return -1;

	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_6_SRC) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_SRC))
		if (buf_append(buf, buf_len, ""
			       "	key->ipv6_src.u32[0] = ip6h->saddr.in6_u.u6_addr32[0];\n"
			       "	key->ipv6_src.u32[1] = ip6h->saddr.in6_u.u6_addr32[1];\n"
			       "	key->ipv6_src.u32[2] = ip6h->saddr.in6_u.u6_addr32[2];\n"
			       "	key->ipv6_src.u32[3] = ip6h->saddr.in6_u.u6_addr32[3];\n"
			       ""))
			return -1;
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_6_DST) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_DST))
		if (buf_append(buf, buf_len, ""
			       "	key->ipv6_dst.u32[0] = ip6h->saddr.in6_u.u6_addr32[0];\n"
			       "	key->ipv6_dst.u32[1] = ip6h->saddr.in6_u.u6_addr32[1];\n"
			       "	key->ipv6_dst.u32[2] = ip6h->saddr.in6_u.u6_addr32[2];\n"
			       "	key->ipv6_dst.u32[3] = ip6h->saddr.in6_u.u6_addr32[3];\n"
			       ""))
			return -1;
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_6_L4PROTO) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_L4PROTO))
		if (buf_append(buf, buf_len, ""
			       "	/* Extension headers not supported for now */\n"
			       "	key->ipv6_l4proto = ip6h->nexthdr;\n"
			       ""))
			return -1;
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_6_TOS) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_TOS))
		if (buf_append(buf, buf_len, "	key->ipv6_tos = ip6h->priority << 2 + ip6h->flow_lbl[0] >> 2; // to be checked\n"))
			return -1;
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_6_TTL) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_TTL))
		if (buf_append(buf, buf_len, "	key->ipv6_ttl = ip6h->hop_limit;\n"))
			return -1;

	if (prog->options.flags & OPT_FLAGS_NEED_L4)
		if (buf_append(buf, buf_len, ""
			       "\n"
			       "	if (process_l4(data, data_end, nh_off + sizeof(struct ipv6hdr), key))\n"
			       "		return -1;\n"
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
cprog_func_extract_key(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	bool need_ether = prog->options.flags & OPT_FLAGS_NEED_ETHER;
	bool need_ipv4 = prog->options.flags & OPT_FLAGS_NEED_IPV4;
	bool need_ipv6 = prog->options.flags & OPT_FLAGS_NEED_IPV6;

	if (buf_append(buf, buf_len, ""
		       "%sint extract_key(void *data, void *data_end, struct filter_key *key)\n"
		       "{\n"
		       "	struct ethhdr *eth = data;\n"
		       "	__u32 eth_proto;\n"
		       "	__u32 nh_off;\n"
		       "\n"
		       "	nh_off = sizeof(struct ethhdr);\n"
		       "	if (data + nh_off > data_end)\n"
		       "		return -1;\n"
		       "	eth_proto = eth->h_proto;\n"
		       "\n"
		       "", cprog_attr_func_static_inline))
		return -1;

	if (need_ether)
		if (buf_append(buf, buf_len, ""
			       "	//process_ether(ctx);\n"
			       "\n"
			       ""))
			return -1;

	if (need_ipv4 || need_ipv6) {
		if (buf_append(buf, buf_len, ""
			       "	switch (bpf_ntohs(eth_proto)) {\n"
			       ""))
			return -1;

		if (need_ipv4)
			if (buf_append(buf, buf_len, ""
				       "	case ETH_P_IP:\n"
				       "		if (process_ipv4(data, data_end, nh_off, key))\n"
				       "			return 0;\n"
				       "		break;\n"
				       ""))
				return -1;

		if (need_ipv6)
			if (buf_append(buf, buf_len, ""
				       "	case ETH_P_IPV6:\n"
				       "		if (process_ipv6(data, data_end, nh_off, key))\n"
				       "			return 0;\n"
				       "		break;\n"
				       ""))
				return -1;

		if (buf_append(buf, buf_len, ""
			       "	default:\n"
			       "		return 0;\n"
			       "	}\n"
			       "\n"
			       ""))
			return -1;
	}

	if (buf_append(buf, buf_len, ""
		       "	return 0;\n"
		       "}\n"
		       "\n"
		       ""))
		return -1;

	return 0;
}
static int
cprog_func_check_rules(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	bool use_masks = prog->options.flags & OPT_FLAGS_USE_MASKS;
	const kefir_filter *filter = prog->filter;
	//bool only_equal = filter_all_comp_equal(filter);
	bool only_equal = false; // TODO: optim does not work with offload (only 15 unroll work) + much more insns

	if (buf_append(buf, buf_len, ""
		       "%sbool check_match(void *matchval, size_t matchlen, struct rule_match *match)\n"
		       "{\n"
		       "	size_t i;\n"
		       "", cprog_attr_func_static_inline))
		return -1;

	if (only_equal) {
		if (buf_append(buf, buf_len, ""
			       "\n"
			       "#pragma clang loop unroll(full)\n"
			       "	for (i = 0; i < 16; i++) {\n"
			       ""))
			return -1;

		if (use_masks && buf_append(buf, buf_len, ""
			       "		uint8_t mask = (match->flags & MATCH_FLAGS_USE_MASK) ?\n"
			       "			match->mask[i] : 0xff;\n"
			       "\n"
			       ""))
			return -1;

		if (buf_append(buf, buf_len, ""
			       "		if (i >= matchlen)\n"
			       "			break;\n"
			       "		if (*((__u8 *)matchval + i)%s != match->value.u8[i])\n"
			       "			return false;\n"
			       "	}\n"
			       "	return true;\n"
			       "", use_masks ? " & mask" : ""))
			return -1;
	} else {
		if (buf_append(buf, buf_len, ""
			       "	union {\n"
			       "		__u8	u8[16];\n"
			       "		__u64	u64[2];\n"
			       "	} copy = {{0}};\n"
			       "\n"
			       "static const char format[] = \"%%d - %%d\\n\";\n"
			       "#pragma clang loop unroll(full)\n"
			       "	for (i = 0; i < 16; i++) {\n"
			       ""))
			return -1;

		if (use_masks && buf_append(buf, buf_len, ""
			       "		uint8_t mask = (match->flags & MATCH_FLAGS_USE_MASK) ?\n"
			       "			match->mask[i] : 0xff;\n"
			       "\n"
			       ""))
			return -1;

		if (buf_append(buf, buf_len, ""
			       "		if (i >= matchlen)\n"
			       "			break;\n"
			       "		copy.u8[i] = *((__u8 *)matchval + i)%s;\n"
			       "	}\n"
			       "\n"
			       "	if (match->comp_operator == OPER_EQUAL) {\n"
			       "		if (copy.u64[0] != match->value.u64[0])\n"
			       "			return false;\n"
			       "		if (matchlen > sizeof(__u64) &&\n"
			       "		    copy.u64[1] != match->value.u64[1])\n"
			       "			return false;\n"
			       "		return true;\n"
			       "	}\n"
			       "\n"
			       "	switch (match->comp_operator) {\n"
			       "", use_masks ? " & mask" : ""))
			return -1;
		if (filter_has_comp_oper(prog->filter, OPER_LT))
			if (buf_append(buf, buf_len, ""
				       "	case OPER_LT:\n"
				       "		return copy.u64[0] < match->value.u64[0] ||\n"
				       "			(copy.u64[0] == match->value.u64[0] &&\n"
				       "			 copy.u64[1] < copy.u64[1]);\n"
				       ""))
				return -1;
		if (filter_has_comp_oper(prog->filter, OPER_LEQ))
			if (buf_append(buf, buf_len, ""
				       "	case OPER_LEQ:\n"
				       "		return copy.u64[0] < match->value.u64[0] ||\n"
				       "			(copy.u64[0] == match->value.u64[0] &&\n"
				       "			 copy.u64[1] <= copy.u64[1]);\n"
				       ""))
				return -1;
		if (filter_has_comp_oper(prog->filter, OPER_GT))
			if (buf_append(buf, buf_len, ""
				       "	case OPER_GT:\n"
				       "		return copy.u64[0] > match->value.u64[0] ||\n"
				       "			(copy.u64[0] == match->value.u64[0] &&\n"
				       "			 copy.u64[1] > copy.u64[1]);\n"
				       ""))
				return -1;
		if (filter_has_comp_oper(prog->filter, OPER_GEQ))
			if (buf_append(buf, buf_len, ""
				       "	case OPER_GEQ:\n"
				       "		return copy.u64[0] > match->value.u64[0] ||\n"
				       "			(copy.u64[0] == match->value.u64[0] &&\n"
				       "			 copy.u64[1] >= copy.u64[1]);\n"
				       ""))
				return -1;
		if (buf_append(buf, buf_len, ""
			       "	default:\n"
			       "		return false;\n"
			       "	}\n"
			       ""))
			return -1;
	}

	if (buf_append(buf, buf_len, ""
		       "}\n"
		       "\n"
		       "%sint get_retval(enum action_code code)\n"
		       "{\n"
		       "	switch (code) {\n"
		       "	case ACTION_CODE_DROP:\n"
		       "		return RET_DROP;\n"
		       "	case ACTION_CODE_PASS:\n"
		       "		return RET_PASS;\n"
		       "	default:\n"
		       "		return RET_PASS;\n" // ABORT?
		       "	}\n"
		       "}\n"
		       "\n"
		       "%sint check_nth_rule(struct filter_key *key, int n, int *res)\n"
		       "{\n"
		       "	struct filter_rule *rule;\n"
		       "	struct rule_match *match;\n"
		       "	bool does_match = true;\n"
		       "	size_t i;\n"
		       "\n"
		       "	rule = (struct filter_rule *)bpf_map_lookup_elem(&rules, &n);\n"
		       "	if (!rule)\n"
		       "		return 0;\n"
		       "\n"
		       "#pragma clang loop unroll(full)\n"
		       "	for (i = 0; i < %d; i++) {\n"
		       "		match = &rule->matches[i];\n"
		       "\n"
		       "		switch (match->match_type) {\n"
		       "", cprog_attr_func_static_inline,
		       cprog_attr_func_static_inline,
		       prog->options.nb_matches))
		return -1;

	// We should have the type (IPv4/IPv6) of packet by now, no need to
	// test all cases every time

	/* IPv4 */

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_ANY))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_IPV4_SRC:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->ipv4_src,\n"
			       "					    sizeof(key->ipv4_src), match);\n"
			       "			break;\n"
			       ""))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_ANY))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_IPV4_DST:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->ipv4_dst,\n"
			       "					    sizeof(key->ipv4_dst), match);\n"
			       "			break;\n"
			       ""))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_TOS))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_IPV4_TOS:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->ipv4_tos,\n"
			       "					    sizeof(key->ipv4_tos), match);\n"
			       "			break;\n"
			       ""))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_TTL))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_IPV4_TTL:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->ipv4_ttl,\n"
			       "					    sizeof(key->ipv4_ttl), match);\n"
			       "			break;\n"
			       ""))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PROTO))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_IPV4_L4PROTO:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->ipv4_l4proto,\n"
			       "					    sizeof(key->ipv4_l4proto), match);\n"
			       "			break;\n"
			       ""))
			return -1;

	/* IPv6 */

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_ANY))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_IPV6_SRC:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->ipv6_src,\n"
			       "					    sizeof(key->ipv6_src), match);\n"
			       "			break;\n"
			       ""))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_ANY))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_IPV6_DST:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->ipv6_dst,\n"
			       "					    sizeof(key->ipv6_dst), match);\n"
			       "			break;\n"
			       ""))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_TOS))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_IPV6_TOS:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->ipv6_tos,\n"
			       "					    sizeof(key->ipv6_tos), match);\n"
			       "			break;\n"
			       ""))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_TTL))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_IPV6_TTL:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->ipv6_ttl,\n"
			       "					    sizeof(key->ipv6_ttl), match);\n"
			       "			break;\n"
			       ""))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PROTO))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_IPV6_L4PROTO:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->ipv6_l4proto,\n"
			       "					    sizeof(key->ipv6_l4proto), match);\n"
			       "			break;\n"
			       ""))
			return -1;

	/* IPv4 or IPv6 */

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_ANY))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_IP_ANY_SRC:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->ipv4_src,\n"
			       "					    sizeof(key->ipv4_src), match);\n"
			       "			break;\n"
			       ""))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_ANY))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_IP_ANY_DST:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->ipv4_dst,\n"
			       "					    sizeof(key->ipv4_dst), match);\n"
			       "			break;\n"
			       ""))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_TOS))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_IP_ANY_TOS:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->ipv4_tos,\n"
			       "					    sizeof(key->ipv4_tos), match);\n"
			       "			break;\n"
			       ""))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_TTL))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_IP_ANY_TTL:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->ipv4_ttl,\n"
			       "					    sizeof(key->ipv4_ttl), match);\n"
			       "			break;\n"
			       ""))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4PROTO))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_IP_ANY_L4PROTO:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->ipv4_l4proto,\n"
			       "					    sizeof(key->ipv4_l4proto), match);\n"
			       "			break;\n"
			       ""))
			return -1;

	/* L4 */

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_L4_PORT_SRC))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_L4_PORT_SRC:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->l4port_src,\n"
			       "					    sizeof(key->l4port_src), match);\n"
			       "			break;\n"
			       ""))
			return -1;
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_L4_PORT_DST))
		if (buf_append(buf, buf_len, ""
			       "		case MATCH_L4_PORT_DST:\n"
			       "			does_match = does_match &&\n"
			       "				check_match(&key->l4port_dst,\n"
			       "					    sizeof(key->l4port_dst), match);\n"
			       "			break;\n"
			       ""))
			return -1;

	if (buf_append(buf, buf_len, ""
		       "		default:\n"
		       "			break;\n"
		       "		}\n"
		       "\n"
		       "		if (!does_match)\n"
		       "			break;\n"
		       "	}\n"
		       "\n"
		       "	if (does_match) {\n"
		       "		*res = get_retval(rule->action_code);\n"
		       "		return 1;\n"
		       "	} else {\n"
		       "		return 0;\n"
		       "	}\n"
		       "}\n"
		       "\n"
		       ""))
		return -1;

	return 0;
}

static int
make_cprog_main(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	size_t i, nb_rules;

	if (buf_append(buf, buf_len, "%s",
		       cprog_prog_starts[prog->options.target]))
		return -1;

	if (buf_append(buf, buf_len, ""
		       "{\n"
		       "	void *data_end = (void *)(long)ctx->data_end;\n"
		       "	void *data = (void *)(long)ctx->data;\n"
		       "	struct filter_key key = {0};\n"
		       "	struct ethhdr *eth = data;\n"
		       "	__u32 eth_proto;\n"
		       "	__u32 nh_off;\n"
		       "	int res;\n"
		       "\n"
		       "	if (extract_key(data, data_end, &key))\n"
		       "		return RET_PASS;\n" // OR ABORT?
		       "\n"
		       ""))
		return -1;

	nb_rules = list_count(prog->filter->rules);

	for (i = 0; i < nb_rules; i++) {
		if (buf_append(buf, buf_len, ""
			       "	if (check_nth_rule(&key, %zd, &res))\n"
			       "		return res;\n"
			       "\n"
			       "", i))
			return -1;
	}

	if (buf_append(buf, buf_len, ""
		       "	return RET_PASS;\n"
		       "}\n"
		       "\n"
		       ""))
		return -1;

	return 0;
}

static void
update_options_from_matchtype(enum match_type match_type,
			      struct kefir_cprog_options *options)
{
	switch (match_type) {
	case KEFIR_MATCH_TYPE_ETHER_SRC:
	case KEFIR_MATCH_TYPE_ETHER_DST:
	case KEFIR_MATCH_TYPE_ETHER_ANY:
	case KEFIR_MATCH_TYPE_ETHER_PROTO:
		options->flags |= OPT_FLAGS_NEED_ETHER;
	default:
		break;
	}

	switch (match_type) {
	case KEFIR_MATCH_TYPE_IP_4_L4PROTO:
	case KEFIR_MATCH_TYPE_IP_4_L4DATA:
		options->flags |= OPT_FLAGS_NEED_L4;
		/* fall through */
	case KEFIR_MATCH_TYPE_IP_4_SRC:
	case KEFIR_MATCH_TYPE_IP_4_DST:
	case KEFIR_MATCH_TYPE_IP_4_ANY:
	case KEFIR_MATCH_TYPE_IP_4_TOS:
	case KEFIR_MATCH_TYPE_IP_4_TTL:
	case KEFIR_MATCH_TYPE_IP_4_FLAGS:
	case KEFIR_MATCH_TYPE_IP_4_SPI:
		options->flags |= OPT_FLAGS_NEED_IPV4;
		break;
	case KEFIR_MATCH_TYPE_IP_6_L4PROTO:
	case KEFIR_MATCH_TYPE_IP_6_L4DATA:
		options->flags |= OPT_FLAGS_NEED_L4;
		/* fall through */
	case KEFIR_MATCH_TYPE_IP_6_SRC:
	case KEFIR_MATCH_TYPE_IP_6_DST:
	case KEFIR_MATCH_TYPE_IP_6_ANY:
	case KEFIR_MATCH_TYPE_IP_6_TOS:
	case KEFIR_MATCH_TYPE_IP_6_TTL:
	case KEFIR_MATCH_TYPE_IP_6_FLAGS:
	case KEFIR_MATCH_TYPE_IP_6_SPI:
		options->flags |= OPT_FLAGS_NEED_IPV6;
		break;
	case KEFIR_MATCH_TYPE_IP_ANY_L4PROTO:
	case KEFIR_MATCH_TYPE_IP_ANY_L4DATA:
		options->flags |= OPT_FLAGS_NEED_L4;
		/* fall through */
	case KEFIR_MATCH_TYPE_IP_ANY_SRC:
	case KEFIR_MATCH_TYPE_IP_ANY_DST:
	case KEFIR_MATCH_TYPE_IP_ANY_ANY:
	case KEFIR_MATCH_TYPE_IP_ANY_TOS:
	case KEFIR_MATCH_TYPE_IP_ANY_TTL:
	case KEFIR_MATCH_TYPE_IP_ANY_FLAGS:
	case KEFIR_MATCH_TYPE_IP_ANY_SPI:
		options->flags |= OPT_FLAGS_NEED_IPV4;
		options->flags |= OPT_FLAGS_NEED_IPV6;
		break;
	default:
		break;
	}

	switch (match_type) {
	case KEFIR_MATCH_TYPE_L4_PORT_SRC:
	case KEFIR_MATCH_TYPE_L4_PORT_DST:
	case KEFIR_MATCH_TYPE_L4_PORT_ANY:
		options->flags |= OPT_FLAGS_NEED_L4;
	default:
		break;
	}
}

/*
 * Should be called as
 * int update_cprog_options(struct kefir_rule *rule_ptr, kefir_cprog *prog)
 */
static int update_cprog_options(void *rule_ptr, va_list ap)
{
	struct kefir_rule *rule = (struct kefir_rule *)rule_ptr;
	kefir_cprog *prog;
	size_t i;

	prog = va_arg(ap, kefir_cprog *);

	for (i = 0; i < KEFIR_MAX_MATCH_PER_RULE &&
	     rule->matches[i].match_type != KEFIR_MATCH_TYPE_UNSPEC; i++) {
		update_options_from_matchtype(rule->matches[i].match_type,
					      &prog->options);

		if (rule->matches[i].flags & MATCH_FLAGS_USE_MASK)
			prog->options.flags |= OPT_FLAGS_USE_MASKS;
	}

	prog->options.nb_matches = max(prog->options.nb_matches, i);

	// FIXME
	/************* for test */
	add_req_helper(prog, BPF_FUNC_map_lookup_elem);
	add_req_helper(prog, BPF_FUNC_trace_printk);
	/************* for test */

	return 0;
}

kefir_cprog *
proggen_make_cprog_from_filter(const kefir_filter *filter,
			       enum kefir_cprog_target target)
{
	kefir_cprog *prog;

	prog = cprog_create();
	if (!prog) {
		err_fail("failed to allocate memory for C prog object");
		return NULL;
	}

	if (!filter || !kefir_sizeof_filter(filter)) {
		err_fail("cannot convert empty filter");
		return NULL;
	}

	prog->options.target = target;

	list_for_each((struct list *)filter->rules,
		      update_cprog_options, prog);

	// TODO: We probably want to copy the filter to avoid bad surprises
	// Needs to move init filter function somewhere accessible from here
	prog->filter = filter;

	return prog;
}

/*
static int load_rule_to_table(void *rule_ptr, va_list ap)
{
	struct kefir_rule *rule = (struct kefir_rule *)rule_ptr;
	unsigned int *index;
	size_t *buf_len;
	char value[256];
	char **buf;

	buf = va_arg(ap, char **);
	buf_len = va_arg(ap, size_t *);
	index = va_arg(ap, unsigned int *);

	if (buf_append(buf, buf_len, ""
		       "bpftool map update id $MAP_ID "
		       "key %d %d %d %d "
		       "value hex  "
		       "",
		       *index & 0xff,
		       (*index >> 8) & 0xff,
		       (*index >> 16) & 0xff,
		       *index >> 24))
		return -1;
	*index += 1;

	sprintf(value,
		"%02x %02x %02x %02x  "
		"%02x %02x %02x %02x  "
		"%02x %02x %02x %02x  "
		"%02x %02x %02x %02x  "
		"%02x %02x %02x %02x  "
		"%02x %02x %02x %02x  "
		"%02x %02x %02x %02x  "
		"00 00 00 00\n", / * padding * /
		rule->match.match_type & 0xff,
		(rule->match.match_type >> 8) & 0xff,
		(rule->match.match_type >> 16) & 0xff,
		rule->match.match_type >> 24,
		rule->match.comp_operator & 0xff,
		(rule->match.comp_operator >> 8) & 0xff,
		(rule->match.comp_operator >> 16) & 0xff,
		rule->match.comp_operator >> 24,
		rule->match.value.data.raw[0],
		rule->match.value.data.raw[1],
		rule->match.value.data.raw[2],
		rule->match.value.data.raw[3],
		rule->match.value.data.raw[4],
		rule->match.value.data.raw[5],
		rule->match.value.data.raw[6],
		rule->match.value.data.raw[7],
		rule->match.value.data.raw[8],
		rule->match.value.data.raw[9],
		rule->match.value.data.raw[10],
		rule->match.value.data.raw[11],
		rule->match.value.data.raw[12],
		rule->match.value.data.raw[13],
		rule->match.value.data.raw[14],
		rule->match.value.data.raw[15],
		rule->action & 0xff,
		(rule->action >> 8) & 0xff,
		(rule->action >> 16) & 0xff,
		rule->action >> 24);

	if (buf_append(buf, buf_len, "%s", value))
		return -1;

	return 0;
}
*/

static int
cprog_fill_table(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	// unsigned int i = 0;
	if (buf_append(buf, buf_len, "\n/******\n"))
		return -1;

	/******/
	size_t rules_buf_len = 1024;
	char rules_buf[rules_buf_len];

	rules_buf[0] = '\0';

	kefir_dump_filter_to_buf(prog->filter, rules_buf, rules_buf_len);

	if (buf_append(buf, buf_len, ""
		       "This BPF program was generated from the following filter:\n"
		       "\n"
		       "%s"
		       "\n"
		       "Load it with the following commands:\n"
		       "\n"
		       "", rules_buf))
		return -1;
	/******/

	if (buf_append(buf, buf_len, ""
		       "IFACE=nfp_p1\n"
		       "ip -force link set dev $IFACE xdpoffload obj /tmp/libkefir_tmp_cprog.o section xdp\n"
		       "\n"
		       "MAP_ID=$(bpftool -jp prog show | jq '.[]|select(.dev.ifname == \"'$IFACE'\")|.map_ids[0]')\n"
		       ""))
		return -1;

	/*
	if (list_for_each(prog->filter->rules, load_rule_to_table,
			  buf, buf_len, &i))
		return -1;
	*/

	if (buf_append(buf, buf_len, "******/\n"))
		return -1;

	return 0;
}

int proggen_cprog_to_buf(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	if (!prog) {
		err_fail("cannot dump empty C prog object");
		return -1;
	}

	/* Deactivate inlining */
	// TODO: add a switch to trigger this
	if (false)
		snprintf(cprog_attr_func_static_inline,
			 sizeof(cprog_attr_func_static_inline), "static ");

	if (buf_append(buf, buf_len, "%s", cprog_header))
		return -1;

	if (make_helpers_decl(prog, buf, buf_len))
		return -1;

	if (make_retval_decl(prog, buf, buf_len))
		return -1;

	if (make_key_decl(prog, buf, buf_len))
		return -1;

	if (make_rule_table_decl(prog, buf, buf_len))
		return -1;

	if (cprog_func_process_l4(prog, buf, buf_len))
		return -1;

	if (cprog_func_process_ipv4(prog, buf, buf_len))
		return -1;

	if (cprog_func_process_ipv6(prog, buf, buf_len))
		return -1;

	if (cprog_func_extract_key(prog, buf, buf_len))
		return -1;

	if (cprog_func_check_rules(prog, buf, buf_len))
		return -1;

	if (make_cprog_main(prog, buf, buf_len))
		return -1;

	if (buf_append(buf, buf_len, "%s", cprog_license))
		return -1;

	//// MOVE THIS
	if (cprog_fill_table(prog, buf, buf_len))
		return -1;

	return 0;
}
