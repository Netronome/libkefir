// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include <linux/bpf.h>

#include "list.h"
#include "libkefir_buffer.h"
#include "libkefir_error.h"
#include "libkefir_dump.h"
#include "libkefir_internals.h"
#include "libkefir_proggen.h"

#define MAX_LABELS_FOR_UNROLL	3

DEFINE_ERR_FUNCTIONS("proggen")

/*
 * Note the use of magic variable names, and the conditional "return -1"
 * embedded in this macro
 */
#define GEN(...)	\
	{ if (buf_append(buf, buf_len, __VA_ARGS__)) return -1; }

#define static_inline_attr(flags)	\
	((flags) & OPT_FLAGS_INLINE_FUNC ? \
	 "static __attribute__((always_inline))\n" : \
	 "static ")

#define trace_printk(flags, ...)	\
	((flags) & OPT_FLAGS_USE_PRINTK ? \
	 "\ttrace_printk(" #__VA_ARGS__ ");\n" : "")

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
	"	__attribute__((section(\".maps.\" #name), used))		\\\n"
	"		____btf_map_##name = { }\n"
	"\n"
	"";

static const char *cprog_license = ""
	"char _license[] __attribute__((section(\"license\"), used)) = \"Dual BSD/GPL\";\n"
	"";

static const char * const cprog_return_values[] = {
	[KEFIR_CPROG_TARGET_XDP] = ""
		"#define RET_PASS XDP_PASS\n"
		"#define RET_DROP XDP_DROP\n"
		"\n",
	[KEFIR_CPROG_TARGET_TC] = ""
		"#define RET_PASS TC_ACT_OK\n"
		"#define RET_DROP TC_ACT_SHOT\n"
		"\n",
};

static const char * const cprog_prog_starts[] = {
	[KEFIR_CPROG_TARGET_XDP] = ""
		"__attribute__((section(\"xdp\"), used))\n"
		"int xdp_main(struct xdp_md *ctx)\n",
	[KEFIR_CPROG_TARGET_TC] = ""
		"__attribute__((section(\"classifier\"), used))\n"
		"int cls_main(struct __sk_buff *ctx)\n",
};

static const char * const cprog_helpers[] = {
	[BPF_FUNC_map_lookup_elem] = ""
		"static void *(*bpf_map_lookup_elem)(void *map, void *key) =\n"
		"	(void *) BPF_FUNC_map_lookup_elem;\n",
	[BPF_FUNC_map_update_elem] = ""
		"static int (*bpf_map_update_elem)(void *map, void *key,\n"
		"				  void *value,\n"
		"				  unsigned long long flags) =\n"
		"	(void *) BPF_FUNC_map_update_elem;\n",
	[BPF_FUNC_map_delete_elem] = ""
		"static int (*bpf_map_delete_elem)(void *map, void *key) =\n"
		"	(void *) BPF_FUNC_map_delete_elem;\n",
	[BPF_FUNC_trace_printk] = ""
		"static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =\n"
		"	(void *) BPF_FUNC_trace_printk;\n"
		"#define trace_printk(fmt, ...)	({			\\\n"
		"	char fmt_array[] = fmt;				\\\n"
		"	bpf_trace_printk(fmt_array, sizeof(fmt_array),	\\\n"
		"			 ##__VA_ARGS__);		\\\n"
		"})\n",
};

static kefir_cprog *cprog_create(void)
{
	kefir_cprog *prog;

	prog = calloc(1, sizeof(*prog));
	return prog;
}

void proggen_cprog_destroy(kefir_cprog *cprog)
{
	if (cprog->options.flags & OPT_FLAGS_CLONE_FILTER)
		kefir_filter_destroy((kefir_filter *)cprog->filter);

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
			GEN("%s", cprog_helpers[i]);

	GEN("\n");
	return 0;
}

static int
make_retval_decl(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	GEN("%s", cprog_return_values[prog->options.target]);
	return 0;
}

/*
 * Variadic list should contain:
 *     enum kefir_match_type type
 */
static int rule_has_matchtype(void *rule_ptr, va_list ap)
{
	struct kefir_rule *rule = (struct kefir_rule *)rule_ptr;
	enum kefir_match_type type;
	bool found = false;
	size_t i;

	type = va_arg(ap, enum kefir_match_type);
	for (i = 0; i < KEFIR_MAX_MATCH_PER_RULE &&
	     rule->matches[i].match_type != KEFIR_MATCH_TYPE_UNSPEC; i++) {
		found = type == rule->matches[i].match_type;
		if (found)
			break;
	}

	return found;
}

static bool
filter_has_matchtype(const kefir_filter *filter, enum kefir_match_type type)
{
	return !!list_for_each((struct list *)filter->rules, rule_has_matchtype,
			       type);
}

/*
 * Variadic list should contain:
 *     enum comp_operator op
 *     int expect_op
 */
static int rule_has_comp_operator(void *rule_ptr, va_list ap)
{
	struct kefir_rule *rule = (struct kefir_rule *)rule_ptr;
	enum kefir_comp_operator op;
	bool found = false;
	int expect_op; /* bool, but va_arg promotes bools to ints */
	size_t i;

	op = va_arg(ap, enum kefir_comp_operator);
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
filter_has_comp_oper(const kefir_filter *filter, enum kefir_comp_operator op)
{
	return list_for_each((struct list *)filter->rules,
			     rule_has_comp_operator, op, 1);
}

static bool
filter_all_comp_equal(const kefir_filter *filter)
{
	return !list_for_each((struct list *)filter->rules,
			      rule_has_comp_operator, KEFIR_OPER_EQUAL, 0);
}

static unsigned int filter_diff_matchtypes(const kefir_filter *filter)
{
	enum kefir_match_type i;
	unsigned int res = 0;

	for (i = KEFIR_MATCH_TYPE_UNSPEC + 1; i < __KEFIR_MAX_MATCH_TYPE; i++)
		if (filter_has_matchtype(filter, i))
			res++;

	return res;
}

static int
make_key_decl(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	const kefir_filter *filter = prog->filter;

	GEN("struct filter_key {\n");

	/* Ether */

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_ETHER_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_ETHER_ANY))
		GEN("	uint8_t		ether_src[6];\n");
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_ETHER_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_ETHER_ANY))
		GEN("	uint8_t		ether_dst[6];\n");
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_ETHER_PROTO))
		GEN("	uint16_t	ether_proto;\n");

	/* IPv4 */

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_ANY))
		GEN("	uint32_t	ipv4_src;\n");
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_ANY))
		GEN("	uint32_t	ipv4_dst;\n");
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_TOS) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_TOS))
		GEN("	uint8_t		ipv4_tos;\n");
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_TTL) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_TTL))
		GEN("	uint8_t		ipv4_ttl;\n");

	/* IPv6 */

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_ANY))
		GEN(""
		    "	union {\n"
		    "		uint8_t		u8[16];\n"
		    "		uint32_t	u32[4];\n"
		    "		uint64_t	u64[2];\n"
		    "	} ipv6_src;\n"
		    "");
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_ANY))
		GEN(""
		    "	union {\n"
		    "		uint8_t		u8[16];\n"
		    "		uint32_t	u32[4];\n"
		    "		uint64_t	u64[2];\n"
		    "	} ipv6_dst;\n"
		    "");
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_TOS) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_TOS))
		GEN("	uint8_t		ipv6_tclass;\n");
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_TTL) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_TTL))
		GEN("	uint8_t		ipv6_ttl;\n");

	/* L4 */

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PROTO) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PROTO) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4PROTO))
		GEN("	uint16_t	l4proto;\n");
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4DATA) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4DATA) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4DATA))
		GEN("	uint32_t	l4data;\n");

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PORT_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PORT_SRC))
		GEN("	uint16_t	l4port_src;\n");
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PORT_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PORT_DST))
		GEN("	uint16_t	l4port_dst;\n");

	/* VLAN */

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_VLAN_ID) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_CVLAN_ID) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_SVLAN_ID))
		GEN("	uint16_t	vlan_id[2];\n");
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_VLAN_PRIO) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_CVLAN_PRIO) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_SVLAN_PRIO))
		GEN("	uint8_t		vlan_prio[2];\n");
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_VLAN_ETHERTYPE) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_CVLAN_ETHERTYPE) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_SVLAN_ETHERTYPE))
		GEN("	uint16_t	vlan_etype[2];\n");

	GEN("};\n\n");

	return 0;
}

static int
make_rule_table_decl(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	const kefir_filter *filter = prog->filter;

	GEN("enum match_type {\n");

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_ETHER_SRC))
		GEN("	MATCH_ETHER_SRC		= %d,\n",
		    KEFIR_MATCH_TYPE_ETHER_SRC);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_ETHER_DST))
		GEN("	MATCH_ETHER_DST		= %d,\n",
		    KEFIR_MATCH_TYPE_ETHER_DST);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_ETHER_ANY))
		GEN("	MATCH_ETHER_ANY		= %d,\n",
		    KEFIR_MATCH_TYPE_ETHER_ANY);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_ETHER_PROTO))
		GEN("	MATCH_ETHER_PROTO	= %d,\n",
		    KEFIR_MATCH_TYPE_ETHER_PROTO);

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_SRC))
		GEN("	MATCH_IPV4_SRC		= %d,\n",
		    KEFIR_MATCH_TYPE_IP_4_SRC);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_DST))
		GEN("	MATCH_IPV4_DST		= %d,\n",
		    KEFIR_MATCH_TYPE_IP_4_DST);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_ANY))
		GEN("	MATCH_IPV4_ANY		= %d,\n",
		    KEFIR_MATCH_TYPE_IP_4_ANY);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_TOS))
		GEN("	MATCH_IPV4_TOS		= %d,\n",
		    KEFIR_MATCH_TYPE_IP_4_TOS);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_TTL))
		GEN("	MATCH_IPV4_TTL		= %d,\n",
		    KEFIR_MATCH_TYPE_IP_4_TTL);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PROTO))
		GEN("	MATCH_IPV4_L4PROTO	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_4_L4PROTO);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4DATA))
		GEN("	MATCH_IPV4_L4DATA	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_4_L4DATA);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PORT_SRC))
		GEN("	MATCH_IPV4_L4PORT_SRC	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_4_L4PORT_SRC);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PORT_DST))
		GEN("	MATCH_IPV4_L4PORT_DST	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_4_L4PORT_DST);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PORT_ANY))
		GEN("	MATCH_IPV4_L4PORT_ANY	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_4_L4PORT_ANY);

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_SRC))
		GEN("	MATCH_IPV6_SRC		= %d,\n",
		    KEFIR_MATCH_TYPE_IP_6_SRC);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_DST))
		GEN("	MATCH_IPV6_DST		= %d,\n",
		    KEFIR_MATCH_TYPE_IP_6_DST);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_ANY))
		GEN("	MATCH_IPV6_ANY		= %d,\n",
		    KEFIR_MATCH_TYPE_IP_6_ANY);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_TOS))
		GEN("	MATCH_IPV6_TCLASS	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_6_TOS);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_TTL))
		GEN("	MATCH_IPV6_TTL		= %d,\n",
		    KEFIR_MATCH_TYPE_IP_6_TTL);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PROTO))
		GEN("	MATCH_IPV6_L4PROTO	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_6_L4PROTO);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4DATA))
		GEN("	MATCH_IPV6_L4DATA	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_6_L4DATA);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PORT_SRC))
		GEN("	MATCH_IPV6_L4PORT_SRC	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_6_L4PORT_SRC);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PORT_DST))
		GEN("	MATCH_IPV6_L4PORT_DST	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_6_L4PORT_DST);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PORT_ANY))
		GEN("	MATCH_IPV6_L4PORT_ANY	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_6_L4PORT_ANY);

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_SRC))
		GEN("	MATCH_IP_ANY_SRC	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_ANY_SRC);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_DST))
		GEN("	MATCH_IP_ANY_DST	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_ANY_DST);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_ANY))
		GEN("	MATCH_IP_ANY_ANY	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_ANY_ANY);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_TOS))
		GEN("	MATCH_IP_ANY_TOS	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_ANY_TOS);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_TTL))
		GEN("	MATCH_IP_ANY_TTL	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_ANY_TTL);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4PROTO))
		GEN("	MATCH_IP_ANY_L4PROTO	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_ANY_L4PROTO);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4DATA))
		GEN("	MATCH_IP_ANY_L4DATA	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_ANY_L4DATA);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4PORT_SRC))
		GEN("	MATCH_IP_ANY_L4PORT_SRC	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_ANY_L4PORT_SRC);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4PORT_DST))
		GEN("	MATCH_IP_ANY_L4PORT_DST	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_ANY_L4PORT_DST);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4PORT_ANY))
		GEN("	MATCH_IP_ANY_L4PORT_ANY	= %d,\n",
		    KEFIR_MATCH_TYPE_IP_ANY_L4PORT_ANY);

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_VLAN_ID))
		GEN("	MATCH_VLAN_ID		= %d,\n",
		    KEFIR_MATCH_TYPE_VLAN_ID);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_VLAN_PRIO))
		GEN("	MATCH_VLAN_PRIO		= %d,\n",
		    KEFIR_MATCH_TYPE_VLAN_PRIO);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_VLAN_ETHERTYPE))
		GEN("	MATCH_VLAN_ETHERTYPE	= %d,\n",
		    KEFIR_MATCH_TYPE_VLAN_ETHERTYPE);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_CVLAN_ID))
		GEN("	MATCH_CVLAN_ID		= %d,\n",
		    KEFIR_MATCH_TYPE_CVLAN_ID);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_CVLAN_PRIO))
		GEN("	MATCH_CVLAN_PRIO	= %d,\n",
		    KEFIR_MATCH_TYPE_CVLAN_PRIO);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_CVLAN_ETHERTYPE))
		GEN("	MATCH_CVLAN_ETHERTYPE	= %d,\n",
		    KEFIR_MATCH_TYPE_CVLAN_ETHERTYPE);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_SVLAN_ID))
		GEN("	MATCH_SVLAN_ID		= %d,\n",
		    KEFIR_MATCH_TYPE_SVLAN_ID);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_SVLAN_PRIO))
		GEN("	MATCH_SVLAN_PRIO	= %d,\n",
		    KEFIR_MATCH_TYPE_SVLAN_PRIO);
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_SVLAN_ETHERTYPE))
		GEN("	MATCH_SVLAN_ETHERTYPE	= %d,\n",
		    KEFIR_MATCH_TYPE_SVLAN_ETHERTYPE);

	GEN(""
	    "};\n"
	    "\n"
	    "enum comp_operator {\n"
	    "	OPER_EQUAL	= %d,\n"
	    "", KEFIR_OPER_EQUAL);

	if (filter_has_comp_oper(filter, KEFIR_OPER_LT))
		GEN("	OPER_LT		= %d,\n", KEFIR_OPER_LT);
	if (filter_has_comp_oper(filter, KEFIR_OPER_LEQ))
		GEN("	OPER_LEQ	= %d,\n", KEFIR_OPER_LEQ);
	if (filter_has_comp_oper(filter, KEFIR_OPER_GT))
		GEN("	OPER_GT		= %d,\n", KEFIR_OPER_GT);
	if (filter_has_comp_oper(filter, KEFIR_OPER_GEQ))
		GEN("	OPER_GEQ	= %d,\n", KEFIR_OPER_GEQ);

	GEN(""
	    "};\n"
	    "\n"
	    "enum action_code {\n"
	    "	ACTION_CODE_DROP	= %d,\n"
	    "	ACTION_CODE_PASS	= %d,\n"
	    "};\n"
	    "\n"
	    "", KEFIR_ACTION_CODE_DROP, KEFIR_ACTION_CODE_PASS);

	if (prog->options.flags & OPT_FLAGS_USE_MASKS)
		GEN(""
		    "#define MATCH_FLAGS_USE_MASK	%d\n"
		    "\n"
		    "", MATCH_FLAGS_USE_MASK);

	/*
	 * Note that struct filter_rule must be identically defined in
	 * libkefir_compile.c
	 */
	GEN(""
	    "struct rule_match {\n"
	    "	enum match_type		match_type;\n"
	    "	enum comp_operator	comp_operator;\n"
	    "	__u64			value[2];\n"
	    "");

	if (prog->options.flags & OPT_FLAGS_USE_MASKS)
		GEN(""
		    "	__u64	flags;\n"
		    "	__u64	mask[2];\n"
		    "");

	GEN(""
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
	    "", prog->options.nb_matches, list_count(prog->filter->rules));

	return 0;
}

static int
cprog_func_process_l4(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	const kefir_filter *filter = prog->filter;

	if (!(prog->options.flags & OPT_FLAGS_NEED_L4))
		return 0;

	GEN(""
	    "%sint process_l4(void *data, void *data_end, __u32 l4_off, struct filter_key *key)\n"
	    "{\n"
	    "	struct tcphdr *tcph = data + l4_off;\n"
	    "\n"
	    "", static_inline_attr(prog->options.flags));

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4DATA) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4DATA) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4DATA))
		GEN(""
		    "	if ((void *)tcph + 4 > data_end)\n"
		    "		return -1;\n"
		    "\n"
		    "	key->l4data = *(uint32_t *)tcph;\n"
		    "");

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PORT_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PORT_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PORT_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PORT_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4PORT_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4PORT_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PORT_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PORT_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PORT_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PORT_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4PORT_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4PORT_ANY))
		GEN(""
		    "	if ((void *)(tcph + 1) > data_end)\n"
		    "		return -1;\n"
		    "\n"
		    "");

	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PORT_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PORT_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PORT_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PORT_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4PORT_SRC) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4PORT_ANY))
		GEN("	key->l4port_src = tcph->source;\n");
	if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PORT_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PORT_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PORT_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PORT_ANY) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4PORT_DST) ||
	    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_L4PORT_ANY))
		GEN("	key->l4port_dst = tcph->dest;\n");

	GEN(""
	    "\n"
	    "	return 0;\n"
	    "}\n"
	    "\n"
	    "");

	return 0;
}

static int
cprog_func_process_ipv4(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	if (!(prog->options.flags & OPT_FLAGS_NEED_IPV4))
		return 0;

	GEN(""
	    "%sint process_ipv4(void *data, void *data_end, uint8_t nh_off,\n"
	    "		 struct filter_key *key)\n"
	    "{\n"
	    "	struct iphdr *iph = data + nh_off;\n"
	    "\n"
	    "%s"
	    "	if ((void *)(iph + 1) > data_end)\n"
	    "		return -1;\n"
	    "	if ((void *)iph + 4 * iph->ihl > data_end)\n"
	    "		return -1;\n"
	    "\n"
	    "", static_inline_attr(prog->options.flags),
	    trace_printk(prog->options.flags, "process IPv4 header\n"));

	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_4_SRC) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_4_ANY) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_SRC) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_ANY))
		GEN("	key->ipv4_src = iph->saddr;\n");
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_4_DST) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_4_ANY) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_DST) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_ANY))
		GEN("	key->ipv4_dst = iph->daddr;\n");
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_4_L4PROTO) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_L4PROTO))
		GEN("	key->l4proto = iph->protocol;\n");
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_4_TOS) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_TOS))
		GEN("	key->ipv4_tos = iph->tos;\n");
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_4_TTL) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_TTL))
		GEN("	key->ipv4_ttl = iph->ttl;\n");

	if (prog->options.flags & OPT_FLAGS_NEED_L4)
		GEN(""
		    "\n"
		    "	if (process_l4(data, data_end, nh_off + 4 * iph->ihl, key))\n"
		    "		return -1;\n"
		    "");

	GEN(""
	    "\n"
	    "	return 0;\n"
	    "}\n"
	    "\n"
	    "");

	return 0;
}

static int
cprog_func_process_ipv6(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	if (!(prog->options.flags & OPT_FLAGS_NEED_IPV6))
		return 0;

	GEN(""
	    "%sint process_ipv6(void *data, void *data_end, uint8_t nh_off,\n"
	    "		 struct filter_key *key)\n"
	    "{\n"
	    "	struct ipv6hdr *ip6h = data + nh_off;\n"
	    "\n"
	    "%s"
	    "	if ((void *)(ip6h + 1) > data_end)\n"
	    "		return -1;\n"
	    "\n"
	    "", static_inline_attr(prog->options.flags),
	    trace_printk(prog->options.flags, "process IPv6 header\n"));

	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_6_SRC) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_6_ANY) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_SRC) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_ANY))
		GEN(""
		    "	key->ipv6_src.u32[0] = ip6h->saddr.in6_u.u6_addr32[0];\n"
		    "	key->ipv6_src.u32[1] = ip6h->saddr.in6_u.u6_addr32[1];\n"
		    "	key->ipv6_src.u32[2] = ip6h->saddr.in6_u.u6_addr32[2];\n"
		    "	key->ipv6_src.u32[3] = ip6h->saddr.in6_u.u6_addr32[3];\n"
		    "");
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_6_DST) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_6_ANY) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_DST) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_ANY))
		GEN(""
		    "	key->ipv6_dst.u32[0] = ip6h->daddr.in6_u.u6_addr32[0];\n"
		    "	key->ipv6_dst.u32[1] = ip6h->daddr.in6_u.u6_addr32[1];\n"
		    "	key->ipv6_dst.u32[2] = ip6h->daddr.in6_u.u6_addr32[2];\n"
		    "	key->ipv6_dst.u32[3] = ip6h->daddr.in6_u.u6_addr32[3];\n"
		    "");
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_6_L4PROTO) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_L4PROTO))
		GEN(""
		    "	/* Extension headers not supported for now */\n"
		    "	key->l4proto = ip6h->nexthdr;\n"
		    "");
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_6_TOS) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_TOS))
		GEN("	key->ipv6_tclass = (ip6h->priority << 4) + (ip6h->flow_lbl[0] >> 4);\n");
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_6_TTL) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_IP_ANY_TTL))
		GEN("	key->ipv6_ttl = ip6h->hop_limit;\n");

	if (prog->options.flags & OPT_FLAGS_NEED_L4)
		GEN(""
		    "\n"
		    "	if (process_l4(data, data_end, nh_off + sizeof(struct ipv6hdr), key))\n"
		    "		return -1;\n"
		    "");

	GEN(""
	    "\n"
	    "	return 0;\n"
	    "}\n"
	    "\n"
	    "");

	return 0;
}

static int
cprog_func_process_ether(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	if (!(prog->options.flags & OPT_FLAGS_NEED_ETHER))
		return 0;

	GEN(""
	    "%sint process_ether(void *data, void *data_end, struct filter_key *key)\n"
	    "{\n"
	    "	struct ethhdr *eth = data;\n"
	    "\n"
	    "%s"
	    "", static_inline_attr(prog->options.flags),
	    trace_printk(prog->options.flags, "process L2 header\n"));

	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_ETHER_SRC) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_ETHER_ANY))
		GEN("	memcpy(&key->ether_src, eth->h_source, sizeof(eth->h_source));\n");
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_ETHER_DST) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_ETHER_ANY))
		GEN("	memcpy(&key->ether_dst, eth->h_dest, sizeof(eth->h_dest));\n");

	GEN(""
	    "\n"
	    "	return 0;\n"
	    "}\n"
	    "\n"
	    "");

	return 0;
}

static int
cprog_func_extract_key(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	bool need_ether = prog->options.flags & OPT_FLAGS_NEED_ETHER;
	bool need_ipv4 = prog->options.flags & OPT_FLAGS_NEED_IPV4;
	bool need_ipv6 = prog->options.flags & OPT_FLAGS_NEED_IPV6;

	GEN(""
	    "%sint extract_key(void *data, void *data_end, struct filter_key *key,\n"
	    "		__u16 *eth_proto)\n"
	    "{\n"
	    "	struct ethhdr *eth = data;\n"
	    "	unsigned int i;\n"
	    "	uint8_t nh_off;\n"
	    "\n"
	    "	nh_off = sizeof(struct ethhdr);\n"
	    "	if (data + nh_off > data_end)\n"
	    "		return -1;\n"
	    "	*eth_proto = bpf_ntohs(eth->h_proto);\n"
	    "\n"
	    "", static_inline_attr(prog->options.flags));

	if (!(prog->options.flags & OPT_FLAGS_NO_VLAN)) {
		GEN(""
		    "#pragma clang loop unroll(full)\n"
		    "	for (i = 0; i < 2; i++) {\n"
		    "		if (*eth_proto == ETH_P_8021Q || *eth_proto == ETH_P_8021AD) {\n"
		    "			void *vlan_hdr;\n"
		    "\n"
		    "			vlan_hdr = data + nh_off;\n"
		    "			nh_off += 4;\n"
		    "			if (data + nh_off > data_end)\n"
		    "				return -1;\n"
		    "			*eth_proto = *(uint16_t *)(data + nh_off - 2);\n"
		    "			*eth_proto = bpf_ntohs(*eth_proto);\n"
		    "");
	}

	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_VLAN_ID) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_CVLAN_ID) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_SVLAN_ID))
		GEN("			key->vlan_id[i] = *(uint16_t *)(vlan_hdr);\n");
	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_VLAN_PRIO) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_CVLAN_PRIO) ||
	    filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_SVLAN_PRIO))
		GEN("			key->vlan_prio[i] = (*(uint8_t *)(vlan_hdr + 1) & 0xe0) >> 5;\n");
	if (filter_has_matchtype(prog->filter,
				 KEFIR_MATCH_TYPE_VLAN_ETHERTYPE) ||
	    filter_has_matchtype(prog->filter,
				 KEFIR_MATCH_TYPE_CVLAN_ETHERTYPE) ||
	    filter_has_matchtype(prog->filter,
				 KEFIR_MATCH_TYPE_SVLAN_ETHERTYPE))
		GEN("			key->vlan_etype[i] = *(uint16_t *)(vlan_hdr + 2);\n");

	if (!(prog->options.flags & OPT_FLAGS_NO_VLAN)) {
		GEN(""
		    "		}\n"
		    "	}\n"
		    "\n"
		    "");
	}

	if (filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_ETHER_PROTO))
		GEN("	key->ether_proto = *(uint16_t *)(data + nh_off - 2);\n");

	if (need_ether)
		GEN(""
		    "	if (process_ether(data, data_end, key))\n"
		    "		return 0;\n"
		    "\n"
		    "");

	if (need_ipv4 || need_ipv6) {
		GEN("	switch (*eth_proto) {\n");

		if (need_ipv4)
			GEN(""
			    "	case ETH_P_IP:\n"
			    "		if (process_ipv4(data, data_end, nh_off, key))\n"
			    "			return 0;\n"
			    "		break;\n"
			    "");

		if (need_ipv6)
			GEN(""
			    "	case ETH_P_IPV6:\n"
			    "		if (process_ipv6(data, data_end, nh_off, key))\n"
			    "			return 0;\n"
			    "		break;\n"
			    "");

		GEN(""
		    "	default:\n"
		    "		return 0;\n"
		    "	}\n"
		    "\n"
		    "");
	}

	GEN(""
	    "	return 0;\n"
	    "}\n"
	    "\n"
	    "");

	return 0;
}

static int
cprog_func_check_rules(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	bool use_masks = prog->options.flags & OPT_FLAGS_USE_MASKS;
	bool only_equal = filter_all_comp_equal(prog->filter);
	const kefir_filter *filter = prog->filter;
	size_t loop_cnt, loop_max = 1;
	bool manual_unroll = false;
	char indent[] = "\t";

	GEN(""
	    "%sbool check_match(void *matchval, size_t matchlen, struct rule_match *match)\n"
	    "{\n"
	    "	uint64_t copy[2] = {0};\n"
	    "	size_t i;\n"
	    "\n"
	    "	memcpy(copy, matchval, matchlen);\n"
	    "\n"
	    "%s"
	    "%s"
	    "", static_inline_attr(prog->options.flags),
	    trace_printk(prog->options.flags, "collected value: %x %x\n",
			 copy[0], copy[1]),
	    trace_printk(prog->options.flags, "compared with:   %x %x\n",
			 match->value[0], match->value[1]));

	if (use_masks)
		GEN(""
		    "#pragma clang loop unroll(full)\n"
		    "	for (i = 0; i < 2; i++)\n"
		    "		copy[i] &= (match->flags * MATCH_FLAGS_USE_MASK) ?\n"
		    "			match->mask[i] : 0xffffffffffffffff;\n"
		    "\n"
		    "");

	GEN(""
	    "\n"
	    "	if (match->comp_operator == OPER_EQUAL) {\n"
	    "		if (copy[0] != match->value[0])\n"
	    "			return false;\n"
	    "		if (matchlen > sizeof(__u64) &&\n"
	    "		    copy[1] != match->value[1])\n"
	    "			return false;\n"
	    "		return true;\n"
	    "	}\n"
	    "\n"
	    "");
	if (!only_equal) {
		GEN("	switch (match->comp_operator) {\n");
		if (filter_has_comp_oper(prog->filter, KEFIR_OPER_LT))
			GEN(""
			    "	case OPER_LT:\n"
			    "		return copy[0] < match->value[0] ||\n"
			    "			(copy[0] == match->value[0] &&\n"
			    "			 copy[1] < copy[1]);\n"
			    "");
		if (filter_has_comp_oper(prog->filter, KEFIR_OPER_LEQ))
			GEN(""
			    "	case OPER_LEQ:\n"
			    "		return copy[0] < match->value[0] ||\n"
			    "			(copy[0] == match->value[0] &&\n"
			    "			 copy[1] <= copy[1]);\n"
			    "");
		if (filter_has_comp_oper(prog->filter, KEFIR_OPER_GT))
			GEN(""
			    "	case OPER_GT:\n"
			    "		return copy[0] > match->value[0] ||\n"
			    "			(copy[0] == match->value[0] &&\n"
			    "			 copy[1] > copy[1]);\n"
			    "");
		if (filter_has_comp_oper(prog->filter, KEFIR_OPER_GEQ))
			GEN(""
			    "	case OPER_GEQ:\n"
			    "		return copy[0] > match->value[0] ||\n"
			    "			(copy[0] == match->value[0] &&\n"
			    "			 copy[1] >= copy[1]);\n"
			    "");
		GEN(""
		    "	default:\n"
		    "		return false;\n"
		    "	}\n"
		    "\n"
		    "");
	}
	/* Default action: let packet pass. TODO: Provide a way to change it? */
	GEN(""
	    "	return false;\n"
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
	    "		return RET_PASS;\n"
	    "	}\n"
	    "}\n"
	    "\n"
	    "%sint check_nth_rule(struct filter_key *key, int n, __u16 *eth_proto, int *res)\n"
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
	    "", static_inline_attr(prog->options.flags),
	    static_inline_attr(prog->options.flags));

	/*
	 * Clang fails to unroll the loops if the switch contains 10 labels or
	 * more. In such case, we must manually unroll the loop when generating
	 * the program. Ugh.
	 */
	if (filter_diff_matchtypes(prog->filter) >= MAX_LABELS_FOR_UNROLL ||
	    prog->options.flags & OPT_FLAGS_USE_PRINTK) {
		manual_unroll = true;
		loop_max = prog->options.nb_matches;
		indent[0] = '\0';
	}

	for (loop_cnt = 0; loop_cnt < loop_max; loop_cnt++) {
		if (manual_unroll) {
			/* Unroll loop */
			GEN(""
			    "	match = &rule->matches[%zd];\n"
			    "\n"
			    "", loop_cnt);
		} else {
			/*
			 * Ask clang to unroll the loop for us. Same result,
			 * but C code is much more readable.
			 */
			GEN(""
			    "#pragma clang loop unroll(full)\n"
			    "	for (i = 0; i < %d; i++) {\n"
			    "		match = &rule->matches[i];\n"
			    "\n"
			    "", prog->options.nb_matches);
		}

		GEN("%s	switch (match->match_type) {\n",
		    indent);

		/* Ether */

		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_ETHER_SRC))
			GEN(""
			    "%s	case MATCH_ETHER_SRC:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->ether_src,\n"
			    "%s				    sizeof(key->ether_src), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_ETHER_DST))
			GEN(""
			    "%s	case MATCH_ETHER_DST:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->ether_dst,\n"
			    "%s				    sizeof(key->ether_dst), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_ETHER_ANY))
			GEN(""
			    "%s	case MATCH_ETHER_ANY:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(check_match(&key->ether_src,\n"
			    "%s				     sizeof(key->ether_src), match) ||\n"
			    "%s			 check_match(&key->ether_dst,\n"
			    "%s				     sizeof(key->ether_dst), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent,
			    indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_ETHER_PROTO))
			GEN(""
			    "%s	case MATCH_ETHER_PROTO:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->ether_proto,\n"
			    "%s				    sizeof(key->ether_proto), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);

		/* IPv4 */

		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_SRC))
			GEN(""
			    "%s	case MATCH_IPV4_SRC:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->ipv4_src,\n"
			    "%s				    sizeof(key->ipv4_src), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_DST))
			GEN(""
			    "%s	case MATCH_IPV4_DST:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->ipv4_dst,\n"
			    "%s				    sizeof(key->ipv4_dst), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_ANY))
			GEN(""
			    "%s	case MATCH_IPV4_ANY:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(check_match(&key->ipv4_src,\n"
			    "%s				    sizeof(key->ipv4_src), match) ||\n"
			    "%s			 check_match(&key->ipv4_dst,\n"
			    "%s				    sizeof(key->ipv4_dst), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent,
			    indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_TOS))
			GEN(""
			    "%s	case MATCH_IPV4_TOS:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->ipv4_tos,\n"
			    "%s				    sizeof(key->ipv4_tos), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_TTL))
			GEN(""
			    "%s	case MATCH_IPV4_TTL:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->ipv4_ttl,\n"
			    "%s				    sizeof(key->ipv4_ttl), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4PROTO))
			GEN(""
			    "%s	case MATCH_IPV4_L4PROTO:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(*eth_proto == ETH_P_IP) &&\n"
			    "%s			check_match(&key->l4proto,\n"
			    "%s				    sizeof(key->l4proto), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_4_L4DATA))
			GEN(""
			    "%s	case MATCH_IPV4_L4DATA:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(*eth_proto == ETH_P_IP) &&\n"
			    "%s			check_match(&key->l4data,\n"
			    "%s				    sizeof(key->l4data), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter,
					 KEFIR_MATCH_TYPE_IP_4_L4PORT_SRC))
			GEN(""
			    "%s	case MATCH_IPV4_L4PORT_SRC:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(*eth_proto == ETH_P_IP) &&\n"
			    "%s			check_match(&key->l4port_src,\n"
			    "%s				    sizeof(key->l4port_src), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter,
					 KEFIR_MATCH_TYPE_IP_4_L4PORT_DST))
			GEN(""
			    "%s	case MATCH_IPV4_L4PORT_DST:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(*eth_proto == ETH_P_IP) &&\n"
			    "%s			check_match(&key->l4port_dst,\n"
			    "%s				    sizeof(key->l4port_dst), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter,
					 KEFIR_MATCH_TYPE_IP_4_L4PORT_ANY))
			GEN(""
			    "%s	case MATCH_IPV4_L4PORT_ANY:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(*eth_proto == ETH_P_IP) &&\n"
			    "%s			(check_match(&key->l4port_src,\n"
			    "%s				    sizeof(key->l4port_src), match) ||\n"
			    "%s			 check_match(&key->l4port_dst,\n"
			    "%s				    sizeof(key->l4port_dst), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent,
			    indent, indent);

		/* IPv6 */

		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_SRC) ||
		    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_ANY))
			GEN(""
			    "%s	case MATCH_IPV6_SRC:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->ipv6_src,\n"
			    "%s				    sizeof(key->ipv6_src), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_DST) ||
		    filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_ANY))
			GEN(""
			    "%s	case MATCH_IPV6_DST:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->ipv6_dst,\n"
			    "%s				    sizeof(key->ipv6_dst), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_ANY))
			GEN(""
			    "%s	case MATCH_IPV6_ANY:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(check_match(&key->ipv6_src,\n"
			    "%s				    sizeof(key->ipv6_src), match) ||\n"
			    "%s			 check_match(&key->ipv6_dst,\n"
			    "%s				    sizeof(key->ipv6_dst), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent,
			    indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_TOS))
			GEN(""
			    "%s	case MATCH_IPV6_TCLASS:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->ipv6_tclass,\n"
			    "%s				    sizeof(key->ipv6_tclass), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_TTL))
			GEN(""
			    "%s	case MATCH_IPV6_TTL:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->ipv6_ttl,\n"
			    "%s				    sizeof(key->ipv6_ttl), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4PROTO))
			GEN(""
			    "%s	case MATCH_IPV6_L4PROTO:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(*eth_proto == ETH_P_IPV6) &&\n"
			    "%s			check_match(&key->l4proto,\n"
			    "%s				    sizeof(key->l4proto), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_6_L4DATA))
			GEN(""
			    "%s	case MATCH_IPV6_L4DATA:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(*eth_proto == ETH_P_IPV6) &&\n"
			    "%s			check_match(&key->l4data,\n"
			    "%s				    sizeof(key->l4data), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter,
					 KEFIR_MATCH_TYPE_IP_6_L4PORT_SRC))
			GEN(""
			    "%s	case MATCH_IPV6_L4PORT_SRC:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(*eth_proto == ETH_P_IPV6) &&\n"
			    "%s			check_match(&key->l4port_src,\n"
			    "%s				    sizeof(key->l4port_src), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter,
					 KEFIR_MATCH_TYPE_IP_6_L4PORT_DST))
			GEN(""
			    "%s	case MATCH_IPV6_L4PORT_DST:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(*eth_proto == ETH_P_IPV6) &&\n"
			    "%s			check_match(&key->l4port_dst,\n"
			    "%s				    sizeof(key->l4port_dst), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter,
					 KEFIR_MATCH_TYPE_IP_6_L4PORT_ANY))
			GEN(""
			    "%s	case MATCH_IPV6_L4PORT_ANY:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(*eth_proto == ETH_P_IPV6) &&\n"
			    "%s			(check_match(&key->l4port_src,\n"
			    "%s				    sizeof(key->l4port_src), match) ||\n"
			    "%s			 check_match(&key->l4port_dst,\n"
			    "%s				    sizeof(key->l4port_dst), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent,
			    indent, indent);

		/* IPv4 or IPv6 */

		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_SRC))
			GEN(""
			    "%s	case MATCH_IP_ANY_SRC:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(check_match(&key->ipv4_src,\n"
			    "%s				    sizeof(key->ipv4_src), match) ||\n"
			    "%s			 check_match(&key->ipv6_src,\n"
			    "%s				    sizeof(key->ipv6_src), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent,
			    indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_DST))
			GEN(""
			    "%s	case MATCH_IP_ANY_DST:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(check_match(&key->ipv4_dst,\n"
			    "%s				    sizeof(key->ipv4_dst), match) ||\n"
			    "%s			 check_match(&key->ipv6_dst,\n"
			    "%s				    sizeof(key->ipv6_dst), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent,
			    indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_ANY))
			GEN(""
			    "%s	case MATCH_IP_ANY_ANY:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(check_match(&key->ipv4_src,\n"
			    "%s				    sizeof(key->ipv4_src), match) ||\n"
			    "%s			 check_match(&key->ipv4_dst,\n"
			    "%s				    sizeof(key->ipv4_dst), match) ||\n"
			    "%s			 check_match(&key->ipv6_src,\n"
			    "%s				    sizeof(key->ipv6_src), match) ||\n"
			    "%s			 check_match(&key->ipv6_dst,\n"
			    "%s				    sizeof(key->ipv6_dst), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent,
			    indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_TOS))
			GEN(""
			    "%s	case MATCH_IP_ANY_TOS:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(check_match(&key->ipv4_tos,\n"
			    "%s				    sizeof(key->ipv4_tos), match) ||\n"
			    "%s			 check_match(&key->ipv6_tclass,\n"
			    "%s				    sizeof(key->ipv6_tclass), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent,
			    indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_IP_ANY_TTL))
			GEN(""
			    "%s	case MATCH_IP_ANY_TTL:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(check_match(&key->ipv4_ttl,\n"
			    "%s				    sizeof(key->ipv4_ttl), match) ||\n"
			    "%s			 check_match(&key->ipv6_ttl,\n"
			    "%s				    sizeof(key->ipv6_ttl), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent,
			    indent);
		if (filter_has_matchtype(filter,
					 KEFIR_MATCH_TYPE_IP_ANY_L4PROTO))
			GEN(""
			    "%s	case MATCH_IP_ANY_L4PROTO:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(check_match(&key->l4proto,\n"
			    "%s				    sizeof(key->l4proto), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter,
					 KEFIR_MATCH_TYPE_IP_ANY_L4DATA))
			GEN(""
			    "%s	case MATCH_IP_ANY_L4DATA:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(check_match(&key->l4data,\n"
			    "%s				    sizeof(key->l4data), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter,
					 KEFIR_MATCH_TYPE_IP_ANY_L4PORT_SRC))
			GEN(""
			    "%s	case MATCH_IP_ANY_L4PORT_SRC:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(check_match(&key->l4port_src,\n"
			    "%s				    sizeof(key->l4port_src), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter,
					 KEFIR_MATCH_TYPE_IP_ANY_L4PORT_DST))
			GEN(""
			    "%s	case MATCH_IP_ANY_L4PORT_DST:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(check_match(&key->l4port_dst,\n"
			    "%s				    sizeof(key->l4port_dst), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter,
					 KEFIR_MATCH_TYPE_IP_ANY_L4PORT_ANY))
			GEN(""
			    "%s	case MATCH_IP_ANY_L4PORT_ANY:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(check_match(&key->l4port_src,\n"
			    "%s				    sizeof(key->l4port_src), match) ||\n"
			    "%s			 check_match(&key->l4port_dst,\n"
			    "%s				    sizeof(key->l4port_dst), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent,
			    indent);

		/* VLAN */

		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_VLAN_ID))
			GEN(""
			    "%s	case MATCH_VLAN_ID:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(check_match(&key->vlan_id[0],\n"
			    "%s				     sizeof(key->vlan_id[0]), match) ||\n"
			    "%s			 check_match(&key->vlan_id[1],\n"
			    "%s				     sizeof(key->vlan_id[1]), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent,
			    indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_VLAN_PRIO))
			GEN(""
			    "%s	case MATCH_VLAN_PRIO:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(check_match(&key->vlan_prio[0],\n"
			    "%s				     sizeof(key->vlan_prio[0]), match) ||\n"
			    "%s			 check_match(&key->vlan_prio[1],\n"
			    "%s				     sizeof(key->vlan_prio[1]), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent,
			    indent);
		if (filter_has_matchtype(filter,
					 KEFIR_MATCH_TYPE_VLAN_ETHERTYPE))
			GEN(""
			    "%s	case MATCH_VLAN_ETHERTYPE:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			(check_match(&key->vlan_etype[0],\n"
			    "%s				     sizeof(key->vlan_etype[0]), match) ||\n"
			    "%s			 check_match(&key->vlan_etype[1],\n"
			    "%s				     sizeof(key->vlan_etype[1]), match));\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent, indent,
			    indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_CVLAN_ID))
			GEN(""
			    "%s	case MATCH_CVLAN_ID:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->vlan_id[1],\n"
			    "%s				    sizeof(key->vlan_id[1]), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_CVLAN_PRIO))
			GEN(""
			    "%s	case MATCH_CVLAN_PRIO:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->vlan_prio[1],\n"
			    "%s				    sizeof(key->vlan_prio[1]), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter,
					 KEFIR_MATCH_TYPE_CVLAN_ETHERTYPE))
			GEN(""
			    "%s	case MATCH_CVLAN_ETHERTYPE:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->vlan_etype[1],\n"
			    "%s				     sizeof(key->vlan_etype[1]), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_SVLAN_ID))
			GEN(""
			    "%s	case MATCH_SVLAN_ID:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->vlan_id[0],\n"
			    "%s				    sizeof(key->vlan_id[0]), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter, KEFIR_MATCH_TYPE_SVLAN_PRIO))
			GEN(""
			    "%s	case MATCH_SVLAN_PRIO:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->vlan_prio[0],\n"
			    "%s				    sizeof(key->vlan_prio[0]), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);
		if (filter_has_matchtype(filter,
					 KEFIR_MATCH_TYPE_SVLAN_ETHERTYPE))
			GEN(""
			    "%s	case MATCH_SVLAN_ETHERTYPE:\n"
			    "%s		does_match = does_match &&\n"
			    "%s			check_match(&key->vlan_etype[0],\n"
			    "%s				    sizeof(key->vlan_etype[0]), match);\n"
			    "%s		break;\n"
			    "", indent, indent, indent, indent, indent);

		GEN(""
		    "%s	default:\n"
		    "%s		break;\n"
		    "%s	}\n"
		    "\n"
		    "", indent, indent, indent);

		if (!manual_unroll) {
			/* Clang unrolls: get out of loop if no match */
			GEN(""
			    "		if (!does_match)\n"
			    "			break;\n"
			    "	}\n"
			    "\n");
		} else if (loop_cnt < prog->options.nb_matches - 1) {
			/* Manual unroll: exit early if no match */
			GEN(""
			    "	if (!does_match)\n"
			    "		return 0;\n"
			    "\n");
		}
	}

	GEN(""
	    "	if (does_match) {\n"
	    "		*res = get_retval(rule->action_code);\n"
	    "		return 1;\n"
	    "	} else {\n"
	    "		return 0;\n"
	    "	}\n"
	    "}\n"
	    "\n"
	    "");

	return 0;
}

static int
make_cprog_main(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	bool use_printk = prog->options.flags & OPT_FLAGS_USE_PRINTK;
	size_t i, nb_rules;

	GEN("%s", cprog_prog_starts[prog->options.target]);

	GEN(""
	    "{\n"
	    "	void *data_end = (void *)(long)ctx->data_end;\n"
	    "	void *data = (void *)(long)ctx->data;\n"
	    "	struct filter_key key = {0};\n"
	    "	struct ethhdr *eth = data;\n"
	    "	__u16 eth_proto;\n"
	    "	uint8_t nh_off;\n"
	    "");

	if (use_printk) {
		GEN(""
		    "	int res = 0;\n"
		    "	int tmp, i = 0;\n"
		    "");
	} else {
		GEN("	int res;\n");
	}

	/* Default action: let packet pass. TODO: Provide a way to change it? */
	GEN(""
	    "\n"
	    "	if (extract_key(data, data_end, &key, &eth_proto))\n"
	    "		return RET_PASS;\n"
	    "\n"
	    "");

	nb_rules = list_count(prog->filter->rules);

	if (use_printk) {
		for (i = 0; i < nb_rules; i++)
			GEN(""
			    "	trace_printk(\"check rule %%d\\n\", i++);\n"
			    "	tmp = check_nth_rule(&key, %zd, &eth_proto, &res);\n"
			    "	trace_printk(\"> match?: %%d\\n\", tmp);\n"
			    "	if (tmp) {\n"
			    "		trace_printk(\"> action: %%d\\n\", res);\n"
			    "		return res;\n"
			    "	}\n"
			    "\n"
			    "", i);
	} else {
		for (i = 0; i < nb_rules; i++)
			GEN(""
			    "	if (check_nth_rule(&key, %zd, &eth_proto, &res))\n"
			    "		return res;\n"
			    "\n"
			    "", i);
	}

	GEN(""
	    "	return RET_PASS;\n"
	    "}\n"
	    "\n"
	    "");

	return 0;
}

static void
update_options_from_matchtype(enum kefir_match_type match_type,
			      struct kefir_cprog_options *options)
{
	switch (match_type) {
	case KEFIR_MATCH_TYPE_ETHER_SRC:
	case KEFIR_MATCH_TYPE_ETHER_DST:
	case KEFIR_MATCH_TYPE_ETHER_ANY:
		options->flags |= OPT_FLAGS_NEED_ETHER;
		break;

	case KEFIR_MATCH_TYPE_IP_4_L4DATA:
	case KEFIR_MATCH_TYPE_IP_4_L4PORT_SRC:
	case KEFIR_MATCH_TYPE_IP_4_L4PORT_DST:
	case KEFIR_MATCH_TYPE_IP_4_L4PORT_ANY:
		options->flags |= OPT_FLAGS_NEED_L4;
		/* fall through */
	case KEFIR_MATCH_TYPE_IP_4_SRC:
	case KEFIR_MATCH_TYPE_IP_4_DST:
	case KEFIR_MATCH_TYPE_IP_4_ANY:
	case KEFIR_MATCH_TYPE_IP_4_TOS:
	case KEFIR_MATCH_TYPE_IP_4_TTL:
	case KEFIR_MATCH_TYPE_IP_4_FLAGS:
	case KEFIR_MATCH_TYPE_IP_4_SPI:
	case KEFIR_MATCH_TYPE_IP_4_L4PROTO:
		options->flags |= OPT_FLAGS_NEED_IPV4;
		break;

	case KEFIR_MATCH_TYPE_IP_6_L4DATA:
	case KEFIR_MATCH_TYPE_IP_6_L4PORT_SRC:
	case KEFIR_MATCH_TYPE_IP_6_L4PORT_DST:
	case KEFIR_MATCH_TYPE_IP_6_L4PORT_ANY:
		options->flags |= OPT_FLAGS_NEED_L4;
		/* fall through */
	case KEFIR_MATCH_TYPE_IP_6_SRC:
	case KEFIR_MATCH_TYPE_IP_6_DST:
	case KEFIR_MATCH_TYPE_IP_6_ANY:
	case KEFIR_MATCH_TYPE_IP_6_TOS:
	case KEFIR_MATCH_TYPE_IP_6_TTL:
	case KEFIR_MATCH_TYPE_IP_6_FLAGS:
	case KEFIR_MATCH_TYPE_IP_6_SPI:
	case KEFIR_MATCH_TYPE_IP_6_L4PROTO:
		options->flags |= OPT_FLAGS_NEED_IPV6;
		break;

	case KEFIR_MATCH_TYPE_IP_ANY_L4DATA:
	case KEFIR_MATCH_TYPE_IP_ANY_L4PORT_SRC:
	case KEFIR_MATCH_TYPE_IP_ANY_L4PORT_DST:
	case KEFIR_MATCH_TYPE_IP_ANY_L4PORT_ANY:
		options->flags |= OPT_FLAGS_NEED_L4;
		/* fall through */
	case KEFIR_MATCH_TYPE_IP_ANY_SRC:
	case KEFIR_MATCH_TYPE_IP_ANY_DST:
	case KEFIR_MATCH_TYPE_IP_ANY_ANY:
	case KEFIR_MATCH_TYPE_IP_ANY_TOS:
	case KEFIR_MATCH_TYPE_IP_ANY_TTL:
	case KEFIR_MATCH_TYPE_IP_ANY_FLAGS:
	case KEFIR_MATCH_TYPE_IP_ANY_SPI:
	case KEFIR_MATCH_TYPE_IP_ANY_L4PROTO:
		options->flags |= OPT_FLAGS_NEED_IPV4;
		options->flags |= OPT_FLAGS_NEED_IPV6;
		break;

	default:
		break;
	}
}

/*
 * Variadic list should contain:
 *     kefir_cprog *prog
 *     struct kefir_cprog_attr *attr
 */
static int update_cprog_options(void *rule_ptr, va_list ap)
{
	struct kefir_rule *rule = (struct kefir_rule *)rule_ptr;
	struct kefir_cprog_attr *attr;
	kefir_cprog *prog;
	size_t i;

	prog = va_arg(ap, kefir_cprog *);
	attr = va_arg(ap, struct kefir_cprog_attr *);

	for (i = 0; i < KEFIR_MAX_MATCH_PER_RULE &&
	     rule->matches[i].match_type != KEFIR_MATCH_TYPE_UNSPEC; i++) {
		update_options_from_matchtype(rule->matches[i].match_type,
					      &prog->options);

		if (rule->matches[i].flags & MATCH_FLAGS_USE_MASK)
			prog->options.flags |= OPT_FLAGS_USE_MASKS;
	}

	prog->options.nb_matches = max(prog->options.nb_matches, i);

	if (attr->flags & KEFIR_CPROG_FLAG_INLINE_FUNC)
		prog->options.flags |= OPT_FLAGS_INLINE_FUNC;

	if (attr->flags & KEFIR_CPROG_FLAG_CLONE_FILTER)
		prog->options.flags |= OPT_FLAGS_CLONE_FILTER;

	if (attr->flags & KEFIR_CPROG_FLAG_NO_VLAN &&
	    !filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_VLAN_ID) &&
	    !filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_VLAN_PRIO) &&
	    !filter_has_matchtype(prog->filter,
				  KEFIR_MATCH_TYPE_VLAN_ETHERTYPE) &&
	    !filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_CVLAN_ID) &&
	    !filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_CVLAN_PRIO) &&
	    !filter_has_matchtype(prog->filter,
				  KEFIR_MATCH_TYPE_CVLAN_ETHERTYPE) &&
	    !filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_SVLAN_ID) &&
	    !filter_has_matchtype(prog->filter, KEFIR_MATCH_TYPE_SVLAN_PRIO) &&
	    !filter_has_matchtype(prog->filter,
				  KEFIR_MATCH_TYPE_SVLAN_ETHERTYPE))
		prog->options.flags |= OPT_FLAGS_NO_VLAN;

	if (attr->flags & KEFIR_CPROG_FLAG_USE_PRINTK) {
		prog->options.flags |= OPT_FLAGS_USE_PRINTK;
		add_req_helper(prog, BPF_FUNC_trace_printk);
	}

	add_req_helper(prog, BPF_FUNC_map_lookup_elem);

	return 0;
}

kefir_cprog *
proggen_make_cprog_from_filter(const kefir_filter *filter,
			       const struct kefir_cprog_attr *attr)
{
	kefir_cprog *prog;

	if (!filter || !kefir_filter_size(filter)) {
		err_fail("cannot convert NULL or empty filter");
		return NULL;
	}

	prog = cprog_create();
	if (!prog) {
		err_fail("failed to allocate memory for C prog object");
		return NULL;
	}

	if (attr->flags & KEFIR_CPROG_FLAG_CLONE_FILTER) {
		kefir_filter *clone;

		clone = kefir_filter_clone(filter);
		if (!clone) {
			proggen_cprog_destroy(prog);
			return NULL;
		}
		prog->filter = clone;
	} else {
		prog->filter = filter;
	}

	prog->options.target = attr->target;

	list_for_each((struct list *)prog->filter->rules, update_cprog_options,
		      prog, attr);

	return prog;
}

static int cprog_comment(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	size_t rules_buf_len;
	char *rules_buf;

	dump_filter_to_buf(prog->filter, &rules_buf, &rules_buf_len, " * ");

	GEN(""
	    "/*\n"
	    " * This BPF program was generated from the following filter:\n"
	    " *\n"
	    "%s"
	    " */\n"
	    "", rules_buf);

	free(rules_buf);
	return 0;
}

/* On success, caller is responsible for freeing buffer */
int proggen_cprog_to_buf(const kefir_cprog *prog, char **buf, size_t *buf_len)
{
	if (!prog) {
		err_fail("cannot dump NULL C prog object");
		return -1;
	}

	*buf_len = KEFIR_CPROG_INIT_BUFLEN;
	*buf = calloc(*buf_len, sizeof(*buf));
	if (!*buf) {
		err_fail("failed to allocate memory for C prog buffer");
		*buf_len = 0;
		return -1;
	}

	if (buf_append(buf, buf_len, "%s", cprog_header))
		goto err_free_buf;

	if (make_helpers_decl(prog, buf, buf_len))
		goto err_free_buf;

	if (make_retval_decl(prog, buf, buf_len))
		goto err_free_buf;

	if (make_key_decl(prog, buf, buf_len))
		goto err_free_buf;

	if (make_rule_table_decl(prog, buf, buf_len))
		goto err_free_buf;

	if (cprog_func_process_l4(prog, buf, buf_len))
		goto err_free_buf;

	if (cprog_func_process_ipv4(prog, buf, buf_len))
		goto err_free_buf;

	if (cprog_func_process_ipv6(prog, buf, buf_len))
		goto err_free_buf;

	if (cprog_func_process_ether(prog, buf, buf_len))
		goto err_free_buf;

	if (cprog_func_extract_key(prog, buf, buf_len))
		goto err_free_buf;

	if (cprog_func_check_rules(prog, buf, buf_len))
		goto err_free_buf;

	if (make_cprog_main(prog, buf, buf_len))
		goto err_free_buf;

	if (buf_append(buf, buf_len, "%s", cprog_license))
		goto err_free_buf;

	if (cprog_comment(prog, buf, buf_len))
		goto err_free_buf;

	return 0;

err_free_buf:
	free(*buf);
	*buf = NULL;
	*buf_len = 0;
	return -1;
}
