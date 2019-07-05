/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef LIBKEFIR_H
#define LIBKEFIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <net/ethernet.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bpf_object;

#ifndef LIBKEFIR_API
#define LIBKEFIR_API __attribute__((visibility("default")))
#endif

#ifndef bit
#define bit(n) (1 << (n))
#endif

#define KEFIR_MAX_MATCH_PER_RULE	5

/*
 *
 * Rule crafting
 *
 */

enum kefir_comp_operator {
	KEFIR_OPER_EQUAL,
	KEFIR_OPER_LT,
	KEFIR_OPER_LEQ,
	KEFIR_OPER_GT,
	KEFIR_OPER_GEQ,
	KEFIR_OPER_DIFF,
	__KEFIR_MAX_OPER
};

enum kefir_action_code {
	KEFIR_ACTION_CODE_DROP,
	KEFIR_ACTION_CODE_PASS,
	__KEFIR_MAX_ACTION_CODE
};

enum kefir_match_type {
	KEFIR_MATCH_TYPE_UNSPEC = 0,

	KEFIR_MATCH_TYPE_ETHER_SRC,
	KEFIR_MATCH_TYPE_ETHER_DST,
	KEFIR_MATCH_TYPE_ETHER_ANY,	/* Either source or destination */
	KEFIR_MATCH_TYPE_ETHER_PROTO,

	KEFIR_MATCH_TYPE_IP_4_SRC,
	KEFIR_MATCH_TYPE_IP_4_DST,
	KEFIR_MATCH_TYPE_IP_4_ANY,
	KEFIR_MATCH_TYPE_IP_4_TOS,
	KEFIR_MATCH_TYPE_IP_4_TTL,
	KEFIR_MATCH_TYPE_IP_4_L4PROTO,
	KEFIR_MATCH_TYPE_IP_4_L4DATA,
	KEFIR_MATCH_TYPE_IP_4_L4PORT_SRC,
	KEFIR_MATCH_TYPE_IP_4_L4PORT_DST,
	KEFIR_MATCH_TYPE_IP_4_L4PORT_ANY,

	KEFIR_MATCH_TYPE_IP_6_SRC,
	KEFIR_MATCH_TYPE_IP_6_DST,
	KEFIR_MATCH_TYPE_IP_6_ANY,
	KEFIR_MATCH_TYPE_IP_6_TOS,	/* Actually TCLASS, traffic class */
	KEFIR_MATCH_TYPE_IP_6_TTL,
	KEFIR_MATCH_TYPE_IP_6_L4PROTO,
	KEFIR_MATCH_TYPE_IP_6_L4DATA,
	KEFIR_MATCH_TYPE_IP_6_L4PORT_SRC,
	KEFIR_MATCH_TYPE_IP_6_L4PORT_DST,
	KEFIR_MATCH_TYPE_IP_6_L4PORT_ANY,

	KEFIR_MATCH_TYPE_IP_ANY_TOS,
	KEFIR_MATCH_TYPE_IP_ANY_TTL,
	KEFIR_MATCH_TYPE_IP_ANY_L4PROTO,
	KEFIR_MATCH_TYPE_IP_ANY_L4DATA,
	KEFIR_MATCH_TYPE_IP_ANY_L4PORT_SRC,
	KEFIR_MATCH_TYPE_IP_ANY_L4PORT_DST,
	KEFIR_MATCH_TYPE_IP_ANY_L4PORT_ANY,

	KEFIR_MATCH_TYPE_VLAN_ID,
	KEFIR_MATCH_TYPE_VLAN_PRIO,
	KEFIR_MATCH_TYPE_VLAN_ETHERTYPE,
	KEFIR_MATCH_TYPE_CVLAN_ID,
	KEFIR_MATCH_TYPE_CVLAN_PRIO,
	KEFIR_MATCH_TYPE_CVLAN_ETHERTYPE,
	KEFIR_MATCH_TYPE_SVLAN_ID,
	KEFIR_MATCH_TYPE_SVLAN_PRIO,
	KEFIR_MATCH_TYPE_SVLAN_ETHERTYPE,

	__KEFIR_MAX_MATCH_TYPE
};

/*
 * A value object, to be matched against data collected from one field of a
 * packet.
 */
union kefir_value {
	struct ether_addr	eth;
	struct in6_addr		ipv6;
	struct in_addr		ipv4;
	uint32_t		u32;
	uint16_t		u16;
	uint8_t			u8;
	uint8_t			raw[sizeof(struct in6_addr)];
};

/**
 * A match object, representing a pattern to match against values collected
 * from header fields of a network patcket.
 * @match_type: a type for the match, indicating the size and semantics of the
 *              data to match
 * @comp_operator: comparison operator to indicate what type of comparison
 *                 should be performed (equality, or other arithmetic operator)
 * @value: a value to match
 * @mask: a mask to apply to packet data before trying to match it against the
 *        value
 * @flags: for internal use only, will be overwritten when adding parent rule
 *         to filter
 */
struct kefir_match {
	enum kefir_match_type		match_type;
	enum kefir_comp_operator	comp_operator;
	union kefir_value		value;
	uint8_t				mask[16];
	uint64_t			flags;
};

/**
 * A rule object, representing one rule that will be evaluated against packet
 * data. If all patterns match, the action code will be returned from the BPF
 * program.
 * @matches: array of match objects to try against packet data
 * @action: action code to return from BPF program if packet matches with rule
 */
struct kefir_rule {
	struct kefir_match matches[KEFIR_MAX_MATCH_PER_RULE];
	enum kefir_action_code action;
};

/**
 * Get the number of bytes expected for a value for a match of the given type.
 * @type: match type which length is requested
 * @return length (in bytes) of the value for the given type
 */
LIBKEFIR_API
size_t kefir_bytes_for_type(enum kefir_match_type type);

/**
 * Fill and possibly create a match object.
 * @match: pointer to the match object to fill, if NULL the object will be
 *         allocated by the function and should be later free()-d by the caller
 * @type: type for the match (indicating the header field with which the match
 *        pattern should be compared)
 * @oper: comparison operator for the operation to do to check if a packet
 *        matches a pattern
 * @value: pointer to the data to compare to the content of the packets, which
 *         MUST be of the correct size of the match type in use (this can be a
 *         pointer to a 2-byte long integer for matching on L4 ports, or to a
 *         struct ether_addr for matching on MAC address, for example)
 * @mask: bitmask to apply to packet data before comparing it to the value
 * @is_net_byte_order: true if value and masks are already in network byte
 *                     order (for example if MAC address was obtained with
 *                     ether_aton()), false otherwise
 * @return a pointer to the match object (to be free()-d by the caller if
 *         allocated by the function) on success, NULL otherwise
 */
LIBKEFIR_API
struct kefir_match *
kefir_match_create(struct kefir_match *match,
		   enum kefir_match_type type,
		   enum kefir_comp_operator oper,
		   const void *value,
		   const uint8_t *mask,
		   bool is_net_byte_order);

/**
 * Create and fill a rule object.
 * @matches: array of pointers to match objects to fill the rule with
 * @nb_matches: number of match objects in the array
 * @action: action code to return from the BPF program when a packet matches all
 *          patterns for the rule
 * @return a pointer to the rule object (to be free()-d by the caller) on
 *         success, NULL otherwise
 */
LIBKEFIR_API
struct kefir_rule *
kefir_rule_create(struct kefir_match * const *matches,
		  unsigned int nb_matches,
		  enum kefir_action_code action);

/*
 *
 * Filter management
 *
 */

typedef struct kefir_filter kefir_filter;

enum kefir_rule_type {
	KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
	KEFIR_RULE_TYPE_TC_FLOWER,
};

/**
 * Create and initialize a new filter object.
 * @return a pointer to the filter object on success (to be free()-d by the
 *         caller), NULL otherwise
 */
LIBKEFIR_API
kefir_filter *kefir_filter_init(void);

/**
 * Destroy a filter object and free all associated memory.
 * @filter: filter to destroy
 */
LIBKEFIR_API
void kefir_filter_destroy(kefir_filter *filter);

/**
 * Copy a filter object.
 * @filter: the filter to copy
 * @return a new filter object (the caller is responsible for its destruction)
 */
LIBKEFIR_API
kefir_filter *kefir_filter_clone(const kefir_filter *filter);

/**
 * Count the number of rules present in the list of a filter.
 * @filter: the filter for which to count the rules
 * @return the number of rules in that filter
 */
LIBKEFIR_API
size_t kefir_filter_size(const kefir_filter *filter);

/**
 * Add a rule to a filter.
 * @filter: object to add the rule to
 * @rule: rule to add the the filter (filter links to the rule, does not clone
 *        it)
 * @index: index of the rule in the list (if filter already has a rule at this
 *         index, insert before and shift rules with a greater or equal index),
 *         if negative then start from the end of the list
 * @return 0 on success, error code otherwise
 */
LIBKEFIR_API
int kefir_filter_add_rule(kefir_filter *filter,
			  struct kefir_rule *rule,
			  ssize_t index);

/**
 * Create a rule from an expression and add it to a filter.
 * @filter: object to add the rule to
 * @rule_type: type of the rule to add
 * @user_rule: array of words defining the rule in the format for rule_type
 * @rule_size: number of words in user_rule
 * @index: index of the rule in the list (if filter already has a rule at this
 *         index, insert before and shift rules with a greater or equal index),
 *         if negative then start from the end of the list
 * @return 0 on success, error code otherwise
 */
LIBKEFIR_API
int kefir_rule_load(kefir_filter *filter,
		    enum kefir_rule_type rule_type,
		    const char * const *user_rule,
		    size_t rule_size,
		    ssize_t index);

/**
 * Create a rule from an expression and add it to a filter.
 * @filter: object to add the rule to
 * @rule_type: type of the rule to add
 * @user_rule: single string defining the rule in the format for rule_type
 * @index: index of the rule in the list (if filter already has a rule at this
 *         index, insert before and shift rules with a greater or equal index),
 *         if negative then start from the end of the list
 * @return 0 on success, error code otherwise
 */
LIBKEFIR_API
int kefir_rule_load_l(kefir_filter *filter,
		      enum kefir_rule_type rule_type,
		      const char *user_rule,
		      ssize_t index);

/**
 * Delete a rule at given index from a filter.
 * @filter: object to remove the rule from
 * @index: index of the rule to delete
 * @return 0 on success, error code otherwise
 */
LIBKEFIR_API
int kefir_rule_delete_by_id(kefir_filter *filter,
			    ssize_t index);

/** Dump all rules of a filter to the console.
 * OUTPUT IS NOT STABLE, USE FOR DEBUG ONLY!
 * (See also kefir_filter_save_to_file().)
 * @filter: object to dump
 */
LIBKEFIR_API
void kefir_filter_dump(const kefir_filter *filter);

/*
 *
 * Dump, save and restore filter
 *
 */

/**
 * Save a filter to a file
 * @filter: filter to save
 * @filename: name of the file where to save the filter (it will be created
 *            if necessary, overwritten overwise), if "-" then write to stdout
 * @return 0 on success, error code otherwise
 */
LIBKEFIR_API
int kefir_filter_save_to_file(const kefir_filter *filter,
			      const char *filename);

/**
 * Load a filter from a backup
 * @filename: name of the file to load the filter from, if "-" then read from
 *            stdin
 * @return a pointer to the filter object on success (to be free()-d by the
 *         caller), NULL otherwise
 */
LIBKEFIR_API
kefir_filter *kefir_filter_load_from_file(const char *filename);

/*
 *
 * Back end: Conversion to C
 *
 */

typedef struct kefir_cprog kefir_cprog;

enum kefir_cprog_target {
	KEFIR_CPROG_TARGET_XDP,
	KEFIR_CPROG_TARGET_TC,
};

/**
 * Destroy and free allocated memory for a C program object.
 * @cprog: C program object to destroy
 */
LIBKEFIR_API
void kefir_cprog_destroy(kefir_cprog *cprog);

/*
 * Flags for a struct kefir_cprog_attr.
 *
 * KEFIR_CPROG_FLAG_INLINE_FUNC
 *     Force inlining of functions (no BPF-to-BPF calls).
 * KEFIR_CPROG_FLAG_NO_LOOPS
 *     Ask clang to unroll loops, do not rely on BPF bounded loops support.
 * KEFIR_CPROG_FLAG_CLONE_FILTER
 *     The filter object is normally attached to the cprog object created. Use
 *     this flag to create and attach a clone instead. Use if you intend to
 *     further edit the filter afterwards, but wish to keep the cprog object
 *     unchanged.
 * KEFIR_CPROG_FLAG_NO_VLAN
 *     Disable generation of VLAN-related code (use if traffic and filter rules
 *     never rely on VLAN tags).
 * KEFIR_CPROG_FLAG_USE_PRINTK
 *     Generate some calls to bpf_trace_printk() to help with debug.
 */
#define KEFIR_CPROG_FLAG_INLINE_FUNC	bit(0)
#define KEFIR_CPROG_FLAG_NO_LOOPS	bit(1)
#define KEFIR_CPROG_FLAG_CLONE_FILTER	bit(2)
#define KEFIR_CPROG_FLAG_NO_VLAN	bit(3)
#define KEFIR_CPROG_FLAG_USE_PRINTK	bit(4)

/**
 * Struct containing attributes used when converting a filter into a C program.
 * @target: target for conversion (TC/XDP)
 * @flags: option flags for conversion
 */
struct kefir_cprog_attr {
	enum kefir_cprog_target target;
	unsigned int flags;
};

/**
 * Convert a filter into an eBPF-compatible C program.
 * @filter: filter to convert
 * @target: target for conversion (TC/XDP)
 * @return an object containing all parameters required to create an
 *         eBPF-compatible C program
 */
LIBKEFIR_API
kefir_cprog *kefir_filter_convert_to_cprog(const kefir_filter *filter,
					   const struct kefir_cprog_attr *attr);

/**
 * Dump a C program generated by the library.
 * @cprog: program to dump
 */
LIBKEFIR_API
void kefir_cprog_to_stdout(const kefir_cprog *cprog);

/**
 * Write a generated C program into a buffer.
 * @cprog: C program to write
 * @buf: pointer to a buffer to write the C program into, if NULL the object
 *      will be allocated by the function and should be later free()-d by the
 *      caller
 * @buf_len: pointer to buffer size, will be updated if buffer is reallocated
 * @return 0 on success, error code otherwise
 */
LIBKEFIR_API
int kefir_cprog_to_buf(const kefir_cprog *cprog,
		       char **buf,
		       size_t *buf_len);

/**
 * Save a C program to a file on the disk.
 * @cprog: C program to save
 * @filename: name of file to write into (existing file will be overwritten)
 * @return 0 on success, error code otherwise
 */
LIBKEFIR_API
int kefir_cprog_to_file(const kefir_cprog *cprog,
			const char *filename);

/*
 *
 * Compile to eBPF, load, attach programs
 *
 */

/**
 * Struct containing attributes used when compiling a C program into BPF code.
 * @object_file: optional name for the output file, if NULL will be derived
 *               from c_file if possible (".c" extension will be replaced by
 *               ".o")
 * @ll_file: optional name for intermediary ll file (LLVM IR), if NULL will be
 *           derived from c_file (".ll")
 * @clang_bin: optional path to clang executable, if NULL defaults to
 *             /usr/bin/clang
 * @llc_bin: optional path to llc executable, if NULL defaults to /usr/bin/llc
 */
struct kefir_compil_attr {
	const char *object_file;
	const char *ll_file;
	const char *clang_bin;
	const char *llc_bin;
};

/**
 * Compile a C file into BPF bytecode as an ELF object file.
 * @c_file: input C source code file
 * @attr: object containing optional attributes to use when compiling the
 *        program
 * @return 0 on success, error code otherwise
 */
LIBKEFIR_API
int kefir_cfile_compile_to_bpf(const char *c_file,
			       const struct kefir_compil_attr *attr);

/**
 * Unload and destroy a BPF object and free all associated memory.
 * @obj: pointer to the BPF object to destroy
 */
LIBKEFIR_API
void kefir_bpfobj_destroy(struct bpf_object *obj);

/**
 * Retrieve the file descriptor of the filter program associated with a BPF
 * object.
 * @obj: the BPF object resulting from a program load or attachment
 * @return a file descriptor related to that program
 */
LIBKEFIR_API
int kefir_bpfobj_get_prog_fd(struct bpf_object *obj);

/**
 * Struct containing attributes used when loading a BPF program from an object
 * file.
 * @ifindex: interface index, for indicating where the filter should be
 *           attached (or where the map should be allocated, for hardware
 *           offload, even if the program is simply loaded)
 * @log_level: log level to pass to kernel verifier when loading the program
 * @flags: for XDP: passed to netlink to set XDP mode (socket buffer, driver,
 *         hardware) (see <linux/if_link.h>)
 *         for TC: TODO (No support yet for TC)
 */
struct kefir_load_attr {
	int ifindex;
	int log_level;
	unsigned int flags;
};

/**
 * Load the BPF program associated to a C program object into the kernel.
 * @cprog: cprog used to generate the BPF program
 * @objfile: name of ELF object file containing the BPF program generated from
 *           the filter
 * @attr: object containing optional attributes to use when loading the program
 * @return a BPF object containing information related to the loaded program,
 *         NULL on error
 */
LIBKEFIR_API
struct bpf_object *
kefir_cprog_load_to_kernel(const kefir_cprog *cprog,
			   const char *objfile,
			   const struct kefir_load_attr *attr);

/**
 * Load the BPF program associated to a C program object into the kernel, then
 * immediately attach it to a given interface and fill the map with rules
 * associated to the filter.
 * @cprog: cprog used to generate the BPF program
 * @objfile: name of ELF object file containing the BPF program generated from
 *           the filter
 * @attr: object containing optional attributes to use when loading the program
 * @return a BPF object containing information related to the loaded program,
 *         NULL on error
 */
LIBKEFIR_API
struct bpf_object *
kefir_cprog_load_attach_to_kernel(const kefir_cprog *cprog,
				  const char *objfile,
				  const struct kefir_load_attr *attr);

/**
 * Fill the map associated to a filter loaded in the kernel with the rules
 * associated with that filter.
 * @cprog: cprog used to generate the BPF program loaded on the system
 * @bpf_obj: BPF object resulting from program load
 * @return 0 on success, error code otherwise
 */
LIBKEFIR_API
int kefir_cprog_fill_map(const kefir_cprog *cprog,
			 struct bpf_object *bpf_obj);

/**
 * Dump the commands (bpftool format) that can be used to fill the rules
 * associated with a cprog object (loaded or not).
 * @cprog: cprog used to generate the BPF program
 * @bpf_obj: optional BPF object resulting from program load, used if not NULL
 *           for retrieving map id
 * @buf: pointer to a buffer where to store the commands, if NULL the object
 *       will be allocated by the function and should be later free()-d by the
 *       caller
 * @buf_len: pointer to buffer size, will be updated if buffer is reallocated
 * @return 0 on success, error code otherwise
 */
LIBKEFIR_API
int kefir_cprog_map_update_cmd(const kefir_cprog *cprog,
			       struct bpf_object *bpf_obj,
			       char **buf,
			       size_t *buf_len);

/**
 * All-in-one shortcut function to turn a filter into a cprog object, convert
 * it into a BPF program, load it, and attach it to an interface.
 * @filter: filter to use
 * @ifindex: interface to which the filter should be attached
 * @return a BPF object containing information related to the loaded program,
 *         NULL on error
 */
LIBKEFIR_API
struct bpf_object *
kefir_filter_attach(const kefir_filter *filter,
		    int ifindex);

/**
 * All-in-one shortcut function to turn a filter into a cprog object, convert
 * it into a BPF program, load it, and attach it to an interface.
 * @filter: filter to use
 * @cprog_attr: object containing attributes to use when generating C code from
 *              filter
 * @compil_attr: object containing optional attributes to use when compiling
 *               the filter into BPF
 * @load_attr: object containing attributes to use when loading the program
 * @return a BPF object containing information related to the loaded program,
 *         NULL on error
 */
LIBKEFIR_API
struct bpf_object *
kefir_filter_attach_attr(const kefir_filter *filter,
			 const struct kefir_cprog_attr *cprog_attr,
			 const struct kefir_compil_attr *compil_attr,
			 const struct kefir_load_attr *load_attr);

/*
 *
 * Other
 *
 */

/**
 * Return a pointer to the error messages produced by the library.
 * @return pointer to a buffer containing all error messages produced by the
 *         library
 */
LIBKEFIR_API
const char *kefir_strerror(void);

/**
 * Reset the error string. This is useful to get rid of libbpf warnings that
 * may get incrementally appended to the string.
 */
LIBKEFIR_API
void kefir_strerror_reset(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LIBKEFIR_H */
