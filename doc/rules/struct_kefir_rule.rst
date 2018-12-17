.. Copyright (c) 2019 Netronome Systems, Inc.
.. _struct_kefir_rule:

==============
Building rules
==============

Foreword
========

Libkefir offers several interfaces for building rule objects to add to filters.
Actually, the structure of the rules is part of the API, and exposed to the
user, who is free to build the rules exactly as they intend. This document
provides some precisions on this structure, and some explanations on the
helpers provided by the library to interact with it.

See also section :ref:`api_rule_crafting` of the API documentation for more
details on the structures and functions exposed by the library at that level.

Struct kefir_rule
=================

The ``struct kefir_rule`` and its members are as follow:

.. code-block:: c

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

	/*
	 * - A type for the match, indicating the semantics of the data to match
	 *   (semantics needed for optimizations).
	 * - An operator to indicate what type of comparison should be performed
	 *   (equality, or other arithmetic or logic operator).
	 * - A value to match.
	 * - One mask to apply to the field.
	 * - Option flags, indicating for example that masks are used for this match.
	 */
	struct kefir_match {
		enum match_type		        match_type;
		enum kefir_comp_operator	comp_operator;
		union kefir_value	        value;
		uint8_t			        mask[16];
		uint64_t		        flags;
	};

	/*
	 * A rule object, representing one rule that will be evaluated against packet
	 * data. If all patterns match, the action code will be returned from the BPF
	 * program.
	 */
	struct kefir_rule {
		struct kefir_match matches[KEFIR_MAX_MATCH_PER_RULE];
		enum kefir_action_code action;
	};

A rule contains a fixed number of match objects, but not all of them are used
in the resulting filter (processing stops on the first match object with match
type ``KEFIR_MATCH_TYPE_UNSPEC``). It also contains an action code, indicating
the action to apply to the packet when all patterns in the different match
objects are found to be validated by the packet fields.

Match objects (``struct kefir_match``) contain the value to evaluate against a
specific field in the packet (designated by the match type), and additional
information on how to perform this evaluation (what comparison operator should
be used, what mask, if any). Note that the ``flags`` are for **internal use**
only, and will be reset by the library when the rule is added to a filter.

The value contained in a match object (``union kefir_value``) actually
represents just a single value. Because values to compare with the packet can
take a variety of formats, the object is a ``union``. Here are some important
notes to keep in mind when manipulating values:

* The value MUST be **left-aligned** in the union, whatever its length. So if
  the value is a two-byte integer, representing for example a layer 4 port, the
  two bytes of the value must be stored at the left side of the union, so that
  it can be accessed as the ``.u16`` member.

* All values (longer than 1 byte) MUST be stored in **network-byte order**.
  This is so the BPF program does not loose instructions to convert it before
  comparing it to packet's values. This often means calling helpers like
  ``htons(n)`` for integers. Note that some functions such as ``ether_aton()``
  or ``inet_pton()``, used to convert character strings into Ether or IP
  addresses respectively, already store their results in network-byte order.

Libkefir helpers for building rules
===================================

Because it can feel cumbersome to handle all these aspects for storing the
values correctly in match objects, the library provides two helpers.

The first one, ``kefir_match_create()``, takes the items needed to build a
match object, and takes care of creating and storing the value correctly, This
function deduces the relevant length from the match type provided, therefore
the user does not pass the length of the value. Because it may be useful to
know the expected value for a given type (e.g. to check before calling
``kefir_match_create()`` that the data for which a pointer is passed is big
enough), function ``kefir_bytes_for_type()`` is provided to that effect.

For example:

.. code-block:: c

	struct kefir_match match = {0};
	uint8_t src_ip[4];

	inet_pton(AF_INET, "10.10.10.1", &src_ip);

	/* This check is not necessary if we know the length of the value
	 * associated with KEFIR_MATCH_TYPE_IP_4_SRC, but can be used if in
	 * doubt, to avoid passing a pointer to a memory area shorter than what
	 * kefir_match_create() will read.
	 */
	if (sizeof(src_ip) != kefir_bytes_for_type(KEFIR_MATCH_TYPE_IP_4_SRC))
		return -1;

	if (!kefir_match_create(&match, KEFIR_MATCH_TYPE_IP_4_SRC,
				KEFIR_OPER_EQUAL, &src_ip, NULL, true))
		return -1;

The second helper, called ``kefir_rule_create()``, can be used to build a rule
from one or several match objects, whether or not they were created with
``kefir_match_create()``.

Again, please refer to section section :ref:`api_rule_crafting` of the API
documentation for more details on those functions.
