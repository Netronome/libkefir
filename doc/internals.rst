.. Copyright (c) 2019 Netronome Systems, Inc.
.. _internals:

=========
Internals
=========

This page is not yet a full walk-through review of the internals of the
library. It should rather be seen as a collection on notes about particular
points of interests for a better understanding of how functionalities are
implemented.

Structure of a rule
===================

A filter object contains a list of rules. Each rule contains a set of match
objects. Those match objects each contain:

- A match type, indicating against which field of a packet the value should be
  compared
- A value to match
- A comparison operator
- A mask
- A set of flags, for easier processing

Additionally, a rule associates an action to this set of match objects.

When a rule contains several non-null match objects, it applies to a packet if
and only if all of the values in those objects (conjunction) are successfully
compared to the related values from the packet. Implementing rules based on a
disjunction of patterns is done by creating several distinct rules and trying
them one after the other.

Match objects for which the type is ``KEFIR_MATCH_TYPE_UNSPEC`` are considered
null and ignored. Processing of match objects halts after the first null
element (or when all objects in the rule have been processed).

.. _internals_packet_matching:

Packet matching
===============

It is expected that the library will be used for a moderate number of rules.
Still, we want to support more than just two or three rules, so the translation
of the filter object to C and BPF should not consist in hard-coding all
matching steps in the BPF program itself. To provide more flexibility, it
relies on BPF maps instead:

- The C/BPF program is responsible for dissecting the different headers needed
  by the program to perform the filtering operations (e.g. “is this packet
  UDP?”).
- Then it collects the different values susceptible to be used in the actual
  filtering rules (e.g. UDP source and destination ports).
- At last it tries to apply each rule stored in the map, comparing the
  collected values to those of the match objects in the rule. On the first
  matching rule, the process ends and the action code associated to this rule
  is returned. This effectively means that rules with the lower index in the
  filter list are the ones with the highest priority at the time of evaluation.

If no rule matches against the packet, the packet passes. Future improvements
could offer an option to change this default behavior. In the meantime,
appending a rule that matches all packets to the list of rules can be used as a
workaround.

Filter optimization
===================

No filter optimization has been implemented yet, but this section describes the
concept.

After a new rule has been added to a filter object, an optimization pass should
be run on the filter. It could include:

- Deletion of rules rendered useless by more generic rules
- Reordering of rules, for better performance, as long as the semantics is
  preserved
- Grouping of rules (using masks or value ranges, for example)

Of course, this should not alter the semantics of the rules loaded by the user.
Note that this optimization pass might have consequences in terms of future
management of the filter. Rules are loaded into a filter at an index passed by
the user. This index can be modified if another rule is later inserted at a
lower index, but it remains simple to keep track of the changes. However, if
rules are reorganized or combined, it becomes impossible for users to track
such indices: one would no longer be able to delete a given rule in its
original form, if it has been merged with other rules. If we add filter
optimization to the library in the future, this issue could be addressed in
several ways:

- By keeping a set of rules as provided by the user. This would mean that the
  optimized set of rules may have to be fully regenerated from this
  user-provided set each time the user loads a new rule (instead of adding
  rules incrementally).
- By offering an API function to disable such optimizations.
- By making the library smart enough to split rules that were previously
  merged, whenever required.
- By setting a convention and restricting deletion of rules to the rules
  currently present in the optimized filter, and not allowing users to access
  them by their initial format. This requires a function able to dump the rules
  currently loaded, and to provide a handle for each rule, so as to indicate
  which rule to delete, for example. This last workaround corresponds to the
  current state of the code: the functions to delete a rule based on its
  current index, and to list rules with their index so that users can find the
  index they need, are already provided.

Again, at this date, no such filter optimization has been implemented
(Contributions are welcome!)

C program optimization
======================

The C program generated from the filter should be as simple, short and
efficient as possible. Based on the choices made for creating the program, we
could generate a very generic BPF parser and dissector that could retrieve the
values for all supported fields in the packet, and simply tries to apply the
rules from the map after that. However, that would include a great number of
unused values. Furthermore, some features, such as applying masks, or
comparison operators, would be systematically enforced, making the program
longer and more complex than necessary for many filters.

Therefore the C program generation attempts to limit the amounts of elements
shipped in the program. In particular, the generation depends on the following
items:

- The use in any rule of the filter of any “special” comparison operator,
  “special” meaning in that context “different from equality”. Unused
  comparison operators are optimized out of the program.
- The use of masks in any rule of the filter. If no rule uses a mask, then
  applying masks when comparing values is optimized out. If but one match
  object in at least one rule of the filter uses masks, then masks are checked
  and applied to all values in the program.
- The use of the different match types (header fields). Unused match types are
  not used in the program, and are even optimized out of the struct used in the
  program to store collected information about the packet. If no field in a
  given header is checked, dissection of this header may be left out during
  translation (assuming it is not necessary for processing an upper layer
  header).
- Declarations such as helper functions declarations are done on a
  case-per-case basis, declared only if necessary.

In the future, further optimizations might be applied on the maximum length of
the values present in the rules. Currently, the length is aligned on the
longest possible value (16 bytes, for IPv6 addresses). This is a performance
bottleneck, especially if several comparison operators and/or masks are used,
as comparing values to packet fields become expensive. Having shorter values
only would allow for easier comparison (e.g. just one instruction if the values
are 64-bit long or shorter).

Other optimizations include adapting the number of passes in the loops. This is
used in particular for:

- The number of rules to retrieve from the BPF map, and to apply to the packet
  (this is directly derived from the number of rules present in the table, and
  so in the filter).
- The number of comparisons to realize for each rule, set to the maximal number
  of match objects present for one rule in the set.
