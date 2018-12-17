.. Copyright (c) 2019 Netronome Systems, Inc.
.. _workflow:

========
Workflow
========

Here is a description of how the main functional blocks of the library
articulate with one another, and of the different steps required to apply a
filter to a traffic flow.

Filters and BPF program
========================

From a high-level perspective, there are two distinct, major steps that
constitute libkefir's workflow. The library creates filters and converts then
loads/attaches them onto a system, therefore we have:

1. Create a filter object.
2. Convert, load and attach the filter.

Or with a simple diagram:

.. code-block:: text

    +==============================+
    |                              |
    |        Create filter         |
    |                              |
    +==============+===============+
                   |
                   |
                   |    <filter>
                   |
                   v
    +==============+===============+
    |                              |
    | Convert, load, attach filter |
    |                              |
    +==============================+

On this diagram and on the following ones, double lines (``=``) indicate a
“meta-step” that does not require any action per se in the workflow, but which
is later broken down into smaller steps.

First phase: filter creation
============================

The filter
----------

Creating a filter can in turn be broken down into more steps.

First, a filter has to be initialized (``kefir_filter_init()``). Then rules
must be added to that filter.

.. code-block:: text

    +==============================+
    |                              |    +-----------------------+
    |        Create filter         +-+->+ Initialize filter     +-+
    |                              | |  | * kefir_filter_init() | |
    +==============================+ |  +-----------------------+ |  +---------------------------+
                                     |                            +->+ Add rules to filter       |
                                     |                            |  | * kefir_filter_add_rule() |
                                     |  +=======================+ |  +---------------------------+
                                     +->+     Create rules      +-+
                                        +=======================+

Creating rules
--------------

Rules can be created in several ways. One possibility is to create and build
directly a ``struct kefir_rule`` object, then to pass it to the library to add
it to the filter (``kefir_filter_add_rule()``). Because building all the parts
of the rule can be somewhat tricky, a helper function can be used to help build
the match objects. The flow becomes:

1. Initialize a filter.
2. Build match objects.
3. Build rules.
4. Add rules to filter.

Another possibility is to use function ``kefir_rule_load()`` (or
``kefir_rule_load_l()``) to parse a rule expressed in the syntax of other
filtering tools. This returns a rule object, that can similarly be added to the
filter.

.. code-block:: text

    +=====================+                 +--------------------------+
    |     Create rules    +-+-------------->+ Create rule from expr.   |
    +=====================+ |               | * kefir_load_rule()      |
                            |               | * kefir_load_rule_l()    |
                            |               +--------------------------+
                            |
                            |
                            |  +--------------------------+   +--------------------------+
                            +->+ Build struct kefir_match |   | Build struct kefir_rule  |
                               | * kefir_match_create()   +-->+ * kefir_rule_create()    |
                               | (or manually)            |   | (or manually)            |
                               +--------------------------+   +--------------------------+

See :ref:`api_rule_crafting` and :ref:`rules` for more details on rule
creation.

Second phase: filter conversion and use
=======================================

Simplified workflow
-------------------

Converting the filter into a C program, then into a BPF program, and loading
then attaching the program in the kernel can all be done in a single step, with
one of the two functions provided for that purpose (``kefir_filter_attach()``
or ``kefir_filter_attach_attr()``). This is the “simple way” of getting a
filter up and running, without having to take care of all the details.

.. code-block:: text

    +==============================+     +------------------------------+
    |                              |     | Actually convert/load/attach |
    | Convert, load, attach filter +---->+ * kefir_filter_attach()      |
    |                              |     | * kefir_filter_attach_attr() |
    +==============================+     +------------------------------+

Unrolling the steps
-------------------

Alternatively, the library offers functions with a finer granularity to perform
each task independently. In that case, the steps are the following:

1. Convert the filter into a cprog object
   (``kefir_filter_convert_to_cprog()``).
2. Generate the C source code from that object, save it to a file
   (``kefir_cprog_to_file()``).
3. Compile the C source file into BPF bytecode, stored in an ELF object file
   (``kefir_cfile_compile_to_bpf()``).
4. Load program from object file into the kernel
   (``kefir_cprog_load_to_kernel()``).
5. Possibly attach the program to a hook in the kernel, such as XDP
   (``kefir_cprog_load_attach_to_kernel()``).

The last function, ``kefir_cprog_load_attach_to_kernel()``, is actually an
alternative to ``kefir_cprog_load_to_kernel()``, doing both loading and
attachment.

The diagram becomes as follows:

.. code-block:: text

    +==============================+
    |                              |
    | Convert, load, attach filter |
    |                              |
    +==+===========================+
       |
       |    +---------------------------------------+
       +--->+ Convert filter to cprog               |
            | * kefir_filter_convert_to_cprog()     |
            +--+------------------------------------+
               |
               |    +---------------------------------------+
               +--->+ Generate C source code from cprog     |
                    | * kefir_cprog_to_file()               |
                    +--+------------------------------------+
                       |
                       |    +---------------------------------------+
                       +--->+ Compile C source file to BPF          |
                            | * kefir_cfile_compile_to_bpf()        |
                            +--+------------------------------------+
                               |
                               |    +---------------------------------------+
                               +--->+ Load BPF from object file             |
                               |    | * kefir_cprog_load_to_kernel()        |
                               |    +---------------------------------------+
                               |
                               |    +---------------------------------------+
                               +--->+ Load and attach BPF                   |
                                    | * kefir_cprog_load_attach_to_kernel() |
                                    +---------------------------------------+

Complete diagram
----------------

Here is what the complete diagram, with the different workflows, looks like:

.. code-block:: text

    +==============================+
    |                              |
    |        Create filter         |
    |                              |
    +==+===========================+
       |
       |    +-----------------------+                       <filter>
       +--->+ Initialize filter     +--------------------------------------------------------------+
       |    | * kefir_filter_init() |                                                              |
       |    +-----------------------+                                                              |
       |                                            +--------------------------+                   |
       |                                            | Create rule from expr.   |                   |
       |                            +-------------->+ * kefir_load_rule()      +-------------------+  +---------------------------+
       |    +=====================+ |               | * kefir_load_rule_l()    |          <rule>   +->+ Add rules to filter       |
       +--->+     Create rules    +-+               +--------------------------+                   |  | * kefir_filter_add_rule() |
            +=====================+ |                                                              |  +----------+----------------+
                                    |                            <match>                           |             |
                                    |  +--------------------------+   +--------------------------+ |             |
                                    |  | Build struct kefir_match |   | Build struct kefir_rule  | |             |
                                    +->+ * kefir_match_create()   +-->+ * kefir_rule_create()    +-+             |
                                       | (or manually)            |   | (or manually)            |               |
                                       +--------------------------+   +--------------------------+               |
                                                                                                                 |
                   +---------------------------------------------------------------------------------------------+
                   |                                        <filter>
                   v
    +==============+===============+
    |                              |
    | Convert, load, attach filter |
    |                              |
    +==+===========================+
       |
       |                                      +------------------------------+
       |            <filter                   | Actually convert/load/attach |
       +------------------------------------->+ * kefir_filter_attach()      |
       |                                      | * kefir_filter_attach_attr() |
       | <filter>                             +------------------------------+
       |
       |    +-----------------------------------+
       +--->+ Convert filter to cprog           |
            | * kefir_filter_convert_to_cprog() |
            +--+--------------------------------+
               |
               | <cprog>
               |
               |    +-----------------------------------+
               +--->+ Generate C source code from cprog |
                    | * kefir_cprog_to_file()           |
                    +--+--------------------------------+
                       |
                       | <C file name>
                       |
                       |    +--------------------------------+
                       +--->+ Compile C source file to BPF   |
                            | * kefir_cfile_compile_to_bpf() |
                            +--+-----------------------------+
                               |
                               | <cprog, object file name>
                               |
                               |    +---------------------------------------+
                               +--->+ Load BPF from object file             |
                               |    | * kefir_cprog_load_to_kernel()        |
                               |    +---------------------------------------+
                               |
                               |    +---------------------------------------+
                               +--->+ Load and attach BPF                   |
                                    | * kefir_cprog_load_attach_to_kernel() |
                                    +---------------------------------------+

Clean up
========

Once the objects created with the library are no longer needed, they can be
destroyed to free the memory that was allocated for them.

Rule, match and value objects are simple ``struct``\ s containing no pointer,
so they don't need to be destroyed, or they can simply ``free()``-ed if
pointers to such ``struct``\ s were created. Rules attached to a filter are not
to be freed by the user, the function for destroying a filter object takes care
of it.

Function ``kefir_filter_destroy()`` is the one taking care of the filters
(``struct kefir_filter *``). It frees memory for all the rules attached to the
filter, and for the filter itself.

C program objects (``struct kefir_cprog *``) can be destroyed with
``kefir_cprog_destroy()``. This function may or may not destroy the filter
attached to the cprog object. This depends on how the filter is attached: by
default, a cprog links to a filter at its creation, but when this cprog object
is destroyed the filter remains, and can be reused for other cprog objects.
However, if the ``KEFIR_CPROG_FLAG_CLONE_FILTER`` was pass in a ``struct
kefir_cprog_attr`` when creating the cprog, then a clone of the filter is
attached instead. Since the user has no means to retrieve a pointer to this
clone, the clone filter is destroyed at the same time as the cprog object.

At last, the ``kefir_bpfobj_destroy()`` can be used to destroy a ``struct
bpf_object *`` produced when loading a BPF program into the kernel. The
function just calls ``bpf_object__close()`` from libbpf really, but it felt
more consistent to provide a wrapper in this library for all objects produced
by functions of the library.
