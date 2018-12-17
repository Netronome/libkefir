.. Copyright (c) 2019 Netronome Systems, Inc.
.. _intro:

============
Introduction
============

.. rst-class:: center

**libkefir** /lɪbkəˈfɪər/ -- **KE**\ rnel **FI**\ ltering **R**\ ules

.. image:: _static/kefir.png
    :align: center
    :alt: libkefir logo

.. rst-class:: center

*All your filters in one bottle.*

.. rst-class:: center

`Libkefir repository on GitHub <https://github.com/Netronome/libkefir>`_

About libkefir
==============

Libkefir is a project aiming at simplifying network filtering rules management
on recent Linux systems. Its main objective is to provide an interface to
easily turn rules in a variety of formats into flexible, editable, ready-to-use
BPF programs.

Filtering rules can be constructed *ex nihilo*, or can be converted from an
expression coming from other filtering tools. Currently supported are
expressions from:

- ethtool receive-side ntuples filters
- TC (Linux Traffic Control) flower classifier rules

In the future, support could be added for:

- libpcap expressions used for example with tcpdump or Wireshark
- iptable rules
- ...

.. Note::

   In all pages of this documentation, “BPF” should be interpreted as “eBPF”,
   the “extended” 64 bit instructions BPF version with support for maps,
   function calls etc. Unless otherwise specified, it does not refer to the
   legacy “classic“ BPF.

Concepts
========

High-level overview
-------------------

Libkefir works with *filters*, which are sets of *rules*, themselves containing
one or more *match* objects. Please refer to the :ref:`api_terminology`
section of the API documentation for more details about those terms.

A filter is a set of rules that can be converted into a BPF program, which can
later be loaded and attached to the program. This entails a number of
functional blocks that are provided by the library to achieve those tasks.
Below is a high-level description of this different functional blocks.

See also available documentation on the :ref:`workflow` for the library, where
the articulation between the main blocks is more deeply addressed.

Creating rules
--------------

Before a filter can be converted and applied to a traffic flow, it first needs
to be created. Libkefir provides several interfaces for building rules, and to
attach them to a filter object.

One way to build a rule is to “manually” create the rule object (the C struct
associated to it). Helpers in libkefir can be used to ease the creation of
match objects for the rule. Once the rule is built, it can be passed to the
library in order to be added to a given filter (initialized by the library).

Another way of building rules is to call into functions taking expressions from
other filtering tools as arguments, and converting those strings into rule
objects that can be similarly attached to a filter.

See :ref:`api_rule_crafting` and :ref:`rules` for more details on rule
creation, or :ref:`api_filter_management` for building and handling filters.

Conversion to BPF
-----------------

Filters can eventually be turned into a BPF program, but this is not a direct
step. A C file is produced first (although some API functions can hide this
intermediary step). This C program depends on the features used by the filter
(How many match objects in the rules? What fields are necessary to collect in
packet headers? Does the filter use masks?). See also :ref:`api_proggen`.

The second step is obviously to convert this C program into BPF bytecode. This
is done by calling the clang and llc executables, that must be present on the
machine. The result is an ELF object file, that can later be reused to load the
BPF bytecode into the kernel. More details are provided in section
:ref:`api_c2bpf` of the API documentation.

Loading and attaching the program
---------------------------------

Functions are provided to easily load and attach the BPF program derived from
the filter. These functions also take care of creating and initializing a BPF
maps, in which the filtering rules are stored. Additional details on how rules
are stored and applied can be found in section
:ref:`internals_packet_matching`. Information about the relevant functions for
loading and attaching the BPF programs also are in section :ref:`api_c2bpf` of
the API documentation.

Saving, restoring
-----------------

Besides being converted to BPF and loaded onto the system, a filter generated
with the library can be saved into an external file as a JSON object, for being
restored at a later time.

Additional Resources
====================

- LWN.net article: `A thorough introduction to eBPF <https://lwn.net/Articles/740157/>`_
- Cilium's `BPF and XDP Reference Guide <https://docs.cilium.io/en/latest/bpf/>`_
- Netronome's `eBPF Offload Getting Started Guide <https://www.netronome.com/documents/305/eBPF-Getting_Started_Guide.pdf>`_
- Blog post: `Dive into BPF: a list of reading material <https://qmonnet.github.io/whirl-offload/2016/09/01/dive-into-bpf/>`_
