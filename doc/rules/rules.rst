.. Copyright (c) 2019 Netronome Systems, Inc.
.. _rules:

==========================
Building rules in libkefir
==========================

The library offers several ways to build rules for filter objects. They can be
built “manually”, by constructing a C structure that will be directly added to
the filter, or they can be built by the library from an expression in one of
the supported syntaxes.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   struct_kefir_rule
   ethtool
   tc_flower
