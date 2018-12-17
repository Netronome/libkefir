.. Copyright (c) 2019 Netronome Systems, Inc.
.. _ethtool:

=======================
Ethtool ntuples filters
=======================

About ethtool hardware filters
==============================

Ethtool is a utility used to query or control network driver and hardware
settings. It relies on a specific syntax to parse and set up what it calls
“ntuples filters” on the hardware, for those NICs that support it (mostly
Intel's). Such filters allow for sending a packet into a specific hardware
queue, for configuring the hash options for packets matching a rule for RSS
(Receive-Side Scaling), or for dropping the packet. The latter is of particular
interest in our context.

As these filters are designed to be used at the hardware level, the syntax for
ethtool rules is rather simple, and mostly consist in a combination of fields
to check (possibly with masks).

For these reasons, the syntax for ethtool ntuples is well suited for expressing
filtering rules, and was integrated to libkefir as a way to build a filter
object.

Example
=======

Here is an example rule used to drop incoming IPv4 HTTP traffic with ethtool:

.. code-block:: console

    # ethtool -U flow-type tcp4 src-port 80 action -1

Libkefir expects an expression identical to that command line, starting after
the name of the binary (``ethtool``) and the options (``-U``). So the relevant
expression would be:

.. code-block:: text

    flow-type tcp4 src-port 80 action -1

Which can be fed to ``kefir_rule_load_l()``, for example:

.. code-block:: c

   if (kefir_rule_load_l(filter,
                         KEFIR_RULE_TYPE_ETHTOOL_NTUPLE,
                         "flow-type tcp4 src-port 80 action -1",
                         0)) {
           printf("Error: %s\n", kefir_strerror());
           return -1;
   }

Example rules can be found in `ethtool-based tests`_. More details on ethtool
ntuples syntax and semantics can be found on the `ethtool manual page`_.

.. _ethtool-based tests:
   https://github.com/Netronome/libkefir/blob/master/tests/ethtool_basic.c
.. _ethtool manual page:
   http://man7.org/linux/man-pages/man8/ethtool.8.html

Current support
===============

Supported keywords:

- ``src xx:yy:zz:aa:bb:cc [m xx:yy:zz:aa:bb:cc]``
- ``dst xx:yy:zz:aa:bb:cc [m xx:yy:zz:aa:bb:cc]``
- ``proto N [m N]``
- ``src-ip ip-address [m ip-address]``
- ``dst-ip ip-address [m ip-address]``
- ``tos N [m N]``
- ``tclass N [m N]``
- ``l4proto N [m N]``
- ``src-port N [m N]``
- ``dst-port N [m N]``
- ``l4data N [m N]``
- ``vlan-etype N [m N]``
- ``vlan N [m N]``
- ``dst-mac xx:yy:zz:aa:bb:cc [m xx:yy:zz:aa:bb:cc]``

- ``action N``

Unsupported keywords:

- ``spi N [m N]``
- ``user-def N [m N]``

Non-relevant keywords:

- ``context N``
- ``vf N``
- ``queue N``
- ``loc N``
- ``delete N``
