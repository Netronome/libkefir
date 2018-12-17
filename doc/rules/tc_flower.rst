.. Copyright (c) 2019 Netronome Systems, Inc.
.. _tc_flower:

=========
TC flower
=========

About TC flower filters
=======================

When compared with :ref:`ethtool` ntuples, TC filters are applied higher in the
Linux stack. Socket buffers have been assigned and provide a number of offsets
that can help matching packets, which results in a number of additional
filtering options that can be supported.

Some of them are supported by libkefir, in order to quickly generate rules from
TC flower expressions.

Example
=======

The following rule can be used to filter out incoming IPv4 HTTP packets:

.. code-block:: console

   # tc flower protocol ip flower ip_proto tcp dst_port 80 action drop

The same line, starting after ``tc flower``, can be passed to the library to
create a new rule. In our example, it would be the following string:

.. code-block:: text

   protocol ip flower ip_proto tcp dst_port 80 action drop

So a call to the ``kefir_rule_load_l()``, used to build rules from a string
containing the whole expression, would look like this:

.. code-block:: c

   if (kefir_rule_load_l(filter,
                         KEFIR_RULE_TYPE_TC_FLOWER,
                         "protocol ip flower ip_proto tcp dst_port 80 action drop",
                         0)) {
           printf("Error: %s\n", kefir_strerror());
           return -1;
   }

Other example rules displaying the various supported options can be found in
the `tests for TC flower-based filters`_. For details on the syntax and the
semantics of the different keywords in TC flower expressions, please refer to
the `tc-flower manual page`_.

.. _tests for TC flower-based filters:
   https://github.com/Netronome/libkefir/blob/master/tests/tcflower_basic.c
.. _tc-flower manual page:
   http://man7.org/linux/man-pages/man8/tc-flower.8.html

Current support
===============

Supported keywords:

- ``dst_mac MASKED_LLADDR``
- ``src_mac MASKED_LLADDR``
- ``vlan_id VID``
- ``vlan_prio PRIORITY``
- ``vlan_ethtype VLAN_ETH_TYPE``
- ``cvlan_id VID``
- ``cvlan_prio PRIORITY``
- ``cvlan_ethtype VLAN_ETH_TYPE``
- ``ip_proto IP_PROTO``
- ``ip_tos MASKED_IP_TOS``
- ``ip_ttl MASKED_IP_TTL``
- ``dst_ip PREFIX``
- ``src_ip PREFIX``
- ``dst_port NUMBER``
- ``src_port NUMBER``

- ``action ACTION_SPEC``

Unsupported keywords:

- ``mpls_label LABEL``
- ``mpls_tc TC``
- ``mpls_bos BOS``
- ``mpls_ttl TTL``
- ``dst_port MIN_VALUE-MAX_VALUE``
- ``src_port MIN_VALUE-MAX_VALUE``
- ``tcp_flags MASKED_TCP_FLAGS``
- ``type MASKED_TYPE``
- ``code MASKED_CODE``
- ``arp_tip IPV4_PREFIX``
- ``arp_sip IPV4_PREFIX``
- ``arp_op ARP_OP``
- ``arp_sha MASKED_LLADDR``
- ``arp_tha MASKED_LLADDR``
- ``enc_key_id NUMBER``
- ``enc_dst_ip PREFIX``
- ``enc_src_ip PREFIX``
- ``enc_dst_port NUMBER``
- ``enc_tos NUMBER``
- ``enc_ttl NUMBER``
- ``geneve_opts OPTIONS``
- ``ip_flags IP_FLAGS``

Non-relevant keywords:

- ``classid CLASSID``
- ``hw_tc TCID``
- ``indev ifname``
- ``verbose``
- ``skip_sw``
- ``skip_hw``
