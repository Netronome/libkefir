.. Copyright (c) 2019 Netronome Systems, Inc.
.. _roadmap:

=======
Roadmap
=======

This document lists ideas for future evolutions of the library. **It should not
be interpreted as a commitment from the authors**, but only as notes on the
possible features and improvements to come. They are provided for informational
purpose, and to share ideas with people willing to help. Any contribution
welcome!

Here is the current list:

- Complete support for all keywords for ethtool/TC flower (some are not
  supported at the moment, e.g. anything related to IPsec).

- Add support for additional rule expression syntax: iptables, libpcap filters,
  Open vSwitch, ...

- Add other return actions (to do things more complex than binary “pass or
  drop”).

- Offer an alternative C-generation mode for some compatible filters, where
  rules would not be stored into an array and checked one after the other but
  instead put into a hash table, in order to avoid sequential lookup and gain
  in performance.

- Implement the “optimizations” for the filters mentioned in section
  :ref:`internals` (removal of rule duplicates, merging of rules when possible,
  reordering when relevant, etc.).

- Improve test framework from a generic point of view (so we can do other
  things than just validating filters).

- Complete test suite (comparison operators, more JSON-loading tests, ...).

- Add API functions taking a list of rules and two filter arguments and sorting
  the rules into the two filters, based on whether they should be offloaded or
  not (depending on `skip_sw` keyword for TC for example)?

- Documentation:

    - Create better (nicer) diagrams in :ref:`workflow`.
    - Generate and publish a better API documentation (Doxygen?).

If you feel like working on this, or if you see other elements to improve, do
not hesitate to send a pull request!
