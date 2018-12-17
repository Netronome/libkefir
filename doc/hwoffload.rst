.. Copyright (c) 2019 Netronome Systems, Inc.
.. _hwoffload:

============================
Notes about hardware offload
============================

BPF filters with Libkefir are compatible with BPF hardware offload. However,
users trying to run such filters on the hardware should be aware of the
following points.

This applies to Netronome's Agilio SmartNICs, which are the only ones at this
date to support BPF hardware offload.

- No BTF support. Hardware offload does not have BTF support, although the
  library attempts to load BTF objects whenever possible, so users compiling
  the filters with a recent compiler (LLVM v8+) should expect (harmless)
  warnings.

- Limited entry size. Hardware offload has a limited size for map entries, 64
  bytes per entry (key + value). Therefore, the program may fail to load if the
  generated map entries are too big. This can happen if:

  - The filter has at least one rule that uses many match objects (e.g. 3 or
    more).
  - The filter has at least one rule that uses masks.

- Not all BPF helpers are supported. When generating C code, do not use the
  flag for generating calls to ``bpf_trace_printk()`` helper for debug,
  hardware does not support it.
