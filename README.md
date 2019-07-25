# Libkefir

![libkefir logo](doc/_static/kefir.png)

Libkefir – All your rules in one bottle.

## About

Libkefir is a C library designed to turn sets of simple network filtering rules
into BPF programs, and to load and attach them to the Linux kernel.

A filtering rule is a rule with a pattern to match, and an action to perform
(pass or drop the packet) for packets. For example, “drop IPv4 packets with
destination address 10.0.0.1”. Rules can have several patterns (in which case
all of them must match), and patterns can use masks.

Filtering rules can be provided in a variety of ways. They can be a fully
constructed rule object passed to the library, or they can be created from the
syntax used by other Linux filtering mechanisms – such as TC flower or ethtool
hardware filters. Once a filter containing a set of rules has been created, it
can be converted into a BPF program.

Conversion to BPF is not straightforward. Instead, the library first creates a
C program, which is in turn compiled with clang/llc. Helpers are provided to
load and attach this program to a kernel hook such as XDP. Alternatively, users
can dump the C program and modify it according to their needs.

Filters can also be saved as JSON files for later utilisation.

## Documentation

Documentation for the library's concepts and usage is available on
[Read the Docs](https://libkefir.readthedocs.io/en/latest/) ([source](doc/)).

## Requirements

* A recent Linux kernel (v4.18 should work fine).

* Clang and llc must be installed on the system (v6.0) where filters are
  converted to BPF programs.

* Libbpf is required. It is set as a submodule of the current repository, which
  makes things easy to build libkefir. Note that building programs with
  libkefir also requires linking against libbpf.

## Build the library

Get the code:

    $ git clone --recurse-submodules https://github.com/Netronome/libkefir.git

Build the library (`libkefir.a`, `libkefir.so`, and a file for `pkg-config`).

    $ cd libkefir
    $ make

This will create and populate the `build/` directory.

Optionally, install the library and the header file:

    # make install install_headers

## License

The greatest part of this software is licensed under the terms of the
[2-Clause BSD License](LICENSE.BSD).

Exceptions:

* Files src/json\_writer.{c,h} come from package
  [iproute2](https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/) and
  are dual-licensed under both the 2-Clause BSD license and the
  [GPL v2.0 license](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html).
* Files src/jsmn.{c,h} come from <https://github.com/zserge/jsmn> and are
  licensed under the [MIT License](https://opensource.org/licenses/MIT).
