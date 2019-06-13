# Libkefir examples

This directory contains sample applications that rely on the library.

## Build the samples

Building the samples is straightforward. Simply run:

    $ make

These example programs obviously relies on libkefir. So if the library has not
been built already, building the tests will attempt to do so. This means that
all dependencies for building libkefir must be met for building and running
those samples.

## Run the samples

### Create and load a filter: `simple_filter`

This program illustrates how to build a filter by crafting `struct kefir_rule`
objects and adding them to the filter. It contains a single rule, dropping SSH
packets from IPv4 address 10.10.10.1.

This filter is later converted to BPF, loaded and attached to the provided
interface in a single step, with a call to `kefir_filter_attach()`.

The sample can be launched with the following command. Because this application
attempts to load and attach an XDP program, it should be run as root:

    # ./simple_filter -i eth0

The sample does not clean up the loaded BPF filter on exit. To remove that
filter, run the following command:

    # ip link set dev eth0 xdp off

### Unroll the steps: `simple_filter_steps`

This program is not too different from `simple_filter`, but it unrolls all the
different steps for converting and attaching the program:

- First it converts the filter into a C file
  (`kefir_filter_convert_to_cprog()`, `kefir_cprog_to_file()`).
- Then this C file is compiled into BPF bytecode stored in an object file
  (`kefir_cfile_compile_to_bpf()`).
- At last the BPF program is loaded into the kernel and attached to the
  provided interface (`kefir_cprog_load_attach_to_kernel()`).

There is no real advantage to unroll the steps in this example. In more complex
applications, this can be used for example to dump the C source code of the
program and possibly to edit it before compiling into BPF instructions, or to
compile it with different options, or to compile it but not to run it on the
current machine, etc.

This sample application also illustrates another method for building the filter
in the first place. It calls `kefir_rule_load()` to parse expressions coming
from ethtool ntuple filters and TC flower filters syntaxes, instead of directly
building the `struct kefir_rule` object.

The sample can be launched with the following command. Because this application
attempts to load and attach an XDP program, it should be run as root:

    # ./simple_filter_steps -i eth0

The program can take a number of additional options, as described below:

    -h, --help                      Display a help message
    -o, --hw_offload                Attempt hardware offload for filter
    -l, --log_level    <level>      Log level for kernel verifier
    -c, --llvm_version <version>    LLVM version suffix (e.g. '-8')
                                    to append to clang/llc binary names
    --clang-bin        <path>       clang binary to use (overrides -l)
    --llc-bin          <path>       llc binary to use (overrides -l)
    --no_loops                      do not use BPF bounded loops, unroll

The sample does not clean up the loaded BPF filter on exit. To remove that
filter, run the following command (replace `xdp` with `xdpoffload` if the BPF
program was offloaded to the hardware):

    # ip link set dev eth0 xdp off

### Play with TC flower syntax, JSON: `tcflower2json`

The program reads from the command line. It expects a TC flower expression, and
turns that into a JSON object that can later be loaded as a libkefir filter.

For example, one could try:

    $ ./tcflower2json protocol ip flower src_ip 10.10.10.1/24 \
            ip_proto udp dst_port 8888 action drop

### Load JSON, dump C code: `json2c`

This program expects a filename as its sole argument. The file is supposed to
contain a libkefir filter saved as a JSON object. It is loaded and turned into
a C program, which is printed to the console.

It can be run like this:

    $ ./json2c filter.json

For example:

    $ ./tcflower2json protocol ip flower src_ip 10.10.10.1/24 \
            ip_proto udp dst_port 8888 action drop > filter.json
    $ ./json2c filter.json

Passing a single dash (`-`) as a file name instructs the library (hence our
sample program) to read from standard input, so we could even use:

    $ ./tcflower2json protocol ip flower src_ip 10.10.10.1/24 \
            ip_proto udp dst_port 8888 action drop | ./json2c -
