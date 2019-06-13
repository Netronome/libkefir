# Tests for libkefir

This directory contains a set of functional tests for the library.

## Build the tests

Building the tests is very simple, just run:

    $ make

The program used for running the tests obviously relies on libkefir. So if the
library has not been built already, building the tests will attempt to do so.
This means that all dependencies for building libkefir must be met for building
and running the tests.

## Run the tests

Launch the generated program to run the tests. Note that tests include loading
XDP BPF programs into the kernel, and therefore require to be launched as root.

    # ./tester

Note that the program relies on the BPF testing feature provided by the kernel,
which means that it runs the BPF programs with a context passed by the user,
but does not attach the program to an actual XDP interface and does not process
real packets.

A number of options are provided by the application:

    -h, --help                      Display help message
    -i, --ifname       <ifname>     Interface to attach test programs to, for
                                    hardware offload
    -o, --hw_offload                Attempt hardware offload for test programs
                                    (just load them, not run them)
    -k, --keep_files                Keep produced test files
    -t          <list of tests>     Run only given tests (comma-separated list)

    -c, --llvm_version <version>    LLVM version suffix (e.g. '-8')
                                    to append to clang/llc binary names
    --clang-bin        <path>       clang binary to use (overrides -l)
    --llc-bin          <path>       llc binary to use (overrides -l)

    --inline_fn                     inline BPF functions (no BPF-to-BPF)
    --no_loops                      do not use BPF bounded loops, unroll loops
                                    at compile time
    --no_vlan                       do not generate VLAN parsing in BPF
    --clone_filter                  clone filters before attaching to cprog
    --use_prink                     use bpf_trace_printk() for debug in BPF

## Clean up

The tests do not leave any program loaded, so there is nothing to clean up. The
temporary files produced under `/tmp/` (containing the C program before
conversion to BPF, then the related llc and object files) should have been
automatically removed after the tests completed, unless the `-k|--keep_files`
option was provided to the application.
