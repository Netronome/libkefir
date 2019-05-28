# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2019 Netronome Systems, Inc.

EXAMPLES = simple_filter_steps

LIBKEFIR_DIR	= ..
LIBKEFIR_OBJECT	= $(LIBKEFIR_DIR)/build/libkefir.a
LIBBPF_DIR	= $(LIBKEFIR_DIR)/libbpf/src
LIBBPF_OBJECT	= $(LIBBPF_DIR)/libbpf.a
HDR_INSTALL_DIR	= build/headers
HDR_PREFIX	?= /usr/local
HDR_DIR	= $(LIBKEFIR_DIR)/$(HDR_INSTALL_DIR)$(HDR_PREFIX)/include

EXTRA_WARNINGS += -Wbad-function-cast
EXTRA_WARNINGS += -Wdeclaration-after-statement
EXTRA_WARNINGS += -Wformat-security
EXTRA_WARNINGS += -Wformat-y2k
EXTRA_WARNINGS += -Winit-self
EXTRA_WARNINGS += -Wmissing-declarations
EXTRA_WARNINGS += -Wmissing-prototypes
EXTRA_WARNINGS += -Wnested-externs
EXTRA_WARNINGS += -Wno-system-headers
EXTRA_WARNINGS += -Wold-style-definition
EXTRA_WARNINGS += -Wpacked
EXTRA_WARNINGS += -Wredundant-decls
EXTRA_WARNINGS += -Wshadow
EXTRA_WARNINGS += -Wstrict-prototypes
EXTRA_WARNINGS += -Wswitch-default
EXTRA_WARNINGS += -Wundef
EXTRA_WARNINGS += -Wwrite-strings
EXTRA_WARNINGS += -Wformat

EXTRA_WARNINGS += -Wno-switch-enum

CFLAGS ?= -g -Wall -Wextra -Wpedantic $(EXTRA_WARNINGS)
CFLAGS += -I$(HDR_DIR)

all: $(EXAMPLES)

$(HDR_DIR)/kefir/libkefir.h:
	$(Q)DESTDIR=$(HDR_INSTALL_DIR) PREFIX=$(HDR_PREFIX) \
		$(MAKE) -C $(LIBKEFIR_DIR) install_headers

$(addsuffix .o,$(EXAMPLES)): $(HDR_DIR)/kefir/libkefir.h

simple_filter_steps: simple_filter_steps.o cl_options.o $(LIBKEFIR_OBJECT) $(LIBBPF_OBJECT)
	$(CC) $(CFLAGS) -o $@ $^ -lelf

## Build with shared library (.so) instead of static one (.a)
## Requires installing the libraries first
##
#LDFLAGS ?= -L$(LIBKEFIR_DIR)/build -L$(LIBBPF_DIR)
#simple_filter_test: simple_filter_test.c cl_options.c
#	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkefir -lbpf -lelf

$(LIBBPF_OBJECT): $(LIBKEFIR_OBJECT)

$(LIBKEFIR_OBJECT):
	$(MAKE) -C $(LIBKEFIR_DIR)

clean:
	$(RM) -- *.o
	$(RM) -- $(EXAMPLES)

.PHONY: all clean
