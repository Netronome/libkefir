# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2019 Netronome Systems, Inc.

LIBKEFIR_DIR	= ..
LIBKEFIR_OBJECT	= $(LIBKEFIR_DIR)/build/libkefir.a
LIBBPF_DIR	= $(LIBKEFIR_DIR)/libbpf/src
LIBBPF_OBJECT	= $(LIBBPF_DIR)/libbpf.a
HDR_INSTALL_DIR	= build/headers
HDR_PREFIX	?= /usr/local
HDR_DIR	= $(LIBKEFIR_DIR)/$(HDR_INSTALL_DIR)$(HDR_PREFIX)/include

OBJECTS := $(wildcard *.c)
OBJECTS := $(patsubst %.c,%.o,$(OBJECTS))

CFLAGS ?= -g -Wall -Wextra -Wpedantic
CFLAGS += -I$(HDR_DIR)

default: tester

$(HDR_DIR)/kefir/libkefir.h:
	$(Q)DESTDIR=$(HDR_INSTALL_DIR) PREFIX=$(HDR_PREFIX) \
		$(MAKE) -C $(LIBKEFIR_DIR) install_headers

$(HDR_DIR)/bpf/libbpf.h:
	$(Q)DESTDIR=../../$(HDR_INSTALL_DIR) PREFIX=$(HDR_PREFIX) \
		$(MAKE) -C $(LIBBPF_DIR) install_headers

$(OBJECTS): $(HDR_DIR)/bpf/libbpf.h $(HDR_DIR)/kefir/libkefir.h

tester: $(OBJECTS) $(LIBKEFIR_OBJECT) $(LIBBPF_OBJECT)
	$(CC) $(CFLAGS) -o $@ $^ -lelf

$(LIBBPF_OBJECT): $(LIBKEFIR_OBJECT)

$(LIBKEFIR_OBJECT):
	$(MAKE) -C $(LIBKEFIR_DIR)

clean:
	$(Q)$(RM) -- tester
	$(Q)$(RM) -- $(wildcard *.o)
	$(Q)$(RM) -- $(wildcard *.gch)

.PHONY: default clean
