# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2019 Netronome Systems, Inc.

KEFIR_VERSION		= 0
KEFIR_PATCHLEVEL	= 1
KEFIR_EXTRAVERSION	= 0
KEFIR_FULLVERSION	= $(KEFIR_VERSION).$(KEFIR_PATCHLEVEL).$(KEFIR_EXTRAVERSION)

SRC	= src/
TESTS	= tests/
OUTPUT	= build/
PREFIX	?= /usr/local
OBJECTS	:= $(wildcard $(SRC)*.c)
OBJECTS	:= $(patsubst %.c,%.o,$(OBJECTS))
OBJECTS	:= $(patsubst $(SRC)%,$(OUTPUT)%,$(OBJECTS))

LIBBPF_DIR	= libbpf/src
LIBBPF_OBJECT	= $(LIBBPF_DIR)/libbpf.a
LIBBPF_HDR_DIR	= $(OUTPUT)headers
LIBBPF_HDRS	= $(LIBBPF_HDR_DIR)$(PREFIX)/include/bpf/bpf.h

LIBKEFIR_A	= $(OUTPUT)libkefir.a
LIBKEFIR_SO	= $(OUTPUT)libkefir.so
PC_FILE		= $(OUTPUT)libkefir.pc

W ?= 1
ifeq ($(W), 1)
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
EXTRA_WARNINGS += -Wundef
EXTRA_WARNINGS += -Wwrite-strings
EXTRA_WARNINGS += -Wformat

# EXTRA_WARNINGS += -Wswitch-default	# Warning from src/jsmn.c
# EXTRA_WARNINGS += -Wswitch-enum
endif

CFLAGS ?= -g -Wall -Wextra -Wpedantic $(EXTRA_WARNINGS)
CFLAGS += -fPIC
CFLAGS += -I$(LIBBPF_HDR_DIR)$(PREFIX)/include/
CFLAGS += -fvisibility=hidden

all: $(LIBKEFIR_A) $(LIBKEFIR_SO) $(PC_FILE)

ifeq ($(Q), @)
SILENCE = -s
endif

$(LIBBPF_OBJECT):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	fi
	$(Q)$(MAKE) $(SILENCE) -C $(LIBBPF_DIR) all

$(LIBBPF_HDRS): $(LIBBPF_OBJECT)
	@mkdir -p $(LIBBPF_HDR_DIR)
	$(Q)DESTDIR=../../$(LIBBPF_HDR_DIR) PREFIX=$(PREFIX) \
		$(MAKE) $(SILENCE) -C $(LIBBPF_DIR) install_headers

$(LIBKEFIR_SO): $(LIBKEFIR_SO).$(KEFIR_FULLVERSION)
	$(Q)ln -sf $(^F) $@
	$(Q)ln -sf $(^F) $(OUTPUT)libkefir.so.$(KEFIR_VERSION)

$(LIBKEFIR_SO).$(KEFIR_FULLVERSION): $(OBJECTS)
	$(Q)$(CC) $(CFLAGS) -shared \
		-Wl,-soname,libkefir.so.$(KEFIR_FULLVERSION) -o $@ $^

$(LIBKEFIR_A): $(OBJECTS)
	$(Q)$(RM) -- $@; $(AR) rcs $@ $^

$(OUTPUT)%.o: $(SRC)%.c $(LIBBPF_OBJECT) $(LIBBPF_HDRS)
	@mkdir -p $(OUTPUT)
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -c -o $@ $< \
		-DKEFIR_VERSION=$(KEFIR_VERSION) \
		-DKEFIR_PATCHLEVEL=$(KEFIR_PATCHLEVEL) \
		-DKEFIR_EXTRAVERSION=$(KEFIR_EXTRAVERSION)

kefir-clean:
	$(Q)$(RM) -r -- $(OUTPUT)
	$(Q)$(RM) -- $(wildcard $(SRC)*.gch)

clean: kefir-clean
	$(Q)$(MAKE) -C $(LIBBPF_DIR) clean

.PHONY: all kefir-clean clean

# Code checks

IWYU_DEP := $(shell command -v include-what-you-use 2>/dev/null)
iwyu-dep:
ifndef IWYU_DEP
	$(error "include-what-you-use not found, cannot check included headers")
endif

iwyu: CC = include-what-you-use
iwyu: iwyu-dep kefir-clean all

.PHONY: iwyu-dep iwyu

azan: CC = $(CLANG) -fsanitize=address -fno-omit-frame-pointer
azan: kefir-clean all

.PHONY: azan

# Tests

tests: $(LIBKEFIR_A) $(LIBBPF_OBJECT) $(LIBBPF_HDRS)
	$(Q)$(MAKE) -C $(TESTS)

tests-clean:
	$(Q)$(MAKE) -C $(TESTS) clean

.PHONY: tests tests-clean

# Package config file

$(PC_FILE):
	@mkdir -p $(OUTPUT)
	$(Q)sed -e "s|@PREFIX@|$(PREFIX)|" \
		-e "s|@LIBDIR@|$(PREFIX)/$(LIBDIR)|" \
		-e "s|@VERSION@|$(KEFIR_VERSION)|" \
		< $(SRC)libkefir.pc.template > $@

# Installation

INSTALL = install

DESTDIR ?= ''
DESTPREF = $(DESTDIR)$(PREFIX)
LIBDIR = lib

install_headers:
	$(Q)$(INSTALL) -d -m 755 $(DESTPREF)/include/kefir
	$(Q)$(INSTALL) -t $(DESTPREF)/include/kefir -m 644 $(SRC)libkefir.h

install_lib: all
	@if ! pkg-config --libs libbpf >/dev/null 2>&1; then \
		>&2 echo "WARNING: libkefir requires libbpf, you may want to install it as well"; fi
	$(Q)$(INSTALL) -d -m 755 $(DESTPREF)/$(LIBDIR)
	$(Q)cp -fpt $(DESTPREF)/$(LIBDIR) $(LIBKEFIR_A) $(LIBKEFIR_SO).$(KEFIR_FULLVERSION)
	$(Q)ln -sf $(DESTPREF)/$(LIBDIR)/$(notdir $(LIBKEFIR_SO)).$(KEFIR_FULLVERSION) \
		$(DESTPREF)/$(LIBDIR)/$(notdir $(LIBKEFIR_SO)).$(KEFIR_VERSION)
	$(Q)ln -sf $(DESTPREF)/$(LIBDIR)/$(notdir $(LIBKEFIR_SO)).$(KEFIR_FULLVERSION) \
		$(DESTPREF)/$(LIBDIR)/$(notdir $(LIBKEFIR_SO))

install_pkgconfig: $(PC_FILE)
	$(Q)$(INSTALL) -d -m 755 $(DESTPREF)/$(LIBDIR)/pkgconfig
	$(Q)$(INSTALL) -m 644 -t $(DESTPREF)/$(LIBDIR)/pkgconfig $<

install: install_headers install_lib install_pkgconfig

uninstall:
	$(Q)$(RM) -r -- $(DESTPREF)/include/kefir
	$(Q)$(RM) -- $(DESTPREF)/$(LIBDIR)/$(notdir $(LIBKEFIR_SO))
	$(Q)$(RM) -- $(DESTPREF)/$(LIBDIR)/$(notdir $(LIBKEFIR_SO).$(KEFIR_VERSION))
	$(Q)$(RM) -- $(DESTPREF)/$(LIBDIR)/$(notdir $(LIBKEFIR_SO).$(KEFIR_FULLVERSION))
	$(Q)$(RM) -- $(DESTPREF)/$(LIBDIR)/$(notdir $(LIBKEFIR_A))
	$(Q)$(RM) -- $(DESTPREF)/$(LIBDIR)/pkgconfig/$(notdir $(PC_FILE))

.PHONY: install install_headers install_lib install_pkgconfig uninstall
