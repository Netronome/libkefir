/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef LIBKEFIR_PARSE_H
#define LIBKEFIR_PARSE_H

#include "libkefir_internals.h"

int parse_check_and_store_uint(unsigned int res, void *output,
			       uint32_t nb_bits);
int parse_uint(const char *input, void *output, uint32_t nb_bits);
int parse_uint_slash_mask(const char *input, void *output, uint32_t nb_bits,
			  uint8_t *mask);
int parse_eth_addr(const char *input, struct ether_addr *output);
int parse_eth_addr_slash_mask(const char *input, struct ether_addr *output,
			      uint8_t *mask);
int parse_ipv4_addr(const char *input, uint32_t *output);
int parse_ipv4_addr_slash_mask(const char *input, uint32_t *output,
			       uint8_t *mask);
int parse_ipv6_addr(const char *input, uint32_t *output);
int parse_ipv6_addr_slash_mask(const char *input, uint32_t *output,
			       uint8_t *mask);

#endif /* LIBKEFIR_PARSE_H */
