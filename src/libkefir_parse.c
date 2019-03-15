// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <string.h>

#include <arpa/inet.h>

#include "libkefir_parse.h"

DEFINE_ERR_FUNCTIONS("parser")

int parse_uint(const char *input, void *output, uint32_t nb_bits)
{
	unsigned int res;
	char *endptr;

	res = strtoul(input, &endptr, 10);
	if (*endptr != '\0') {
		err_fail("could not parse %s as int", input);
		return -1;
	}
	if (res >= (unsigned int)(2 << (nb_bits - 1))) {
		err_fail("value %s is too big", input);
		return -1;
	}

	if (nb_bits <= 8)
		*(uint8_t *)output = res;
	else if (nb_bits <= 16)
		*(uint16_t *)output = htons(res);
	else
		*(uint32_t *)output = htonl(res);
	return 0;
}

int parse_eth_addr(const char *input, struct ether_addr *output)
{
	struct ether_addr *addr;

	addr = ether_aton(input);

	if (!addr) {
		err_fail("could not parse ether address %s", input);
		return -1;
	}

	memcpy(output, addr, sizeof(struct ether_addr));

	/* "addr" statically allocated in ether_aton(), do not free it */

	return 0;
}

int parse_ipv4_addr(const char *input, uint32_t *output)
{
	if (inet_pton(AF_INET, input, output) != 1) {
		//err_fail("could not parse IPv4 %s", input);
		return -1;
	}

	return 0;
}

int parse_ipv6_addr(const char *input, uint8_t **output)
{
	if (inet_pton(AF_INET6, input, output) != 1) {
		//err_fail("could not parse IPv6 %s", input);
		return -1;
	}

	return 0;
}
