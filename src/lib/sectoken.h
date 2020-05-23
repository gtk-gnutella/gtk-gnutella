/*
 * Copyright (c) 2011, Raphael Manfredi
 *
 *----------------------------------------------------------------------
 * This file is part of gtk-gnutella.
 *
 *  gtk-gnutella is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  gtk-gnutella is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with gtk-gnutella; if not, write to the Free Software
 *  Foundation, Inc.:
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Security tokens.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _sectoken_h_
#define _sectoken_h_

#include "host_addr.h"
#include "timestamp.h"

struct sectoken_gen;
typedef struct sectoken_gen sectoken_gen_t;

#define SECTOKEN_RAW_SIZE	4

/*
 * The security tokens we generate.
 */
typedef struct {
	uchar v[SECTOKEN_RAW_SIZE];
} sectoken_t;

/*
 * The security tokens we receive from other hosts.
 */
typedef struct {
	void *v;				/**< Token value (NULL if none) */
	uint8 length;			/**< Token length (0 if none) */
} sectoken_remote_t;

/*
 * Public interface.
 */

time_delta_t sectoken_lifetime(const sectoken_gen_t *stg);
void sectoken_generate(sectoken_gen_t *stg,
	sectoken_t *tok, host_addr_t addr, uint16 port);
void sectoken_generate_with_context(sectoken_gen_t *stg,
	sectoken_t *tok, host_addr_t addr, uint16 port,
	const void *data, size_t len);
bool sectoken_is_valid(sectoken_gen_t *stg,
	const sectoken_t *tok, host_addr_t addr, uint16 port);
bool sectoken_is_valid_with_context(sectoken_gen_t *stg,
	const sectoken_t *tok, host_addr_t addr, uint16 port,
	const void *data, size_t len);
sectoken_remote_t *sectoken_remote_alloc(uint8 length);
void sectoken_remote_free(sectoken_remote_t *token, bool freedata);
sectoken_gen_t *sectoken_gen_new(size_t keys, time_delta_t refresh);
void sectoken_gen_free_null(sectoken_gen_t **stg_ptr);

#endif /* _sectoken_h_ */

/* vi: set ts=4 sw=4 cindent: */
