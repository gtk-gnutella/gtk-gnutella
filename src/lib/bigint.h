/*
 * Copyright (c) 2012, Raphael Manfredi
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Big integer arithmetic operations.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _bigint_h_
#define _bigint_h_

enum bigint_magic { BIGINT_MAGIC = 0x3c1a6f4e };

/**
 * Fake structure defined to allow static variables of type bigint_t.
 */
struct bigint_fake {
	const enum bigint_magic m;
	const size_t len;
	const uint8 *p;
	const unsigned flags;
};

typedef struct bigint_fake bigint_t;

/*
 * Public interface.
 */

void bigint_use(bigint_t *bi, void *array, size_t len);
bigint_t *bigint_new(size_t len);
void bigint_init(bigint_t *bi, size_t len);
void bigint_free(bigint_t *bi);
void bigint_zero(bigint_t *bi);
void bigint_copy(bigint_t *res, const bigint_t *other);
bool bigint_is_zero(const bigint_t *bi);
int bigint_cmp(const bigint_t *bi1, const bigint_t *bi2);
void bigint_set32(bigint_t *bi, uint32 val);
void bigint_set64(bigint_t *bi, uint64 val);
void bigint_set_nth_bit(bigint_t *bi, size_t n);
bool bigint_is_positive(const bigint_t *bi);
void bigint_negate(bigint_t *bi);
void bigint_not(bigint_t *bi);
bool bigint_add(bigint_t *res, const bigint_t *other);
bool bigint_add_u8(bigint_t *bi, uint8 val);
bool bigint_lshift(bigint_t *bi);
void bigint_rshift(bigint_t *bi);
void bigint_rshift_bytes(bigint_t *bi, size_t n);
uint8 bigint_mult_u8(bigint_t *bi, uint8 val);
void bigint_divide(const bigint_t *bi1, const bigint_t *bi2,
	bigint_t *qi, bigint_t *ri);
double bigint_to_double(const bigint_t *bi);
uint64 bigint_to_uint64(const bigint_t *bi);
const char *bigint_to_hex_string(const bigint_t *bi);

#endif /* _bigint_h_ */

/* vi: set ts=4 sw=4 cindent: */
