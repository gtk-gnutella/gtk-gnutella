/*
 * Copyright (c) 2008 Raphael Manfredi
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
 * Binary memory stream parsing.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#ifndef _bstr_h_
#define _bstr_h_

#include "common.h"

#include "host_addr.h"

/*
 * A binary stream.
 */

struct bstr;
typedef struct bstr bstr_t;

/*
 * Flags for bstr_open(), on 16 bits.
 */

#define BSTR_F_ERROR	(1 << 0)	/**< Build error message string */

/*
 * Public interface
 */

bstr_t *bstr_open(const void *arena, size_t len, uint32 flags);
bstr_t *bstr_create(void);
void bstr_close(bstr_t *);
void bstr_reset(bstr_t *, const void *arena, size_t len, uint32 flags);
bool bstr_has_error(const bstr_t *);
void bstr_clear_error(bstr_t *);
void bstr_free(bstr_t **);
const char *bstr_error(const bstr_t *);
bool bstr_ended(const bstr_t *bs);
void bstr_trailing_error(bstr_t *bs);

size_t bstr_unread_size(const bstr_t *);
const void *bstr_read_base(const bstr_t *);
bool bstr_skip(bstr_t *, size_t count);
bool bstr_read(bstr_t *, void *buf, size_t count);
bool bstr_read_u8(bstr_t *, uint8 *pv);
bool bstr_read_boolean(bstr_t *, bool *pv);
bool bstr_read_le16(bstr_t *, uint16 *pv);
bool bstr_read_be16(bstr_t *, uint16 *pv);
bool bstr_read_le32(bstr_t *, uint32 *pv);
bool bstr_read_be32(bstr_t *, uint32 *pv);
bool bstr_read_be64(bstr_t *, uint64 *pv);
bool bstr_read_time(bstr_t *, time_t *pv);
bool bstr_read_float_be(bstr_t *, float *pv);
bool bstr_read_ipv4_addr(bstr_t *, host_addr_t *);
bool bstr_read_ipv6_addr(bstr_t *, host_addr_t *);
bool bstr_read_packed_ipv4_or_ipv6_addr(bstr_t *, host_addr_t *);
bool bstr_read_packed_array_u8(bstr_t *,
	size_t max, void *ptr, uint8 *pr);
bool bstr_read_ule64(bstr_t *, uint64 *pv);
bool bstr_read_fixed_string(bstr_t *, size_t *slen, char *buf, size_t len);
bool bstr_read_string(bstr_t *, size_t *slen, char **sptr);

#endif	/* _bstr_h_ */

/* vi: set ts=4 sw=4 cindent: */
