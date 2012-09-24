/*
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * Zlib wrapper functions.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _zlib_util_h_
#define _zlib_util_h_

#include "common.h"

struct zlib_deflater;
typedef struct zlib_deflater zlib_deflater_t;

/*
 * Public interface.
 */

const char *zlib_strerror(int errnum);

zlib_deflater_t *zlib_deflater_make(const void *data, int len, int level);
zlib_deflater_t *zlib_deflater_make_into(
	const void *data, int len, void *dest, int destlen, int level);
int zlib_deflate(zlib_deflater_t *zd, int amount);
int zlib_deflate_step(zlib_deflater_t *zd, int amount, bool may_close);
bool zlib_deflate_data(zlib_deflater_t *zd, const void *data, int len);
bool zlib_deflate_close(zlib_deflater_t *zd);
void zlib_deflater_free(zlib_deflater_t *zd, bool output);
void zlib_deflater_reset(zlib_deflater_t *zd, const void *data, int len);
void zlib_deflater_reset_into(zlib_deflater_t *zd,
	const void *data, int len, void *dest, int destlen);

bool zlib_deflater_closed(const struct zlib_deflater *zd);
int zlib_deflater_inlen(const struct zlib_deflater *zd);
int zlib_deflater_outlen(const struct zlib_deflater *zd);
void *zlib_deflater_out(const struct zlib_deflater *zd);

void *zlib_uncompress(const void *data, int len, ulong uncompressed_len);
int zlib_inflate_into(const void *data, int len, void *out, int *outlen);
bool zlib_is_valid_header(const void *data, int len);

void zlib_free_func(void *unused_opaque, void *p);
void *zlib_alloc_func(void *unused_opaque, uint n, uint m);

#endif	/* _zlib_util_h_ */

/* vi: set ts=4 sw=4 cindent: */

