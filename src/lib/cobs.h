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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Consistant Overhead Byte Stuffing (COBS).
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _cobs_h_
#define _cobs_h_

#include "common.h"

enum cobs_magic { COBS_MAGIC = 0xc0befU };

/**
 * A COBS stream is used to fill a buffer space with COBS-ed data where
 * the input data is not known beforehand but gathered a piece at a time.
 */
typedef struct cobs_stream {
	enum cobs_magic magic;	/**< Magic number */
	char *outbuf;			/**< Output buffer start */
	char *end;				/**< First char beyond output buffer */
	char *o;				/**< Where next non-NUL data will be written */
	char *cp;				/**< Where we'll write the code length */
	uchar code;				/**< Current code length */
	uchar last_code;		/**< Last code we emitted */
	bool saw_nul;			/**< True if we saw a NUL in the input */
	bool closed;			/**< True if the stream has been closed */
} cobs_stream_t;

/*
 * Public interface.
 */


char *cobs_encode(char *buf, size_t len, size_t *retlen);
char *cobs_encodev(iovec_t *iov, int iovcnt, size_t *retlen);
char *cobs_decode(char *buf, size_t len, size_t *retlen, bool inplace);
bool cobs_decode_into(
	const char *buf, size_t len, char *out, size_t outlen, size_t *retlen);

bool cobs_is_valid(const char *buf, size_t len);

void cobs_stream_init(cobs_stream_t *cs, void *data, size_t len);
size_t cobs_stream_close(cobs_stream_t *cs, bool *saw_nul);
bool cobs_stream_write(cobs_stream_t *cs, void *data, size_t len);
void cobs_stream_invalidate(cobs_stream_t *cs);
bool cobs_stream_is_valid(cobs_stream_t *cs);

#endif	/* _cobs_h_ */

/* vi: set ts=4 sw=4 cindent: */
