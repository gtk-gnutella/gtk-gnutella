/*
 * $Id$
 *
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
	gchar *outbuf;			/**< Output buffer start */
	gchar *end;				/**< First char beyond output buffer */
	gchar *o;				/**< Where next non-NUL data will be written */
	gchar *cp;				/**< Where we'll write the code length */
	guchar code;			/**< Current code length */
	guchar last_code;		/**< Last code we emitted */
	gboolean saw_nul;		/**< True if we saw a NUL in the input */
	gboolean closed;		/**< True if the stream has been closed */
} cobs_stream_t;

/*
 * Public interface.
 */

struct iovec;

gchar *cobs_encode(gchar *buf, size_t len, size_t *retlen);
gchar *cobs_encodev(struct iovec *iov, gint iovcnt, size_t *retlen);
gchar *cobs_decode(gchar *buf, size_t len, size_t *retlen, gboolean inplace);
gboolean cobs_decode_into(
	const gchar *buf, size_t len, gchar *out, size_t outlen, size_t *retlen);

gboolean cobs_is_valid(const gchar *buf, size_t len);

void cobs_stream_init(cobs_stream_t *cs, gpointer data, size_t len);
size_t cobs_stream_close(cobs_stream_t *cs, gboolean *saw_nul);
gboolean cobs_stream_write(cobs_stream_t *cs, gpointer data, size_t len);
void cobs_stream_invalidate(cobs_stream_t *cs);
gboolean cobs_stream_is_valid(cobs_stream_t *cs);

#endif	/* _cobs_h_ */

/* vi: set ts=4 sw=4 cindent: */
