/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Consistant Overhead Byte Stuffing (COBS).
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

#ifndef _cobs_h_
#define _cobs_h_

#include <glib.h>

/*
 * A COBS stream is used to fill a buffer space with COBS-ed data where
 * the input data is not known beforehand but gathered a piece at a time.
 */
typedef struct cobs_stream {
	gchar *outbuf;			/* Output buffer start */
	gchar *end;				/* First char beyond output buffer */
	gchar *o;				/* Where next non-NUL data will be written */
	gchar *cp;				/* Where we'll write the code length */
	gint code;				/* Current code length */
	gint last_code;			/* Last code we emitted */
	gboolean saw_nul;		/* True if we saw a NUL in the input */
} cobs_stream_t;

/*
 * Public interface.
 */

struct iovec;

gchar *cobs_encode(gchar *buf, gint len, gint *retlen);
gchar *cobs_encodev(struct iovec *iov, gint iovcnt, gint *retlen);
gchar *cobs_decode(gchar *buf, gint len, gint *retlen, gboolean inplace);
gboolean cobs_decode_into(
	gchar *buf, gint len, gchar *out, gint outlen, gint *retlen);

gboolean cobs_is_valid(gchar *buf, gint len);

void cobs_stream_init(cobs_stream_t *cs, gpointer data, gint len);
gint cobs_stream_close(cobs_stream_t *cs, gboolean *saw_nul);
gboolean cobs_stream_write(cobs_stream_t *cs, gpointer data, gint len);

#endif	/* _cobs_h_ */

/* vi: set ts=4: */

