/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
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

#ifndef __cobs_h__
#define __cobs_h__

#include <glib.h>

/*
 * Public interface.
 */

struct iovec;

guchar *cobs_encode(const guchar *buf, gint len, gint *retlen);
guchar *cobs_encodev(struct iovec *iov, gint iovcnt, gint *retlen);
guchar *cobs_decode(guchar *buf, gint len, gint *retlen, gboolean inplace);
gboolean cobs_decode_into(
	guchar *buf, gint len, guchar *out, gint outlen, gint *retlen);

#endif	/* __cobs_h__ */

/* vi: set ts=4: */

