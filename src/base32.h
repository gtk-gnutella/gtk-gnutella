/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Base32 encoding/decoding.
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

#ifndef __base32_h__
#define __base32_h__

#include <glib.h>

/*
 * Public interaface.
 */

guchar *base32_encode(const guchar *buf, gint len, gint *retpad);
void base32_encode_into(const guchar *buf, gint len,
	guchar *encbuf, gint enclen);

guchar *base32_decode(const guchar *buf, gint len);
gboolean base32_decode_into(const guchar *buf, gint len,
	guchar *decbuf, gint declen);

#endif	/* __base32_h__ */

/* vi: set ts=4: */

