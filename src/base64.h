/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
 *
 * Base64 encoding/decoding.
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

#ifndef _base64_h_
#define _base64_h_

#include <glib.h>

/*
 * Public interface.
 */

guchar *base64_encode(const guchar *buf, gint len, gint *retpad);
void base64_encode_into(const guchar *buf, gint len,
	guchar *encbuf, gint enclen);

guchar *base64_decode(const guchar *buf, gint len);
gboolean base64_decode_into(const guchar *buf, gint len,
	guchar *decbuf, gint declen);

#endif	/* _base64_h_ */

/* vi: set ts=4: */

