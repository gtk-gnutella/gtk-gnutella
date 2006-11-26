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
 * Base32 encoding/decoding.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _base32_h_
#define _base32_h_

#include "common.h"

/*
 * Public interface.
 */

gchar *base32_encode(const gchar *buf, gint len, gint *retpad, gboolean padding);
void base32_encode_into(const gchar *buf, gint len,
	gchar *encbuf, gint enclen);
void base32_encode_str_into(const gchar *buf, gint len,
	gchar *encbuf, gint enclen, gboolean padding);

gchar *base32_decode(const gchar *buf, gint len, gint *outbuf);
gint base32_decode_into(const gchar *buf, gint len,
	gchar *decbuf, gint declen);
gint base32_decode_old_into(const gchar *buf, gint len,
	gchar *decbuf, gint declen);

#endif	/* _base32_h_ */

/* vi: set ts=4: */

