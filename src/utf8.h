/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Unicode Transformation Format 8 bits.
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

#ifndef _utf8_h_
#define _utf8_h_

#include <glib.h>

gint utf8_is_valid_char(guchar *s);
gint utf8_is_valid_string(guchar *s, gint len);
guint32 utf8_decode_char(guchar *s, gint len, gint *retlen, gboolean warn);
gint utf8_to_iso8859(guchar *s, gint len, gboolean space);

#endif	/* _utf8_h_ */

/* vi: set ts=4: */

