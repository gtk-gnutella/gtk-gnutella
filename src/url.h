/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
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

#ifndef _url_h_
#define _url_h_

#include <glib.h>

/*
 * Public interface.
 */

gchar *url_escape(gchar *url);
gchar *url_escape_query(gchar *url);
gint url_escape_into(const gchar *url, gchar *target, gint len);
gchar *url_escape_cntrl(gchar *url);
gchar *url_unescape(gchar *url, gboolean inplace);

#endif	/* _url_h_ */

/* vi: set ts=4: */

