/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Globally Unique ID (GUID) manager.
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

#ifndef _guid_h_
#define _guid_h_

#include <glib.h>

/*
 * Public interface.
 */

void guid_init(void);
gboolean guid_is_gtkg(guchar *xuid, guint8 *majp, guint8 *minp, gboolean *relp);
gboolean guid_is_requery(guchar *xuid);
void guid_random_fill(guchar *xuid);
void guid_random_muid(guchar *muid);
void guid_ping_muid(guchar *muid);
void guid_query_muid(guchar *muid, gboolean initial);

#endif /* _guid_h_ */
