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
 * @ingroup core
 * @file
 *
 * Alive status checking ping/pongs.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_alive_h_
#define _core_alive_h_

#include <glib.h>

struct gnutella_node;

/*
 * Public interface.
 */

gpointer alive_make(struct gnutella_node *n, gint max);
void alive_free(gpointer obj);
gboolean alive_send_ping(gpointer obj);
gboolean alive_ack_ping(gpointer obj, const gchar *muid);
void alive_ack_first(gpointer obj, const gchar *muid);
void alive_get_roundtrip_ms(gconstpointer obj, guint32 *avg, guint32 *last);

#endif /* _core_alive_h_ */

