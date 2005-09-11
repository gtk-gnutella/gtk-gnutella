/*
 * $Id$
 *
 * Copyright (c) 2004, Jeroen Asselman
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
 * @ingroup undoc
 * @file
 *
 * Glue between Gtk-Gnutella and the G2 'lib'.
 *
 * @author Jeroen Asselman
 * @date 2004
 */

#ifdef ENABLE_G2

#include "pmsg.h"
#include "nodes.h"
#include "g2node.h"
#include "g2/packetstream.h"

void
g2_node_init()
{
	g2_packetstream_init();
}

void
g2_node_close()
{
	g2_packetstream_close();
}

gboolean
g2_node_read(struct gnutella_node *n, pmsg_t *mb)
{
	g2packetstream_t *packetstream = g2_packetstream_get((gpointer) n);
	char *data = NULL;
	int r;

	if (packetstream == NULL) {
		packetstream = g2_packetstream_new((gpointer) n);

		/* Get the amount of data expected */
		n->size = g2_packetstream_put_data(packetstream, NULL, 0);
	}

	data = malloc(n->size);

	r = pmsg_read(mb, data, n->size);

	n->size = g2_packetstream_put_data(packetstream, data, r);

	if (data != NULL)
		free(data);

	return FALSE;
}

void
g2_node_disconnected(struct gnutella_node *n)
{
	g2packetstream_t *packetstream = g2_packetstream_get((gpointer) n);
	if (packetstream != NULL)
		g2_packetstream_free((gpointer) n);
}

#endif /* ENABLE_G2 */

/* vi: set ts=4 sw=4 cindent: */
