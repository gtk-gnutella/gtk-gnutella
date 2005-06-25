/*
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
 * Needs short description here.
 *
 * @author Jeroen Asselman
 * @date 2004
 */

#ifndef _packetstream_h_
#define _packetstream_h_

#include <glib.h>
#include "packet.h"

typedef struct g2packetstream_s g2packetstream_t;

g2packetstream_t *g2_packetstream_new(gpointer *connection);
g2packetstream_t *g2_packetstream_get(gpointer *connection);
void g2_packetstream_free(gpointer *connection);
int g2_packetstream_put_data(g2packetstream_t *stream, char *data, int length);
g2packet_t *g2_packetstream_get_packet(g2packetstream_t *stream);
int g2_packetstream_get_error(g2packetstream_t *stream, char **errormessage);

#endif /* _packetstream_h_ */

/* vi: set ts=4 sw=4 cindent: */
