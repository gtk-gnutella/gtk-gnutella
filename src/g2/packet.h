/*
 * Copyright (c) 2004, Jeroen Asselman
 *
 * G2 packet parser / constructor
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
 
#include <glib.h>

typedef struct g2packet_s g2packet_t;
struct g2packet_s
{
	gboolean     compound;
	gboolean     has_children;
	gboolean     big_endian;

	char	 control;
	int		 name_length;
	char	*name;
	char	*payload;
	char	*orig_payload;
	int		 payload_length;
};

g2packet_t *g2_new_packet();
void g2_free_packet(g2packet_t *packet);
char *g2_packet_get_name(g2packet_t *packet);
g2packet_t *g2_packet_get_next_child(g2packet_t *basepacket);
char *g2_packet_get_payload(g2packet_t *packet, int *length);
void g2_packet_add_child(g2packet_t *packet, g2packet_t *child);
void g2_packet_add_payload(g2packet_t *packet, char *payload, int length);
char *g2_packet_pack(g2packet_t *packet, int *length);
