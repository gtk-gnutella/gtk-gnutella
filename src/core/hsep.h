/*
 * Copyright (c) 2004, Thomas Schuerger & Jeroen Asselman
 *
 * Horizon Size Estimation Protocol 0.2
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

#ifndef _core_hsep_h_
#define _core_hsep_h_

#include "lib/event.h"		/* For frequency_t */
#include "if/core/hsep.h"

#define HSEP_VERSION_MAJOR 0
#define HSEP_VERSION_MINOR 2

/*
 * average time in seconds before resending a HSEP message to a node
 * (can be increased to 60)
 */
#define HSEP_MSG_INTERVAL 30 

/*
 * random skew in seconds for message interval
 * time is in the interval msg_interval +/- msg_skew
 */
#define HSEP_MSG_SKEW 10

/*
 * Public interface.
 */

typedef void (*hsep_global_listener_t) (hsep_triple *table, guint32 triples);

void hsep_init(void);
void hsep_reset(void);
void hsep_close(void);
void hsep_connection_init(struct gnutella_node *n);
void hsep_connection_close(struct gnutella_node *n);
void hsep_send_msg(struct gnutella_node *, time_t now);
void hsep_process_msg(struct gnutella_node *, time_t now);
void hsep_dump_table(void);
void hsep_timer(time_t now);
void hsep_notify_shared(guint64 ownfiles, guint64 ownkibibytes);
void hsep_sanity_check(void);
void hsep_fire_global_table_changed(time_t now);
gboolean hsep_has_global_table_changed(time_t since);
gboolean hsep_check_monotony(hsep_triple *table, unsigned int triples);
unsigned int hsep_triples_to_send(const hsep_triple *table,
	unsigned int triples);
unsigned int hsep_get_global_table(hsep_triple *buffer,
	unsigned int maxtriples);
unsigned int hsep_get_connection_table(struct gnutella_node *n,
	hsep_triple *buffer, unsigned int maxtriples);
const gchar *hsep_get_static_str(gint row, gint column);

#endif /* _core_hsep_h_ */

/* vi: set ts=4: */
