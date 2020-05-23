/*
 * Copyright (c) 2004, Thomas Schuerger & Jeroen Asselman
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Horizon Size Estimation Protocol 0.2.
 *
 * @author Thomas Schuerger
 * @author Jeroen Asselman
 * @date 2004
 */

#ifndef _core_hsep_h_
#define _core_hsep_h_

#include "common.h"

#include "lib/event.h"		/* For frequency_t */
#include "if/core/hsep.h"

#define HSEP_VERSION_MAJOR 0
#define HSEP_VERSION_MINOR 2

/**
 * Average time in seconds before resending a HSEP message to a node
 * (can be increased to 60).
 */
#define HSEP_MSG_INTERVAL 30

/**
 * Random skew in seconds for message interval times is in the interval
 * msg_interval +/- msg_skew.
 */
#define HSEP_MSG_SKEW 10

/*
 * Public interface.
 */

typedef void (*hsep_global_listener_t) (hsep_triple *table, uint32 triples);

struct gnutella_node;

void hsep_init(void);
void hsep_reset(void);
void hsep_close(void);
void hsep_connection_init(struct gnutella_node *n, uint8 major, uint8 minor);
void hsep_connection_close(struct gnutella_node *n, bool in_shutdown);
void hsep_send_msg(struct gnutella_node *, time_t now);
void hsep_process_msg(struct gnutella_node *, time_t now);
void hsep_timer(time_t now);
void hsep_notify_shared(uint64 ownfiles, uint64 ownkibibytes);
unsigned int hsep_get_global_table(hsep_triple *buffer,
	unsigned int maxtriples);
unsigned int hsep_get_connection_table(const struct gnutella_node *n,
	hsep_triple *buffer, unsigned int maxtriples);

#endif /* _core_hsep_h_ */

/* vi: set ts=4 sw=4 cindent: */
