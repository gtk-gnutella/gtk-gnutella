/*
 * Copyright (c) 2004, Raphael Manfredi
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
 * Time synchronization support.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _core_tsync_h_
#define _core_tsync_h_

#include "common.h"

#include "lib/tm.h"

/*
 * Public interface.
 */

struct gnutella_node;
struct nid;

void tsync_init(void);
void tsync_close(void);

void tsync_send(struct gnutella_node *n, const struct nid *node_id);
void tsync_send_timestamp(tm_t *orig, tm_t *final);
void tsync_got_request(struct gnutella_node *n, tm_t *got);
void tsync_got_reply(struct gnutella_node *n,
	tm_t *sent, tm_t *received, tm_t *replied, tm_t *got, bool ntp);

#endif /* _core_tsync_h_ */

/* vi: set ts=4 sw=4 cindent: */
