/* -*- mode: cc-mode; tab-width:4; -*-
 *
 * $Id$
 *
 * Copyright (c) 2002-2003, Alex Bennee <alex@bennee.com> & Raphael Manfredi
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

#ifndef _sq_h_
#define _sq_h_

#include <sys/time.h> 	/* for time_t */
#include <glib.h>	 	/* for glib types */

#include "pmsg.h"
#include "ui_core_interface_sq_defs.h"

/*
 * Public interfaces
 */

squeue_t *sq_make(struct gnutella_node *node);
void sq_clear(squeue_t *sq);
void sq_free(squeue_t *sq);
void sq_putq(squeue_t *sq, gnet_search_t sh, pmsg_t *mb);
void sq_process(squeue_t *sq, time_t now);
void sq_search_closed(squeue_t *sq, gnet_search_t sh);

/* vi: set ts=4: */
#endif /* _sq_h_ */
