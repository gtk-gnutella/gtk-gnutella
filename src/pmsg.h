/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * PDU Messages.
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

#ifndef _pmsg_h_
#define _pmsg_h_

#include <glib.h>
#include "ui_core_interface_pmsg_defs.h"

/*
 * Public interface
 */

void pmsg_init(void);
void pmsg_close(void);

gint pmsg_size(pmsg_t *mb);
pmsg_t *pmsg_new(gint prio, void *buf, gint len);
pmsg_t * pmsg_new_extend(
	gint prio, void *buf, gint len, pmsg_free_t free, gpointer arg);
pmsg_t *pmsg_alloc(gint prio, pdata_t *db, gint roff, gint woff);
pmsg_t *pmsg_clone(pmsg_t *mb);
pmsg_t *pmsg_clone_extend(pmsg_t *mb, pmsg_free_t free, gpointer arg);
void pmsg_free(pmsg_t *mb);
gint pmsg_write(pmsg_t *mb, gpointer data, gint len);
gint pmsg_read(pmsg_t *mb, gpointer data, gint len);

pdata_t *pdata_new(gint len);
pdata_t *pdata_allocb(void *buf, gint len,
	pdata_free_t freecb, gpointer freearg);
pdata_t *pdata_allocb_ext(void *buf, gint len,
	pdata_free_t freecb, gpointer freearg);
void pdata_free_nop(gpointer p, gpointer arg);
void pdata_unref(pdata_t *db);

#endif	/* _pmsg_h_ */

/* vi: set ts=4: */
