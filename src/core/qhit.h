/*
 * $Id$
 *
 * Copyright (c) 2001-2004, Raphael Manfredi
 *
 * Query hit management.
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

#ifndef _core_qhit_h_
#define _core_qhit_h_

#include <glib.h>

typedef void (*qhit_process_t)(gpointer data, gint len, gpointer udata);

/*
 * Public interface.
 */

struct gnutella_node;

void qhit_init(void);
void qhit_close(void);

void qhit_send_results(
	struct gnutella_node *n, GSList *files, gint count, gboolean use_ggep_h);
void qhit_build_results(
	qhit_process_t cb, gpointer udata,
	gchar *muid, GSList *files, gint count, gboolean use_ggep_h);

#endif /* _core_qhit_h_ */

/* vi: set ts=4: */
