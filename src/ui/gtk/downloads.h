/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Richard Eckart
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

#ifndef _gtk_downloads_h_
#define _gtk_downloads_h_

#include "gui.h"
#include "downloads_common.h"

struct download;

/** Indicates that a dl node is a header node */
#define DL_GUI_IS_HEADER GINT_TO_POINTER(0x1)

/*
 * Global Functions
 */

void downloads_gui_init(void);
void downloads_gui_shutdown(void);
void downloads_gui_update_display(time_t now);

#ifdef USE_GTK1
GList *downloads_gui_collect_ctree_data(GtkCTree *ctree, GList *node_list,
	gboolean unselect, gboolean add_children);
void downloads_gui_expand_all(GtkCTree *ctree);
void downloads_gui_collapse_all(GtkCTree *ctree);
void downloads_update_active_pane(void);
void downloads_update_queue_pane(void);
#endif	/* Gtk+ 1.2 */

#endif /* _gtk_downloads_h_ */

/* vi: set ts=4 sw=4 cindent: */
