/*
 * Copyright (c) 2007, Christian Biere
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
 * @ingroup gtk
 * @file
 *
 * Drag support - no dropping, just dragging.
 *
 * @author Christian Biere
 * @date 2007
 */

#ifndef _drag_init_h_
#define _drag_init_h_

#include "common.h"
#include "gtk/gui.h"

/**
 * This callback must return either NULL or a newly-allocated string.
 */
typedef char *(*drag_get_data_cb)(GtkWidget *);

void drag_attach_text(GtkWidget *, drag_get_data_cb);
void drag_attach_uri(GtkWidget *, drag_get_data_cb);

#if GTK_CHECK_VERSION(2,0,0)
gboolean drag_get_iter(GtkTreeView *, GtkTreeModel **, GtkTreeIter *);
#endif /* GTK+ >= 2 */

#endif /* _drag_init_h_ */

/* vi: set ts=4 sw=4 cindent: */
