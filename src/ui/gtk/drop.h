/*
 * Copyright (c) 2004, Christian Biere
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
 * Drop support - no dragging, just dropping.
 *
 * @author Christian Biere
 * @date 2004
 */

#ifndef _drop_h_
#define _drop_h_

#include "gui.h"

typedef void (*drag_data_received_cb)(GtkWidget *widget, GdkDragContext *dc,
				gint x, gint y, GtkSelectionData *data,
				guint info, guint stamp, gpointer udata);

void drop_widget_init(GtkWidget *widget, drag_data_received_cb callback,
		void *user_data);

#endif /* _drop_h_ */

/* vi: set ts=4 sw=4 cindent: */
