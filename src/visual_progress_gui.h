/*
 * $Id$
 *
 * Copyright (c) 2003-2004, Hans de Graaff
 *
 * Displaying the visual progress of downloading graphically.
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

#ifndef _visual_progress_gui_h_
#define _visual_progress_gui_h_

#include "gui.h"

/* 
 * General entry points for the control
 */
void vp_gui_init(void);
void vp_gui_shutdown(void);


/* 
 * External function for drawing information in supplied pixmap
 */
void vp_draw_fi_progress(gboolean valid, gnet_fi_t fih);


/*
 * Glade-generated callbacks
 */
gboolean
on_visual_progress_configure_event     (GtkWidget       *widget,
                                        GdkEventConfigure *event,
                                        gpointer         user_data);

gboolean
on_visual_progress_expose_event        (GtkWidget       *widget,
                                        GdkEventExpose  *event,
                                        gpointer         user_data);

void
on_visual_progress_realize             (GtkWidget       *widget,
                                        gpointer         user_data);

void
on_drawingarea_fi_progress_realize     (GtkWidget       *widget,
                                        gpointer         user_data);

gboolean
on_drawingarea_fi_progress_configure_event
                                        (GtkWidget       *widget,
                                        GdkEventConfigure *event,
                                        gpointer         user_data);

gboolean
on_drawingarea_fi_progress_expose_event
                                        (GtkWidget       *widget,
                                        GdkEventExpose  *event,
                                        gpointer         user_data);

#endif /* _visual_progress_gui_h_ */

