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

#ifndef _uploads_gui_h_
#define _uploads_gui_h_

#include <glib.h>
#include <gtk/gtk.h>
#include <time.h>
#include "uploads.h"

typedef struct upload_row_data {
    gnet_upload_t handle;      /* upload handle in backend */
    gboolean      valid;       /* handle still valid in backend */
    time_t        start_date;
    time_t        last_update; /* last time the gui updated */
    guint32       range_start;
    guint32       range_end;
    upload_stage_t status;      /* last known status */
#ifdef USE_GTK2
    GtkTreeIter   iter;
	guint32       ip;
	guint32       size;
	gboolean      push; 
	gchar         *user_agent;	/* atom */
	gchar         *name;		/* atom */
#endif
} upload_row_data_t;

void uploads_gui_early_init(void);
void uploads_gui_init(void);
void uploads_gui_shutdown(void);

void uploads_gui_update_display(time_t now);
void uploads_gui_clear_completed(void);


#endif /* _uploads_gui_h_ */
