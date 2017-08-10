/*
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

#ifndef _gtk_uploads_h_
#define _gtk_uploads_h_

#include "gui.h"
#include "if/core/uploads.h"

typedef struct upload_row_data {
    gnet_upload_t handle;       /**< upload handle in backend */
    gboolean      valid;        /**< handle still valid in backend */
    time_t        start_date;	/**< time at which "row" was created */
    time_t        send_date;	/**< time at which we began sending back data */
    time_t        last_update;  /**< last time the gui updated */
    filesize_t    range_start;
    filesize_t    range_end;
    upload_stage_t status;      /**< last known status */
	host_addr_t   gnet_addr;	/**< Advertised IP address for browsing */
	guint16       gnet_port;	/**< Advertised port for browsing */
#ifdef USE_GTK2
    GtkTreeIter   iter;
	host_addr_t   addr;
	filesize_t    size;
	const gchar   *user_agent;	/**< atom */
	const gchar   *name;		/**< atom */
	gboolean      push;
	guint16       country;
#endif /* USE_GTK2 */
} upload_row_data_t;

void uploads_gui_init(void);
void uploads_gui_shutdown(void);

void uploads_gui_clear_completed(void);

#endif /* _gtk_uploads_h_ */

/* vi: set ts=4 sw=4 cindent: */
