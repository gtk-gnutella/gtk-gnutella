/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

#ifndef _if_ui_gtk_downloads_h_
#define _if_ui_gtk_downloads_h_

#include "common.h"

/*
 * Public interface, visible from the bridge.
 */

#ifdef GUI_SOURCES

struct download;

void gui_download_enable_start_now(
	guint32 running_downloads, guint32 max_downloads);

void download_gui_add(struct download *d);
void download_gui_remove(struct download *d);

void gui_update_download(struct download *, gboolean);
void gui_update_download_server(struct download *);
void gui_update_download_range(struct download *d);
void gui_update_download_size(struct download *d);
void gui_update_download_host(struct download *d);
void gui_update_download_abort_resume(void);
void gui_update_download_clear(void);
void gui_update_queue_frozen(void);
void gui_update_download_clear_now(void);

#endif /* GUI_SOURCES */
#endif /* _if_ui_gtk_downloads_h_ */

/* vi: set ts=4 sw=4 cindent: */
