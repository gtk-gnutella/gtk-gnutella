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

#ifndef _if_ui_gtk_upload_stats_h_
#define _if_ui_gtk_upload_stats_h_

#include "common.h"

/*
 * Public interface, visible from the bridge.
 */

#ifdef GUI_SOURCES

struct ul_stats;

void upload_stats_gui_init(void);
void upload_stats_gui_update(const gchar *name, guint64 size);
void upload_stats_gui_clear_all(void);
void upload_stats_gui_add(struct ul_stats *s);

#endif /* GUI_SOURCES */
#endif /* _if_ui_gtk_upload_stats_h_ */

/* vi: set ts=4 sw=4 cindent: */
