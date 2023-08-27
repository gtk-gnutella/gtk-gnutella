/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _if_ui_gtk_misc_h_
#define _if_ui_gtk_misc_h_

/*
 * Public interface, visible from the bridge.
 */

#ifdef GUI_SOURCES

void gui_update_files_scanned(void);
void gui_allow_rescan_dir(gboolean flag);

#endif /* GUI_SOURCES */
#endif /* _if_ui_gtk_misc_h_ */

/* vi: set ts=4 sw=4 cindent: */
