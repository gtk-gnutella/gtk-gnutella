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

#ifndef _gtk_downloads_common_h_
#define _gtk_downloads_common_h_

#include "if/ui/gtk/downloads.h"

void gui_update_download_clear_now(void);

void gui_update_c_downloads(gint, gint);

void on_button_downloads_clear_stopped_clicked(
	GtkButton *button, gpointer user_data);
void on_togglebutton_queue_freeze_toggled(
	GtkToggleButton *togglebutton, gpointer user_data);

#endif /* _gtk_downloads_common_h_ */
