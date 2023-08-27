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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _gtk_settings_h_
#define _gtk_settings_h_

/***
 *** Properties
 ***/

#include "if/gui_property.h"

void settings_gui_early_init(void);
void settings_gui_init(void);
void settings_gui_restore_panes(void);
const gchar *settings_gui_config_dir(void);
GtkTooltips *settings_gui_tooltips(void);
void settings_gui_save_if_dirty(void);
void settings_gui_shutdown(void);
gboolean show_metric_units(void);

void ancient_version_dialog_show(void);
void ancient_version_dialog_hide(void);

#endif /* _gtk_settings_h_ */

/* vi: set ts=4 sw=4 cindent: */
