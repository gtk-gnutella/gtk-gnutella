/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Richard Eckart
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

#ifndef _settings_gui_h_
#define _settings_gui_h_

#include "gui.h"

/***
 *** Properties
 ***/
#include "gui_property.h"

extern gchar *gui_config_dir;

prop_def_t *gui_prop_get_def(gui_property_t);

void gui_prop_add_prop_changed_listener
    (property_t, prop_changed_listener_t, gboolean);
void gui_prop_remove_prop_changed_listener
    (property_t, prop_changed_listener_t);

void settings_gui_init(void);
void settings_gui_shutdown(void);

#endif /* _settings_gui_h_ */
