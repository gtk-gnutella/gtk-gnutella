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

#ifndef _statusbar_gui_h_
#define _statusbar_gui_h_

#include "gui.h"

/* 
 * Context ids for the status bar 
 */
extern guint scid_hostsfile;
extern guint scid_search_autoselected;
extern guint scid_queue_freezed;
extern guint scid_info;
extern guint scid_warn;
extern guint scid_ip_changed;

typedef enum {
    SB_MESSAGE,
    SB_WARNING
} sb_types_t;

typedef struct {
    guint scid;
    guint msgid;
} statusbar_msgid_t;

/*
 * Public interface.
 */
#define statusbar_gui_message(t, ...) \
	statusbar_gui_push(SB_MESSAGE, scid_info, t, __VA_ARGS__)

#define statusbar_gui_warning(t, ...) \
	statusbar_gui_push(SB_WARNING, scid_warn, t, __VA_ARGS__)

void statusbar_gui_init(void);
void statusbar_gui_shutdown(void);

void statusbar_gui_clear_timeouts(time_t now);

void statusbar_gui_set_default(const gchar *, ...) G_GNUC_PRINTF(1, 2);
statusbar_msgid_t statusbar_gui_push
    (sb_types_t, guint, guint, const gchar *, ...) G_GNUC_PRINTF(4, 5);
void statusbar_gui_remove(statusbar_msgid_t);

/* vi: set ts=4: */
#endif /* _statusbar_gui_h_ */
