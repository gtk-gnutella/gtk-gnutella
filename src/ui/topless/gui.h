/*
 * $Id$
 *
 * Copyright (c) 2005, Christian Biere
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

#ifndef _gui_gui_h_
#define _gui_gui_h_

/* Diverse dummy definitions */
#define settings_gui_save_if_dirty()

#define main_gui_early_init(argc, argv)
#define main_gui_init()
#define main_gui_timer()
#define main_gui_update_coords()
#define main_gui_shutdown()
#define main_gui_shutdown_tick(remain)
#define settings_gui_shutdown()

#define drop_init()
#define drop_close()

#define search_gui_store_searches()

#define icon_timer()

static inline void
main_gui_run(void)
{
	GMainLoop *ml;

#if defined(USE_GLIB1)
	ml = g_main_new(FALSE);
	g_main_run(ml);
#elif defined(USE_GLIB2)
	ml = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(ml);
#endif /* GLIB */
}

#endif /* _gui_gui_h_ */
/* vi: set ts=4 sw=4 cindent: */
