/*
 * Copyright (c) 2001-2004, Raphael Manfredi & Richard Eckart
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

#ifndef _gtk_notebooks_h_
#define _gtk_notebooks_h_

/**
 * For GTK1 these must be in the same order as the notebook tabs.
 */
enum {
    nb_main_page_network,
    nb_main_page_search,
    nb_main_page_downloads,
    nb_main_page_uploads,

    nb_main_page_stats,
    nb_main_page_monitor,

    nb_main_page_uploads_stats,
    nb_main_page_hostcache,
    nb_main_page_search_stats,

    nb_main_page_num
};


/**
 * Notebook tabs in the preferences dialog.
 */
enum {
    nb_prefs_net = 0,
    nb_prefs_gnet,
    nb_prefs_bw,
    nb_prefs_dl,
    nb_prefs_ul,
    nb_prefs_ui,
    nb_prefs_dbg,

    nb_prefs_num
};

#endif /* _gtk_notebooks_h_ */

/* vi: set sw=4 ts=4 cindent: */
