/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

#ifndef _gtk_notebooks_h_
#define _gtk_notebooks_h_

enum {
    nb_main_page_gnet = 0,
    nb_main_page_uploads,
    nb_main_page_uploads_stats,
    nb_main_page_downloads,
    nb_main_page_search,
    nb_main_page_monitor,
    nb_main_page_search_stats,
    nb_main_page_gnet_stats,
    nb_main_page_hostcache,

    nb_main_page_num
};


/*
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

/*
 * Notebook tabs in the downloads page.
 */
enum {
	nb_downloads_page_downloads = 0,
	nb_downloads_page_fileinfo,
	nb_downloads_page_num
};

/*
 * Nodes in the treemenu
 */
enum {
    TREEMENU_NODE_GNET = 0,
    TREEMENU_NODE_GNET_STATS,
    TREEMENU_NODE_HOSTCACHE,
    TREEMENU_NODE_UL,
    TREEMENU_NODE_UL_STATS,
    TREEMENU_NODE_DL,
    TREEMENU_NODE_SEARCH,
    TREEMENU_NODE_SEARCH_MON,
    TREEMENU_NODE_SEARCH_STATS,
    TREEMENU_NODE_CFG_SEL,
    TREEMENU_NODE_CFG_NET,
    TREEMENU_NODE_CFG_GNET,
    TREEMENU_NODE_CFG_BWC,
    TREEMENU_NODE_CFG_DL,
    TREEMENU_NODE_CFG_UL,
    TREEMENU_NODE_CFG_UI,
    TREEMENU_NODE_CFG_DBG,

    TREEMENU_NODES
};

#endif /* _gtk_notebooks_h_ */

/* vi: set ts=4: */
