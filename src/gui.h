/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi & Richard Eckart
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

#ifndef _gui_h_
#define _gui_h_

#include "gnet.h"

#include <gtk/gtk.h>

#include "interface-glade1.h"
#include "support-glade1.h"

#include "gui_property.h"
#include "gui_property_priv.h"
#include "gtk-missing.h"


#ifndef USE_GTK2
#define g_ascii_strcasecmp g_strcasecmp
#endif

/*
 * Uploads table columns
 */
enum {
    c_ul_filename = 0,
    c_ul_host,
    c_ul_size,
    c_ul_range,
    c_ul_agent,
    c_ul_status
};



/*
 * Uploads table columns
 */
enum {
    c_us_filename = 0,
    c_us_size,
    c_us_attempts,
    c_us_complete,
    c_us_norm,
	c_us_size_val,
	c_us_norm_val,
	c_us_stat,

	c_us_num
};




/*
 * Downloads table columns
 */
enum {
    c_dl_filename = 0,
    c_dl_host,
    c_dl_size,
    c_dl_range,
    c_dl_server,
    c_dl_status
};

/*
 * Queue table columns
 */
enum {
    c_queue_filename = 0,
    c_queue_host,
    c_queue_size,
    c_queue_server,
    c_queue_status
};



/*
 * Searches table columns
 */
enum {
    c_sr_filename = 0,
    c_sr_size,
    c_sr_speed,
    c_sr_host,
    c_sr_urn,
    c_sr_info,
#ifdef USE_GTK2
	c_sr_record, /* invisible, pointer to the record_t of this entry */
#endif
	c_sr_num
};



/*
 * Gnet stats table columns
 */
enum {
    c_gs_type = 0,
    c_gs_received,
    c_gs_expired,
    c_gs_dropped,
    c_gs_relayed,
    c_gs_generated
};



/*
 * Searches overview table columns
 */
enum {
    c_sl_name = 0,
    c_sl_hit,
    c_sl_new,
#ifdef USE_GTK2
	c_sl_sch, /* invisible, pointer to the search_t for this entry */
#endif
	c_sl_num
};



/*
 * Search stats table columns
 */
enum {
    c_st_term = 0,
    c_st_period,
    c_st_total
};



/*
 * Notebook tabs in the main notebook.
 */
enum {
    nb_main_page_gnet = 0,
    nb_main_page_uploads,
    nb_main_page_uploads_stats,
    nb_main_page_downloads,
    nb_main_page_search,
    nb_main_page_monitor,
    nb_main_page_search_stats,
    nb_main_page_config,
    nb_main_page_gnet_stats
};

/*
 * Nodes in the treemenu
 */
enum {
    TREEMENU_NODE_GNET = 0,
    TREEMENU_NODE_GNET_STATS,
    TREEMENU_NODE_UL,
    TREEMENU_NODE_UL_STATS,
    TREEMENU_NODE_DL,
    TREEMENU_NODE_SEARCH,
    TREEMENU_NODE_SEARCH_MON,
    TREEMENU_NODE_SEARCH_STATS,
    TREEMENU_NODE_CFG,

    TREEMENU_NODES
};

/*
 * Public variables.
 */
extern GtkWidget *main_window;
extern GtkWidget *shutdown_window;
extern GtkWidget *main_window;
extern GtkWidget *shutdown_window;
extern GtkWidget *dlg_about;
extern GtkWidget *dlg_quit;
extern GtkWidget *popup_downloads;
extern GtkWidget *popup_uploads;
extern GtkWidget *popup_search;
extern GtkWidget *popup_nodes;
extern GtkWidget *popup_monitor;
extern GtkWidget *popup_queue;

/*
 * Public interface.
 */
void gui_init(void);
void gui_update_all(void);
void gui_update_files_scanned(void);
void gui_update_global(void);
void gui_update_traffic_stats(void);
void gui_update_stats(void);
void gui_update_stats_frames();
void gui_allow_rescan_dir(gboolean flag);
#endif /* _gui_h_ */
