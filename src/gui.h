/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi & Richard Eckart
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

#ifdef USE_GTK2
#include "support-glade2.h"
#else
#include "support-glade1.h"
#endif

#include "gui_property.h"
#include "gui_property_priv.h"
#include "gtk-missing.h"

#ifndef USE_GTK2
#define g_ascii_strcasecmp g_strcasecmp
#define gdk_drawable_get_size gdk_window_get_size
#endif

#define GUI_CELL_RENDERER_YPAD ((guint) 0)

/*
 * Gnet table columns.
 */

enum {
	c_gnet_host = 0,
	c_gnet_flags,
	c_gnet_user_agent,
	c_gnet_version,
	c_gnet_connected,
	c_gnet_uptime,
	c_gnet_info,
#ifdef USE_GTK2
	c_gnet_handle,
	c_gnet_fg,
#endif
	c_gnet_num
};

/*
 * Uploads table columns
 */
enum {
    c_ul_filename = 0,
    c_ul_host,
    c_ul_size,
    c_ul_range,
    c_ul_agent,
    c_ul_status,
#ifdef USE_GTK2
#define UPLOADS_GUI_VISIBLE_COLUMNS 6
    c_ul_fg,
    c_ul_data,
#endif

	c_ul_num
};

/*
 * Upload stats columns
 */
enum {
    c_us_filename = 0,
    c_us_size,
    c_us_attempts,
    c_us_complete,
    c_us_norm,
#define UPLOAD_STATS_GUI_VISIBLE_COLUMNS 5
	c_us_stat,

	c_us_num
};

/*
 * Downloads table columns
 */

#ifdef USE_GTK1
enum {
    c_dl_filename = 0,
    c_dl_host,
    c_dl_size,
    c_dl_range,
    c_dl_server,
    c_dl_status,
	c_dl_num
};
#endif

#ifdef USE_GTK2
enum {
    c_dl_filename = 0,
    c_dl_size,
    c_dl_host,
    c_dl_range,
    c_dl_server,
    c_dl_status,
#ifdef USE_GTK2
	c_dl_fg, /* invisible, holds the foreground color for the row */
	c_dl_bg, /* invisible, holds the background color for the row */
	c_dl_record, /* invisible, pointer to the record_t of this entry */
#endif
	c_dl_num
};
#endif

/*
 * Queue table columns
 */

#ifdef USE_GTK1
enum {
    c_queue_filename = 0,
    c_queue_host,
    c_queue_size,
    c_queue_server,
    c_queue_status,
	c_queue_num
};
#endif

#ifdef USE_GTK2
enum {
    c_queue_filename = 0,
    c_queue_size,
    c_queue_host,
    c_queue_server,
    c_queue_status,
	c_queue_fg, /* invisible, holds the foreground color for the row */
	c_queue_bg, /* invisible, holds the background color for the row */
	c_queue_record, /* invisible, pointer to the record_t of this entry */
	c_queue_num
};
#endif


/*
 * Fileinfo table columns.
 */

enum {
	c_fi_filename = 0,
	c_fi_size,
	c_fi_done,
	c_fi_sources,
	c_fi_status,
#ifdef USE_GTK2
	c_fi_handle,
	c_fi_isize,
	c_fi_idone,
	c_fi_isources,
#endif
	c_fi_num
};

/*
 * Searches table columns
 */
enum {
    c_sr_filename = 0,
    c_sr_size,
	c_sr_count,
#ifdef USE_GTK1
    c_sr_speed,
    c_sr_host,
    c_sr_sha1,	
#endif
    c_sr_info,
#ifdef USE_GTK2
	c_sr_fg, /* invisible, holds the foreground color for the row */
	c_sr_bg, /* invisible, holds the background color for the row */
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
    c_sl_fg,
    c_sl_bg,
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
#ifdef USE_GTK2
    nb_main_page_config_sel,
    nb_main_page_config_net,
    nb_main_page_config_gnet,
    nb_main_page_config_bwc,
    nb_main_page_config_dl,
    nb_main_page_config_ul,
    nb_main_page_config_ui,
    nb_main_page_config_dbg,
#else
    nb_main_page_config,
#endif
    nb_main_page_gnet_stats,

    nb_main_page_num
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

/*
 * Public variables.
 */
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
void gui_update_stats_frames(void);
void gui_allow_rescan_dir(gboolean flag);

/*
 * Create a new search based on a search result record.
 */
struct record;
struct filter;
void gui_add_targetted_search(struct record *rec, struct filter *noneed);

/*
 * Hit record comparison functions.
 */
gint gui_record_name_eq(gconstpointer rec1, gconstpointer rec2);
gint gui_record_sha1_eq(gconstpointer rec1, gconstpointer rec2);
gint gui_record_host_eq(gconstpointer rec1, gconstpointer rec2);
gint gui_record_sha1_or_name_eq(gconstpointer rec1, gconstpointer rec2);

#ifdef USE_GTK2
void gui_merge_window_as_tab(GtkWidget *toplvl, GtkWidget *notebook,
							 GtkWidget *window);
#endif

void icon_init(void);
void icon_close(void);

#endif /* _gui_h_ */
