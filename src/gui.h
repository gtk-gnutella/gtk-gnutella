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

#ifndef __gui_h__
#define __gui_h__

#include "gnet.h"

#include <gtk/gtk.h>

#include "downloads.h" // FIXME: remove this dependency
#include "uploads.h" // FIXME: remove this dependency

#include "interface-glade1.h"
#include "support-glade1.h"

#include "gui_property.h"
#include "gui_property_priv.h"
#include "gtk-missing.h"




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
    c_sr_info
};



/*
 * Searches overview table columns
 */
enum {
    c_sl_name = 0,
    c_sl_hit,
    c_sl_new
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
    nb_main_page_gnutellaNet = 0,
    nb_main_page_uploads,
    nb_main_page_uploads_stats,
    nb_main_page_downloads,
    nb_main_page_search,
    nb_main_page_monitor,
    nb_main_page_search_stats,
    nb_main_page_config
};



/*
 * Public variables.
 */
extern GtkWidget *main_window;
extern GtkWidget *shutdown_window;
extern GtkWidget *main_window;
extern GtkWidget *shutdown_window;
extern GtkWidget *dlg_about;
extern GtkWidget *popup_downloads;
extern GtkWidget *popup_uploads;
extern GtkWidget *popup_search;
extern GtkWidget *popup_nodes;
extern GtkWidget *popup_monitor;
extern GtkWidget *popup_queue;


struct search;

/*
 * Public interface.
 */
void gui_init(void);
void gui_update_all(void);
//void gui_new_version_found(gchar *text, gboolean stable);
void gui_update_guid(void);
void gui_update_c_downloads(gint, gint);
void gui_update_c_gnutellanet(void);
void gui_update_c_uploads(void);
void gui_update_config_force_ip(gboolean force);
void gui_update_connection_speed(void);
void gui_update_files_scanned(void);
void gui_update_global(void);
void gui_update_traffic_stats(void);
void gui_update_scan_extensions(void);
void gui_update_c_gnutellanet(void);
void gui_update_c_uploads(void);
void gui_update_c_downloads(gint, gint);
void gui_update_files_scanned(void);
void gui_update_connection_speed(void);
void gui_update_stats(void);
void gui_update_proxy_auth();
void gui_update_proxy_connections();
void gui_update_upload(struct upload *);
void gui_update_upload_kill(void);
void gui_update_config_netmasks();
void gui_update_stats_frames();
void gui_update_queue_frozen();
void gui_allow_rescan_dir(gboolean flag);
#endif /* __gui_h__ */
