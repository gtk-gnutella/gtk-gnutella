/*
 * Copyright (c) 2001-2003, Richard Eckart
 *
 * THIS FILE IS AUTOGENERATED! DO NOT EDIT!
 * This file is generated from gui_props.ag using autogen.
 * Autogen is available at http://autogen.sourceforge.net/.
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

#ifndef _gui_property_priv_h_
#define _gui_property_priv_h_

#include <glib.h>

#include "lib/prop.h"

#ifdef GUI_SOURCES

/*
 * Includes specified by "uses"-statement in .ag file
 */
#include "if/ui/gtk/gnet_stats.h"
#include "ui/gtk/columns.h"


extern const gboolean monitor_enabled;
extern const guint32  monitor_max_items;
extern const gboolean queue_regex_case;
extern const gboolean fi_regex_case;
extern const gboolean search_hide_downloaded;
extern const guint32  nodes_col_widths[NODES_VISIBLE_COLUMNS];
extern const gboolean nodes_col_visible[NODES_VISIBLE_COLUMNS];
extern const guint32  dl_active_col_widths[DOWNLOADS_VISIBLE_COLUMNS];
extern const gboolean dl_active_col_visible[DOWNLOADS_VISIBLE_COLUMNS];
extern const guint32  dl_queued_col_widths[DOWNLOAD_QUEUE_VISIBLE_COLUMNS];
extern const gboolean dl_queued_col_visible[DOWNLOAD_QUEUE_VISIBLE_COLUMNS];
extern const guint32  file_info_col_widths[FILEINFO_VISIBLE_COLUMNS];
extern const gboolean search_results_col_visible[c_sr_num];
extern const guint32  search_list_col_widths[c_sr_num];
extern const guint32  search_results_col_widths[SEARCH_RESULTS_VISIBLE_COLUMNS];
extern const guint32  search_stats_col_widths[3];
extern const guint32  ul_stats_col_widths[UPLOAD_STATS_GUI_VISIBLE_COLUMNS];
extern const gboolean ul_stats_col_visible[UPLOAD_STATS_GUI_VISIBLE_COLUMNS];
extern const guint32  uploads_col_widths[UPLOADS_GUI_VISIBLE_COLUMNS];
extern const gboolean uploads_col_visible[UPLOADS_GUI_VISIBLE_COLUMNS];
extern const guint32  filter_rules_col_widths[4];
extern const guint32  filter_filters_col_widths[3];
extern const guint32  gnet_stats_msg_col_widths[8];
extern const guint32  gnet_stats_fc_ttl_col_widths[10];
extern const guint32  gnet_stats_fc_hops_col_widths[10];
extern const guint32  gnet_stats_fc_col_widths[10];
extern const guint32  gnet_stats_horizon_col_widths[4];
extern const guint32  gnet_stats_drop_reasons_col_widths[2];
extern const guint32  gnet_stats_recv_col_widths[10];
extern const guint32  hcache_col_widths[4];
extern const guint32  window_coords[4];
extern const guint32  filter_dlg_coords[4];
extern const guint32  downloads_divider_pos;
extern const guint32  fileinfo_divider_pos;
extern const guint32  main_divider_pos;
extern const guint32  gnet_stats_divider_pos;
extern const guint32  side_divider_pos;
extern const guint32  results_divider_pos;
extern const guint32  search_max_results;
extern const guint32  gui_debug;
extern const guint32  filter_main_divider_pos;
extern const gboolean search_results_show_tabs;
extern const gboolean toolbar_visible;
extern const gboolean statusbar_visible;
extern const gboolean progressbar_uploads_visible;
extern const gboolean progressbar_downloads_visible;
extern const gboolean progressbar_connections_visible;
extern const gboolean progressbar_bws_in_visible;
extern const gboolean progressbar_bws_out_visible;
extern const gboolean progressbar_bws_gin_visible;
extern const gboolean progressbar_bws_gout_visible;
extern const gboolean progressbar_bws_glin_visible;
extern const gboolean progressbar_bws_glout_visible;
extern const gboolean autohide_bws_gleaf;
extern const gboolean progressbar_bws_in_avg;
extern const gboolean progressbar_bws_out_avg;
extern const gboolean progressbar_bws_gin_avg;
extern const gboolean progressbar_bws_gout_avg;
extern const gboolean progressbar_bws_glin_avg;
extern const gboolean progressbar_bws_glout_avg;
extern const gboolean search_sort_casesense;
extern const gboolean show_search_results_settings;
extern const gboolean show_dl_settings;
extern const gboolean search_autoselect_similar;
extern const gboolean search_autoselect_samesize;
extern const gboolean search_autoselect_fuzzy;
extern const guint32  search_stats_mode;
extern const guint32  search_stats_update_interval;
extern const guint32  search_stats_delcoef;
extern const gboolean confirm_quit;
extern const gboolean show_tooltips;
extern const gboolean expert_mode;
extern const gboolean gnet_stats_perc;
extern const gboolean gnet_stats_bytes;
extern const gboolean gnet_stats_hops;
extern const guint32  gnet_stats_source;
extern const gboolean gnet_stats_with_headers;
extern const gboolean gnet_stats_drop_perc;
extern const guint32  gnet_stats_general_col_widths[2];
extern const gboolean clear_uploads_complete;
extern const gboolean clear_uploads_failed;
extern const gboolean node_show_uptime;
extern const gboolean node_show_handshake_version;
extern const gboolean node_show_detailed_info;
extern const gboolean show_gnet_info_txc;
extern const gboolean show_gnet_info_rxc;
extern const gboolean show_gnet_info_tx_wire;
extern const gboolean show_gnet_info_rx_wire;
extern const gboolean show_gnet_info_tx_speed;
extern const gboolean show_gnet_info_rx_speed;
extern const gboolean show_gnet_info_tx_queries;
extern const gboolean show_gnet_info_rx_queries;
extern const gboolean show_gnet_info_tx_hits;
extern const gboolean show_gnet_info_rx_hits;
extern const gboolean show_gnet_info_gen_queries;
extern const gboolean show_gnet_info_sq_queries;
extern const gboolean show_gnet_info_tx_dropped;
extern const gboolean show_gnet_info_rx_dropped;
extern const gboolean show_gnet_info_qrp_stats;
extern const gboolean show_gnet_info_dbw;
extern const gboolean show_gnet_info_rt;
extern const gboolean show_gnet_info_shared_size;
extern const gboolean show_gnet_info_shared_files;
extern const guint32  search_accumulation_period;
extern const guint32  treemenu_nodes_expanded[17];
extern const guint32  gnet_stats_pkg_col_widths[6];
extern const guint32  gnet_stats_byte_col_widths[6];
extern const guint32  config_toolbar_style;


prop_set_t *gui_prop_init(void);
void gui_prop_shutdown(void);

#endif /* GUI_SOURCES */

#endif /* _gui_property_priv_h_ */

