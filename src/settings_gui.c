/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Richard Eckart
 *
 * Reflection of changes in backend or gui properties in the GUI.
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

#include "gui.h"

#include "downloads.h" /* FIXME: remove this dependency */

#include "settings.h" /* For settings_config_dir() */
#include "settings_gui.h"

#include "monitor_gui.h"
#include "statusbar_gui.h"
#include "search_gui.h"
#include "filter_gui.h"
#include "search_stats_gui.h"

#include "settings_cb.h"

RCSID("$Id$");

/* Uncomment to override debug level for this file. */
/* #define gui_debug 10 */

/* 
 * This file has five parts:
 *
 * I.     General variables/defines used in this module
 * II.    Property-to-callback map
 * III.   Simple default callbacks
 * IV.    Special case callbacks
 * V.     Control functions.
 *
 * To add another property change listener, just define the callback
 * in the callback section (IV), or use a standard call like
 * update_spinbutton (from part III) and add an entry to 
 * the property_map table. The rest will be done automatically.
 * If debugging is activated, you will get a list of unmapped and
 * ignored properties on startup.
 * To ignore a property, just set the cb, fn_toplevel and wid attributes
 * in the property_map to IGNORE,
 * To create a listener which is not bound to a signle widget, set
 * the fn_toplevel and wid attributed of your property_map entry to
 * NULL.
 */

/***
 *** I. General variables/defines used in this module
 ***/

#define NOT_IN_MAP (-1)

static prop_set_stub_t *gui_prop_set_stub = NULL;
static prop_set_stub_t *gnet_prop_set_stub = NULL;

static gint gui_init_list[GUI_PROPERTY_NUM];
static gint gnet_init_list[GNET_PROPERTY_NUM];
static GtkTooltips* tooltips = NULL;

static gchar *home_dir = NULL;
static const gchar *property_file = "config_gui";

static gchar set_tmp[4096];

static prop_set_t *properties = NULL;

/***
 *** II. Property-to-callback map
 ***/

/*
 * These functions can fetch the toplevel widget necessary for the
 * stock-callbacks to work. Even if you use no stock callback, they
 * are needed for setting the tooltip.
 */
static GtkWidget *get_main_window(void) {
    return main_window;
}

static GtkWidget *get_filter_dialog(void) {
    return filter_dialog;
}

static GtkWidget *get_search_popup(void) {
    return popup_search;
}

typedef GtkWidget *(*fn_toplevel_t)(void);

/*
 * The property maps contain informaiton about which widget should reflect
 * which property.
 */
typedef struct prop_map {
    const fn_toplevel_t fn_toplevel;  /* get toplevel widget */
    const property_t prop;            /* property handle */
    const prop_changed_listener_t cb; /* callback function */
    const gboolean init;              /* init widget with current value */
    const gchar *wid;                 /* name of the widget for tooltip */
    enum frequency_type f_type;
    guint32 f_interval;
    
    /*
     * Automatic field filled in by settings_gui_init_prop_map
     */
    prop_type_t type;                 /* property type */
    prop_set_stub_t *stub;            /* property set stub */
    gint *init_list;                  /* init_list for reverse lookup */
} prop_map_t;

#define IGNORE NULL

/*
 * Callback declarations.
 */
static gboolean update_entry(property_t prop);
static gboolean update_label(property_t prop);
static gboolean update_spinbutton(property_t prop);
static gboolean update_togglebutton(property_t prop);
static gboolean update_multichoice(property_t prop);
static gboolean update_split_pane(property_t prop);
static gboolean update_clist_col_widths(property_t prop);
static gboolean update_bandwidth_spinbutton(property_t prop);
static gboolean update_window_geometry(property_t prop);

#ifdef USE_GTK2
static gboolean update_treeview_col_widths(property_t prop);
static gboolean config_toolbar_style_changed(property_t prop);
#endif
static gboolean bw_gnet_lin_enabled_changed(property_t prop);
static gboolean bw_gnet_lout_enabled_changed(property_t prop);
static gboolean bw_http_in_enabled_changed(property_t prop);
static gboolean bw_gnet_in_enabled_changed(property_t prop);
static gboolean bw_gnet_out_enabled_changed(property_t prop);
static gboolean bw_ul_usage_enabled_changed(property_t prop);
static gboolean bw_http_out_enabled_changed(property_t prop);
static gboolean proxy_ip_changed(property_t prop);
static gboolean monitor_enabled_changed(property_t prop);
static gboolean reading_hostfile_changed(property_t prop);
static gboolean ancient_version_changed(property_t prop);
static gboolean new_version_str_changed(property_t prop);
static gboolean send_pushes_changed(property_t prop);
static gboolean statusbar_visible_changed(property_t prop);
static gboolean toolbar_visible_changed(property_t prop);
static gboolean hosts_in_catcher_changed(property_t prop);
static gboolean hosts_in_ultra_catcher_changed(property_t prop);
static gboolean progressbar_bws_in_visible_changed(property_t prop);
static gboolean progressbar_bws_out_visible_changed(property_t prop);
static gboolean progressbar_bws_gin_visible_changed(property_t prop);
static gboolean progressbar_bws_gout_visible_changed(property_t prop);
static gboolean progressbar_bws_glin_visible_changed(property_t prop);
static gboolean progressbar_bws_glout_visible_changed(property_t prop);
static gboolean progressbar_downloads_visible_changed(property_t prop);
static gboolean progressbar_uploads_visible_changed(property_t prop);
static gboolean progressbar_connections_visible_changed(property_t prop);
static gboolean search_results_show_tabs_changed(property_t prop);
static gboolean autoclear_completed_downloads_changed(property_t prop);
static gboolean autoclear_failed_downloads_changed(property_t prop);
static gboolean autoclear_unavailable_downloads_changed(property_t prop);
static gboolean socks_user_changed(property_t prop);
static gboolean socks_pass_changed(property_t prop);
static gboolean traffic_stats_mode_changed(property_t prop);
static gboolean is_firewalled_changed(property_t prop);
static gboolean min_dup_ratio_changed(property_t prop);
static gboolean plug_icon_changed(property_t prop);
static gboolean show_search_results_settings_changed(property_t prop);
static gboolean show_dl_settings_changed(property_t prop);
static gboolean local_address_changed(property_t prop);
static gboolean force_local_ip_changed(property_t prop);
static gboolean listen_port_changed(property_t prop);
static gboolean use_netmasks_changed(property_t prop);
static gboolean guid_changed(property_t prop);
static gboolean show_tooltips_changed(property_t prop);
static gboolean expert_mode_changed(property_t prop);
static gboolean search_stats_mode_changed(property_t prop);
static gboolean sha1_rebuilding_changed(property_t prop);
static gboolean library_rebuilding_changed(property_t prop);
static gboolean sha1_verifying_changed(property_t prop);
static gboolean file_moving_changed(property_t prop);
static gboolean dl_running_count_changed(property_t prop);
static gboolean dl_active_count_changed(property_t prop);
static gboolean dl_aqueued_count_changed(property_t prop);
static gboolean gnet_connections_changed(property_t prop);
static gboolean uploads_count_changed(property_t prop);
static gboolean downloads_count_changed(property_t prop);
static gboolean current_peermode_changed(property_t prop);
static gboolean clock_skew_changed(property_t prop);
static gboolean update_monitor_unstable_ip(property_t prop);
static gboolean spinbutton_input_bw_changed(property_t prop);
static gboolean spinbutton_output_bw_changed(property_t prop);
static void update_output_bw_display(void);
static void update_input_bw_display(void);
#ifdef USE_GTK1
static gboolean dl_http_latency_changed(property_t prop);
#endif

/* FIXME:
 * move to separate file and autogenerate from high-level description.
 */
static prop_map_t property_map[] = {
    {
        get_main_window,
        PROP_MONITOR_MAX_ITEMS,
        update_spinbutton,
        TRUE,
        "spinbutton_monitor_items",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MONITOR_ENABLED,
        monitor_enabled_changed,
        TRUE,
        "checkbutton_monitor_enable",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_QUEUE_REGEX_CASE,
        update_togglebutton,
        TRUE,
        "checkbutton_queue_regex_case",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SEARCH_AUTOSELECT,
        update_togglebutton,
        TRUE,
        "checkbutton_search_autoselect",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SEARCH_AUTOSELECT_IDENT,
        update_togglebutton,
        TRUE,
        "checkbutton_search_autoselect_ident",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SEARCH_AUTOSELECT_FUZZY,
        update_togglebutton,
        TRUE,
        "checkbutton_search_autoselect_fuzzy",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MAIN_DIVIDER_POS,
        update_split_pane,
        TRUE,
        "hpaned_main",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_GNET_STATS_DIVIDER_POS,
        update_split_pane,
        TRUE,
        "hpaned_gnet_stats",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SIDE_DIVIDER_POS,
        update_split_pane,
        TRUE,
        "vpaned_sidebar",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DOWNLOADS_DIVIDER_POS,
        update_split_pane,
        TRUE,
        "vpaned_downloads",
        FREQ_UPDATES, 0
    },
    {
        get_filter_dialog,
        PROP_FILTER_MAIN_DIVIDER_POS,
        update_split_pane,
        TRUE,
        "hpaned_filter_main",
        FREQ_UPDATES, 0
    },
#ifdef USE_GTK2
    {
        get_main_window,
        PROP_RESULTS_DIVIDER_POS,
        update_split_pane,
        TRUE,
        "vpaned_results",
        FREQ_UPDATES, 0
    },
#endif
    {
        get_main_window,
        PROP_STATUSBAR_VISIBLE,
        statusbar_visible_changed,
        TRUE,
        "menu_statusbar_visible",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_TOOLBAR_VISIBLE,
        toolbar_visible_changed,
        TRUE,
        "menu_toolbar_visible",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_JUMP_TO_DOWNLOADS,
        update_togglebutton,
        TRUE,
        "checkbutton_search_jump_to_downloads",
        FREQ_UPDATES, 0
    },
#ifdef USE_GTK2
    {
        get_main_window,
        PROP_NODES_COL_WIDTHS,
        update_treeview_col_widths,
        TRUE,
        "treeview_nodes",
        FREQ_UPDATES, 0
    },
#else
    {
        get_main_window,
        PROP_NODES_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_nodes",
        FREQ_UPDATES, 0
    },
#endif
    {
        get_main_window,
        PROP_DL_ACTIVE_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_downloads",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DL_QUEUED_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_downloads_queue",
        FREQ_UPDATES, 0
    },
#ifdef USE_GTK2
    {
        get_main_window,
        PROP_FILE_INFO_COL_WIDTHS,
        update_treeview_col_widths,
        TRUE,
        "treeview_fileinfo",
        FREQ_UPDATES, 0
    },
#else
    {
        get_main_window,
        PROP_FILE_INFO_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_fileinfo",
        FREQ_UPDATES, 0
    },
#endif
#ifdef USE_GTK2
    {
        get_main_window,
        PROP_SEARCH_STATS_COL_WIDTHS,
        update_treeview_col_widths,
        TRUE,
        "treeview_search_stats",
        FREQ_UPDATES, 0
    },
#else
    {
        get_main_window,
        PROP_SEARCH_STATS_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_search_stats",
        FREQ_UPDATES, 0
    },
#endif
#ifdef USE_GTK2
    {
        get_main_window,
        PROP_UPLOADS_COL_WIDTHS,
        update_treeview_col_widths,
        TRUE,
        "treeview_uploads",
        FREQ_UPDATES, 0
    },
#else	
    {
        get_main_window,
        PROP_UPLOADS_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_uploads",
        FREQ_UPDATES, 0
    },
#endif
#ifndef USE_GTK2
    {
        get_main_window,
        PROP_UL_STATS_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_ul_stats",
        FREQ_UPDATES, 0
    },
#endif
#ifdef USE_GTK2
    {
        get_main_window,
        PROP_SEARCH_LIST_COL_WIDTHS,
        update_treeview_col_widths,
        TRUE,
        "tree_view_search",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_GNET_STATS_MSG_COL_WIDTHS,
        update_treeview_col_widths,
        TRUE,
        "treeview_gnet_stats_messages",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_GNET_STATS_FC_TTL_COL_WIDTHS,
        update_treeview_col_widths,
        TRUE,
        "treeview_gnet_stats_flowc",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_GNET_STATS_FC_HOPS_COL_WIDTHS,
        update_treeview_col_widths,
        TRUE,
        "treeview_gnet_stats_flowc",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_GNET_STATS_DROP_REASONS_COL_WIDTHS,
        update_treeview_col_widths,
        TRUE,
        "treeview_gnet_stats_drop_reasons",
        FREQ_UPDATES, 0
    },
#else
    {
        get_main_window,
        PROP_SEARCH_LIST_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_search",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_GNET_STATS_MSG_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_gnet_stats_msg",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_GNET_STATS_FC_TTL_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_gnet_stats_fc_ttl",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_GNET_STATS_FC_HOPS_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_gnet_stats_fc_hops",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_GNET_STATS_DROP_REASONS_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_gnet_stats_drop_reasons",
        FREQ_UPDATES, 0
    },
#endif
    {
        get_filter_dialog,
        PROP_FILTER_RULES_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_filter_rules",
        FREQ_UPDATES, 0
    },
    {
        get_filter_dialog,
        PROP_FILTER_FILTERS_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_filter_filters",
        FREQ_UPDATES, 0
    },
#ifndef USE_GTK2 
    {
        get_main_window,
        PROP_SEARCH_RESULTS_COL_WIDTHS,
        search_gui_search_results_col_widths_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    },
#endif
    {
        get_main_window,
        PROP_SEARCH_RESULTS_COL_VISIBLE,
        search_gui_search_results_col_visible_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PROGRESSBAR_BWS_IN_VISIBLE,
        progressbar_bws_in_visible_changed,
        TRUE,
        "menu_bws_in_visible",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PROGRESSBAR_BWS_OUT_VISIBLE,
        progressbar_bws_out_visible_changed,
        TRUE,
        "menu_bws_out_visible",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PROGRESSBAR_BWS_GIN_VISIBLE,
        progressbar_bws_gin_visible_changed,
        TRUE,
        "menu_bws_gin_visible",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PROGRESSBAR_BWS_GOUT_VISIBLE,
        progressbar_bws_gout_visible_changed,
        TRUE,
        "menu_bws_gout_visible",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PROGRESSBAR_BWS_GLIN_VISIBLE,
        progressbar_bws_glin_visible_changed,
        TRUE,
        "menu_bws_glin_visible",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PROGRESSBAR_BWS_GLOUT_VISIBLE,
        progressbar_bws_glout_visible_changed,
        TRUE,
        "menu_bws_glout_visible",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PROGRESSBAR_DOWNLOADS_VISIBLE,
        progressbar_downloads_visible_changed,
        TRUE,
        "menu_downloads_visible",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PROGRESSBAR_UPLOADS_VISIBLE,
        progressbar_uploads_visible_changed,
        TRUE,
        "menu_uploads_visible",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PROGRESSBAR_CONNECTIONS_VISIBLE,
        progressbar_connections_visible_changed,
        TRUE,
        "menu_connections_visible",
        FREQ_UPDATES, 0
    },
    {
        get_search_popup,
        PROP_SEARCH_RESULTS_SHOW_TABS,
        search_results_show_tabs_changed,
        TRUE,
        "popup_search_toggle_tabs",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_GUI_DEBUG,
        update_spinbutton,
        TRUE,
        "spinbutton_config_gui_debug",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DBG,
        update_spinbutton,
        TRUE,
        "spinbutton_config_dbg",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_TRACK_PROPS,
        update_spinbutton,
        TRUE,
        "spinbutton_config_track_props",
        FREQ_UPDATES, 0
    },
    { 
        get_main_window,
        PROP_UP_CONNECTIONS, 
        update_spinbutton, 
        TRUE,
        "spinbutton_up_connections",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MAX_CONNECTIONS,
        update_spinbutton,
        TRUE,
        "spinbutton_max_connections",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MAX_ULTRAPEERS,
        update_spinbutton,
        TRUE,
        "spinbutton_max_ultrapeers",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_NODE_LEAF_COUNT,
        gnet_connections_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_NODE_NORMAL_COUNT,
        gnet_connections_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_NODE_ULTRA_COUNT,
        gnet_connections_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    },
	{
        get_main_window,
        PROP_UL_RUNNING,
        uploads_count_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_UL_REGISTERED,
        uploads_count_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
	},
	{
        get_main_window,
        PROP_MAX_DOWNLOADS,
        update_spinbutton,
        TRUE,
        "spinbutton_max_downloads",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MAX_HOST_DOWNLOADS,
        update_spinbutton,
        TRUE,
        "spinbutton_max_host_downloads",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MAX_UPLOADS,
        update_spinbutton,
        TRUE,
        "spinbutton_max_uploads",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MAX_UPLOADS_IP,
        update_spinbutton,
        TRUE,
        "spinbutton_max_uploads_ip",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PROXY_IP,
        proxy_ip_changed,
        TRUE,
        "entry_config_proxy_ip",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MAX_HOSTS_CACHED,
        update_spinbutton,
        TRUE,
        "spinbutton_nodes_max_hosts_cached",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MAX_TTL,
        update_spinbutton,
        TRUE,
        "spinbutton_config_maxttl",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MY_TTL,
        update_spinbutton,
        TRUE,
        "spinbutton_config_myttl",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SEARCH_REISSUE_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_search_reissue_timeout",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PROXY_PORT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_proxy_port",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_UL_USAGE_MIN_PERCENTAGE,
        update_spinbutton,
        TRUE,
        "spinbutton_config_ul_usage_min_percentage",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_CONNECTION_SPEED,
        update_spinbutton,
        TRUE,
        "spinbutton_config_speed",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_QUERY_RESPONSE_MAX_ITEMS,
        update_spinbutton,
        TRUE,
        "spinbutton_config_search_items",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MAX_HIGH_TTL_RADIUS,
        update_spinbutton,
        TRUE,
        "spinbutton_config_max_high_ttl_radius",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MAX_HIGH_TTL_MSG,
        update_spinbutton,
        TRUE,
        "spinbutton_config_max_high_ttl_msg",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_HARD_TTL_LIMIT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_hard_ttl_limit",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DOWNLOAD_OVERLAP_RANGE,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_overlap_range",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DOWNLOAD_MAX_RETRIES,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_max_retries",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DOWNLOAD_RETRY_STOPPED_DELAY,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_stopped_delay",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DOWNLOAD_RETRY_REFUSED_DELAY,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_refused_delay",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DOWNLOAD_RETRY_BUSY_DELAY,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_busy_delay",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DOWNLOAD_RETRY_TIMEOUT_DELAY,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_timeout_delay",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DOWNLOAD_RETRY_TIMEOUT_MAX,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_timeout_max",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DOWNLOAD_RETRY_TIMEOUT_MIN,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_timeout_min",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DOWNLOAD_CONNECTING_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_connecting_timeout",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DOWNLOAD_CONNECTED_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_connected_timeout",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DOWNLOAD_PUSH_SENT_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_push_sent_timeout",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_NODE_TX_FLOWC_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_node_tx_flowc_timeout",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_NODE_CONNECTING_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_node_connecting_timeout",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_NODE_CONNECTED_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_node_connected_timeout",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_UPLOAD_CONNECTING_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_upload_connecting_timeout",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_UPLOAD_CONNECTED_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_upload_connected_timeout",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SOCKS_USER,
        socks_user_changed,
        TRUE,
        "entry_config_socks_username",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SOCKS_PASS,
        socks_pass_changed,
        TRUE,
        "entry_config_socks_password",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SEARCH_REMOVE_DOWNLOADED,
        update_togglebutton,
        TRUE,
        "checkbutton_search_remove_downloaded",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DL_REMOVE_FILE_ON_MISMATCH,
        update_togglebutton,
        TRUE,
        "checkbutton_dl_remove_file_on_mismatch",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_GIVE_SERVER_HOSTNAME,
        update_togglebutton,
        TRUE,
        "checkbutton_give_server_hostname",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SERVER_HOSTNAME,
        update_entry,
        TRUE,
        "entry_server_hostname",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PFSP_SERVER,
        update_togglebutton,
        TRUE,
        "checkbutton_pfsp_server",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PFSP_FIRST_CHUNK,
        update_spinbutton,
        TRUE,
        "spinbutton_pfsp_first_chunk",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SEARCH_HIDE_DOWNLOADED,
        update_togglebutton,
        TRUE,
        "checkbutton_search_hide_downloaded",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DOWNLOAD_DELETE_ABORTED,
        update_togglebutton,
        TRUE,
        "checkbutton_download_delete_aborted",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BW_HTTP_IN_ENABLED,
        bw_http_in_enabled_changed,
        TRUE,
        "checkbutton_config_bws_in",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BW_HTTP_OUT_ENABLED,
        bw_http_out_enabled_changed,
        TRUE,
        "checkbutton_config_bws_out",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BW_GNET_IN_ENABLED,
        bw_gnet_in_enabled_changed,
        TRUE,
        "checkbutton_config_bws_gin",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BW_GNET_OUT_ENABLED,
        bw_gnet_out_enabled_changed,
        TRUE,
        "checkbutton_config_bws_gout",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BW_HTTP_IN,
        spinbutton_input_bw_changed,
        TRUE,
        "spinbutton_config_bws_in",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BW_HTTP_OUT,
        spinbutton_output_bw_changed,
        TRUE,
        "spinbutton_config_bws_out",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BW_GNET_IN,
        spinbutton_input_bw_changed,
        TRUE,
        "spinbutton_config_bws_gin",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BW_GNET_OUT,
        spinbutton_output_bw_changed,
        TRUE,
        "spinbutton_config_bws_gout",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BW_UL_USAGE_ENABLED,
        bw_ul_usage_enabled_changed,
        TRUE,
        "checkbutton_config_bw_ul_usage_enabled",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_ANCIENT_VERSION,
        ancient_version_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_NEW_VERSION_STR,
        new_version_str_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SEND_PUSHES,
        send_pushes_changed,
        TRUE,
        "checkbutton_downloads_never_push",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_AUTOCLEAR_COMPLETED_UPLOADS,
        update_togglebutton,
        TRUE,
        "checkbutton_uploads_auto_clear_complete",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_AUTOCLEAR_FAILED_UPLOADS,
        update_togglebutton,
        TRUE,
        "checkbutton_uploads_auto_clear_failed",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_AUTOCLEAR_COMPLETED_DOWNLOADS,
        autoclear_completed_downloads_changed,
        TRUE,
        "checkbutton_dl_clear_complete",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_AUTOCLEAR_FAILED_DOWNLOADS,
        autoclear_failed_downloads_changed,
        TRUE,
        "checkbutton_dl_clear_failed",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_AUTOCLEAR_UNAVAILABLE_DOWNLOADS,
        autoclear_unavailable_downloads_changed,
        TRUE,
        "checkbutton_dl_clear_unavailable",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_FORCE_LOCAL_IP,
        force_local_ip_changed,
        TRUE,
        "checkbutton_config_force_ip",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PROXY_AUTH,
        update_togglebutton,
        TRUE,
        "checkbutton_config_proxy_auth",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_HOSTS_IN_CATCHER,
        hosts_in_catcher_changed,
        TRUE,
        "progressbar_hosts_in_catcher",
        FREQ_SECS, 0
    },
    {
        get_main_window,
        PROP_READING_HOSTFILE,
        reading_hostfile_changed,
        TRUE,
        NULL,
        FREQ_SECS, 1
    },
    {
        get_main_window,
        PROP_TOTAL_DOWNLOADS,
        update_entry,
        TRUE,
        "entry_count_downloads",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_TOTAL_UPLOADS,
        update_entry,
        TRUE,
        "entry_count_uploads",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SEARCH_STATS_MODE,
        search_stats_mode_changed,
        FALSE, /* search_stats_gui_init takes care of that */
        "combo_search_stats_type",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SEARCH_STATS_UPDATE_INTERVAL,
        update_spinbutton,
        TRUE,
        "spinbutton_search_stats_update_interval",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SEARCH_STATS_DELCOEF,
        update_spinbutton,
        TRUE,
        "spinbutton_search_stats_delcoef",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_USE_NETMASKS,
        use_netmasks_changed,
        TRUE,
        "checkbutton_config_use_netmasks",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_LOCAL_NETMASKS_STRING,
        update_entry,
        TRUE,
        "entry_config_netmasks",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_ALLOW_PRIVATE_NETWORK_CONNECTION,
        update_togglebutton,
        TRUE,
        "checkbutton_config_no_rfc1918",
        FREQ_UPDATES, 0
    },
	{
		get_main_window,
		PROP_USE_IP_TOS,
		update_togglebutton,
		TRUE,
		"checkbutton_config_use_ip_tos",
        FREQ_UPDATES, 0
	},
    {
        get_main_window,
        PROP_FORCED_LOCAL_IP,
        update_entry,
        TRUE,
        "entry_config_force_ip",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_LISTEN_PORT,
        listen_port_changed,
        TRUE,
        "spinbutton_config_port",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SCAN_EXTENSIONS,
        update_entry,
        TRUE,
        "entry_config_extensions",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SCAN_IGNORE_SYMLINK_DIRS,
        update_togglebutton,
        TRUE,
        "checkbutton_scan_ignore_symlink_dirs",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SCAN_IGNORE_SYMLINK_REGFILES,
        update_togglebutton,
        TRUE,
        "checkbutton_scan_ignore_symlink_regfiles",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SAVE_FILE_PATH,
        update_entry,
        TRUE,
        "entry_config_save_path",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MOVE_FILE_PATH,
        update_entry,
        TRUE,
        "entry_config_move_path",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BAD_FILE_PATH,
        update_entry,
        TRUE,
        "entry_config_bad_path",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SHARED_DIRS_PATHS,
        update_entry,
        TRUE,
        "entry_config_path",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MIN_DUP_MSG,
        update_spinbutton,
        TRUE,
        "spinbutton_config_min_dup_msg",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MIN_DUP_RATIO,
        min_dup_ratio_changed,
        TRUE,
        "spinbutton_config_min_dup_ratio",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PREFER_COMPRESSED_GNET,
        update_togglebutton,
        TRUE,
        "checkbutton_prefer_compressed_gnet",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DL_MINCHUNKSIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_dl_minchunksize",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DL_MAXCHUNKSIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_dl_maxchunksize",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_FUZZY_THRESHOLD,
        update_spinbutton,
        TRUE,
        "spinbutton_config_fuzzy_threshold",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_AUTO_DOWNLOAD_IDENTICAL,
        update_togglebutton,
        TRUE,
        "checkbutton_config_use_alternate_sources",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_STRICT_SHA1_MATCHING,
        update_togglebutton,
        TRUE,
        "checkbutton_config_strict_sha1_matching",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_USE_FUZZY_MATCHING,
        update_togglebutton,
        TRUE,
        "checkbutton_config_use_fuzzy_matching",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_USE_SWARMING,
        update_togglebutton,
        TRUE,
        "checkbutton_config_use_swarming",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_USE_AGGRESSIVE_SWARMING,
        update_togglebutton,
        TRUE,
        "checkbutton_config_aggressive_swarming",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_STOP_HOST_GET,
        update_togglebutton,
        TRUE,
        "checkbutton_config_stop_host_get",
        FREQ_UPDATES, 0
    },
    {
        NULL,
        PROP_SEARCH_QUERIES_FORWARD_SIZE,
        IGNORE,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        NULL,
        PROP_SEARCH_QUERIES_KICK_SIZE,
        IGNORE,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        NULL,
        PROP_SEARCH_ANSWERS_FORWARD_SIZE,
        IGNORE,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        NULL,
        PROP_SEARCH_ANSWERS_KICK_SIZE,
        IGNORE,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        NULL,
        PROP_OTHER_MESSAGES_KICK_SIZE,
        IGNORE,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_HOPS_RANDOM_FACTOR,
        update_spinbutton,
        TRUE,
        "spinbutton_config_hops_random_factor",
        FREQ_UPDATES, 0
    },
    {
        NULL,
        PROP_PROGRESSBAR_BWS_IN_AVG,
        traffic_stats_mode_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        NULL,
        PROP_PROGRESSBAR_BWS_OUT_AVG,
        traffic_stats_mode_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        NULL,
        PROP_PROGRESSBAR_BWS_GIN_AVG,
        traffic_stats_mode_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        NULL,
        PROP_PROGRESSBAR_BWS_GOUT_AVG,
        traffic_stats_mode_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        NULL,
        PROP_PROGRESSBAR_BWS_GLIN_AVG,
        traffic_stats_mode_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        NULL,
        PROP_PROGRESSBAR_BWS_GLOUT_AVG,
        traffic_stats_mode_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        NULL,
        PROP_NODE_SENDQUEUE_SIZE,
        IGNORE,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_GUID,
        guid_changed,
        TRUE,
#ifdef USE_GTK2
        "label_nodes_guid",
#else
        "entry_nodes_guid",
#endif
        FREQ_UPDATES, 0
    },
    {
        NULL,
        PROP_LOCAL_IP,
        local_address_changed,
        FALSE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        NULL,
        PROP_IS_FIREWALLED,
        is_firewalled_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_WINDOW_COORDS,
        update_window_geometry,
        TRUE,
        NULL, /* uses fn_toplevel as widget */
        FREQ_UPDATES, 0
    },
    {
        get_filter_dialog,
        PROP_FILTER_DLG_COORDS,
        update_window_geometry,
        TRUE,
        NULL, /* uses fn_toplevel as widget */
        FREQ_UPDATES, 0
    },
    {
        NULL,
        PROP_IS_INET_CONNECTED,
        plug_icon_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_ONLINE_MODE,
        plug_icon_changed,
        TRUE,
        "togglebutton_online",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SHOW_SEARCH_RESULTS_SETTINGS,
        show_search_results_settings_changed,
        TRUE,
        "checkbutton_search_results_show_settings",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SHOW_DL_SETTINGS,
        show_dl_settings_changed,
        TRUE,
        "checkbutton_dl_show_settings",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_CONFIRM_QUIT,
        update_togglebutton,
        TRUE,
        "checkbutton_config_confirm_quit",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SHOW_TOOLTIPS,
        show_tooltips_changed,
        TRUE,
        "checkbutton_config_show_tooltips",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_EXPERT_MODE,
        expert_mode_changed,
        TRUE,
        "checkbutton_expert_mode",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_GNET_STATS_BYTES,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_stats_bytes",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_GNET_STATS_PERC,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_stats_perc",
        FREQ_UPDATES, 0
    },
#ifdef USE_GTK2
    {
        get_main_window,
        PROP_GNET_STATS_HOPS,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_stats_hops",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_GNET_STATS_WITH_HEADERS,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_stats_with_headers",
        FREQ_UPDATES, 0
    },
#endif
    {
        get_main_window,
        PROP_GNET_STATS_DROP_PERC,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_stats_drop_perc",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_GNET_COMPACT_QUERY,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_compact_query",
        FREQ_UPDATES, 0
    },
#ifdef USE_GTK2
    {
        get_main_window,
        PROP_GNET_STATS_GENERAL_COL_WIDTHS,
        update_treeview_col_widths,
        TRUE,
        "treeview_gnet_stats_general",
        FREQ_UPDATES, 0
	},
#else
    {
        get_main_window,
        PROP_GNET_STATS_GENERAL_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_gnet_stats_general",
        FREQ_UPDATES, 0
    },
#endif
    {
        get_main_window,
        PROP_DOWNLOAD_OPTIMISTIC_START,
        update_togglebutton,
        TRUE,
        "checkbutton_config_download_optimistic_start",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_LIBRARY_REBUILDING,
        library_rebuilding_changed,
        TRUE,
        "eventbox_image_lib", /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SHA1_REBUILDING,
        sha1_rebuilding_changed,
        TRUE,
        "eventbox_image_sha", /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SHA1_VERIFYING,
        sha1_verifying_changed,
        TRUE,
        "eventbox_image_shav", /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_FILE_MOVING,
        file_moving_changed,
        TRUE,
        "eventbox_image_save", /* need eventbox because image has no tooltip */
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DOWNLOAD_REQUIRE_URN,
        update_togglebutton,
        TRUE,
        "checkbutton_config_req_urn",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DOWNLOAD_REQUIRE_SERVER_NAME,
        update_togglebutton,
        TRUE,
        "checkbutton_config_req_srv_name",
        FREQ_UPDATES, 0,
    },
    {
        get_main_window,
        PROP_AUTO_FEED_DOWNLOAD_MESH,
        update_togglebutton,
        TRUE,
        "checkbutton_auto_feed_dmesh",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_FUZZY_FILTER_DMESH,
        update_togglebutton,
        TRUE,
        "checkbutton_fuzzy_filter_dmesh",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_CONFIGURED_PEERMODE,
        update_multichoice,
        TRUE,
        "combo_config_peermode",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SEARCH_HANDLE_IGNORED_FILES,
        update_multichoice,
        TRUE,
        "combo_search_handle_ignored_files",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_CURRENT_PEERMODE,
        current_peermode_changed,
        TRUE,
        NULL,
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_LIB_DEBUG,
        update_spinbutton,
        TRUE,
        "spinbutton_config_lib_debug",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BAN_RATIO_FDS,
        update_spinbutton,
        TRUE,
        "spinbutton_config_ban_ratio_fds",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BAN_MAX_FDS,
        update_spinbutton,
        TRUE,
        "spinbutton_config_ban_max_fds",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PROXY_PROTOCOL,
        update_multichoice,
        TRUE,
        "combo_config_proxy_protocol",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BW_ALLOW_STEALING,
        update_togglebutton,
        TRUE,
        "checkbutton_config_bw_allow_stealing",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MAX_ULTRA_HOSTS_CACHED,
        update_spinbutton,
        TRUE,
        "spinbutton_nodes_max_ultra_hosts_cached",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_HOSTS_IN_ULTRA_CATCHER,
        hosts_in_ultra_catcher_changed,
        TRUE,
        "progressbar_hosts_in_ultra_catcher",
        FREQ_SECS, 0
    },
    {
        get_main_window,
        PROP_UL_BYTE_COUNT,
        update_entry,
        TRUE,
        "entry_ul_byte_count",
        FREQ_SECS, 1
    },
    {
        get_main_window,
        PROP_DL_BYTE_COUNT,
        update_entry,
        TRUE,
        "entry_dl_byte_count",
        FREQ_SECS, 1
    },
    {
        get_main_window,
        PROP_DL_QUEUE_COUNT,
        update_label,
        TRUE,
        "label_dl_queue_count",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DL_QALIVE_COUNT,
        update_label,
        TRUE,
        "label_dl_qalive_count",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DL_PQUEUED_COUNT,
        update_label,
        TRUE,
        "label_dl_pqueued_count",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DL_RUNNING_COUNT,
        dl_running_count_changed,
        TRUE,
        "label_dl_running_count",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DL_ACTIVE_COUNT,
        dl_active_count_changed,
        TRUE,
        "label_dl_active_count",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_DL_AQUEUED_COUNT,
        dl_aqueued_count_changed,
        TRUE,
        "label_dl_aqueued_count",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_FI_ALL_COUNT,
        update_label,
        TRUE,
        "label_fi_all_count",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_FI_WITH_SOURCE_COUNT,
        update_label,
        TRUE,
        "label_fi_with_source_count",
        FREQ_UPDATES, 0
    },
#ifdef USE_GTK1
    {
        get_main_window,
        PROP_DL_HTTP_LATENCY,
        dl_http_latency_changed,
        TRUE,
        "label_dl_http_latency",
        FREQ_SECS, 1
    },
#endif
    {
        get_main_window,
        PROP_SEARCH_MAX_RESULTS,
        update_spinbutton,
        TRUE,
        "spinbutton_search_max_results",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BW_GNET_LEAF_IN_ENABLED,
        bw_gnet_lin_enabled_changed,
        TRUE,
        "checkbutton_config_bws_glin",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BW_GNET_LEAF_OUT_ENABLED,
        bw_gnet_lout_enabled_changed,
        TRUE,
        "checkbutton_config_bws_glout",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BW_GNET_LIN,
        spinbutton_input_bw_changed,
        TRUE,
        "spinbutton_config_bws_glin",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_BW_GNET_LOUT,
        spinbutton_output_bw_changed,
        TRUE,
        "spinbutton_config_bws_glout",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_MAX_LEAVES,
        update_spinbutton,
        TRUE,
        "spinbutton_config_max_leaves",
        FREQ_UPDATES, 0
    }, 
    {
        get_main_window,
        PROP_MAX_BANNED_FD,
        update_entry,
        TRUE,
        "entry_config_max_banned_fd",
        FREQ_UPDATES, 1
    },
    {
        get_main_window,
        PROP_INCOMING_CONNECTING_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_incoming_connecting_timeout",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_NODE_RX_FLOWC_RATIO,
        update_spinbutton,
        TRUE,
        "spinbutton_config_node_rx_flowc_ratio",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_NORMAL_CONNECTIONS,
        update_spinbutton,
        TRUE,
        "spinbutton_normal_connections",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_READING_ULTRAFILE,
        update_entry,
        TRUE,
        "entry_reading_ultrafile",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_CURRENT_IP_STAMP,
        update_entry,
        TRUE,
        "entry_current_ip_stamp",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_AVERAGE_IP_UPTIME,
        update_entry,
        TRUE,
        "entry_average_ip_uptime",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_START_STAMP,
        update_entry,
        TRUE,
        "entry_start_stamp",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_AVERAGE_SERVENT_UPTIME,
        update_entry,
        TRUE,
        "entry_average_servent_uptime",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_PROXY_CONNECTIONS,
        update_entry,
        TRUE,
        "entry_proxy_connections",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SYS_NOFILE,
        update_entry,
        TRUE,
        "entry_sys_nofile",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_SYS_PHYSMEM,
        update_entry,
        TRUE,
        "entry_sys_physmem",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_CRAWLER_VISIT_COUNT,
        update_entry,
        TRUE,
        "entry_crawler_visit_count",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_CLOCK_SKEW,
        clock_skew_changed,
        TRUE,
        "label_clock_skew",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_HOST_RUNS_NTP,
        update_togglebutton,
        TRUE,
        "checkbutton_host_runs_ntp",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_NODE_MONITOR_UNSTABLE_IP,
        update_monitor_unstable_ip,
        TRUE,
        "checkbutton_gnet_monitor_ip",
        FREQ_UPDATES, 0
    },
    {
        get_main_window,
        PROP_NODE_MONITOR_UNSTABLE_SERVENTS,
        update_togglebutton,
        TRUE,
        "checkbutton_gnet_monitor_servents",
        FREQ_UPDATES, 0
    },
#ifdef USE_GTK2
    {
        get_main_window,
        PROP_CONFIG_TOOLBAR_STYLE,
        config_toolbar_style_changed,
        TRUE,
        "combo_config_toolbar_style",
        FREQ_UPDATES, 0
    },
#endif
    {
        get_main_window,
        PROP_RESERVE_GTKG_NODES,
        update_spinbutton,
        TRUE,
        "spinbutton_config_reserve_gtkg_nodes"
    },
    {
        get_main_window,
        PROP_UNIQUE_NODES,
        update_spinbutton,
        TRUE,
        "spinbutton_config_unique_nodes"
    },
#ifdef USE_GTK1
    {
        get_main_window,
        PROP_DOWNLOAD_RX_SIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_download_rx_size"
    },
    {
        get_main_window,
        PROP_NODE_RX_SIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_node_rx_size"
    },
#endif
};

/***
 *** III. Simple default callbacks
 ***/

/*
 * settings_gui_get_map_entry:
 *
 * Fetches a pointer to the map entry which handles the given
 * property. This can be use only when settings_gui_init_prop_map
 * has successfully been called before.
 */
static prop_map_t *settings_gui_get_map_entry(property_t prop)
{
    gint entry = NOT_IN_MAP;

    if (
        (prop >= gui_prop_set_stub->offset) && 
        (prop < gui_prop_set_stub->offset+gui_prop_set_stub->size)
    ) {
        entry = gui_init_list[prop-GUI_PROPERTY_MIN];
    } else
    if (
        (prop >= gnet_prop_set_stub->offset) && 
        (prop < gnet_prop_set_stub->offset+gnet_prop_set_stub->size)
    ) {
        entry = gnet_init_list[prop-GNET_PROPERTY_MIN];
    } else
        g_error("settings_gui_get_map_entry: "
                "property does not belong to known set: %u", prop);

    g_assert(entry != NOT_IN_MAP);

    return &property_map[entry];
}

/* 
 * prop_to_string:
 *
 * Helper function for update_label() and update_entry()
 */
#if 0
static gchar *prop_to_string(property_t prop)
{
    static gchar s[4096];
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;

    switch (map_entry->type) {
        case PROP_TYPE_GUINT32: {
            guint32 val;
        
            stub->guint32.get(prop, &val, 0, 1);

            gm_snprintf(s, sizeof(s), "%u", val);
            break;
        }
        case PROP_TYPE_STRING: {
            gchar *buf = stub->string.get(prop, NULL, 0);
            gm_snprintf(s, sizeof(s), "%s", buf);
            g_free(buf);
            break;
        }
        case PROP_TYPE_IP: {
            guint32 val;
        
            stub->guint32.get(prop, &val, 0, 1);

            gm_snprintf(s, sizeof(s), "%s", ip_to_gchar(val));
            break;
        }
        case PROP_TYPE_BOOLEAN: {
            gboolean val;
        
            stub->boolean.get(prop, &val, 0, 1);

            gm_snprintf(s, sizeof(s), "%s", val ? "TRUE" : "FALSE");
            break;
        }
        default:
            s[0] = '\0';
            g_error("update_entry_gnet: incompatible type %s", 
                prop_type_str[map_entry->type]);
    }

    return s;
}

#endif


static gboolean update_entry(property_t prop)
{
    GtkWidget *w;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);

    if (w == NULL) {
		if (gui_debug)
			g_warning("%s - widget not found: [%s]", 
				 G_GNUC_PRETTY_FUNCTION, map_entry->wid);
        return FALSE;
    }

    gtk_entry_set_text(GTK_ENTRY(w), stub->to_string(prop));

    return FALSE;
}

static gboolean update_label(property_t prop)
{
    GtkWidget *w;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);

    if (w == NULL) {
		if (gui_debug)
			g_warning("%s - widget not found: [%s]", 
				 G_GNUC_PRETTY_FUNCTION, map_entry->wid);
        return FALSE;
    }

    gtk_label_set_text(GTK_LABEL(w), stub->to_string(prop));

    return FALSE;
}


static gboolean update_spinbutton(property_t prop)
{
    GtkWidget *w;
    guint32 val = 0;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();
    GtkAdjustment *adj;

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);

    if (w == NULL) {
		if (gui_debug)
			g_warning("%s - widget not found: [%s]", 
				 G_GNUC_PRETTY_FUNCTION, map_entry->wid);
        return FALSE;
    }
   
    switch (map_entry->type) {
        case PROP_TYPE_GUINT32:
            stub->guint32.get(prop, &val, 0, 1);
            break;
         default:
            val = 0;
            g_error("update_spinbutton: incompatible type %s", 
                prop_type_str[map_entry->type]);
    }

    adj = gtk_spin_button_get_adjustment(GTK_SPIN_BUTTON(w));
    gtk_adjustment_set_value(adj, val);
    
    return FALSE;
}

static gboolean update_togglebutton(property_t prop)
{
    GtkWidget *w;
    gboolean val = 0;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);

    if (w == NULL) {
		if (gui_debug)
			g_warning("update_togglebutton - widget not found: [%s]", 
				 map_entry->wid);
        return FALSE;
    }
   
    switch (map_entry->type) {
        case PROP_TYPE_BOOLEAN:
            stub->boolean.get(prop, &val, 0, 1);
            break;
        default:
            val = 0;
            g_error("update_togglebutton: incompatible type %s", 
                prop_type_str[map_entry->type]);
    }

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);

    return FALSE;
}

static gboolean update_multichoice(property_t prop)
{
    GtkWidget *w;
    guint32 val = 0;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();
    GList *l;

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);

    if (w == NULL) {
		if (gui_debug)
			g_warning("%s - widget not found: [%s]", 
				 G_GNUC_PRETTY_FUNCTION, map_entry->wid);
        return FALSE;
    }
   
    switch (map_entry->type) {
        case PROP_TYPE_MULTICHOICE:
            stub->guint32.get(prop, &val, 0, 1);
            break;
        default:
            val = 0;
            g_error("update_multichoice: incompatible type %s", 
                prop_type_str[map_entry->type]);
    }

    l = GTK_LIST(GTK_COMBO(w)->list)->children;
    while (l) {
        gpointer cur;

        cur = gtk_object_get_user_data(GTK_OBJECT(l->data));

        if (GPOINTER_TO_UINT(cur) == val) {
            gtk_list_item_select(GTK_LIST_ITEM(l->data));
            break;
        }

        l = g_list_next(l);
    }

    return FALSE;
}

static gboolean update_split_pane(property_t prop)
{
    GtkWidget *w;
    guint32 val = 0;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);

    if (w == NULL) {
		if (gui_debug)
			g_warning("%s - widget not found: [%s]", 
				 G_GNUC_PRETTY_FUNCTION, map_entry->wid);
        return FALSE;
    }
    
    switch (map_entry->type) {
        case PROP_TYPE_GUINT32:
            stub->guint32.get(prop, &val, 0, 1);
            break;
        default:
            val = 0;
            g_error("update_split_pane: incompatible type %s", 
                prop_type_str[map_entry->type]);
    }

    gtk_paned_set_position(GTK_PANED(w), val);

    return FALSE;
}

static gboolean update_clist_col_widths(property_t prop)
{
    GtkWidget *w;
    guint32* val = NULL;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);

    if (w == NULL) {
		if (gui_debug)
			g_warning("%s - widget not found: [%s]", 
				 G_GNUC_PRETTY_FUNCTION, map_entry->wid);
        return FALSE;
    }

    switch (map_entry->type) {
        case PROP_TYPE_GUINT32: {
            gint n = 0;
            prop_def_t *def;

            val = stub->guint32.get(prop, NULL, 0, 0);
            def = stub->get_def(prop);

            for (n = 0; n < def->vector_size; n ++)
                gtk_clist_set_column_width(GTK_CLIST(w), n, val[n]);

            prop_free_def(def);
            break;
        }
        default:
            val = 0;
            g_error("update_clist_col_widths: incompatible type %s", 
                prop_type_str[map_entry->type]);
    }

    g_free(val);
    return FALSE;
}

#ifdef USE_GTK2
/* FIXME: Dummy function; verify whether we need it all. */
static gboolean update_treeview_col_widths(property_t prop)
{
	return FALSE;
}
#endif

#if 0
static gboolean update_treeview_col_widths(property_t prop)
{
    GtkWidget *w;
    guint32* val = NULL;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);

    if (w == NULL) {
		if (gui_debug)
			g_warning("%s - widget not found: [%s]", 
				 G_GNUC_PRETTY_FUNCTION, map_entry->wid);
        return FALSE;
    }

    switch (map_entry->type) {
        case PROP_TYPE_GUINT32: {
            gint n = 0;
            prop_def_t *def;

            val = stub->guint32.get(prop, NULL, 0, 0);
            def = stub->get_def(prop);

            for (n = 0; n < def->vector_size; n ++) {
            	GtkTreeViewColumn *col = gtk_tree_view_get_column(
            		GTK_TREE_VIEW(w), n);
            		
            	if (col && val[n] > 0)
            		gtk_tree_view_column_set_fixed_width(col, val[n]);
            }

            prop_free_def(def);
            break;
        }
        default:
            val = 0;
            g_error("update_treeview_col_widths: incompatible type %s",
                prop_type_str[map_entry->type]);
    }

    g_free(val);
    return FALSE;
}
#endif /* 0 */

static gboolean update_window_geometry(property_t prop)
{
    GtkWidget *w;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = top;
    
    if (!w->window) {
		if (gui_debug)
			g_warning("%s - top level window not available (NULL)", 
				 G_GNUC_PRETTY_FUNCTION);
        return FALSE;
    }
 
    switch (map_entry->type) {
        case PROP_TYPE_GUINT32: {
            guint32 geo[4];

            stub->guint32.get(prop, geo, 0, 4);
            gdk_window_move_resize(w->window, geo[0], geo[1], geo[2], geo[3]);

            break;
        }
        default:
            g_error("update_window_geometry: incompatible type %s", 
                prop_type_str[map_entry->type]);
    }

    return FALSE;
}

/*
 * update_bandwidth_spinbutton:
 *
 * This is not really a generic updater. It's just here because it's used
 * by all bandwidths spinbuttons. It divides the property value by 1024
 * before setting the value to the widget, just like the callbacks of those
 * widget multiply the widget value by 1024 before setting the property.
 */
static gboolean update_bandwidth_spinbutton(property_t prop)
{
    GtkWidget *w;
    guint32 val = 0;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);

    if (w == NULL) {
		if (gui_debug)
			g_warning("%s - widget not found: [%s]", 
				 G_GNUC_PRETTY_FUNCTION, map_entry->wid);
        return FALSE;
    }
   
    switch (map_entry->type) {
        case PROP_TYPE_GUINT32:
            stub->guint32.get(prop, &val, 0, 1);
            break;
         default:
            val = 0;
            g_error("update_spinbutton: incompatible type %s", 
                prop_type_str[map_entry->type]);
    }

    gtk_spin_button_set_value(GTK_SPIN_BUTTON(w), (float)val/1024.0);

    return FALSE;
}

/***
 *** IV. Special case callbacks
 ***/

#define ENTRY(v, widget)                                    \
    static gboolean CAT2(v,_changed)(property_t prop)       \
    {                                                       \
        gchar *val   = gnet_prop_get_string(prop, NULL, 0); \
        GtkWidget *w = lookup_widget(main_window, widget);  \
                                                            \
        gtk_entry_set_text(GTK_ENTRY(w), val);              \
                                                            \
        g_free(val);                                        \
        return FALSE;                                       \
    }


ENTRY(
    socks_user, 
    "entry_config_socks_username")
ENTRY(
    socks_pass, 
    "entry_config_socks_password")

static gboolean bw_gnet_lin_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;

    w = lookup_widget(main_window, "checkbutton_config_bws_glin");
    s = lookup_widget(main_window, "spinbutton_config_bws_glin");

    gnet_prop_get_boolean_val(prop, &val);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    gtk_widget_set_sensitive(s, val);
	update_input_bw_display();

    return FALSE;
}

static gboolean bw_gnet_lout_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;

    gnet_prop_get_boolean_val(prop, &val);

    w = lookup_widget(main_window, "checkbutton_config_bws_glout");
    s = lookup_widget(main_window, "spinbutton_config_bws_glout");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    gtk_widget_set_sensitive(s, val);
	update_output_bw_display();

    return FALSE;
}

static gboolean bw_http_in_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;

    gnet_prop_get_boolean_val(prop, &val);

    w = lookup_widget(main_window, "checkbutton_config_bws_in");
    s = lookup_widget(main_window, "spinbutton_config_bws_in");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    gtk_widget_set_sensitive(s, val);
	update_input_bw_display();

    return FALSE;
}

static gboolean bw_gnet_in_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;

    gnet_prop_get_boolean_val(prop, &val);

    w = lookup_widget(main_window, "checkbutton_config_bws_gin");
    s = lookup_widget(main_window, "spinbutton_config_bws_gin");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    gtk_widget_set_sensitive(s, val);
	update_input_bw_display();

    return FALSE;
}

static gboolean bw_gnet_out_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;

    gnet_prop_get_boolean_val(prop, &val);

    w = lookup_widget(main_window, "checkbutton_config_bws_gout");
    s = lookup_widget(main_window, "spinbutton_config_bws_gout");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    gtk_widget_set_sensitive(s, val);
	update_output_bw_display();

    return FALSE;
}

static gboolean bw_ul_usage_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;
    gboolean val2;

    gnet_prop_get_boolean_val(prop, &val);
    gnet_prop_get_boolean_val(PROP_BW_HTTP_OUT_ENABLED, &val2);

    w = lookup_widget
        (main_window, "checkbutton_config_bw_ul_usage_enabled");
    s = lookup_widget
        (main_window, "spinbutton_config_ul_usage_min_percentage");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    gtk_widget_set_sensitive(s, val && val2);

    return FALSE;
}

static gboolean bw_http_out_enabled_changed(property_t prop)
{
    gboolean val;
    gboolean val2;

    GtkWidget *w = lookup_widget
        (main_window, "checkbutton_config_bws_out");
    GtkWidget *s1 = lookup_widget
        (main_window, "spinbutton_config_ul_usage_min_percentage");
    GtkWidget *s2 = lookup_widget
        (main_window, "spinbutton_config_bws_out");
    GtkWidget *c = lookup_widget
        (main_window, "checkbutton_config_bw_ul_usage_enabled");

    gnet_prop_get_boolean_val(prop, &val);
    gnet_prop_get_boolean_val(PROP_BW_UL_USAGE_ENABLED, &val2);

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);

    gtk_widget_set_sensitive(s2, val);
    gtk_widget_set_sensitive(c, val);
    gtk_widget_set_sensitive(s1, val && val2);
	update_output_bw_display();

    return FALSE;
}

static gboolean proxy_ip_changed(property_t prop)
{
    GtkWidget *w = lookup_widget(main_window, "entry_config_proxy_ip");
    guint32 val;

    gnet_prop_get_guint32_val(prop, &val);

    gtk_entry_set_text(GTK_ENTRY(w), ip_to_gchar(val));

    return FALSE;
}

static gboolean is_firewalled_changed(property_t prop)
{
	GtkWidget *icon_firewall;
	GtkWidget *icon_open;
	gboolean val;

    icon_firewall = lookup_widget(main_window, "eventbox_image_firewall");
	icon_open = lookup_widget(main_window, "eventbox_image_no_firewall");

    gnet_prop_get_boolean_val(prop, &val);
	if (val) {
		gtk_widget_hide(icon_open);
		gtk_widget_show(icon_firewall);
	} else {
		gtk_widget_hide(icon_firewall);
		gtk_widget_show(icon_open);
	}

	return FALSE;
}

static gboolean plug_icon_changed(property_t prop)
{
	GtkWidget *image_online;
	GtkWidget *image_offline;
	GtkWidget *tb;
	gboolean val_is_connected;
	gboolean val_online_mode;

    image_online = lookup_widget(main_window, "image_online");
	image_offline = lookup_widget(main_window, "image_offline");
	tb = lookup_widget(main_window, "togglebutton_online");

    gnet_prop_get_boolean_val(PROP_IS_INET_CONNECTED, &val_is_connected);
    gnet_prop_get_boolean_val(PROP_ONLINE_MODE, &val_online_mode);
	
	if (val_is_connected && val_online_mode) {
		gtk_widget_show(image_online);
		gtk_widget_hide(image_offline);
	} else {
		gtk_widget_hide(image_online);
		gtk_widget_show(image_offline);
	}
	
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(tb), val_online_mode);

	return FALSE;
}

static gboolean current_peermode_changed(property_t prop)
{
	GtkWidget *hbox_normal_ultrapeer = lookup_widget(main_window,
											"hbox_normal_or_ultrapeer");
	GtkWidget *hbox_leaf = lookup_widget(main_window, "hbox_leaf");
    GtkWidget *icon_ultra;
	GtkWidget *icon_leaf;
	GtkWidget *icon_legacy;
	guint32 mode;

    icon_ultra = lookup_widget(main_window, "eventbox_image_ultra");
	icon_leaf = lookup_widget(main_window, "eventbox_image_leaf");
	icon_legacy = lookup_widget(main_window, "eventbox_image_legacy");

    gnet_prop_get_guint32_val(prop, &mode);
	gtk_widget_hide(icon_ultra);
	gtk_widget_hide(icon_leaf);
	gtk_widget_hide(icon_legacy);

	switch (mode) {
	case NODE_P_ULTRA:
		gtk_widget_show(icon_ultra);
		gtk_widget_show(hbox_leaf);
		gtk_widget_show(hbox_normal_ultrapeer);
		break;
	case NODE_P_LEAF:
		gtk_widget_show(icon_leaf);
		gtk_widget_show(hbox_leaf);
		gtk_widget_show(hbox_normal_ultrapeer);
		break;
	case NODE_P_NORMAL:
		gtk_widget_show(icon_legacy);
		gtk_widget_show(hbox_normal_ultrapeer);
		gtk_widget_hide(hbox_leaf);
		break;
	default:
		g_assert_not_reached();
	}	

	return FALSE;
}

static gboolean monitor_enabled_changed(property_t prop) 
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "checkbutton_monitor_enable");

    gui_prop_get_boolean_val(PROP_MONITOR_ENABLED, &val);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    monitor_gui_enable_monitor(val);

    return FALSE;
}

static gboolean reading_hostfile_changed(property_t prop)
{
    gboolean state;
    static statusbar_msgid_t id = {0, 0};

    gnet_prop_get_boolean_val(PROP_READING_HOSTFILE, &state);
    if (state) {
        GtkProgressBar *pg = GTK_PROGRESS_BAR
            (lookup_widget(main_window, "progressbar_hosts_in_catcher"));
        gtk_progress_bar_set_text(pg, _("loading..."));
        id = statusbar_gui_message(0, _("Reading host cache..."));
    } else {
    	hosts_in_catcher_changed(PROP_HOSTS_IN_CATCHER);
		if (0 != id.scid)
       		statusbar_gui_remove(id);
    }
    return FALSE;
}

static gboolean ancient_version_changed(property_t prop)
{
    gboolean b;

    gnet_prop_get_boolean_val(prop, &b);
    if (b)
        statusbar_gui_warning(15, _("*** RUNNING AN OLD VERSION! ***"));

    return FALSE;
}

static gboolean new_version_str_changed(property_t prop)
{
    gchar *str;

    str = gnet_prop_get_string(PROP_NEW_VERSION_STR, NULL, 0);
    statusbar_gui_set_default(str);

	if (str)
		g_free(str);

    return FALSE;
}

static gboolean send_pushes_changed(property_t prop)
{
    gboolean val;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    stub->boolean.get(prop, &val, 0, 1);

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
        (lookup_widget(top, map_entry->wid)), !val);

  	gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_push"), val);

    return FALSE;
}

static gboolean statusbar_visible_changed(property_t prop)
{
    gboolean b;

    gui_prop_get_boolean_val(prop, &b);
    gtk_check_menu_item_set_active(
        GTK_CHECK_MENU_ITEM
            (lookup_widget(main_window, "menu_statusbar_visible")), 
        b);

   	if (b) {
		gtk_widget_show
            (lookup_widget(main_window, "hbox_statusbar"));
	} else {
		gtk_widget_hide
            (lookup_widget(main_window, "hbox_statusbar"));
	}

    return FALSE;
}

static gboolean toolbar_visible_changed(property_t prop)
{
    gboolean b;

    gui_prop_get_boolean_val(prop, &b);
    gtk_check_menu_item_set_active(
        GTK_CHECK_MENU_ITEM
            (lookup_widget(main_window, "menu_toolbar_visible")), 
        b);

   	if (b) {
		gtk_widget_show
            (lookup_widget(main_window, "hb_toolbar"));
	} else {
		gtk_widget_hide
            (lookup_widget(main_window, "hb_toolbar"));
	}

    return FALSE;
}

static void set_host_progress(const gchar *w, guint32 cur, guint32 max)
{
    GtkProgressBar *pg = GTK_PROGRESS_BAR(lookup_widget(main_window, w));
    gfloat frac;

    frac = MIN(cur, max) != 0 ? (float)MIN(cur, max) / max : 0;

	gm_snprintf(set_tmp, sizeof(set_tmp), 
#ifdef USE_GTK2
		_("%u/%u host%s (%u%%)"),
#else
		_("%u/%u host%s (%u%%%%)"),
#endif
        cur, max, (cur == 1 && max == 1) ? "" : "s",
        (guint)(frac*100));

    gtk_progress_bar_set_text(pg, set_tmp);
    gtk_progress_bar_set_fraction(pg, frac);
}

static gboolean hosts_in_catcher_changed(property_t prop)
{
    guint32 hosts_in_catcher;
    guint32 max_hosts_cached;

    gnet_prop_get_guint32_val(PROP_HOSTS_IN_CATCHER, &hosts_in_catcher);
    gnet_prop_get_guint32_val(PROP_MAX_HOSTS_CACHED, &max_hosts_cached);

    gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_host_catcher_clear"), 
        hosts_in_catcher != 0);

    set_host_progress(
        "progressbar_hosts_in_catcher", 
        hosts_in_catcher,
        max_hosts_cached);
    
    return FALSE;
}

static gboolean hosts_in_ultra_catcher_changed(property_t prop)
{
    guint32 hosts;
    guint32 max_hosts;

    gnet_prop_get_guint32_val(PROP_HOSTS_IN_ULTRA_CATCHER, &hosts);
    gnet_prop_get_guint32_val(PROP_MAX_ULTRA_HOSTS_CACHED, &max_hosts);

    gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_ultra_catcher_clear"), hosts != 0);

    set_host_progress("progressbar_hosts_in_ultra_catcher", hosts, max_hosts);
    
    return FALSE;
}

/*
 * update_stats_visibility:
 *
 * Change the menu item cm and show/hide the widget w to reflect the
 * value of val. val = TRUE means w should be visible.
 */
static void update_stats_visibility
    (GtkCheckMenuItem *cm, GtkWidget *w, gboolean val)
{
    gtk_check_menu_item_set_state(cm, val);

    if (val) {
        gtk_widget_show(w);
    } else {
        gtk_widget_hide(w);
    }

    gui_update_stats_frames();
}

static gboolean progressbar_bws_in_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "progressbar_bws_in");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (lookup_widget(main_window, "menu_bws_in_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean progressbar_bws_out_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "progressbar_bws_out");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (lookup_widget(main_window, "menu_bws_out_visible"));

    gui_prop_get_boolean_val(prop, &val);

    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean progressbar_bws_gin_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "progressbar_bws_gin");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (lookup_widget(main_window, "menu_bws_gin_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean progressbar_bws_gout_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "progressbar_bws_gout");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (lookup_widget(main_window, "menu_bws_gout_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean progressbar_bws_glin_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "progressbar_bws_lin");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (lookup_widget(main_window, "menu_bws_glin_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean progressbar_bws_glout_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "progressbar_bws_lout");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (lookup_widget(main_window, "menu_bws_glout_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean progressbar_downloads_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "hbox_stats_downloads");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (lookup_widget(main_window, "menu_downloads_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean progressbar_uploads_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "hbox_stats_uploads");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (lookup_widget(main_window, "menu_uploads_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean progressbar_connections_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "hbox_stats_connections");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (lookup_widget(main_window, "menu_connections_visible"));

    gui_prop_get_boolean_val(prop, &val);
    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean search_results_show_tabs_changed(property_t prop)
{
    gboolean val;

    gui_prop_get_boolean_val(prop, &val);
	gtk_notebook_set_show_tabs(
        GTK_NOTEBOOK(lookup_widget(main_window, "notebook_search_results")),
		val);
    gtk_notebook_set_page(
        GTK_NOTEBOOK(lookup_widget(main_window, "notebook_sidebar")),
        search_results_show_tabs ? 1 : 0);

    return FALSE;
}

static gboolean autoclear_completed_downloads_changed(property_t prop)
{
    gboolean val;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    stub->boolean.get(prop, &val, 0, 1);

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
        (lookup_widget(top, map_entry->wid)), val);

    if(val)
        download_clear_stopped(TRUE, FALSE, FALSE, TRUE);

    return FALSE;
}

static gboolean autoclear_failed_downloads_changed(property_t prop)
{
    gboolean val;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    stub->boolean.get(prop, &val, 0, 1);

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
        (lookup_widget(top, map_entry->wid)), val);

    if(val)
        download_clear_stopped(FALSE, TRUE, FALSE, TRUE);

    return FALSE;
}

static gboolean autoclear_unavailable_downloads_changed(property_t prop)
{
    gboolean val;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    stub->boolean.get(prop, &val, 0, 1);

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
        (lookup_widget(top, map_entry->wid)), val);

    if(val)
        download_clear_stopped(FALSE, FALSE, TRUE, TRUE);

    return FALSE;
}

static gboolean traffic_stats_mode_changed(property_t prop)
{
    gui_update_traffic_stats();

    return FALSE;
}

static gboolean min_dup_ratio_changed(property_t prop)
{
    GtkWidget *w;
    guint32 val = 0;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);
    stub->guint32.get(prop, &val, 0, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(w), (float)val/100.0);

    return FALSE;
}

static gboolean show_search_results_settings_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *frame;
    gboolean val;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    stub->boolean.get(prop, &val, 0, 1);

    w = lookup_widget(top, map_entry->wid);
    frame = lookup_widget(top, "frame_search_results_settings");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);

    if (val) {
        gtk_label_set_text(
            GTK_LABEL(lookup_widget(top, 
                "label_search_results_show_settings")),
            "Hide settings");
        gtk_widget_show(frame);
    } else {
        gtk_label_set_text(
            GTK_LABEL(lookup_widget(top, 
                "label_search_results_show_settings")),
            "Show settings");
        gtk_widget_hide(frame);
    }

    return FALSE;
}

static gboolean show_dl_settings_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *frame;
    gboolean val;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    stub->boolean.get(prop, &val, 0, 1);

    w = lookup_widget(top, map_entry->wid);
    frame = lookup_widget(top, "frame_dl_settings");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);

    if (val) {
        gtk_label_set_text(
            GTK_LABEL(lookup_widget(top, 
                "label_dl_show_settings")),
            "Hide settings");
        gtk_widget_show(frame);
    } else {
        gtk_label_set_text(
            GTK_LABEL(lookup_widget(top, 
                "label_dl_show_settings")),
            "Show settings");
        gtk_widget_hide(frame);
    }

    return FALSE;
}

static gboolean _update_address_information(void)
{
    static guint32 old_address = 0;
    static guint16 old_port = 0;
    gboolean force_local_ip;
    guint32 listen_port;
    guint32 current_ip;

    gnet_prop_get_boolean_val(PROP_FORCE_LOCAL_IP, &force_local_ip);
    gnet_prop_get_guint32_val(PROP_LISTEN_PORT, &listen_port);

    if (force_local_ip)
        gnet_prop_get_guint32_val(PROP_FORCED_LOCAL_IP, &current_ip);
    else
        gnet_prop_get_guint32_val(PROP_LOCAL_IP, &current_ip);
   
    if (old_address != current_ip || old_port != listen_port) {
        const gchar * iport;

      	iport = ip_port_to_gchar(current_ip, listen_port);

        old_address = current_ip;
        old_port = listen_port;

        statusbar_gui_message(15, "Address/port changed to: %s", iport);
        gtk_label_set_text(
            GTK_LABEL(lookup_widget(main_window, "label_current_port")) , 
            iport);

#ifdef USE_GTK2
        gtk_label_set_text(
			GTK_LABEL(lookup_widget(main_window, "label_nodes_ip")), iport);
#else
        gtk_entry_set_text(
			GTK_ENTRY(lookup_widget(main_window, "entry_nodes_ip")), iport);
#endif
    }

    return FALSE;
}

static void update_input_bw_display(void)
{
	gboolean enabled;
	guint32 val = 0;
	guint32 bw;

#ifdef USE_GTK1
	gnet_prop_get_boolean_val(PROP_BW_GNET_LEAF_IN_ENABLED, &enabled);
	if (enabled) {
		gnet_prop_get_guint32_val(PROP_BW_GNET_LIN, &bw);
		val += bw;
	}
	gnet_prop_get_boolean_val(PROP_BW_HTTP_IN_ENABLED, &enabled);
	if (enabled) {
		gnet_prop_get_guint32_val(PROP_BW_HTTP_IN, &bw);
		val += bw;
		/* Leaf bandwidth is taken from HTTP traffic, when enabled */
		gnet_prop_get_boolean_val(PROP_BW_GNET_LEAF_IN_ENABLED, &enabled);
		if (enabled) {
			gnet_prop_get_guint32_val(PROP_BW_GNET_LIN, &bw);
			val -= bw;
		}
	}
	gnet_prop_get_boolean_val(PROP_BW_GNET_IN_ENABLED, &enabled);
	if (enabled) {
		gnet_prop_get_guint32_val(PROP_BW_GNET_IN, &bw);
		val += bw;
	}

	gtk_label_printf(
		GTK_LABEL(lookup_widget(main_window, "label_input_bw_limit")),
		"%.2f", val / 1024.0);
#endif
}

static gboolean spinbutton_input_bw_changed(property_t prop)
{
	gboolean ret;

	ret = update_bandwidth_spinbutton(prop);
	update_input_bw_display();
	return ret;
}

static void update_output_bw_display(void)
{
	gboolean enabled;
	guint32 val = 0;
	guint32 bw;

#ifdef USE_GTK1
	gnet_prop_get_boolean_val(PROP_BW_GNET_LEAF_OUT_ENABLED, &enabled);
	if (enabled) {
		gnet_prop_get_guint32_val(PROP_BW_GNET_LOUT, &bw);
		val += bw;
	}
	gnet_prop_get_boolean_val(PROP_BW_HTTP_OUT_ENABLED, &enabled);
	if (enabled) {
		gnet_prop_get_guint32_val(PROP_BW_HTTP_OUT, &bw);
		val += bw;
		/* Leaf bandwidth is taken from HTTP traffic, when enabled */
		gnet_prop_get_boolean_val(PROP_BW_GNET_LEAF_OUT_ENABLED, &enabled);
		if (enabled) {
			gnet_prop_get_guint32_val(PROP_BW_GNET_LOUT, &bw);
			val -= bw;
		}
	}
	gnet_prop_get_boolean_val(PROP_BW_GNET_OUT_ENABLED, &enabled);
	if (enabled) {
		gnet_prop_get_guint32_val(PROP_BW_GNET_OUT, &bw);
		val += bw;
	}

	gtk_label_printf(
		GTK_LABEL(lookup_widget(main_window, "label_output_bw_limit")),
		"%.2f", val / 1024.0);
#endif
}

static gboolean spinbutton_output_bw_changed(property_t prop)
{
	gboolean ret;

	ret = update_bandwidth_spinbutton(prop);
	update_output_bw_display();
	return ret;
}

static gboolean force_local_ip_changed(property_t prop)
{
    update_togglebutton(prop);
    _update_address_information();
    return FALSE;
}

static gboolean listen_port_changed(property_t prop)
{
    update_spinbutton(prop);
    _update_address_information();
    return FALSE;
}

static gboolean local_address_changed(property_t prop)
{
    _update_address_information();
    return FALSE;
}

static gboolean use_netmasks_changed(property_t prop)
{
    gboolean b;
    
    gnet_prop_get_boolean_val(prop, &b);
    update_togglebutton(prop);
    gtk_widget_set_sensitive(
        lookup_widget(main_window, "entry_config_netmasks"), b);

    return FALSE;
}

static gboolean guid_changed(property_t prop)
{
    gchar guid_buf[16];
   
    gnet_prop_get_storage(prop, (guint8 *) guid_buf, sizeof(guid_buf));

#ifdef USE_GTK2
    gtk_label_set_text(
        GTK_LABEL(lookup_widget(main_window, "label_nodes_guid")),
        guid_hex_str(guid_buf));
#else
    gtk_entry_set_text(
        GTK_ENTRY(lookup_widget(main_window, "entry_nodes_guid")),
        guid_hex_str(guid_buf));
#endif

    return FALSE;
}

static gboolean update_monitor_unstable_ip(property_t prop)
{
	gboolean b;

	gnet_prop_get_boolean_val(prop, &b);

	gtk_widget_set_sensitive(
		lookup_widget(main_window, "checkbutton_gnet_monitor_servents"), b);

	return update_togglebutton(prop);
}

static gboolean show_tooltips_changed(property_t prop)
{
    gboolean b;

    update_togglebutton(prop);
    gui_prop_get_boolean_val(prop, &b);
    if (b) {
        gtk_tooltips_enable(tooltips);
        gtk_tooltips_enable(
            GTK_TOOLTIPS(gtk_object_get_data(
                GTK_OBJECT(main_window), "tooltips")));
    } else {
        gtk_tooltips_disable(tooltips);
        gtk_tooltips_disable(
            GTK_TOOLTIPS(gtk_object_get_data(
                GTK_OBJECT(main_window), "tooltips")));
    }

    return FALSE;
}

static gboolean expert_mode_changed(property_t prop)
{
    static const gchar *expert_widgets[] = {
        "frame_expert_nw_local",
        "frame_expert_nw_misc",
        "frame_expert_gnet_timeout",
        "frame_expert_gnet_ttl",
        "frame_expert_gnet_quality",
        "frame_expert_gnet_connections",
        "frame_expert_gnet_other",
        "frame_expert_dl_timeout",
        "frame_expert_ul_timeout",
        "frame_expert_dl_source_quality",
        "frame_expert_unmapped",
#ifdef USE_GTK1
        "frame_expert_rx_buffers",
#endif
        NULL
    };
    gint n;
    gboolean b;

    update_togglebutton(prop);
    gui_prop_get_boolean_val(prop, &b);

    for (n = 0; expert_widgets[n] != NULL; n++) {
        GtkWidget *w = lookup_widget(main_window, expert_widgets[n]);

        if (w == NULL)
            continue;

        if (b)
            gtk_widget_show(w);
        else
            gtk_widget_hide(w);
    }

    return FALSE;
}

static gboolean search_stats_mode_changed(property_t prop)
{
    guint32 val;

    gui_prop_get_guint32_val(prop, &val);
    update_multichoice(prop);
    search_stats_gui_set_type(val);
    search_stats_gui_reset();

    return FALSE;
}

static inline gboolean widget_set_sensitive(const gchar *name, property_t prop)
{
	gboolean val;

    gnet_prop_get_boolean_val(prop, &val);
    gtk_widget_set_sensitive(lookup_widget(main_window, name), val);
	
	return FALSE;
}

static gboolean sha1_rebuilding_changed(property_t prop)
{
	return widget_set_sensitive("image_sha", prop);
}

static gboolean sha1_verifying_changed(property_t prop)
{
	return widget_set_sensitive("image_shav", prop);
}

static gboolean library_rebuilding_changed(property_t prop)
{
	return widget_set_sensitive("image_lib", prop);
}

static gboolean file_moving_changed(property_t prop)
{
	return widget_set_sensitive("image_save", prop);
}

static gboolean dl_running_count_changed(property_t prop)
{
	guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
    if (val == 0) {
        gtk_label_printf(
            GTK_LABEL(lookup_widget(main_window, "label_dl_running_count")),
            _("no sources"));
    } else {
        gtk_label_printf(
            GTK_LABEL(lookup_widget(main_window, "label_dl_running_count")),
            _("%u source%s"), val, (val != 1) ? "s" : "");
    }

	downloads_count_changed(prop);

	return FALSE;
}

static gboolean dl_active_count_changed(property_t prop)
{
	guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
	gtk_label_printf(
		GTK_LABEL(lookup_widget(main_window, "label_dl_active_count")),
		_("%u active"), val);

	downloads_count_changed(prop);

	return FALSE;
}

static gboolean dl_http_latency_changed(property_t prop)
{
	guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
	gtk_label_printf(
		GTK_LABEL(lookup_widget(main_window, "label_dl_http_latency")),
		"%.3lf", val / 1000.0);

	return FALSE;
}

static gboolean dl_aqueued_count_changed(property_t prop)
{
	guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
	gtk_label_printf(
		GTK_LABEL(lookup_widget(main_window, "label_dl_aqueued_count")),
		_("%u queued"), val);

	return FALSE;
}

#ifdef USE_GTK2
static gboolean config_toolbar_style_changed(property_t prop)
{
	guint32 val;
	GtkToolbarStyle style;

	gui_prop_get_guint32_val(PROP_CONFIG_TOOLBAR_STYLE, &val);
	
	switch (val) {
		case 1:
			style = GTK_TOOLBAR_ICONS;
			break;
		case 2:
			style = GTK_TOOLBAR_TEXT;
			break;
		case 3:
			style = GTK_TOOLBAR_BOTH;
			break;
		case 4:
#ifdef USE_GTK2
			style = GTK_TOOLBAR_BOTH_HORIZ;
#else
			style = GTK_TOOLBAR_BOTH;
#endif
			break;
		default:
			style = GTK_TOOLBAR_BOTH;
			g_warning(
				"config_toolbar_style_changed: Unknown toolbar style (val=%ld)",
				(gulong) val);
	}

	gtk_toolbar_set_style(
   		GTK_TOOLBAR(lookup_widget(main_window, "toolbar_main")), style);
	update_multichoice(prop);
	return FALSE;
}
#endif

static gboolean gnet_connections_changed(property_t prop)
{
    guint32 leaf_count;
    guint32 normal_count;
    guint32 ultra_count;
    guint32 max_connections;
    guint32 max_leaves;
    guint32 max_normal;
    guint32 max_ultrapeers;
    gfloat  frac;
    guint32 cnodes;
    guint32 nodes = 0;
    guint32 peermode;

    GtkProgressBar *pg = GTK_PROGRESS_BAR(
        lookup_widget(main_window, "progressbar_connections"));

    gnet_prop_get_guint32_val(PROP_NODE_LEAF_COUNT, &leaf_count);
    gnet_prop_get_guint32_val(PROP_NODE_NORMAL_COUNT, &normal_count);
    gnet_prop_get_guint32_val(PROP_NODE_ULTRA_COUNT, &ultra_count);
    gnet_prop_get_guint32_val(PROP_MAX_CONNECTIONS, &max_connections);
    gnet_prop_get_guint32_val(PROP_MAX_LEAVES, &max_leaves);
    gnet_prop_get_guint32_val(PROP_MAX_ULTRAPEERS, &max_ultrapeers);
    gnet_prop_get_guint32_val(PROP_NORMAL_CONNECTIONS, &max_normal);
    gnet_prop_get_guint32_val(PROP_CURRENT_PEERMODE, &peermode);

    cnodes = leaf_count + normal_count + ultra_count;

    switch (peermode) {
    case NODE_P_LEAF: /* leaf */
    case NODE_P_NORMAL: /* normal */
        nodes = (peermode == NODE_P_NORMAL) ? 
            max_connections : max_ultrapeers;
        gm_snprintf(set_tmp, sizeof(set_tmp), 
            _("%u/%u connection%s"),
            cnodes, nodes, (cnodes == 1 && nodes == 1) ? "" : "s");
        break;
    case NODE_P_ULTRA: /* ultra */
        nodes = max_connections + max_leaves + max_normal;
        gm_snprintf(set_tmp, sizeof(set_tmp), 
            "%u/%uU | %u/%uN | %u/%uL",
            ultra_count,
			max_connections < max_normal ? 0 : max_connections - max_normal, 
            normal_count, max_normal, 
            leaf_count, max_leaves);
        break;
    default:
        g_assert_not_reached();
    }
    frac = MIN(cnodes, nodes) != 0 ? (gfloat) MIN(cnodes, nodes) / nodes : 0;

    gtk_progress_bar_set_text(pg, set_tmp);
    gtk_progress_bar_set_fraction(pg, frac);

    return FALSE;
}

static gboolean uploads_count_changed(property_t prop)
{
    GtkProgressBar *pg = GTK_PROGRESS_BAR
         (lookup_widget(main_window, "progressbar_uploads"));
    gfloat frac;
	guint32 registered;
	guint32 running;
	guint32 min;

    gnet_prop_get_guint32_val(PROP_UL_REGISTERED, &registered);
    gnet_prop_get_guint32_val(PROP_UL_RUNNING, &running);
	gm_snprintf(set_tmp, sizeof(set_tmp), _("%u/%u upload%s"),
		running, registered, (1 == running && 1 == registered) ? "" : "s");

	min = MIN(running, registered);
    frac = min != 0 ? (gfloat) min / registered : 0;

    gtk_progress_bar_set_text(pg, set_tmp);
    gtk_progress_bar_set_fraction(pg, frac);
	return FALSE;
}

static gboolean downloads_count_changed(property_t prop)
{
    GtkProgressBar *pg = GTK_PROGRESS_BAR
         (lookup_widget(main_window, "progressbar_downloads"));
    gfloat frac;
    guint32 active;
    guint32 running;
    guint32 min;

    gnet_prop_get_guint32_val(PROP_DL_ACTIVE_COUNT, &active);
    gnet_prop_get_guint32_val(PROP_DL_RUNNING_COUNT, &running);
    gm_snprintf(set_tmp, sizeof(set_tmp), _("%u/%u download%s"),
        active, running, (1 == running && 1 == active) ? "" : "s");

    min = MIN(active, running);
    frac = min != 0 ? (gfloat) min / running : 0;

    gtk_progress_bar_set_text(pg, set_tmp);
    gtk_progress_bar_set_fraction(pg, frac);
    return FALSE;
}

static gboolean clock_skew_changed(property_t prop)
{
    gchar s[64];
    guint32 val;

    gnet_prop_get_guint32_val(prop, &val);
    gm_snprintf(s, sizeof(s), "%d secs", (gint32) val);
    gtk_label_set_text(
		GTK_LABEL(lookup_widget(main_window, "label_clock_skew")), s);
    return FALSE;
}

/***
 *** V.  Control functions.
 ***/

/*
 * spinbutton_adjustment_value_changed:
 *
 * This callbacks is called when a GtkSpinbutton which is referenced in 
 * the property_map changed. It reacts to the "value_changed" signal of 
 * the GtkAdjustement associated with the GtkSpinbutton.
 */
static void spinbutton_adjustment_value_changed
    (GtkAdjustment *adj, gpointer user_data)
{
    prop_map_t *map_entry = (prop_map_t *) user_data;
    prop_set_stub_t *stub = map_entry->stub;
    guint32 val = adj->value;

    /*
     * Special handling for the special cases.
     */
    if (stub == gnet_prop_set_stub) {
        /*
         * Bandwidth spinbuttons need the value multiplied by 1024
         */
        if (
            (map_entry->prop == PROP_BW_HTTP_IN) ||
            (map_entry->prop == PROP_BW_HTTP_OUT) ||
            (map_entry->prop == PROP_BW_GNET_LIN) ||
            (map_entry->prop == PROP_BW_GNET_LOUT) ||
            (map_entry->prop == PROP_BW_GNET_IN) ||
            (map_entry->prop == PROP_BW_GNET_OUT)
        ) {
            val = adj->value * 1024.0;
        }

        /*
         * Some spinbuttons need the multiplied by 100
         */
        if (
            (map_entry->prop == PROP_MIN_DUP_RATIO)
        ) {
            val = adj->value * 100.0;
        }
        
        /*
         * When MAX_DOWNLOADS or MAX_HOST_DOWNLOADS are changed, we
         * have some ancient workaround which may still be necessary.
         */
        if (
            (map_entry->prop == PROP_MAX_DOWNLOADS) ||
            (map_entry->prop == PROP_MAX_HOST_DOWNLOADS)
        ) {
            /*
             * XXX If the user modifies the max simultaneous download 
             * XXX and click on a queued download, gtk-gnutella segfaults 
             * XXX in some cases. This unselected_all() is a first attempt
             * XXX to work around the problem.
             *
             * It's unknown whether this ancient workaround is still
             * needed.
             *      -- Richard, 13/08/2002
             */             
            gtk_clist_unselect_all(GTK_CLIST(
                lookup_widget(main_window, "clist_downloads_queue")));
        }
    }

    stub->guint32.set(map_entry->prop, &val, 0, 1);
}

/*
 * togglebutton_state_changed:
 *
 * This function is called when the state of a GtkToggleButton that
 * is managed by the property_map. It is bound during initialization
 * when the property_map is processed.
 * GtkToggleButtons are normally bound directly to thier associated
 * properties. Special cases are handled here.
 */
static void togglebutton_state_changed(
    GtkToggleButton *tb, gpointer user_data)
{
    prop_map_t *map_entry = (prop_map_t *) user_data;
    prop_set_stub_t *stub = map_entry->stub;
    gboolean val = gtk_toggle_button_get_active(tb);
    
    /*
     * Special handling for the special cases.
     */
    if (stub == gnet_prop_set_stub) {
        /*
         * PROP_SEND_PUSHES needs widget value inversed.
         */
        if (map_entry->prop == PROP_SEND_PUSHES) {
            val = !val;
        }
    }

    stub->boolean.set(map_entry->prop, &val, 0, 1);
}

static void multichoice_item_selected(GtkItem *i, gpointer data)
{
    prop_map_t *map_entry = (prop_map_t *) data;
    prop_set_stub_t *stub = map_entry->stub;
    guint32 val = GPOINTER_TO_UINT(gtk_object_get_user_data(GTK_OBJECT(i)));

    stub->guint32.set(map_entry->prop, &val, 0, 1);
}

/*
 * settings_gui_config_widget:
 *
 * Set up tooltip and constraints where applicable.
 */
static void settings_gui_config_widget(prop_map_t *map, prop_def_t *def)
{
    g_assert(map != NULL);
    g_assert(def != NULL);

    if (map->cb != IGNORE) {
        if (gui_debug >= 8)
            printf("settings_gui_config_widget: %s\n", def->name);

        /*
         * Set tooltip/limits
         */
        if (map->wid != NULL) {
            GtkWidget *top = NULL;
            GtkWidget *w; 

            /*
             * If can't determine the toplevel widget or the target
             * widget we abort.
             */
            top = map->fn_toplevel();
            if (top == NULL)
                return;

            w = lookup_widget(top, map->wid);
            if (w == NULL)
                return;

            /*
             * Set tooltip.
             */
#ifdef USE_GTK2
			if (!GTK_IS_TREE_VIEW(w))
#endif
			{
            	gtk_tooltips_set_tip(tooltips, w, def->desc, "");
				if (gui_debug >= 9)
					printf("\t...added tooltip\n");
			}

            /*
             * If the widget is a spinbutton, configure the bounds
             */
            if (top && GTK_IS_SPIN_BUTTON(w)) {
                GtkAdjustment *adj =
                    gtk_spin_button_get_adjustment(GTK_SPIN_BUTTON(w));
                gdouble divider = 1.0;
            
                g_assert(def->type == PROP_TYPE_GUINT32);
        
                /*
                 * Bandwidth spinbuttons need the value divided by
                 * 1024.
                 */
                if (
                    (map->stub == gnet_prop_set_stub) && (
                        (map->prop == PROP_BW_HTTP_IN) ||
                        (map->prop == PROP_BW_HTTP_OUT) ||
                        (map->prop == PROP_BW_GNET_LIN) ||
                        (map->prop == PROP_BW_GNET_LOUT) ||
                        (map->prop == PROP_BW_GNET_IN) ||
                        (map->prop == PROP_BW_GNET_OUT)
                    )
                ) {
                    divider = 1024.0;
                }
    
                /*
                 * Some others need the value divided by 100.
                 */
                if (
                    (map->stub == gnet_prop_set_stub) && (
                        (map->prop == PROP_MIN_DUP_RATIO)
                    )
                ) {
                    divider = 100.0;
                }

                adj->lower = def->data.guint32.min / divider;
                adj->upper = def->data.guint32.max / divider;

                gtk_adjustment_changed(adj);

                gtk_signal_connect_after(
                    GTK_OBJECT (adj), "value_changed",
                    (GtkSignalFunc) spinbutton_adjustment_value_changed,
                    (gpointer) map);

				if (gui_debug >= 9)
					printf("\t...adjusted lower=%f, upper=%f\n",
						adj->lower, adj->upper);
            }

            if (top && GTK_IS_TOGGLE_BUTTON(w)) {
                g_assert(def->type == PROP_TYPE_BOOLEAN);

                gtk_signal_connect(
                    GTK_OBJECT(w), "toggled",
                    (GtkSignalFunc) togglebutton_state_changed,
                    (gpointer) map);

				if (gui_debug >= 9)
					printf("\t...connected toggle signal\n");
            }

            if (top && GTK_IS_COMBO(w)) {
                g_assert(def->type == PROP_TYPE_MULTICHOICE);

                gtk_combo_init_choices(GTK_COMBO(w),
                    GTK_SIGNAL_FUNC(multichoice_item_selected),
                    def, (gpointer) map);

				if (gui_debug >= 9)
					printf("\t...connected multichoice signal\n");
            }
        }
        if (gui_debug >= 8)
            printf("\t...all done for %s.\n", def->name);

    }
}

/*
 * settings_gui_init_prop_map:
 *
 * Use information from property_map to connect callbacks to
 * signals from the backend. 
 * You can't connect more then one callback to a single property change.
 * You can however IGNORE a property change to suppress a warning in 
 * debugging mode. This is done by settings the cb field (callback) in 
 * property_map to IGNORE.
 * The tooltips for the widgets are set from to the description from the
 * property definition.
 */
static void settings_gui_init_prop_map(void)
{
    gint n;

    if (gui_debug >= 2) {
        printf("settings_gui_init_prop_map: property_map size: %u\n", 
            (guint) G_N_ELEMENTS(property_map));
    }

    /*
     * Fill in automatic fields in property_map.
     */
    for (n = 0; n < G_N_ELEMENTS(property_map); n++) {
        property_t prop = property_map[n].prop;
        prop_def_t *def;

        /*
         * Fill in prop_set_stub
         */
        if (
            (prop >= gui_prop_set_stub->offset) && 
            (prop < gui_prop_set_stub->offset+gui_prop_set_stub->size)
        ) {
            property_map[n].stub = gui_prop_set_stub;
            property_map[n].init_list = gui_init_list;
        } else
        if (
            (prop >= gnet_prop_set_stub->offset) && 
            (prop < gnet_prop_set_stub->offset+gnet_prop_set_stub->size)
        ) {
            property_map[n].stub = gnet_prop_set_stub;
            property_map[n].init_list = gnet_init_list;
        } else
            g_error("settings_init_prop_map: "
                "property does not belong to known set: %u", prop);

        /*
         * Fill in type
         */
        def = property_map[n].stub->get_def(prop);

        property_map[n].type = def->type;

        prop_free_def(def);
    }

    /*
     * Now the map is complete and can be processed.
     */
    for (n = 0; n < G_N_ELEMENTS(property_map); n ++) {
        property_t  prop      = property_map[n].prop;
        prop_def_t *def       = property_map[n].stub->get_def(prop);
        guint32     idx       = prop - property_map[n].stub->offset;
        gint       *init_list = property_map[n].init_list;

        if (init_list[idx] == NOT_IN_MAP) {
            init_list[idx] = n;
        } else {
            g_error("settings_gui_init_prop_map:" 
                " property %s already mapped to %d", 
                def->name, init_list[idx]);
        }
    
        if (property_map[n].cb != IGNORE) {
            settings_gui_config_widget(&property_map[n], def);
        
            /*
             * Add listener
             */
            if (gui_debug >= 10)
                printf("settings_gui_init_prop_map: adding changes listener "
                    "[%s]\n", def ->name);
            property_map[n].stub->prop_changed_listener.add_full(
                property_map[n].prop,
                property_map[n].cb,
                property_map[n].init,
                property_map[n].f_type,
                property_map[n].f_interval);
            if (gui_debug >= 10)
                printf("settings_gui_init_prop_map: adding changes listener "
                    "[%s][done]\n", def->name);
        } else if (gui_debug >= 10) {
            printf("settings_gui_init_prop_map: " 
                "property ignored: %s\n", def->name);
        }
        prop_free_def(def);
    }

    if (gui_debug >= 1) {
        for (n = 0; n < GUI_PROPERTY_NUM; n++) {
            if (gui_init_list[n] == NOT_IN_MAP) {
                printf("settings_gui_init_prop_map: "
					"[GUI] unmapped property: %s\n",
					gui_prop_name(n+GUI_PROPERTY_MIN));
            }
        }
    }

    if (gui_debug >= 1) {
        for (n = 0; n < GNET_PROPERTY_NUM; n++) {
            if (gnet_init_list[n] == NOT_IN_MAP) {
                printf("settings_gui_init_prop_map:" 
                    " [GNET] unmapped property: %s\n",
					gnet_prop_name(n+GNET_PROPERTY_MIN));
            }
        }
    }
}

void settings_gui_init(void)
{
    gint n;

    gui_prop_set_stub = gui_prop_get_stub();
    gnet_prop_set_stub = gnet_prop_get_stub();

    tooltips = gtk_tooltips_new();
    properties = gui_prop_init();

   	prop_load_from_file(properties, settings_gui_config_dir(), property_file);

    for (n = 0; n < GUI_PROPERTY_NUM; n ++) {
        gui_init_list[n] = NOT_IN_MAP;
    }

    for (n = 0; n < GNET_PROPERTY_NUM; n ++) {
        gnet_init_list[n] = NOT_IN_MAP;
    }
    
    settings_gui_init_prop_map();

    /* 
     * Just hide the tabs so we can keep them displayed in glade
     * which is easier for editing.
     *      --BLUE, 11/05/2002
     */
    gtk_notebook_set_show_tabs
        (GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main")), FALSE);
}

void settings_gui_shutdown(void)
{
    gint n;

    /*
     * Remove the listeners
     */
    for (n = 0; n < G_N_ELEMENTS(property_map); n ++) {
        if (property_map[n].cb != IGNORE) {
            property_map[n].stub->prop_changed_listener.remove(
                property_map[n].prop,
                property_map[n].cb);
        }
    }

    /*
     * There are no Gtk signals to listen to, so we must set those
     * values on exit.
     */
    downloads_divider_pos =
        gtk_paned_get_position(GTK_PANED
            (lookup_widget(main_window, "vpaned_downloads")));
    main_divider_pos = 
        gtk_paned_get_position(GTK_PANED
            (lookup_widget(main_window, "hpaned_main")));
    side_divider_pos = 
        gtk_paned_get_position(GTK_PANED
            (lookup_widget(main_window, "vpaned_sidebar")));
    gnet_stats_divider_pos = 
        gtk_paned_get_position(GTK_PANED
            (lookup_widget(main_window, "hpaned_gnet_stats")));

    /*
     * Save properties to file
     */
    prop_save_to_file(properties, settings_gui_config_dir(), property_file);

    /*
     * Free allocated memory.
     */
    gui_prop_shutdown();

    G_FREE_NULL(home_dir);
    G_FREE_NULL(gui_prop_set_stub);
    G_FREE_NULL(gnet_prop_set_stub);
}

/*
 * settings_gui_save_if_dirty
 *
 * Save GUI settings if dirty.
 */
void settings_gui_save_if_dirty(void)
{
    prop_save_to_file_if_dirty(
		properties, settings_gui_config_dir(), property_file);
}

const gchar *settings_gui_config_dir(void)
{
	return settings_config_dir();
}
