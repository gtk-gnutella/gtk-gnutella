/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Richard Eckart
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

#include "settings_gui.h"

#include <pwd.h>
#include <sys/stat.h>

#include "monitor_gui.h"
#include "statusbar_gui.h"
#include "search_gui.h"
#include "gui_property_priv.h"
#include "filter_gui.h"

#include "settings_cb.h"

#include "search_stats.h" // FIXME: remove this dependency

/* Uncomment to override debug level for this file. */
//#define gui_debug 10

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

#define PROP_MAP_SIZE \
    (sizeof(property_map) / sizeof(property_map[0]))
#define NOT_IN_MAP -1

static prop_set_stub_t *gui_prop_set_stub = NULL;
static prop_set_stub_t *gnet_prop_set_stub = NULL;

static gint gui_init_list[GUI_PROPERTY_NUM];
static gint gnet_init_list[GNET_PROPERTY_NUM];
static GtkTooltips* tooltips = NULL;

static gchar *home_dir = NULL;
gchar *gui_config_dir = NULL;
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
GtkWidget *get_main_window(void) {
    return main_window;
}

GtkWidget *get_filter_dialog(void) {
    return filter_dialog;
}

GtkWidget *get_search_popup(void) {
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
static gboolean update_spinbutton(property_t prop);
static gboolean update_togglebutton(property_t prop);
static gboolean update_split_pane(property_t prop);
static gboolean update_clist_col_widths(property_t prop);
static gboolean update_bandwidth_spinbutton(property_t prop);
static gboolean update_window_geometry(property_t prop);

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
static gboolean progressbar_bws_in_visible_changed(property_t prop);
static gboolean progressbar_bws_out_visible_changed(property_t prop);
static gboolean progressbar_bws_gin_visible_changed(property_t prop);
static gboolean progressbar_bws_gout_visible_changed(property_t prop);
static gboolean progressbar_downloads_visible_changed(property_t prop);
static gboolean progressbar_uploads_visible_changed(property_t prop);
static gboolean progressbar_connections_visible_changed(property_t prop);
static gboolean search_results_show_tabs_changed(property_t prop);
static gboolean autoclear_downloads_changed(property_t prop);
static gboolean search_stats_enabled_changed(property_t prop);
static gboolean socks_user_changed(property_t prop);
static gboolean socks_pass_changed(property_t prop);
static gboolean traffic_stats_mode_changed(property_t prop);
static gboolean is_firewalled_changed(property_t prop);
static gboolean min_dup_ratio_changed(property_t prop);
static gboolean is_inet_connected_changed(property_t prop);
static gboolean show_search_results_settings_changed(property_t prop);
static gboolean local_address_changed(property_t prop);
static gboolean force_local_ip_changed(property_t prop);

// FIXME: move to separate file and autoegenerate from high-level
//        description. 
static prop_map_t property_map[] = {
    {
        get_main_window,
        PROP_MONITOR_MAX_ITEMS,
        update_spinbutton,
        TRUE,
        "spinbutton_monitor_items"
    },
    {
        get_main_window,
        PROP_MONITOR_ENABLED,
        monitor_enabled_changed,
        TRUE,
        "checkbutton_monitor_enable"
    },
    {
        get_main_window,
        PROP_QUEUE_REGEX_CASE,
        update_togglebutton,
        TRUE,
        "checkbutton_queue_regex_case",
    },
    {
        get_main_window,
        PROP_SEARCH_AUTOSELECT,
        update_togglebutton,
        TRUE,
        "checkbutton_search_autoselect",
    },
    {
        get_main_window,
        PROP_SEARCH_AUTOSELECT_IDENT,
        update_togglebutton,
        TRUE,
        "checkbutton_search_autoselect_ident",
    },
    {
        get_main_window,
        PROP_SEARCH_AUTOSELECT_FUZZY,
        update_togglebutton,
        TRUE,
        "checkbutton_search_autoselect_fuzzy",
    },
    {
        get_main_window,
        PROP_MAIN_DIVIDER_POS,
        update_split_pane,
        TRUE,
        "hpaned_main"
    },
    {
        get_main_window,
        PROP_SIDE_DIVIDER_POS,
        update_split_pane,
        TRUE,
        "vpaned_sidebar"
    },
    {
        get_main_window,
        PROP_DOWNLOADS_DIVIDER_POS,
        update_split_pane,
        TRUE,
        "vpaned_downloads"
    },
    {
        get_filter_dialog,
        PROP_FILTER_MAIN_DIVIDER_POS,
        update_split_pane,
        TRUE,
        "hpaned_filter_main"
    },
    {
        get_main_window,
        PROP_STATUSBAR_VISIBLE,
        statusbar_visible_changed,
        TRUE,
        "menu_statusbar_visible"
    },
    {
        get_main_window,
        PROP_TOOLBAR_VISIBLE,
        toolbar_visible_changed,
        TRUE,
        "menu_toolbar_visible"
    },
    {
        get_main_window,
        PROP_JUMP_TO_DOWNLOADS,
        update_togglebutton,
        TRUE,
        "checkbutton_search_jump_to_downloads"
    },
    {
        get_main_window,
        PROP_NODES_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_nodes"
    },
    {
        get_main_window,
        PROP_DL_ACTIVE_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_downloads"
    },
    {
        get_main_window,
        PROP_DL_QUEUED_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_downloads_queue"
    },
    {
        get_main_window,
        PROP_SEARCH_STATS_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_search_stats"
    },
    {
        get_main_window,
        PROP_UPLOADS_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_uploads"
    },
    {
        get_main_window,
        PROP_UL_STATS_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_ul_stats"
    },
    {
        get_main_window,
        PROP_SEARCH_LIST_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_search"
    },
    {
        get_filter_dialog,
        PROP_FILTER_RULES_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_filter_rules"
    },
    {
        get_filter_dialog,
        PROP_FILTER_FILTERS_COL_WIDTHS,
        update_clist_col_widths,
        TRUE,
        "clist_filter_filters"
    },
    {
        get_main_window,
        PROP_SEARCH_RESULTS_COL_WIDTHS,
        search_gui_search_results_col_widths_changed,
        TRUE,
        NULL
    },
    {
        get_main_window,
        PROP_SEARCH_RESULTS_COL_VISIBLE,
        search_gui_search_results_col_visible_changed,
        TRUE,
        NULL
    },
    {
        get_main_window,
        PROP_PROGRESSBAR_BWS_IN_VISIBLE,
        progressbar_bws_in_visible_changed,
        TRUE,
        "menu_bws_in_visible"
    },
    {
        get_main_window,
        PROP_PROGRESSBAR_BWS_OUT_VISIBLE,
        progressbar_bws_out_visible_changed,
        TRUE,
        "menu_bws_out_visible"
    },
    {
        get_main_window,
        PROP_PROGRESSBAR_BWS_GIN_VISIBLE,
        progressbar_bws_gin_visible_changed,
        TRUE,
        "menu_bws_gin_visible"
    },
    {
        get_main_window,
        PROP_PROGRESSBAR_BWS_GOUT_VISIBLE,
        progressbar_bws_gout_visible_changed,
        TRUE,
        "menu_bws_gout_visible"
    },
    {
        get_main_window,
        PROP_PROGRESSBAR_DOWNLOADS_VISIBLE,
        progressbar_downloads_visible_changed,
        TRUE,
        "menu_downloads_visible"
    },
    {
        get_main_window,
        PROP_PROGRESSBAR_UPLOADS_VISIBLE,
        progressbar_uploads_visible_changed,
        TRUE,
        "menu_uploads_visible"
    },
    {
        get_main_window,
        PROP_PROGRESSBAR_CONNECTIONS_VISIBLE,
        progressbar_connections_visible_changed,
        TRUE,
        "menu_connections_visible"
    },
    {
        get_search_popup,
        PROP_SEARCH_RESULTS_SHOW_TABS,
        search_results_show_tabs_changed,
        TRUE,
        "popup_search_toggle_tabs"
    },
    {
        get_main_window,
        PROP_GUI_DEBUG,
        update_spinbutton,
        TRUE,
        "spinbutton_config_gui_debug"
    },
    {
        get_main_window,
        PROP_DBG,
        update_spinbutton,
        TRUE,
        "spinbutton_config_dbg"
    },
    { 
        get_main_window,
        PROP_UP_CONNECTIONS, 
        update_spinbutton, 
        TRUE,
        "spinbutton_up_connections"
    },
    {
        get_main_window,
        PROP_MAX_CONNECTIONS,
        update_spinbutton,
        TRUE,
        "spinbutton_max_connections",
    },
    {
        get_main_window,
        PROP_MAX_DOWNLOADS,
        update_spinbutton,
        TRUE,
        "spinbutton_max_downloads",
    },
    {
        get_main_window,
        PROP_MAX_HOST_DOWNLOADS,
        update_spinbutton,
        TRUE,
        "spinbutton_max_host_downloads",
    },
    {
        get_main_window,
        PROP_MAX_UPLOADS,
        update_spinbutton,
        TRUE,
        "spinbutton_max_uploads",
    },
    {
        get_main_window,
        PROP_MAX_UPLOADS_IP,
        update_spinbutton,
        TRUE,
        "spinbutton_max_uploads_ip",
    },
    {
        get_main_window,
        PROP_PROXY_IP,
        proxy_ip_changed,
        TRUE,
        "entry_config_proxy_ip",
    },
    {
        get_main_window,
        PROP_DEFAULT_MINIMUM_SPEED,
        update_spinbutton,
        TRUE,
        "spinbutton_config_search_min_speed",
    },
    {
        get_main_window,
        PROP_MAX_HOSTS_CACHED,
        update_spinbutton,
        TRUE,
        "spinbutton_nodes_max_hosts_cached",
    },
    {
        get_main_window,
        PROP_MAX_TTL,
        update_spinbutton,
        TRUE,
        "spinbutton_config_maxttl",
    },
    {
        get_main_window,
        PROP_MY_TTL,
        update_spinbutton,
        TRUE,
        "spinbutton_config_myttl",
    },
    {
        get_main_window,
        PROP_SEARCH_REISSUE_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_search_reissue_timeout",
    },
    {
        get_main_window,
        PROP_PROXY_PORT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_proxy_port",
    },
    {
        get_main_window,
        PROP_UL_USAGE_MIN_PERCENTAGE,
        update_spinbutton,
        TRUE,
        "spinbutton_config_ul_usage_min_percentage",
    },
    {
        get_main_window,
        PROP_CONNECTION_SPEED,
        update_spinbutton,
        TRUE,
        "spinbutton_config_speed",
    },
    {
        get_main_window,
        PROP_QUERY_RESPONSE_MAX_ITEMS,
        update_spinbutton,
        TRUE,
        "spinbutton_config_search_items",
    },
    {
        get_main_window,
        PROP_MAX_HIGH_TTL_RADIUS,
        update_spinbutton,
        TRUE,
        "spinbutton_config_max_high_ttl_radius",
    },
    {
        get_main_window,
        PROP_MAX_HIGH_TTL_MSG,
        update_spinbutton,
        TRUE,
        "spinbutton_config_max_high_ttl_msg",
    },
    {
        get_main_window,
        PROP_HARD_TTL_LIMIT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_hard_ttl_limit",
    },
    {
        get_main_window,
        PROP_DOWNLOAD_OVERLAP_RANGE,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_overlap_range",
    },
    {
        get_main_window,
        PROP_DOWNLOAD_MAX_RETRIES,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_max_retries",
    },
    {
        get_main_window,
        PROP_DOWNLOAD_RETRY_STOPPED_DELAY,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_stopped_delay",
    },
    {
        get_main_window,
        PROP_DOWNLOAD_RETRY_REFUSED_DELAY,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_refused_delay",
    },
    {
        get_main_window,
        PROP_DOWNLOAD_RETRY_BUSY_DELAY,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_busy_delay",
    },
    {
        get_main_window,
        PROP_DOWNLOAD_RETRY_TIMEOUT_DELAY,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_timeout_delay",
    },
    {
        get_main_window,
        PROP_DOWNLOAD_RETRY_TIMEOUT_MAX,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_timeout_max",
    },
    {
        get_main_window,
        PROP_DOWNLOAD_RETRY_TIMEOUT_MIN,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_retry_timeout_min",
    },
    {
        get_main_window,
        PROP_DOWNLOAD_CONNECTING_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_connecting_timeout",
    },
    {
        get_main_window,
        PROP_DOWNLOAD_CONNECTED_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_connected_timeout",
    },
    {
        get_main_window,
        PROP_DOWNLOAD_PUSH_SENT_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_download_push_sent_timeout",
    },
    {
        get_main_window,
        PROP_NODE_TX_FLOWC_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_node_tx_flowc_timeout",
    },
    {
        get_main_window,
        PROP_NODE_CONNECTING_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_node_connecting_timeout",
    },
    {
        get_main_window,
        PROP_NODE_CONNECTED_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_node_connected_timeout",
    },
    {
        get_main_window,
        PROP_UPLOAD_CONNECTING_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_upload_connecting_timeout",
    },
    {
        get_main_window,
        PROP_UPLOAD_CONNECTED_TIMEOUT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_upload_connected_timeout",
    },
    {
        get_main_window,
        PROP_SOCKS_USER,
        socks_user_changed,
        TRUE,
        "entry_config_socks_username",
    },
    {
        get_main_window,
        PROP_SOCKS_PASS,
        socks_pass_changed,
        TRUE,
        "entry_config_socks_password",
    },
    {
        get_main_window,
        PROP_SEARCH_REMOVE_DOWNLOADED,
        update_togglebutton,
        TRUE,
        "checkbutton_search_remove_downloaded",
    },
    {
        get_main_window,
        PROP_DOWNLOAD_DELETE_ABORTED,
        update_togglebutton,
        TRUE,
        "checkbutton_download_delete_aborted",
    },
    {
        get_main_window,
        PROP_BW_HTTP_IN_ENABLED,
        bw_http_in_enabled_changed,
        TRUE,
        "checkbutton_config_bws_in",
    },
    {
        get_main_window,
        PROP_BW_HTTP_OUT_ENABLED,
        bw_http_out_enabled_changed,
        TRUE,
        "checkbutton_config_bws_out",
    },
    {
        get_main_window,
        PROP_BW_GNET_IN_ENABLED,
        bw_gnet_in_enabled_changed,
        TRUE,
        "checkbutton_config_bws_gin",
    },
    {
        get_main_window,
        PROP_BW_GNET_OUT_ENABLED,
        bw_gnet_out_enabled_changed,
        TRUE,
        "checkbutton_config_bws_gout",
    },
    {
        get_main_window,
        PROP_BW_HTTP_IN,
        update_bandwidth_spinbutton,
        TRUE,
        "spinbutton_config_bws_in"
    },
    {
        get_main_window,
        PROP_BW_HTTP_OUT,
        update_bandwidth_spinbutton,
        TRUE,
        "spinbutton_config_bws_out"
    },
    {
        get_main_window,
        PROP_BW_GNET_IN,
        update_bandwidth_spinbutton,
        TRUE,
        "spinbutton_config_bws_gin"
    },
    {
        get_main_window,
        PROP_BW_GNET_OUT,
        update_bandwidth_spinbutton,
        TRUE,
        "spinbutton_config_bws_gout"
    },
    {
        get_main_window,
        PROP_BW_UL_USAGE_ENABLED,
        bw_ul_usage_enabled_changed,
        TRUE,
        "checkbutton_config_bw_ul_usage_enabled",
    },
    {
        get_main_window,
        PROP_READING_HOSTFILE,
        reading_hostfile_changed,
        TRUE,
        NULL,
    },
    {
        get_main_window,
        PROP_ANCIENT_VERSION,
        ancient_version_changed,
        TRUE,
        NULL,
    },
    {
        get_main_window,
        PROP_NEW_VERSION_STR,
        new_version_str_changed,
        TRUE,
        NULL,
    },
    {
        get_main_window,
        PROP_SEND_PUSHES,
        send_pushes_changed,
        TRUE,
        "checkbutton_downloads_never_push",
    },
    {
        get_main_window,
        PROP_SEARCH_STATS_ENABLED,
        search_stats_enabled_changed,
        TRUE,
        "checkbutton_search_stats_enable"
    },
    {
        get_main_window,
        PROP_AUTOCLEAR_UPLOADS,
        update_togglebutton,
        TRUE,
        "checkbutton_uploads_auto_clear"
    },
    {
        get_main_window,
        PROP_AUTOCLEAR_DOWNLOADS,
        autoclear_downloads_changed,
        TRUE,
        "checkbutton_downloads_auto_clear"
    },
    {
        get_main_window,
        PROP_FORCE_LOCAL_IP,
        force_local_ip_changed,
        TRUE,
        "checkbutton_config_force_ip"
    },
    {
        get_main_window,
        PROP_PROXY_CONNECTIONS,
        update_togglebutton,
        TRUE,
        "checkbutton_config_proxy_connections"
    },
    {
        get_main_window,
        PROP_PROXY_AUTH,
        update_togglebutton,
        TRUE,
        "checkbutton_config_proxy_auth"
    },
    {
        get_main_window,
        PROP_HOSTS_IN_CATCHER,
        hosts_in_catcher_changed,
        TRUE,
        "progressbar_hosts_in_catcher"
    },
    {
        get_main_window,
        PROP_TOTAL_DOWNLOADS,
        update_entry,
        TRUE,
        "entry_count_downloads"
    },
    {
        get_main_window,
        PROP_TOTAL_UPLOADS,
        update_entry,
        TRUE,
        "entry_count_uploads"
    },
    {
        get_main_window,
        PROP_SEARCH_STATS_UPDATE_INTERVAL,
        update_spinbutton,
        TRUE,
        "spinbutton_search_stats_update_interval"
    },
    {
        get_main_window,
        PROP_SEARCH_STATS_DELCOEF,
        update_spinbutton,
        TRUE,
        "spinbutton_search_stats_delcoef"
    },
    {
        get_main_window,
        PROP_USE_NETMASKS,
        update_togglebutton,
        TRUE,
        "checkbutton_config_use_netmasks"
    },
    {
        get_main_window,
        PROP_LOCAL_NETMASKS_STRING,
        update_entry,
        TRUE,
        "entry_config_netmasks"
    },
    {
        get_main_window,
        PROP_FORCED_LOCAL_IP,
        update_entry,
        TRUE,
        "entry_config_force_ip"
    },
    {
        get_main_window,
        PROP_LISTEN_PORT,
        update_spinbutton,
        TRUE,
        "spinbutton_config_port"
    },
    {
        get_main_window,
        PROP_SCAN_EXTENSIONS,
        update_entry,
        TRUE,
        "entry_config_extensions"
    },
    {
        get_main_window,
        PROP_SAVE_FILE_PATH,
        update_entry,
        TRUE,
        "entry_config_save_path"
    },
    {
        get_main_window,
        PROP_MOVE_FILE_PATH,
        update_entry,
        TRUE,
        "entry_config_move_path"
    },
    {
        get_main_window,
        PROP_SHARED_DIRS_PATHS,
        update_entry,
        TRUE,
        "entry_config_path"
    },
    {
        get_main_window,
        PROP_MIN_DUP_MSG,
        update_spinbutton,
        TRUE,
        "spinbutton_config_min_dup_msg"
    },
    {
        get_main_window,
        PROP_MIN_DUP_RATIO,
        min_dup_ratio_changed,
        TRUE,
        "spinbutton_config_min_dup_ratio"
    },
    {
        get_main_window,
        PROP_DL_MINCHUNKSIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_dl_minchunksize"
    },
    {
        get_main_window,
        PROP_DL_MAXCHUNKSIZE,
        update_spinbutton,
        TRUE,
        "spinbutton_dl_maxchunksize"
    },
    {
        get_main_window,
        PROP_FUZZY_THRESHOLD,
        update_spinbutton,
        TRUE,
        "spinbutton_config_fuzzy_threshold"
    },
    {
        get_main_window,
        PROP_AUTO_DOWNLOAD_IDENTICAL,
        update_togglebutton,
        TRUE,
        "checkbutton_config_use_alternate_sources"
    },
    {
        get_main_window,
        PROP_STRICT_SHA1_MATCHING,
        update_togglebutton,
        TRUE,
        "checkbutton_config_strict_sha1_matching"
    },
    {
        get_main_window,
        PROP_USE_FUZZY_MATCHING,
        update_togglebutton,
        TRUE,
        "checkbutton_config_use_fuzzy_matching"
    },
    {
        get_main_window,
        PROP_USE_SWARMING,
        update_togglebutton,
        TRUE,
        "checkbutton_config_use_swarming"
    },
    {
        get_main_window,
        PROP_USE_AGGRESSIVE_SWARMING,
        update_togglebutton,
        TRUE,
        "checkbutton_config_aggressive_swarming"
    },
    {
        get_main_window,
        PROP_STOP_HOST_GET,
        update_togglebutton,
        TRUE,
        "checkbutton_config_stop_host_get"
    },
    {
        NULL,
        PROP_SEARCH_QUERIES_FORWARD_SIZE,
        IGNORE,
        FALSE,
        NULL
    },
    {
        NULL,
        PROP_SEARCH_QUERIES_KICK_SIZE,
        IGNORE,
        FALSE,
        NULL
    },
    {
        NULL,
        PROP_SEARCH_ANSWERS_FORWARD_SIZE,
        IGNORE,
        FALSE,
        NULL
    },
    {
        NULL,
        PROP_SEARCH_ANSWERS_KICK_SIZE,
        IGNORE,
        FALSE,
        NULL
    },
    {
        NULL,
        PROP_OTHER_MESSAGES_KICK_SIZE,
        IGNORE,
        FALSE,
        NULL
    },
    {
        get_main_window,
        PROP_HOPS_RANDOM_FACTOR,
        update_spinbutton,
        TRUE,
        "spinbutton_config_hops_random_factor"
    },
    {
        NULL,
        PROP_PROGRESSBAR_BWS_IN_AVG,
        traffic_stats_mode_changed,
        FALSE,
        NULL
    },
    {
        NULL,
        PROP_PROGRESSBAR_BWS_OUT_AVG,
        traffic_stats_mode_changed,
        FALSE,
        NULL
    },
    {
        NULL,
        PROP_PROGRESSBAR_BWS_GIN_AVG,
        traffic_stats_mode_changed,
        FALSE,
        NULL
    },
    {
        NULL,
        PROP_PROGRESSBAR_BWS_GOUT_AVG,
        traffic_stats_mode_changed,
        FALSE,
        NULL
    },
    {
        NULL,
        PROP_BAN_RATIO_FDS,
        IGNORE,
        FALSE,
        NULL
    },
    {
        NULL,
        PROP_BAN_MAX_FDS,
        IGNORE,
        FALSE,
        NULL
    },
    {
        NULL,
        PROP_NODE_SENDQUEUE_SIZE,
        IGNORE,
        FALSE,
        NULL
    },
    {
        NULL,
        PROP_FILTER_DEFAULT_POLICY,
        IGNORE,
        FALSE,
        NULL
    },
    {
        NULL,
        PROP_GUID,
        IGNORE,
        FALSE,
        NULL
    },
    {
        NULL,
        PROP_LOCAL_IP,
        local_address_changed,
        FALSE,
        NULL
    },
    {
        NULL,
        PROP_IS_FIREWALLED,
        is_firewalled_changed,
        TRUE,
        NULL
    },
    {
        get_main_window,
        PROP_WINDOW_COORDS,
        update_window_geometry,
        TRUE,
        NULL /* uses fn_toplevel as widget */
    },
    {
        get_filter_dialog,
        PROP_FILTER_DLG_COORDS,
        update_window_geometry,
        TRUE,
        NULL /* uses fn_toplevel as widget */
    },
    {
        NULL,
        PROP_IS_INET_CONNECTED,
        is_inet_connected_changed,
        TRUE,
        NULL
    },
    {
        get_main_window,
        PROP_SHOW_SEARCH_RESULTS_SETTINGS,
        show_search_results_settings_changed,
        TRUE,
        "checkbutton_search_results_show_settings"
    }
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

static gboolean update_entry(property_t prop)
{
    GtkWidget *w;
    gchar s[100];
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = lookup_widget(top, map_entry->wid);
   
    switch (map_entry->type) {
        case PROP_TYPE_GUINT32: {
            guint32 val;
        
            stub->guint32.get(prop, &val, 0, 1);

            g_snprintf(s, sizeof(s), "%u", val);
            break;
        }
        case PROP_TYPE_STRING: {
            gchar *buf = stub->string.get(prop, NULL, 0);
            g_snprintf(s, sizeof(s), "%s", buf);
            g_free(buf);
            break;
        }
        case PROP_TYPE_IP: {
            guint32 val;
        
            stub->guint32.get(prop, &val, 0, 1);

            g_snprintf(s, sizeof(s), "%s", ip_to_gchar(val));
            break;
        }
        default:
            s[0] = '\0';
            g_error("update_entry_gnet: incompatible type %s", 
                prop_type_str[map_entry->type]);
    }

    gtk_entry_set_text(GTK_ENTRY(w), s);

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
   
    switch (map_entry->type) {
        case PROP_TYPE_BOOLEAN:
            stub->boolean.get(prop, &val, 0, 1);
            break;
        default:
            val = 0;
            g_error("update_togglenbutton: incompatible type %s", 
                prop_type_str[map_entry->type]);
    }

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);

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
    g_assert(w != NULL);
    
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

static gboolean update_window_geometry(property_t prop)
{
    GtkWidget *w;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    if (!top)
        return FALSE;

    w = top;
    
    if (!w->window)
        return FALSE;
    
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
    static gboolean v##_changed(property_t prop)            \
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

static gboolean bw_http_in_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;

    gnet_prop_get_boolean(prop, &val, 0, 1);

    w = lookup_widget(main_window, "checkbutton_config_bws_in");
    s = lookup_widget(main_window, "spinbutton_config_bws_in");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    gtk_widget_set_sensitive(s, val);

    return FALSE;
}

static gboolean bw_gnet_in_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;

    gnet_prop_get_boolean(prop, &val, 0, 1);

    w = lookup_widget(main_window, "checkbutton_config_bws_gin");
    s = lookup_widget(main_window, "spinbutton_config_bws_gin");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    gtk_widget_set_sensitive(s, val);

    return FALSE;
}

static gboolean bw_gnet_out_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;

    gnet_prop_get_boolean(prop, &val, 0, 1);

    w = lookup_widget(main_window, "checkbutton_config_bws_gout");
    s = lookup_widget(main_window, "spinbutton_config_bws_gout");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);
    gtk_widget_set_sensitive(s, val);

    return FALSE;
}

static gboolean bw_ul_usage_enabled_changed(property_t prop)
{
    GtkWidget *w;
    GtkWidget *s;
    gboolean val;
    gboolean val2;

    gnet_prop_get_boolean(prop, &val, 0, 1);
    gnet_prop_get_boolean(PROP_BW_HTTP_OUT_ENABLED, &val2, 0, 1);

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

    gnet_prop_get_boolean(prop, &val, 0, 1);
    gnet_prop_get_boolean(PROP_BW_UL_USAGE_ENABLED, &val2, 0, 1);

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);

    gtk_widget_set_sensitive(s2, val);
    gtk_widget_set_sensitive(c, val);
    gtk_widget_set_sensitive(s1, val && val2);

    return FALSE;
}

static gboolean proxy_ip_changed(property_t prop)
{
    GtkWidget *w = lookup_widget(main_window, "entry_config_proxy_ip");
    guint32 val;

    gnet_prop_get_guint32(prop, &val, 0, 1);

    gtk_entry_set_text(GTK_ENTRY(w), ip_to_gchar(val));

    return FALSE;
}

static gboolean is_firewalled_changed(property_t prop)
{
	GtkWidget *image_firewall;
	GtkWidget *image_no_firewall;
	gboolean val;

    image_firewall = lookup_widget(main_window, "image_firewall");
	image_no_firewall = lookup_widget(main_window, "image_no_firewall");

    gnet_prop_get_boolean(prop, &val, 0, 1);
	
	if (val) {
		gtk_widget_show(image_firewall);
		gtk_widget_hide(image_no_firewall);
	} else {
		gtk_widget_hide(image_firewall);
		gtk_widget_show(image_no_firewall);
	}

	return FALSE;
}

static gboolean is_inet_connected_changed(property_t prop)
{
	GtkWidget *image_online;
	GtkWidget *image_offline;
	gboolean val;

    image_online = lookup_widget(main_window, "image_online");
	image_offline = lookup_widget(main_window, "image_offline");

    gnet_prop_get_boolean(prop, &val, 0, 1);
	
	if (val) {
		gtk_widget_show(image_online);
		gtk_widget_hide(image_offline);
	} else {
		gtk_widget_hide(image_online);
		gtk_widget_show(image_offline);
	}

	return FALSE;
}

static gboolean monitor_enabled_changed(property_t prop) 
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "checkbutton_monitor_enable");

    gui_prop_get_boolean(PROP_MONITOR_ENABLED, &val, 0, 1);

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), val);

    monitor_gui_enable_monitor(val);

    return FALSE;
}

static gboolean reading_hostfile_changed(property_t prop)
{
    gboolean state;
    static statusbar_msgid_t id = {0, 0};

    gnet_prop_get_boolean(PROP_READING_HOSTFILE, &state, 0, 1);

    if (state) {
        GtkProgressBar *pg = GTK_PROGRESS_BAR
            (lookup_widget(main_window, "progressbar_hosts_in_catcher"));
        id = statusbar_gui_message(0, "Reading host cache...");
        gtk_progress_bar_set_text(pg, "loading...");
    } else {
       	statusbar_gui_remove(id);
    }
    return FALSE;
}

static gboolean ancient_version_changed(property_t prop)
{
    gboolean b;

    gnet_prop_get_boolean(prop, &b, 0, 1);

    if (b)
        statusbar_gui_warning(15, "*** RUNNING AN OLD VERSION! ***");

    return FALSE;
}

static gboolean new_version_str_changed(property_t prop)
{
    gchar *str;

    str = gnet_prop_get_string(PROP_NEW_VERSION_STR, NULL, 0);
    statusbar_gui_set_default(str);

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

    gui_prop_get_boolean(prop, &b, 0, 1);
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

    gui_prop_get_boolean(prop, &b, 0, 1);
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

static gboolean hosts_in_catcher_changed(property_t prop)
{
    GtkProgressBar *pg = GTK_PROGRESS_BAR
        (lookup_widget(main_window, "progressbar_hosts_in_catcher"));
    GtkWidget *clear_button = lookup_widget
        (main_window, "button_host_catcher_clear");
    gfloat frac;
    guint32 hosts_in_catcher;
    guint32 max_hosts_cached;

    gnet_prop_get_guint32(PROP_HOSTS_IN_CATCHER, &hosts_in_catcher, 0, 1);
    gnet_prop_get_guint32(PROP_MAX_HOSTS_CACHED, &max_hosts_cached, 0, 1);

    gtk_widget_set_sensitive(clear_button, hosts_in_catcher != 0);

    frac = MIN(hosts_in_catcher, max_hosts_cached) != 0 ? 
        (float)MIN(hosts_in_catcher, max_hosts_cached) / max_hosts_cached : 0;

	g_snprintf(set_tmp, sizeof(set_tmp), "%u/%u host%s (%u%%%%)", 
        hosts_in_catcher, max_hosts_cached, 
        (hosts_in_catcher == 1 && max_hosts_cached == 1) ? "" : "s",
        (guint)(frac*100));

    gtk_progress_bar_set_text(pg, set_tmp);
    gtk_progress_bar_set_fraction(pg, frac);
    
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

    gui_prop_get_boolean(prop, &val, 0, 1);

    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean progressbar_bws_out_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "progressbar_bws_out");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (lookup_widget(main_window, "menu_bws_out_visible"));

    gui_prop_get_boolean(prop, &val, 0, 1);

    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean progressbar_bws_gin_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "progressbar_bws_gin");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (lookup_widget(main_window, "menu_bws_gin_visible"));

    gui_prop_get_boolean(prop, &val, 0, 1);

    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean progressbar_bws_gout_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "progressbar_bws_gout");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (lookup_widget(main_window, "menu_bws_gout_visible"));

    gui_prop_get_boolean(prop, &val, 0, 1);

    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean progressbar_downloads_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "progressbar_downloads");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (lookup_widget(main_window, "menu_downloads_visible"));

    gui_prop_get_boolean(prop, &val, 0, 1);

    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean progressbar_uploads_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "progressbar_uploads");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (lookup_widget(main_window, "menu_uploads_visible"));

    gui_prop_get_boolean(prop, &val, 0, 1);

    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean progressbar_connections_visible_changed(property_t prop)
{
    gboolean val;
    GtkWidget *w = lookup_widget(main_window, "progressbar_connections");
    GtkCheckMenuItem *cm = GTK_CHECK_MENU_ITEM
        (lookup_widget(main_window, "menu_connections_visible"));

    gui_prop_get_boolean(prop, &val, 0, 1);

    update_stats_visibility(cm, w, val);

    return FALSE;
}

static gboolean search_results_show_tabs_changed(property_t prop)
{
    gboolean val;

    gui_prop_get_boolean(prop, &val, 0, 1);

	gtk_notebook_set_show_tabs(
        GTK_NOTEBOOK(lookup_widget(main_window, "notebook_search_results")),
		val);

    gtk_notebook_set_page(
        GTK_NOTEBOOK(lookup_widget(main_window, "notebook_sidebar")),
        search_results_show_tabs ? 1 : 0);

    return FALSE;
}

static gboolean autoclear_downloads_changed(property_t prop)
{
    gboolean val;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    stub->boolean.get(prop, &val, 0, 1);

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
        (lookup_widget(top, map_entry->wid)), val);

    if(val)
        download_clear_stopped(FALSE, TRUE);

    return FALSE;
}

static gboolean search_stats_enabled_changed(property_t prop)
{
    gboolean val;
    prop_map_t *map_entry = settings_gui_get_map_entry(prop);
    prop_set_stub_t *stub = map_entry->stub;
    GtkWidget *top = map_entry->fn_toplevel();

    stub->boolean.get(prop, &val, 0, 1);

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
        (lookup_widget(top, map_entry->wid)), val);

    if(val)
		search_stats_enable();
	else
		search_stats_disable();

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
        gtk_label_set_text(GTK_LABEL(GTK_BIN(w)->child), "Hide settings");
        gtk_widget_show(frame);
    } else {
        gtk_label_set_text(GTK_LABEL(GTK_BIN(w)->child), "Show settings");
        gtk_widget_hide(frame);
    }

    return FALSE;
}

static gboolean local_address_changed(property_t prop)
{
    static guint32 old_address = 0;
    static guint16 old_port = 0;
    gboolean force_local_ip;
    guint32 listen_port;
    guint32 current_ip;

    gnet_prop_get_boolean(PROP_FORCE_LOCAL_IP, &force_local_ip, 0, 1);
    gnet_prop_get_guint32(PROP_LISTEN_PORT, &listen_port, 0, 1);

    if (force_local_ip)
        gnet_prop_get_guint32(PROP_FORCED_LOCAL_IP, &current_ip, 0, 1);
    else
        gnet_prop_get_guint32(PROP_LOCAL_IP, &current_ip, 0, 1);
   
    if (old_address != current_ip || old_port != listen_port) {
        gchar * iport;
        GtkLabel *label_current_port;
        GtkEntry *entry_nodes_ip;

        label_current_port = 
            GTK_LABEL(lookup_widget(main_window, "label_current_port"));
        entry_nodes_ip =
            GTK_ENTRY(lookup_widget(main_window, "entry_nodes_ip"));

      	iport = ip_port_to_gchar(current_ip, listen_port);

        old_address = current_ip;
        old_port = listen_port;

        statusbar_gui_message
            (15, "Address/port changed to: %s", iport);

        gtk_label_set(label_current_port, iport);
        gtk_entry_set_text(entry_nodes_ip, iport);
    }

    return FALSE;
}

gboolean force_local_ip_changed(property_t prop)
{
    update_togglebutton(prop);
    local_address_changed(prop);
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
void spinbutton_adjustment_value_changed
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
             * XXX If the user modifies the max simulteneous download 
             * XXX and click on a queued download, gtk-gnutella segfaults 
             * XXX in some cases. This unselected_all() is a first attempt
             * XXX to work around the problem.
             *
             * It's unknown wether this ancient workaround is still
             * needed.
             *      -- Richard, 13/08/2002
             */             
            gtk_clist_unselect_all(GTK_CLIST(
                lookup_widget(main_window, "clist_downloads_queue")));
        }
    }

    stub->guint32.set(map_entry->prop, &val, 0, 1);
}

void togglebutton_state_changed
    (GtkToggleButton *tb, gpointer user_data)
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
        if (gui_debug >= 10)
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
            gtk_tooltips_set_tip(tooltips, w, def->desc, "");

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
            }

            if (top && GTK_IS_TOGGLE_BUTTON(w)) {
                g_assert(def->type == PROP_TYPE_BOOLEAN);

                gtk_signal_connect(
                    GTK_OBJECT(w), "toggled",
                    (GtkSignalFunc) togglebutton_state_changed,
                    (gpointer) map);
            }
        }
        if (gui_debug >= 10)
            printf("settings_gui_config_widget: %s [done]\n", def->name);

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
            PROP_MAP_SIZE);
    }

    /*
     * Fill in automatic fields in property_map.
     */
    for (n = 0; n < PROP_MAP_SIZE; n++) {
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
    for (n = 0; n < PROP_MAP_SIZE; n ++) {
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
            property_map[n].stub->prop_changed_listener.add(
                property_map[n].prop,
                property_map[n].cb,
                property_map[n].init);
            if (gui_debug >= 10)
                printf("settings_gui_init_prop_map: adding changes listener "
                    "[%s][done]\n", def ->name);
        } else if (gui_debug >= 10) {
            printf("settings_gui_init_prop_map: " 
                "property ignored: %s\n", def->name);
        }
        prop_free_def(def);
    }

    if (gui_debug >= 1) {
        for (n = 0; n < GUI_PROPERTY_NUM; n++) {
            if (gui_init_list[n] == NOT_IN_MAP) {
                prop_def_t *def = gui_prop_get_def(n+GUI_PROPERTY_MIN);
                printf("settings_gui_init_prop_map:" 
                    " [GUI]  unmapped property: %s\n", def->name);
                prop_free_def(def);
            }
        }
    }

    if (gui_debug >= 1) {
        for (n = 0; n < GNET_PROPERTY_NUM; n++) {
            if (gnet_init_list[n] == NOT_IN_MAP) {
                prop_def_t *def = gnet_prop_get_def(n+GNET_PROPERTY_MIN);
                printf("settings_gui_init_prop_map:" 
                    " [GNET] unmapped property: %s\n", def->name);
                prop_free_def(def);
            }
        }
    }
}

void settings_gui_init(void)
{
    struct passwd *pwd = getpwuid(getuid());
    gint n;

    gui_prop_set_stub = gui_prop_get_stub();
    gnet_prop_set_stub = gnet_prop_get_stub();

    tooltips = gtk_tooltips_new();

    properties = gui_prop_init();

    gui_config_dir = g_strdup(getenv("GTK_GNUTELLA_DIR"));
 
    if (pwd && pwd->pw_dir)
		home_dir = g_strdup(pwd->pw_dir);
	else
		home_dir = g_strdup(getenv("HOME"));

	if (!home_dir)
		g_warning("can't find your home directory!");

	if (!gui_config_dir) {
		if (home_dir) {
			g_snprintf(set_tmp, sizeof(set_tmp),
				"%s/.gtk-gnutella", home_dir);
			gui_config_dir = g_strdup(set_tmp);
		} else
			g_warning("no home directory: prefs will not be saved!");
	}

	if (gui_config_dir && !is_directory(gui_config_dir)) {
		g_warning("creating configuration directory '%s'\n", gui_config_dir);

		if (mkdir(gui_config_dir, 0755) == -1) {
			g_warning("mkdir(%s) failed: %s\n\n",
				gui_config_dir, g_strerror(errno));
			g_free(gui_config_dir);
			gui_config_dir = NULL;
		}
	}

    prop_load_from_file(properties, gui_config_dir, property_file);

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
    GtkCList *clist;
    gint n;
    search_t *current_search;

    current_search = search_gui_get_current_search();

    /*
     * Remove the listeners
     */
    for (n = 0; n < PROP_MAP_SIZE; n ++) {
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

    clist = (current_search != NULL) ? 
        GTK_CLIST(current_search->clist) : 
        GTK_CLIST(default_search_clist);

    for (n = 0; n < clist->columns; n ++)
        search_results_col_visible[n] =  clist->column[n].visible;

    /*
     * Save properties to file
     */
    prop_save_to_file(properties, gui_config_dir, property_file);

    /*
     * Free allocated memory.
     */
    gui_prop_shutdown();

    g_free(home_dir);
    g_free(gui_config_dir);
    g_free(gui_prop_set_stub);
    g_free(gnet_prop_set_stub);
}
