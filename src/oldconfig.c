/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
 *
 * gtk-gnutella configuration.
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

/*
 * This is now merely a loader for legacy config files. For the current
 * configuration scheme see settings.c, gnet_property.c and the respective
 * gui counterparts.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#include "gui.h"

#include "oldconfig.h"
#include "settings_gui.h"
#include "search_stats_gui.h"

RCSID("$Id$");

#define CONFIG_SET_BOOL(v,pref,prop)                 \
    case k_##v: {                                    \
        gboolean b = !g_ascii_strcasecmp(value, "true");   \
        pref##_prop_set_boolean(prop, &b, 0, 1);     \
        return;                                      \
    }

#define CONFIG_SET_BOOL_COMPAT(v,w)                  \
    case k_##w:                                      \
        config_set_param(k_##v, value);              \
        return;

#define CONFIG_SET_STR(v,pref,prop)                  \
    case k_##v:                                      \
        pref##_prop_set_string(prop, value);         \
        return;

#define CONFIG_SET_STR_COMPAT(v,w)                   \
    case k_##w:                                      \
        config_set_param(k_##v, value);              \
        return;

#define CONFIG_SET_IP(v,pref,prop)                   \
    case k_##v: {                                    \
        guint32 val = gchar_to_ip(value);            \
        pref##_prop_set_guint32(prop, &val, 0, 1);   \
        return;                                      \
    }

#define CONFIG_SET_NUM(v,pref,prop)                  \
    case k_##v:                                      \
        pref##_prop_set_guint32(prop, &i, 0, 1);     \
        return;


#define CONFIG_SET_VECTOR(v,pref,prop)               \
    case k_##v: {                                    \
        prop_def_t *def = pref##_prop_get_def(prop); \
        guint32 *b = config_parse_array              \
            (value, def->vector_size);               \
        if (b)                                       \
            pref##_prop_set_guint32(prop, b, 0, 0);  \
        prop_free_def(def);                          \
        return;                                      \
    }

static gchar *config_file = "config";
static gchar *gui_config_dir = NULL;

/* 
 * For backward compatibility these values are still read, but 
 * no longer written to the config file:
 *
 * Variable                    Changed at       New name
 * ----------------            ---------------- -------------
 * socksv5_user                0.90u 12/05/2002 socks_user
 * socksv5_pass                0.90u 12/05/2002 socks_pass
 * progressbar_bps_in_visible  0.90u 15/05/2002 progressbar_bws_in_visible
 * progressbar_bps_out_visible 0.90u 15/05/2002 progressbar_bws_out_visible
 * progressbar_bps_in_avg      0.90u 15/05/2002 progressbar_bws_in_avg
 * progressbar_bps_out_avg     0.90u 15/05/2002 progressbar_bws_out_avg
 */

typedef enum {
	k_up_connections = 0,
	k_clear_uploads, k_max_downloads, k_max_host_downloads,
	k_max_uploads, k_clear_downloads, k_download_delete_aborted,
	k_minimum_speed, k_monitor_enabled, k_monitor_max_items,
	k_old_save_file_path, k_scan_extensions,
	k_listen_port, k_max_ttl, k_my_ttl, k_shared_dirs, k_forced_local_ip,
	k_connection_speed,
	k_search_max_items, k_search_max_results,
	k_local_ip, k_force_local_ip, k_guid,
	k_download_connecting_timeout,
	k_download_push_sent_timeout, k_download_connected_timeout,
	k_download_retry_timeout_min, k_download_retry_timeout_max,
	k_download_retry_timeout_delay, k_download_retry_busy_delay,
	k_download_max_retries, k_download_overlap_range,
	k_download_retry_refused_delay, k_download_retry_stopped,
	k_upload_connecting_timeout, k_upload_connected_timeout,
	k_output_bandwidth, k_input_bandwidth,
	k_output_gnet_bandwidth, k_input_gnet_bandwidth,
	k_node_connected_timeout,
	k_node_connecting_timeout, k_node_sendqueue_size, k_node_tx_flowc_timeout,
	k_search_queries_forward_size,
	k_search_queries_kick_size, k_search_answers_forward_size,
	k_search_answers_kick_size,
	k_other_messages_kick_size, k_save_file_path, k_move_file_path,
	k_win_x, k_win_y, k_win_w, k_win_h, k_win_coords, k_widths_nodes,
	k_widths_uploads,
	k_widths_dl_active, k_widths_dl_queued, k_widths_search_results,
	k_widths_search_stats, k_widths_ul_stats, k_widths_search_list, 
    k_widths_filter_table, k_widths_filter_filters, 
    k_search_results_show_tabs,
	k_hops_random_factor, k_send_pushes, k_jump_to_downloads,
	k_max_connections, k_proxy_connections,
	k_proxy_protocol, k_proxy_ip, k_proxy_port, k_proxy_auth, k_socks_user,
	k_socks_pass, k_search_reissue_timeout,
	k_hard_ttl_limit,
	k_dbg, k_stop_host_get, k_max_uploads_ip,
	k_search_pick_all,
	k_max_high_ttl_msg, k_max_high_ttl_radius,
	k_min_dup_msg, k_min_dup_ratio, k_max_hosts_cached,
	k_search_stats_update_interval, k_search_stats_delcoef,
	k_search_stats_enabled,
	k_toolbar_visible, k_statusbar_visible,
	k_progressbar_uploads_visible, k_progressbar_downloads_visible, 
	k_progressbar_connections_visible, 
	k_progressbar_bws_in_visible,
	k_progressbar_bws_out_visible,
    k_progressbar_bws_gin_visible,
	k_progressbar_bws_gout_visible,
	k_progressbar_bws_in_avg,
	k_progressbar_bws_out_avg,
    k_progressbar_bws_gin_avg,
	k_progressbar_bws_gout_avg,
	k_use_netmasks,
	k_local_netmasks,
    k_queue_regex_case,
    k_search_remove_downloaded,
    k_bws_in_enabled,
    k_bws_out_enabled,
    k_bws_gin_enabled,
    k_bws_gout_enabled,
	k_ul_usage_min_percentage,
	k_bw_ul_usage_enabled,
    k_socksv5_user,
    k_socksv5_pass,
    k_progressbar_bps_in_visible,
    k_progressbar_bps_out_visible,
    k_progressbar_bps_in_avg,
    k_progressbar_bps_out_avg,
    k_downloads_divider_pos,
    k_main_divider_pos,
    k_side_divider_pos,
    k_filter_main_divider_pos,
    k_filter_default_policy,
    k_filter_dlg_coords,
    k_search_autoselect_ident,
    k_search_column_visible,
	k_ban_max_fds, k_ban_ratio_fds,
	k_end
} keyword_t;

static gchar *keywords[k_end] = {
	"up_connections",			/* k_up_connections */
	"auto_clear_completed_uploads",		/* k_clear_uploads */
	"max_simultaneous_downloads",		/* k_max_downloads */
	"max_simultaneous_host_downloads",	/* k_max_host_downloads */
	"max_simultaneous_uploads", /* k_max_uploads */
	"auto_clear_completed_downloads",	/* k_clear_downloads */
    "download_delete_aborted", /* k_download_delete_aborted */
	"search_minimum_speed",		/* k_minimum_speed */
	"monitor_enabled",			/* k_monitor_enabled */
	"monitor_max_items",		/* k_monitor_max_items */
	"save_downloaded_files_to", /* k_old_save_file_path */
	"shared_files_extensions",	/* k_scan_extensions */
	"listen_port",				/* k_listen_port */
	"max_ttl",					/* k_max_ttl */
	"my_ttl",					/* k_my_ttl */
	"shared_dirs",				/* k_shared_dirs */
	"forced_local_ip",			/* k_forced_local_ip */
	"connection_speed",			/* k_connection_speed */
	"limit_search_results",		/* k_search_max_items */
	"search_max_results",		/* k_search_max_results */
	"local_ip",					/* k_local_ip */
	"force_local_ip",			/* k_force_local_ip */
	"guid",						/* k_guid */
	"download_connecting_timeout",		/* k_download_connecting_timeout */
	"download_push_sent_timeout",		/* k_download_push_sent_timeout */
	"download_connected_timeout",		/* k_download_connected_timeout */
	"download_retry_timeout_min",		/* k_download_retry_timeout_min */
	"download_retry_timeout_max",		/* k_download_retry_timeout_max */
	"download_retry_timeout_delay",		/* k_download_retry_timeout_delay */
	"download_retry_busy_delay",		/* k_download_retry_busy_delay */
	"download_max_retries",				/* k_download_max_retries */
	"download_overlap_range",			/* k_download_overlap_range */
	"download_retry_refused_delay",		/* k_download_retry_refused_delay */
	"download_retry_stopped",			/* k_download_retry_stopped */
	"upload_connecting_timeout",		/* k_upload_connecting_timeout */
	"upload_connected_timeout",			/* k_upload_connected_timeout */
	"output_bandwidth",					/* k_output_bandwidth */
	"input_bandwidth",					/* k_input_bandwidth */
	"output_gnet_bandwidth",			/* k_output_gnet_bandwidth */
	"input_gnet_bandwidth",				/* k_input_gnet_bandwidth */
	"node_connected_timeout",	/* k_node_connected_timeout */
	"node_connecting_timeout",	/* k_node_connecting_timeout */
	"node_sendqueue_size",		/* k_node_sendqueue_size */
	"node_tx_flowc_timeout",	/* k_node_tx_flowc_timeout */
	"search_queries_forward_size",		/* k_search_queries_forward_size */
	"search_queries_kick_size", /* k_search_queries_kick_size */
	"search_answers_forward_size",		/* k_search_answers_forward_size */
	"search_answers_kick_size", /* k_search_answers_kick_size */
	"other_messages_kick_size", /* k_other_messages_kick_size */
	"store_downloading_files_to",		/* k_save_file_path */
	"move_downloaded_files_to", /* k_move_file_path */
	"window_x",					/* k_win_x */
	"window_y",					/* k_win_y */
	"window_w",					/* k_win_w */
	"window_h",					/* k_win_h */
	"window_coords",			/* k_win_coords */
	"widths_nodes",				/* k_widths_nodes */
	"widths_uploads",			/* k_widths_uploads */
	"widths_dl_active",			/* k_widths_dl_active */
	"widths_dl_queued",			/* k_widths_dl_queued */
	"widths_search_results",	/* k_widths_search_results */
	"widths_search_stats",		/* k_widths_search_stats */
	"widths_ul_stats",			/* k_widths_ul_stats */
    "widths_search_list",       /* k_widths_search_list */
    "widths_filter_table",      /* k_widths_filter_table */
    "widths_filter_filters",    /* k_widths_filter_filters */
	"show_results_tabs",		/* k_search_results_show_tabs */
	"hops_random_factor",		/* k_hops_random_factor */
	"send_pushes",				/* k_send_pushes */
	"jump_to_downloads",		/* k_jump_to_downloads */
	"max_connections",
	"proxy_connections",
	"proxy_protocol",
	"proxy_ip",
	"proxy_port",
	"proxy_auth",
	"socks_user",
	"socks_pass",
	"search_reissue_timeout",
	"hard_ttl_limit",			/* k_hard_ttl_limit */
	"dbg",
	"stop_host_get",
	"max_uploads_ip",
	"search_pick_all",
	"max_high_ttl_msg",
	"max_high_ttl_radius",
	"min_dup_msg",
	"min_dup_ratio",
	"max_hosts_cached",
	"search_stats_update_interval",
	"search_stats_delcoef",
	"search_stats_enabled",
	"toolbar_visible",
	"statusbar_visible",
	"progressbar_uploads_visible",
	"progressbar_downloads_visible",
	"progressbar_connections_visible",
	"progressbar_bws_in_visible",
	"progressbar_bws_out_visible",
    "progressbar_bws_gin_visible",
	"progressbar_bws_gout_visible",
	"progressbar_bws_in_avg",
	"progressbar_bws_out_avg",
   	"progressbar_bws_gin_avg",
	"progressbar_bws_gout_avg",
	"use_netmasks",
	"local_netmasks",
    "queue_regex_case",
    "search_remove_downloaded",
    "bandwidth_input_limit",
    "bandwidth_output_limit",
    "bandwidth_ginput_limit",
    "bandwidth_goutput_limit",
	"upload_bandwith_min_percentage",		/* k_ul_usage_min_percentage */
	"upload_bandwith_usage_enabled",		/* k_bw_ul_usage_enabled */
    "socksv5_user",
    "socksv5_pass",
    "progressbar_bps_in_visible",
    "progressbar_bps_out_visible",
    "progressbar_bps_in_avg",
    "progressbar_bps_out_avg",
    "downloads_divider_pos",
    "main_divider_pos",
    "side_divider_pos",
    "filter_main_divider_pos",
    "filter_default_policy",
    "filter_dlg_coords",
    "search_autoselect_ident",
    "search_column_visible",
	"ban_max_fds",
	"ban_ratio_fds",
};

static gchar cfg_tmp[4096];
static time_t cfg_mtime = 0;

static void config_read(void);

/*
 * config_init:
 *
 * Read in legacy config file and load values into the property system.
 */
void config_init(void)
{
	struct passwd *pwd = NULL;
    gchar *home_dir = NULL;

	gui_config_dir = g_strdup(getenv("GTK_GNUTELLA_DIR"));

	pwd = getpwuid(getuid());

	if (pwd && pwd->pw_dir)
		home_dir = g_strdup(pwd->pw_dir);
	else
		home_dir = g_strdup(getenv("HOME"));

	if (!home_dir)
		g_warning("can't find your home directory!");

	if (!gui_config_dir) {
		if (home_dir) {
			gm_snprintf(cfg_tmp, sizeof(cfg_tmp),
				"%s/.gtk-gnutella", home_dir);
			gui_config_dir = g_strdup(cfg_tmp);
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

	if (gui_config_dir) {
		/* Parse the configuration */

		config_read();
	}
}

static guint32 *config_parse_array(gchar * str, guint32 n)
{
	/* Parse comma delimited settings */

	static guint32 array[10];
	gchar **h = g_strsplit(str, ",", n + 1);
	guint32 *r = array;
	gint i;

	for (i = 0; i < n; i++) {
		if (!h[i]) {
			r = NULL;
			break;
		}
		array[i] = atol(h[i]);
	}

	g_strfreev(h);
	return r;
}

static void config_set_param(keyword_t keyword, gchar *value)
{
	gint32 i = atol(value);

	switch (keyword) {
        CONFIG_SET_BOOL(
            bws_gin_enabled, gnet, 
            PROP_BW_GNET_IN_ENABLED)
        CONFIG_SET_BOOL(
            bws_gout_enabled, gnet, 
            PROP_BW_GNET_OUT_ENABLED)
        CONFIG_SET_BOOL(
            bws_in_enabled, gnet, 
            PROP_BW_HTTP_IN_ENABLED)
        CONFIG_SET_BOOL(
            bws_out_enabled, gnet, 
            PROP_BW_HTTP_OUT_ENABLED)
		CONFIG_SET_BOOL(
            bw_ul_usage_enabled, gnet, 
            PROP_BW_UL_USAGE_ENABLED)
        CONFIG_SET_BOOL(
            download_delete_aborted, gnet, 
            PROP_DOWNLOAD_DELETE_ABORTED)
        CONFIG_SET_BOOL(
            force_local_ip, gnet, 
            PROP_FORCE_LOCAL_IP)
        CONFIG_SET_BOOL(
            monitor_enabled, gui, 
            PROP_MONITOR_ENABLED)
        CONFIG_SET_BOOL(
            progressbar_bws_gin_avg, gui, 
            PROP_PROGRESSBAR_BWS_GIN_AVG)
        CONFIG_SET_BOOL(
            progressbar_bws_gin_visible, gui, 
            PROP_PROGRESSBAR_BWS_GIN_VISIBLE)
        CONFIG_SET_BOOL(
            progressbar_bws_gout_avg, gui, 
            PROP_PROGRESSBAR_BWS_GOUT_AVG)
        CONFIG_SET_BOOL(
            progressbar_bws_gout_visible, gui, 
            PROP_PROGRESSBAR_BWS_GOUT_VISIBLE)
        CONFIG_SET_BOOL(
            progressbar_bws_in_avg, gui, 
            PROP_PROGRESSBAR_BWS_IN_AVG)
        CONFIG_SET_BOOL(
            progressbar_bws_in_visible, gui, 
            PROP_PROGRESSBAR_BWS_IN_VISIBLE)
        CONFIG_SET_BOOL(
            progressbar_bws_out_avg, gui, 
            PROP_PROGRESSBAR_BWS_OUT_AVG)
        CONFIG_SET_BOOL(
            progressbar_bws_out_visible, gui, 
            PROP_PROGRESSBAR_BWS_OUT_VISIBLE)
        CONFIG_SET_BOOL(
            progressbar_connections_visible, gui, 
            PROP_PROGRESSBAR_CONNECTIONS_VISIBLE)
        CONFIG_SET_BOOL(
            progressbar_downloads_visible, gui, 
            PROP_PROGRESSBAR_DOWNLOADS_VISIBLE)
        CONFIG_SET_BOOL(
            progressbar_uploads_visible, gui, 
            PROP_PROGRESSBAR_UPLOADS_VISIBLE)
        CONFIG_SET_BOOL(
            proxy_auth, gnet, 
            PROP_PROXY_AUTH)
        CONFIG_SET_BOOL(
            queue_regex_case, gui, 
            PROP_QUEUE_REGEX_CASE)
        CONFIG_SET_BOOL(
            search_remove_downloaded, gnet, 
            PROP_SEARCH_REMOVE_DOWNLOADED)
        CONFIG_SET_BOOL(
            search_autoselect_ident, gui, 
            PROP_SEARCH_AUTOSELECT_IDENT)
        CONFIG_SET_BOOL(
            search_results_show_tabs, gui, 
            PROP_SEARCH_RESULTS_SHOW_TABS)
        CONFIG_SET_BOOL(
            statusbar_visible, gui, 
            PROP_STATUSBAR_VISIBLE)
        CONFIG_SET_BOOL(
            toolbar_visible, gui, 
            PROP_TOOLBAR_VISIBLE)
        CONFIG_SET_BOOL(
            use_netmasks, gnet, 
            PROP_USE_NETMASKS)
        CONFIG_SET_BOOL_COMPAT(
            progressbar_bws_in_avg,
            progressbar_bps_in_avg)
        CONFIG_SET_BOOL_COMPAT(
            progressbar_bws_in_visible,
            progressbar_bps_in_visible)
        CONFIG_SET_BOOL_COMPAT(
            progressbar_bws_out_avg,
            progressbar_bps_out_avg)
        CONFIG_SET_BOOL_COMPAT(
            progressbar_bws_out_visible,
            progressbar_bps_out_visible)
        CONFIG_SET_NUM(
            connection_speed, gnet,
            PROP_CONNECTION_SPEED)
        CONFIG_SET_NUM(
            download_connected_timeout, gnet,
            PROP_DOWNLOAD_CONNECTED_TIMEOUT)
        CONFIG_SET_NUM(
            download_connecting_timeout, gnet,
            PROP_DOWNLOAD_CONNECTING_TIMEOUT)
        CONFIG_SET_NUM(
            download_push_sent_timeout, gnet,
            PROP_DOWNLOAD_PUSH_SENT_TIMEOUT)
        CONFIG_SET_NUM(
            download_retry_timeout_max, gnet,
            PROP_DOWNLOAD_RETRY_TIMEOUT_MAX)
        CONFIG_SET_NUM(
            download_retry_timeout_min, gnet,
            PROP_DOWNLOAD_RETRY_TIMEOUT_MIN)
        CONFIG_SET_NUM(
            downloads_divider_pos, gui,
            PROP_DOWNLOADS_DIVIDER_POS)
        CONFIG_SET_NUM(
            main_divider_pos, gui,
            PROP_MAIN_DIVIDER_POS)
        CONFIG_SET_NUM(
            side_divider_pos, gui,
            PROP_SIDE_DIVIDER_POS)
        CONFIG_SET_NUM(
            filter_main_divider_pos, gui,
            PROP_FILTER_MAIN_DIVIDER_POS)
        CONFIG_SET_NUM(
            hard_ttl_limit, gnet,
            PROP_HARD_TTL_LIMIT)
        CONFIG_SET_NUM(
            hops_random_factor, gnet,
            PROP_HOPS_RANDOM_FACTOR)
        CONFIG_SET_NUM(
            listen_port, gnet,
            PROP_LISTEN_PORT)
        CONFIG_SET_NUM(
            max_connections, gnet,
            PROP_MAX_CONNECTIONS)
        CONFIG_SET_NUM(
            max_downloads, gnet,
            PROP_MAX_DOWNLOADS)
        CONFIG_SET_NUM(
            max_host_downloads, gnet,
            PROP_MAX_HOST_DOWNLOADS)
        CONFIG_SET_NUM(
            max_hosts_cached, gnet,
            PROP_MAX_HOSTS_CACHED)
        CONFIG_SET_NUM(
            max_ttl, gnet,
            PROP_MAX_TTL)
        CONFIG_SET_NUM(
            max_uploads, gnet,
            PROP_MAX_UPLOADS)
        CONFIG_SET_NUM(
            max_uploads_ip, gnet,
            PROP_MAX_UPLOADS_IP)
		CONFIG_SET_NUM(
            ul_usage_min_percentage, gnet,
            PROP_UL_USAGE_MIN_PERCENTAGE)
        CONFIG_SET_NUM(
            minimum_speed, gui,
            PROP_DEFAULT_MINIMUM_SPEED)
        CONFIG_SET_NUM(
            monitor_max_items, gui,
            PROP_MONITOR_MAX_ITEMS)
        CONFIG_SET_NUM(
            my_ttl, gnet,
            PROP_MY_TTL)
        CONFIG_SET_NUM(
            node_connected_timeout, gnet,
            PROP_NODE_CONNECTED_TIMEOUT)
        CONFIG_SET_NUM(
            node_connecting_timeout, gnet,
            PROP_NODE_CONNECTING_TIMEOUT)
        CONFIG_SET_NUM(
            node_sendqueue_size, gnet,
            PROP_NODE_SENDQUEUE_SIZE)
        CONFIG_SET_NUM(
            node_tx_flowc_timeout, gnet,
            PROP_NODE_TX_FLOWC_TIMEOUT)
        CONFIG_SET_NUM(
            other_messages_kick_size, gnet,
            PROP_OTHER_MESSAGES_KICK_SIZE)
        CONFIG_SET_NUM(proxy_port, gnet,
            PROP_PROXY_PORT)
        CONFIG_SET_NUM(
            search_answers_forward_size, gnet,
            PROP_SEARCH_ANSWERS_FORWARD_SIZE)
        CONFIG_SET_NUM(
            search_answers_kick_size, gnet,
            PROP_SEARCH_ANSWERS_KICK_SIZE)
        CONFIG_SET_NUM(
            search_max_items, gnet,
            PROP_QUERY_RESPONSE_MAX_ITEMS)
        CONFIG_SET_NUM(
            search_max_results, gui,
            PROP_SEARCH_MAX_RESULTS)
        CONFIG_SET_NUM(
            search_queries_forward_size, gnet,
            PROP_SEARCH_QUERIES_FORWARD_SIZE)
        CONFIG_SET_NUM(
            search_queries_kick_size, gnet,
            PROP_SEARCH_QUERIES_KICK_SIZE)
        CONFIG_SET_NUM(
            search_stats_delcoef, gui,
            PROP_SEARCH_STATS_DELCOEF)
        CONFIG_SET_NUM(
            search_stats_update_interval, gui,
            PROP_SEARCH_STATS_UPDATE_INTERVAL)
        CONFIG_SET_NUM(
            up_connections, gnet,
            PROP_UP_CONNECTIONS)
        CONFIG_SET_IP(
            proxy_ip, gnet,
            PROP_PROXY_IP)
        CONFIG_SET_STR(
            socks_pass, gnet,
            PROP_SOCKS_PASS)
        CONFIG_SET_STR(
            socks_user, gnet,
            PROP_SOCKS_USER)
        CONFIG_SET_STR_COMPAT(
            socks_pass, 
            socksv5_pass)
        CONFIG_SET_STR_COMPAT(
            socks_user, 
            socksv5_user)
        CONFIG_SET_NUM(
            max_high_ttl_msg, gnet,
            PROP_MAX_HIGH_TTL_MSG)
        CONFIG_SET_NUM(
            max_high_ttl_radius, gnet,
            PROP_MAX_HIGH_TTL_RADIUS)
        CONFIG_SET_NUM(
            download_max_retries, gnet,
            PROP_DOWNLOAD_MAX_RETRIES)
        CONFIG_SET_NUM(
            download_overlap_range, gnet,
            PROP_DOWNLOAD_OVERLAP_RANGE)
        CONFIG_SET_NUM(
            download_retry_timeout_delay, gnet,
            PROP_DOWNLOAD_RETRY_TIMEOUT_DELAY)
        CONFIG_SET_NUM(
            download_retry_busy_delay, gnet,
            PROP_DOWNLOAD_RETRY_BUSY_DELAY)
        CONFIG_SET_NUM(
            download_retry_refused_delay, gnet,
            PROP_DOWNLOAD_RETRY_REFUSED_DELAY)
        CONFIG_SET_NUM(
            download_retry_stopped, gnet,
            PROP_DOWNLOAD_RETRY_STOPPED_DELAY)
        CONFIG_SET_NUM(
            upload_connecting_timeout, gnet,
            PROP_UPLOAD_CONNECTING_TIMEOUT)
        CONFIG_SET_NUM(
            upload_connected_timeout, gnet,
            PROP_UPLOAD_CONNECTED_TIMEOUT)
        CONFIG_SET_NUM(
            search_reissue_timeout, gnet,
            PROP_SEARCH_REISSUE_TIMEOUT)
        CONFIG_SET_NUM(
            ban_ratio_fds, gnet,
            PROP_BAN_RATIO_FDS)
        CONFIG_SET_NUM(
            ban_max_fds, gnet,
            PROP_BAN_MAX_FDS)
        CONFIG_SET_NUM(
            min_dup_msg, gnet,
            PROP_MIN_DUP_MSG)
        CONFIG_SET_IP(
            local_ip, gnet,
            PROP_LOCAL_IP)
        CONFIG_SET_IP(
            forced_local_ip, gnet,
            PROP_FORCED_LOCAL_IP)
        CONFIG_SET_NUM(
            output_bandwidth, gnet,
            PROP_BW_HTTP_OUT)
        CONFIG_SET_NUM(
            input_bandwidth, gnet,
            PROP_BW_HTTP_IN)
        CONFIG_SET_NUM(
            input_gnet_bandwidth, gnet,
            PROP_BW_GNET_IN)
        CONFIG_SET_NUM(
            output_gnet_bandwidth, gnet,
            PROP_BW_GNET_OUT)
        CONFIG_SET_STR(
            scan_extensions, gnet,
            PROP_SCAN_EXTENSIONS)
        CONFIG_SET_STR(
            save_file_path, gnet,
            PROP_SAVE_FILE_PATH)
        CONFIG_SET_STR(
            old_save_file_path, gnet,
            PROP_SAVE_FILE_PATH)
        CONFIG_SET_STR(
            move_file_path, gnet,
            PROP_MOVE_FILE_PATH)
        CONFIG_SET_STR(
            shared_dirs, gnet,
            PROP_SHARED_DIRS_PATHS)
        CONFIG_SET_STR(
            local_netmasks, gnet,
            PROP_LOCAL_NETMASKS_STRING)
        CONFIG_SET_VECTOR(
            win_coords, gui,
            PROP_WINDOW_COORDS)
        CONFIG_SET_VECTOR(
            filter_dlg_coords, gui,
            PROP_FILTER_DLG_COORDS)
        CONFIG_SET_VECTOR(
            search_column_visible, gui,
            PROP_SEARCH_RESULTS_COL_VISIBLE)
        CONFIG_SET_VECTOR(
            widths_nodes, gui,
            PROP_NODES_COL_WIDTHS)
        CONFIG_SET_VECTOR(
            widths_uploads, gui,
            PROP_UPLOADS_COL_WIDTHS)
        CONFIG_SET_VECTOR(
            widths_dl_active, gui,
            PROP_DL_ACTIVE_COL_WIDTHS)
        CONFIG_SET_VECTOR(
            widths_dl_queued, gui,
            PROP_DL_QUEUED_COL_WIDTHS)
        CONFIG_SET_VECTOR(
            widths_search_results, gui,
            PROP_SEARCH_RESULTS_COL_WIDTHS)
        CONFIG_SET_VECTOR(
            widths_search_stats, gui,
            PROP_SEARCH_STATS_COL_WIDTHS)
        CONFIG_SET_VECTOR(
            widths_ul_stats, gui,
            PROP_UL_STATS_COL_WIDTHS)
        CONFIG_SET_VECTOR(
            widths_search_list, gui,
            PROP_SEARCH_LIST_COL_WIDTHS)
        CONFIG_SET_VECTOR(
            widths_filter_table, gui,
            PROP_FILTER_RULES_COL_WIDTHS)
        CONFIG_SET_VECTOR(
            widths_filter_filters, gui,
            PROP_FILTER_FILTERS_COL_WIDTHS)

    case k_clear_downloads: {
        gboolean b = !g_ascii_strcasecmp(value, "true");
        gnet_prop_set_boolean(PROP_AUTOCLEAR_COMPLETED_DOWNLOADS, &b, 0, 1);
        gnet_prop_set_boolean(PROP_AUTOCLEAR_FAILED_DOWNLOADS, &b, 0, 1);
        return;
    }
	case k_clear_uploads: {
        gboolean b = !g_ascii_strcasecmp(value, "true");
        gnet_prop_set_boolean(PROP_AUTOCLEAR_COMPLETED_UPLOADS, &b, 0, 1);
        gnet_prop_set_boolean(PROP_AUTOCLEAR_FAILED_UPLOADS, &b, 0, 1);
        return;
    }
    case k_filter_default_policy:
        /* 
         * Removed. This can be accomplished by adding respective rules
         * to global post filter.
         *     -- Richard, 28/12/2002
         */
		return;

    case k_guid:
        if (strlen(value) == 32) {
            guint8 buf[16];

			hex_to_guid(value, buf);
            gnet_prop_set_storage(PROP_GUID, buf, sizeof(buf));
        }
		return;

    /*
     * Those are deferred, since they are not easily mappable to the new scheme
     */
	case k_win_x:
	case k_win_y:
	case k_win_w:
	case k_win_h:
		return;

    case k_search_stats_enabled: {
        guint32 v;
        v = g_ascii_strcasecmp(value, "true") == 0 ? 
            WORD_SEARCH_STATS : NO_SEARCH_STATS;
        gui_prop_set_guint32(PROP_SEARCH_STATS_MODE, &v, 0, 1);
        return;
    }

    case k_min_dup_ratio: {
        guint32 v = atof(value) * 100;
        gnet_prop_set_guint32(PROP_MIN_DUP_RATIO, &v, 0, 1);
		return;
    }

    case k_send_pushes: {
        gboolean b = (gboolean) i;
        
        gnet_prop_set_boolean(PROP_SEND_PUSHES, &b, 0, 1);
		return;
    }

	case k_jump_to_downloads: {
        gboolean b = (gboolean) i;
        
        gui_prop_set_boolean(PROP_JUMP_TO_DOWNLOADS, &b, 0, 1);
		return;
    }
	case k_proxy_connections:
		/* PROP_PROXY_CONNECTIONS is deprecated */
		gnet_prop_set_boolean_val(PROP_PROXY_CONNECTIONS, (gboolean) i);
		return;

	case k_proxy_protocol: {
		gboolean use_proxy;
		
		gnet_prop_get_boolean_val(PROP_PROXY_CONNECTIONS, &use_proxy);
		if (!use_proxy) {
			i = PROXY_NONE;
			gnet_prop_set_boolean_val(PROP_PROXY_CONNECTIONS, TRUE);
		}
       	gnet_prop_set_guint32_val(PROP_PROXY_PROTOCOL, i);
		return;
	}	
	case k_dbg:
		gnet_prop_set_guint32(PROP_DBG, &i, 0, 1);
        gui_prop_set_guint32(PROP_GUI_DEBUG, &i, 0, 1);
		return;

    case k_stop_host_get: {
        gboolean b = (gboolean) i;

		gnet_prop_set_boolean(PROP_STOP_HOST_GET, &b, 0, 1);
		return;
    }

	case k_search_pick_all: {
        gboolean b = (gboolean) i;

		gui_prop_set_boolean(PROP_SEARCH_AUTOSELECT, &b, 0, 1);
		return;
    }

	case k_end:
		g_assert_not_reached();
		return;
 	}
}

static void config_read(void)
{
	FILE *config;
	gchar *s, *k, *v;
	keyword_t i;
	guint32 n = 0;
	struct stat buf;

	static gchar *err = "Bad line %u in config file, ignored\n";

	if (!is_directory(gui_config_dir))
		return;

	gm_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", gui_config_dir, config_file);

	config = fopen(cfg_tmp, "r");
	if (!config)
		return;

	if (-1 == fstat(fileno(config), &buf))
		g_warning("could open but not fstat \"%s\" (fd #%d): %s",
			cfg_tmp, fileno(config), g_strerror(errno));
	else
		cfg_mtime = buf.st_mtime;

	while (fgets(cfg_tmp, sizeof(cfg_tmp), config)) {
		n++;
		s = cfg_tmp;
		while (*s && (*s == ' ' || *s == '\t'))
			s++;
		if (!((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z')))
			continue;
		k = s;
		while (*s == '_' || (*s >= 'A' && *s <= 'Z')
			   || (*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9'))
			s++;
		if (*s != '=' && *s != ' ' && *s != '\t') {
			fprintf(stderr, err, n);
			continue;
		}
		v = s;
		while (*s == ' ' || *s == '\t')
			s++;
		if (*s != '=') {
			fprintf(stderr, err, n);
			continue;
		}
		*v = 0;
		s++;
		while (*s == ' ' || *s == '\t')
			s++;
		if (*s == '"') {
			v = ++s;
			while (*s && *s != '\n' && *s != '"')
				s++;
			if (!*s || *s == '\n') {
				fprintf(stderr, err, n);
				continue;
			}
		} else {
			v = s;
			while (*s && *s != '\n' && *s != ' ' && *s != '\t')
				s++;
		}
		*s = 0;

		for (i = 0; i < k_end; i++)
			if (!g_ascii_strcasecmp(k, keywords[i])) {
				config_set_param(i, v);
				break;
			}

		if (i >= k_end)
			fprintf(stderr,
					"config file, line %u: unknown keyword '%s', ignored\n",
					n, k);
	}

	fclose(config);
}

/* vi: set ts=4: */
