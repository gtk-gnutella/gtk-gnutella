/*
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#include "gnutella.h"
#include "interface.h"
#include "search.h"
#include "misc.h"
#include "hosts.h"
#include "share.h"
#include "gui.h"
#include "search_stats.h"
#include "upload_stats.h"
#include "filter.h"
#include "sockets.h"

#define CONFIG_SET_BOOL(v)                           \
    case k_##v:                                      \
        v = (gboolean) ! g_strcasecmp(value, "true");\
        return;

#define CONFIG_SET_BOOL_COMPAT(v,w)                  \
    case k_##w:                                      \
        v = (gboolean) ! g_strcasecmp(value, "true");\
        return;

#define CONFIG_SET_STR(v)                            \
    case k_##v:                                      \
        v = g_strdup(value);                         \
        return;

#define CONFIG_SET_STR_COMPAT(v,w)                   \
    case k_##w:                                      \
        v = g_strdup(value);                         \
        return;

#define CONFIG_SET_NUM(v,min,max)                    \
    case k_##v:                                      \
		if (i >= min && i <= max) v = i;             \
		return;

#define CONFIG_WRITE_BOOL(v)                         \
  	fprintf(config, "%s = %s\n", keywords[k_##v],    \
			config_boolean(v));

#define CONFIG_WRITE_UINT(v)                         \
    fprintf(config, "%s = %u\n", keywords[k_##v], v);

#define CONFIG_WRITE_INT(v)                          \
    fprintf(config, "%s = %d\n", keywords[k_##v], v);

#define CONFIG_WRITE_STR(v)                          \
    fprintf(config, "%s = \"%s\"\n",                 \
            keywords[k_##v], v);

#define CONFIG_COMMENT(v)                            \
    fprintf(config, "# %s\n", v);

#define CONFIG_SECTION(v)                            \
    fprintf(config, "\n\n#\n#\n# SECTION: %s\n#\n#\n\n", v);

#define CONFIG_SUBSECTION(v)                         \
    fprintf(config, "\n#\n# SUBSECTION: %s\n#\n", v);


static gchar *config_file = "config";
static gchar *host_file = "hosts";
static gchar *ul_stats_file = "upload_stats";


gboolean bws_in_enabled = FALSE;
gboolean bws_out_enabled = FALSE;
gboolean bws_gin_enabled = FALSE;
gboolean bws_gout_enabled = FALSE;
gboolean bw_ul_usage_enabled = TRUE;
gboolean clear_uploads = FALSE;
gboolean clear_downloads = FALSE;
gboolean monitor_enabled = FALSE;
gboolean search_remove_downloaded = FALSE;
gboolean search_autoselect_ident = FALSE;
gboolean force_local_ip = TRUE;
gboolean toolbar_visible = FALSE;
gboolean statusbar_visible = TRUE;
gboolean progressbar_uploads_visible = TRUE;
gboolean progressbar_downloads_visible = TRUE;
gboolean progressbar_connections_visible = TRUE;
gboolean progressbar_bws_in_visible = TRUE;
gboolean progressbar_bws_out_visible = TRUE;
gboolean progressbar_bws_gin_visible = TRUE;
gboolean progressbar_bws_gout_visible = TRUE;
gboolean progressbar_bws_in_avg = FALSE;
gboolean progressbar_bws_out_avg = FALSE;
gboolean progressbar_bws_gin_avg = FALSE;
gboolean progressbar_bws_gout_avg = FALSE;

gboolean use_netmasks = FALSE;
gboolean download_delete_aborted = FALSE;
gboolean queue_regex_case = FALSE;

guint8 max_ttl = 10;
guint8 my_ttl = 7;
guint8 hard_ttl_limit = 15;

guint16 listen_port = 6346;

guint32 up_connections = 4;
guint32 max_connections = 10;
guint32 max_downloads = 10;
guint32 max_host_downloads = 4;
guint32 max_uploads = 5;
guint8 ul_usage_min_percentage = 70;	/* Use at least 70% of available b/w */
guint32 minimum_speed = 0;
guint32 monitor_max_items = 25;
guint32 connection_speed = 28;	/* kbits/s */
gint32 search_max_items = 50;	/* For now, this is limited to 255 anyway */
guint32 forced_local_ip = 0;
guint32 local_ip = 0;
guint32 download_connecting_timeout = 30;
guint32 download_push_sent_timeout = 60;
guint32 download_connected_timeout = 60;
guint32 download_retry_timeout_min = 20;
guint32 download_retry_timeout_max = 120;
guint32 download_max_retries = 256;
guint32 download_retry_timeout_delay = 1200;
guint32 download_retry_busy_delay = 60;
guint32 download_retry_refused_delay = 1800;
guint32 download_retry_stopped = 15;
guint32 download_overlap_range = 512;
guint32 upload_connecting_timeout = 60;		/* Receiving headers */
guint32 upload_connected_timeout = 180;		/* Sending data */
guint32 node_connected_timeout = 45;
guint32 node_connecting_timeout = 5;
guint32 node_sendqueue_size = 98304;		/* 150% of max msg size (64K) */
guint32 node_tx_flowc_timeout = 60;
guint32 search_queries_forward_size = 256;
guint32 search_queries_kick_size = 1024;
guint32 search_answers_forward_size = 65536;
guint32 search_answers_kick_size = 65536;
guint32 other_messages_kick_size = 40960;
guint32 hops_random_factor = 0;
guint32 max_high_ttl_msg = 10;
guint32 max_high_ttl_radius = 2;
guint32 min_dup_msg = 5;
gfloat min_dup_ratio = 1.5;
guint32 max_hosts_cached = 20480;
guint32 search_stats_update_interval = 200;
guint32 search_stats_delcoef = 25;
guint32 ban_max_fds = 100;					/* Max amount of fds for banning */
guint32 ban_ratio_fds = 25;					/* Max %ratio of available fds */

struct conf_bandwidth bandwidth = { 0, 0, 0, 0};	/* No limits */

gchar *local_netmasks_string = NULL;

gint dbg = 0;					// debug level, for development use
gint stop_host_get = 0;			// stop get new hosts, non activity ok (debug)
gint enable_err_log = 0;		// enable writing to log file for errors
gint search_pick_all = 1;		// enable picking all files alike in search
gint max_uploads_ip = 2;		// maximum uploads per IP
gint filter_default_policy = FILTER_PROP_STATE_DO; // default to "display"
guint16 downloads_divider_pos = 160;
guint16 main_divider_pos = 128;
guint16 side_divider_pos = 128;
guint16 filter_main_divider_pos = 200;

time_t tab_update_time = 5;

gchar *scan_extensions = NULL;
gchar *save_file_path = NULL;
gchar *move_file_path = NULL;
gchar *shared_dirs_paths = NULL;
gchar *completed_file_path = NULL;
gchar *home_dir = NULL;
gchar *config_dir = NULL;


guint32 nodes_col_widths[] = { 130, 50, 120, 20, 80 };
guint32 dl_active_col_widths[] = { 240, 80, 80, 80, 80 };
guint32 dl_queued_col_widths[] = { 240, 80, 80, 80, 80 };
guint32 uploads_col_widths[] = { 200, 120, 36, 80, 80, 80 };
guint32 search_results_col_widths[] = { 210, 80, 50, 70, 70, 140 };
guint32 search_stats_col_widths[] = { 200, 80, 80 };
guint32 ul_stats_col_widths[] = { 200, 80, 80, 80, 80 };
guint32 search_list_col_widths[] = { 80, 20, 20 };
guint32 filter_table_col_widths[] = { 10, 240, 80, 40 };
guint32 filter_filters_col_widths[] = { 80,20,20 };
guint32 search_column_visible[6] = { 1,1,1,1,0,1};

gboolean jump_to_downloads = TRUE;

gint win_x = 0, win_y = 0, win_w = 0, win_h = 0;
gint flt_dlg_x = 0, flt_dlg_y = 0, flt_dlg_w = 0, flt_dlg_h = 0;

guint32 search_reissue_timeout = 600;	/* 10 minutes */

gboolean proxy_connections = FALSE;
gint proxy_protocol = 4;
static gchar *static_proxy_ip = "0.0.0.0";
gint proxy_port = 1080;
gchar *proxy_ip = NULL;

#define SOCKS_USER	0
#define SOCKS_PASS	1


gboolean proxy_auth = FALSE;
static gchar *socks[] = { "proxyuser", "proxypass" };
gchar *socks_user = NULL;
gchar *socks_pass = NULL;

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
	k_dbg, k_stop_host_get, k_enable_err_log, k_max_uploads_ip,
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
	"enable_err_log",
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
static gchar *pidfile = "gtk-gnutella.pid";

static gchar *file_extensions =
	"asf;avi;"
	"bz2;"
	"divx;"
	"gif;gz;"
	"it;"
	"jpeg;jpg;"
	"mod;mov;mpg;mpeg;mp3;mp2;mp1;"
	"ogg;"
	"png;ps;pdf;"
	"rar;"
	"s3m;stm;"
	"txt;"
	"voc;vqf;"
	"wav;wma;"
	"xm;"
	"zip"	/* no trailing ";" */
	;

static void config_read(void);

/* ----------------------------------------- */

/*
 * ensure_unicity
 *
 * Look for any existing PID file. If found, look at the pid recorded
 * there and make sure it has died. Abort operations if it hasn't...
 */
static void ensure_unicity(gchar *file)
{
	FILE *fd;
	pid_t pid = (pid_t) 0;
	gchar buf[16];

	fd = fopen(file, "r");
	if (fd == NULL)
		return;				/* Assume it's missing if can't be opened */

	buf[0] = '\0';
	fgets(buf, sizeof(buf) - 1, fd);
	sscanf(buf, "%d", &pid);
	fclose(fd);

	if (pid == 0)
		return;				/* Can't read it back correctly */

	/*
	 * Existence check relies on the existence of signal 0. The kernel
	 * won't actually send anything, but will perform all the existence
	 * checks inherent to the kill() syscall for us...
	 */

	if (-1 == kill(pid, 0)) {
		if (errno != ESRCH)
			g_warning("kill() return unexpected error: %s", g_strerror(errno));
		return;
	}

	fprintf(stderr,
		"You seem to have left another gtk-gnutella running (pid = %d)\n",
		pid);
	exit(1);
}

/*
 * save_pid
 *
 * Write our pid to the pidfile.
 */
static void save_pid(gchar *file)
{
	FILE *fd;

	fd = fopen(file, "w");

	if (fd == NULL) {
		g_warning("unable to create pidfile \"%s\": %s",
			file, g_strerror(errno));
		return;
	}

	fprintf(fd, "%d\n", (gint) getpid());

	if (0 != fclose(fd))
		g_warning("could not flush pidfile \"%s\": %s",
			file, g_strerror(errno));
}

/* ----------------------------------------- */

void config_init(void)
{
//	gint i;
	struct passwd *pwd = NULL;

	config_dir = g_strdup(getenv("GTK_GNUTELLA_DIR"));
	socks_user = socks[SOCKS_USER];
	socks_pass = socks[SOCKS_PASS];
	proxy_ip = static_proxy_ip;
	memset(guid, 0, sizeof(guid));

	pwd = getpwuid(getuid());

	if (pwd && pwd->pw_dir)
		home_dir = g_strdup(pwd->pw_dir);
	else
		home_dir = g_strdup(getenv("HOME"));

	if (!home_dir)
		g_warning("can't find your home directory!");

	if (!config_dir) {
		if (home_dir) {
			g_snprintf(cfg_tmp, sizeof(cfg_tmp),
				"%s/.gtk-gnutella", home_dir);
			config_dir = g_strdup(cfg_tmp);
		} else
			g_warning("no home directory: prefs will not be saved!");
	}

	if (config_dir && !is_directory(config_dir)) {
		g_warning("creating configuration directory '%s'\n", config_dir);

		if (mkdir(config_dir, 0755) == -1) {
			g_warning("mkdir(%s) failed: %s\n\n",
				config_dir, g_strerror(errno));
			g_free(config_dir);
			config_dir = NULL;
		}
	}

	if (config_dir) {
		/* Ensure we're the only instance running */

		g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", config_dir, pidfile);
		ensure_unicity(cfg_tmp);
		save_pid(cfg_tmp);

		/* Parse the configuration */

		config_read();

		g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", config_dir, host_file);
		hosts_read_from_file(cfg_tmp, TRUE);	/* Loads the catched hosts */

		g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s",
			config_dir, ul_stats_file);
		ul_stats_load_history(cfg_tmp);		/* Loads the upload statistics */
	}

	if (!save_file_path || !is_directory(save_file_path))
		save_file_path =
			(home_dir) ? g_strdup(home_dir) : g_strdup("/tmp");

	if (!move_file_path || !is_directory(move_file_path))
		move_file_path = g_strdup(save_file_path);

	if (!forced_local_ip)
		force_local_ip = FALSE;

	if (!shared_dirs_paths)
		shared_dirs_paths = g_strdup("");

	if (!extensions)
		parse_extensions(file_extensions);

	if (!scan_extensions)
		scan_extensions = g_strdup(file_extensions);
	/* watch for filter_file defaults */

	if (hard_ttl_limit < max_ttl) {
		hard_ttl_limit = max_ttl;
		g_warning("hard_ttl_limit was too small, adjusted to %u",
			hard_ttl_limit);
	}

	/* Flow control depends on this being not too small */
	if (node_sendqueue_size < 1.5 * config_max_msg_size()) {
		node_sendqueue_size = (guint32) (1.5 * config_max_msg_size());
		g_warning("node_sendqueue_size was too small, adjusted to %u",
			node_sendqueue_size);
	}
}

guint32 *config_parse_array(gchar * str, guint32 n)
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

void config_set_param(keyword_t keyword, gchar *value)
{
	gint32 i = atol(value);
	guint32 *a;

	switch (keyword) {
        CONFIG_SET_BOOL(bws_gin_enabled)
        CONFIG_SET_BOOL(bws_gout_enabled)
        CONFIG_SET_BOOL(bws_in_enabled)
        CONFIG_SET_BOOL(bws_out_enabled)
		CONFIG_SET_BOOL(bw_ul_usage_enabled)
        CONFIG_SET_BOOL(clear_downloads)
        CONFIG_SET_BOOL(clear_uploads)
        CONFIG_SET_BOOL(download_delete_aborted)
        CONFIG_SET_BOOL(force_local_ip)
        CONFIG_SET_BOOL(monitor_enabled)
        CONFIG_SET_BOOL(progressbar_bws_gin_avg)
        CONFIG_SET_BOOL(progressbar_bws_gin_visible)
        CONFIG_SET_BOOL(progressbar_bws_gout_avg)
        CONFIG_SET_BOOL(progressbar_bws_gout_visible)
        CONFIG_SET_BOOL(progressbar_bws_in_avg)
        CONFIG_SET_BOOL(progressbar_bws_in_visible)
        CONFIG_SET_BOOL(progressbar_bws_out_avg)
        CONFIG_SET_BOOL(progressbar_bws_out_visible)
        CONFIG_SET_BOOL(progressbar_connections_visible)
        CONFIG_SET_BOOL(progressbar_downloads_visible)
        CONFIG_SET_BOOL(progressbar_uploads_visible)
        CONFIG_SET_BOOL(proxy_auth)
        CONFIG_SET_BOOL(queue_regex_case)
        CONFIG_SET_BOOL(search_remove_downloaded)
        CONFIG_SET_BOOL(search_autoselect_ident)
        CONFIG_SET_BOOL(search_results_show_tabs)
        CONFIG_SET_BOOL(search_stats_enabled)
        CONFIG_SET_BOOL(statusbar_visible)
        CONFIG_SET_BOOL(toolbar_visible)
        CONFIG_SET_BOOL(use_netmasks)
        CONFIG_SET_BOOL_COMPAT(progressbar_bws_in_avg,progressbar_bps_in_avg)
        CONFIG_SET_BOOL_COMPAT(progressbar_bws_in_visible,progressbar_bps_in_visible)
        CONFIG_SET_BOOL_COMPAT(progressbar_bws_out_avg,progressbar_bps_out_avg)
        CONFIG_SET_BOOL_COMPAT(progressbar_bws_out_visible,progressbar_bps_out_visible)
        CONFIG_SET_NUM(connection_speed,               0,      2000)
        CONFIG_SET_NUM(download_connected_timeout,     1,    100000)
        CONFIG_SET_NUM(download_connecting_timeout,    1,    100000)
        CONFIG_SET_NUM(download_push_sent_timeout,     1,    100000)
        CONFIG_SET_NUM(download_retry_timeout_max,    15,    100000)
        CONFIG_SET_NUM(download_retry_timeout_min,    15,    100000)
        CONFIG_SET_NUM(downloads_divider_pos,          0,      5000)
        CONFIG_SET_NUM(main_divider_pos,               0,      5000)
        CONFIG_SET_NUM(side_divider_pos,               0,      5000)
        CONFIG_SET_NUM(filter_main_divider_pos,        0,      5000)
        CONFIG_SET_NUM(hard_ttl_limit,                 5,        99)
        CONFIG_SET_NUM(hops_random_factor,             0,         3)
        CONFIG_SET_NUM(listen_port,                    0,     65535)
        CONFIG_SET_NUM(max_connections,                0,       100)
        CONFIG_SET_NUM(max_downloads,                  0,       100)
        CONFIG_SET_NUM(max_host_downloads,             1,       100)
        CONFIG_SET_NUM(max_hosts_cached,             100,    500000)
        CONFIG_SET_NUM(max_ttl,                        1,        99)
        CONFIG_SET_NUM(max_uploads,                    0,       100)
        CONFIG_SET_NUM(max_uploads_ip,                 1,       100)
		CONFIG_SET_NUM(ul_usage_min_percentage,        0,       100)
        CONFIG_SET_NUM(minimum_speed,                  0,      2000)
        CONFIG_SET_NUM(monitor_max_items,              1,      1000)
        CONFIG_SET_NUM(my_ttl,                         1,        99)
        CONFIG_SET_NUM(node_connected_timeout,         1,    100000)
        CONFIG_SET_NUM(node_connecting_timeout,        1,    100000)
        CONFIG_SET_NUM(node_sendqueue_size,         4096,   1048576)
        CONFIG_SET_NUM(node_tx_flowc_timeout,          1,    100000)
        CONFIG_SET_NUM(other_messages_kick_size,     513,   1048575)
        CONFIG_SET_NUM(proxy_port,                     0,     65535)
        CONFIG_SET_NUM(search_answers_forward_size,  513,   1048575)
        CONFIG_SET_NUM(search_answers_kick_size,     513,   1048575)
        CONFIG_SET_NUM(search_max_items,               1,       255)
        CONFIG_SET_NUM(search_max_results,             0,      1000)
        CONFIG_SET_NUM(search_queries_forward_size,   65,     65534)
        CONFIG_SET_NUM(search_queries_kick_size,     513,     65534)
        CONFIG_SET_NUM(search_stats_delcoef,           0,       100)
        CONFIG_SET_NUM(search_stats_update_interval,   0,     50000)
        CONFIG_SET_NUM(up_connections,                 1,       100)
        CONFIG_SET_STR(proxy_ip)
        CONFIG_SET_STR(socks_pass)
        CONFIG_SET_STR(socks_user)
        CONFIG_SET_STR_COMPAT(socks_pass, socksv5_pass)
        CONFIG_SET_STR_COMPAT(socks_user, socksv5_user)

        CONFIG_SET_NUM(max_high_ttl_msg,               0,         99)
        CONFIG_SET_NUM(max_high_ttl_radius,            0,         99)
        CONFIG_SET_NUM(download_max_retries,           0,     100000)
        CONFIG_SET_NUM(download_overlap_range,       128, SOCK_BUFSZ)
        CONFIG_SET_NUM(download_retry_timeout_delay,  15,     100000)
        CONFIG_SET_NUM(download_retry_busy_delay,     15,     100000)
        CONFIG_SET_NUM(download_retry_refused_delay,  15,     100000)
        CONFIG_SET_NUM(download_retry_stopped,        15,     100000)
        CONFIG_SET_NUM(upload_connecting_timeout,      1,     100000)
        CONFIG_SET_NUM(upload_connected_timeout,       1,     100000)
        CONFIG_SET_NUM(search_reissue_timeout,         0,       9999)
        CONFIG_SET_NUM(ban_ratio_fds,                  0,        100)
        CONFIG_SET_NUM(ban_max_fds,                    0,      10000)
        
    case k_output_bandwidth:
        if ((i >= 0) && (i <= BS_BW_MAX))
            bandwidth.output = i;
        break;

    case k_input_bandwidth:
        if ((i >= 0) && (i <= BS_BW_MAX))
            bandwidth.input = i;
        break;

    case k_input_gnet_bandwidth:
        if ((i >= 0) && (i <= BS_BW_MAX))
            bandwidth.ginput = i;
        break;

    case k_output_gnet_bandwidth:
        if ((i >= 0) && (i <= BS_BW_MAX))
            bandwidth.goutput = i;
        break;

    case k_filter_default_policy:
        /*
         * Due to changes in the filter code we have to map
         * 0 to FILTER_PROP_STATE_DONT;
         */
        if (i == 0)
            i = FILTER_PROP_STATE_DONT;

        if (i >= 1 && i <= 2)
            filter_default_policy = i;
		return;

	case k_local_ip:
		local_ip = gchar_to_ip(value);
		return;

	case k_guid:
		if (strlen(value) == 32)
			hex_to_guid(value, guid);
		return;

	case k_scan_extensions:
		parse_extensions(value);
		return;

	case k_old_save_file_path:
	case k_save_file_path:
		save_file_path = g_strdup(value);
		return;

	case k_move_file_path:
		move_file_path = g_strdup(value);
		return;

	case k_shared_dirs:
		shared_dirs_parse(value);
		return;
   
	case k_win_x:
		win_x = i;
		return;

	case k_win_y:
		win_y = i;
		return;

	case k_win_w:
		win_w = i;
		return;

	case k_win_h:
		win_h = i;
		return;

	case k_win_coords:
		if ((a = config_parse_array(value, 4))) {
			win_x = a[0];
			win_y = a[1];
			win_w = a[2];
			win_h = a[3];
		}
		return;

    case k_filter_dlg_coords:
		if ((a = config_parse_array(value, 4))) {
			flt_dlg_x = a[0];
			flt_dlg_y = a[1];
			flt_dlg_w = a[2];
			flt_dlg_h = a[3];
		}
		return;

    case k_search_column_visible:
		if ((a = config_parse_array(value, 6)))
			for (i = 0; i < 6; i++)
				search_column_visible[i] = a[i];
		return;

	case k_widths_nodes:
		if ((a = config_parse_array(value, 5)))
			for (i = 0; i < 5; i++)
				nodes_col_widths[i] = a[i];
		return;

	case k_widths_uploads:
		if ((a = config_parse_array(value, 6)))
			for (i = 0; i < 6; i++)
				uploads_col_widths[i] = a[i];
		return;

	case k_widths_dl_active:
		if ((a = config_parse_array(value, 5)))
			for (i = 0; i < 5; i++)
				dl_active_col_widths[i] = a[i];
		return;

	case k_widths_dl_queued:
		if ((a = config_parse_array(value, 5)))
			for (i = 0; i < 5; i++)
				dl_queued_col_widths[i] = a[i];
		return;

	case k_widths_search_results:
		if ((a = config_parse_array(value, 6)))
			for (i = 0; i < 6; i++)
				search_results_col_widths[i] = a[i];
		return;

	case k_widths_search_stats:
		if ((a = config_parse_array(value, 3)))
			for (i = 0; i < 3; i++)
				search_stats_col_widths[i] = a[i];
		return;

	case k_widths_ul_stats:
		if ((a = config_parse_array(value, 5)))
			for (i = 0; i < 5; i++)
				ul_stats_col_widths[i] = a[i];
		return;

    case k_widths_search_list:
		if ((a = config_parse_array(value, 3)))
			for (i = 0; i < 3; i++)
				search_list_col_widths[i] = a[i];
		return;

    case k_widths_filter_table:
		if ((a = config_parse_array(value, 4)))
			for (i = 0; i < 4; i++)
				filter_table_col_widths[i] = a[i];
		return;

    case k_widths_filter_filters:
		if ((a = config_parse_array(value, 3)))
			for (i = 0; i < 3; i++)
				filter_filters_col_widths[i] = a[i];
		return;

	case k_forced_local_ip:
		forced_local_ip = gchar_to_ip(value);
		return;

	case k_send_pushes:
		send_pushes = i ? 1 : 0;
		return;

	case k_jump_to_downloads:
		jump_to_downloads = i ? TRUE : FALSE;
		return;

	case k_proxy_connections:
		proxy_connections = i ? TRUE : FALSE;
		return;

	case k_proxy_protocol:
		proxy_protocol = i;
		return;

	case k_dbg:
		dbg = i;
		return;

	case k_stop_host_get:
		stop_host_get = i;
		return;

	case k_enable_err_log:
		enable_err_log = i;
		return;

	case k_search_pick_all:
		search_pick_all = i;
		return;

	case k_min_dup_msg:
		min_dup_msg = i;
		return;

	case k_min_dup_ratio:
		min_dup_ratio = atof(value);
		if (min_dup_ratio < 0.0)   min_dup_ratio = 0.0;
		if (min_dup_ratio > 100.0) min_dup_ratio = 100.0;
		return;

 	case k_local_netmasks:
 		local_netmasks_string = g_strdup(value);
 		parse_netmasks(value);
 		return;

	case k_end:
		g_assert(0);		/* Cannot happen */
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

	if (!is_directory(config_dir))
		return;

	g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", config_dir, config_file);

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
			if (!g_strcasecmp(k, keywords[i])) {
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

gchar *config_boolean(gboolean b)
{
	static gchar *b_true = "TRUE";
	static gchar *b_false = "FALSE";
	return (b) ? b_true : b_false;
}

/*
 * config_save
 *
 * Save user configuration.
 */
static void config_save(void)
{
	FILE *config;
	gint win_x, win_y, win_w, win_h;
	gchar *filename;
	time_t mtime = 0;
	struct stat buf;
	gchar *newfile;

	if (!config_dir) {
		g_warning("no configuration directory: preferences were not saved");
		return;
	}

	g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", config_dir, config_file);
	filename = cfg_tmp;

	if (-1 == stat(filename, &buf))
		g_warning("could not stat \"%s\": %s", filename, g_strerror(errno));
	else
		mtime = buf.st_mtime;

	/*
	 * Rename old config file if they changed it whilst we were running.
	 */

	if (cfg_mtime && mtime > cfg_mtime) {
		gchar *old = g_strconcat(filename, ".old", NULL);
		g_warning("config file \"%s\" changed whilst I was running", filename);
		if (-1 == rename(filename, old))
			g_warning("unable to rename as \"%s\": %s", old, g_strerror(errno));
		else
			g_warning("renamed old copy as \"%s\"", old);
		g_free(old);
	}

	/*
	 * Create new file, which will be renamed at the end, so we don't
	 * clobber a good configuration file should we fail abrupbtly.
	 */

	newfile = g_strconcat(filename, ".new", NULL);
	config = fopen(newfile, "w");

	if (!config) {
		fprintf(stderr, "\nfopen(): %s\n"
			"\nUnable to write your configuration in %s\n"
			"Preferences have not been saved.\n\n",
				g_strerror(errno), newfile);
		goto end;
	}

	gdk_window_get_root_origin(main_window->window, &win_x, &win_y);
	gdk_window_get_size(main_window->window, &win_w, &win_h);

#ifdef GTA_REVISION
	fprintf(config,
			"#\n# Gtk-Gnutella %u.%u %s (%s) by Olrick & Co.\n# %s\n#\n",
			GTA_VERSION, GTA_SUBVERSION, GTA_REVISION, GTA_RELEASE,
			GTA_WEBSITE);
#else
	fprintf(config,
			"#\n# Gtk-Gnutella %u.%u (%s) by Olrick & Co.\n# %s\n#\n",
			GTA_VERSION, GTA_SUBVERSION, GTA_RELEASE, GTA_WEBSITE);
#endif
    CONFIG_COMMENT("This is Gtk-Gnutella configuration file")
	CONFIG_COMMENT("you may edit it if you're careful.")
    CONFIG_COMMENT("(only when the program is not running:")
	CONFIG_COMMENT("this file is saved on quit)")

    CONFIG_SECTION("GUI state") {
        CONFIG_WRITE_BOOL(toolbar_visible)
        CONFIG_WRITE_BOOL(statusbar_visible)
        CONFIG_WRITE_BOOL(progressbar_uploads_visible)
        CONFIG_WRITE_BOOL(progressbar_downloads_visible)
        CONFIG_WRITE_BOOL(progressbar_connections_visible)
        CONFIG_WRITE_BOOL(progressbar_bws_in_visible)
        CONFIG_WRITE_BOOL(progressbar_bws_out_visible)
        CONFIG_WRITE_BOOL(progressbar_bws_gin_visible)
        CONFIG_WRITE_BOOL(progressbar_bws_gout_visible)
        CONFIG_WRITE_BOOL(progressbar_bws_in_avg)
        CONFIG_WRITE_BOOL(progressbar_bws_out_avg)
        CONFIG_WRITE_BOOL(progressbar_bws_gin_avg)
        CONFIG_WRITE_BOOL(progressbar_bws_gout_avg)
        CONFIG_WRITE_BOOL(queue_regex_case)
        CONFIG_WRITE_UINT(downloads_divider_pos)
        CONFIG_WRITE_UINT(main_divider_pos)
        CONFIG_WRITE_UINT(side_divider_pos)
        CONFIG_WRITE_UINT(filter_main_divider_pos)
        fprintf(config, "%s = %u,%u,%u,%u,%u,%u\n", 
            keywords[k_search_column_visible],
			search_column_visible[0], search_column_visible[1],
			search_column_visible[2], search_column_visible[3],
			search_column_visible[4], search_column_visible[5] );
        fprintf(config, "%s = %u,%u,%u,%u,%u\n", keywords[k_widths_nodes],
			nodes_col_widths[0], nodes_col_widths[1],
			nodes_col_widths[2], nodes_col_widths[3], nodes_col_widths[4]);
        fprintf(config, "%s = %u,%u,%u,%u,%u,%u\n", keywords[k_widths_uploads],
			uploads_col_widths[0], uploads_col_widths[1],
			uploads_col_widths[2], uploads_col_widths[3],
			uploads_col_widths[4], uploads_col_widths[5] );
        fprintf(config, "%s = %u,%u,%u,%u,%u\n", keywords[k_widths_dl_active],
			dl_active_col_widths[0], dl_active_col_widths[1],
			dl_active_col_widths[2], dl_active_col_widths[3],
            dl_active_col_widths[4]);
        fprintf(config, "%s = %u,%u,%u,%u,%u\n", keywords[k_widths_dl_queued],
			dl_queued_col_widths[0], dl_queued_col_widths[1],
            dl_queued_col_widths[2], dl_queued_col_widths[3],
            dl_queued_col_widths[4]);
        fprintf(config, "%s = %u,%u,%u,%u,%u,%u\n",
			keywords[k_widths_search_results],
			search_results_col_widths[0], search_results_col_widths[1],
			search_results_col_widths[2], search_results_col_widths[3],
			search_results_col_widths[4], search_results_col_widths[5]);
        fprintf(config, "%s = %u,%u,%u\n",
			keywords[k_widths_search_stats],
			search_stats_col_widths[0], search_stats_col_widths[1],
			search_stats_col_widths[2]);
        fprintf(config, "%s = %u,%u,%u,%u,%u\n",
			keywords[k_widths_ul_stats],
			ul_stats_col_widths[0], ul_stats_col_widths[1],
			ul_stats_col_widths[2], ul_stats_col_widths[3],
			ul_stats_col_widths[4]);
        fprintf(config, "%s = %u,%u,%u\n",
			keywords[k_widths_search_list],
			search_list_col_widths[0], search_list_col_widths[1],
			search_list_col_widths[2]);
        fprintf(config, "%s = %u,%u,%u,%u\n",
			keywords[k_widths_filter_table],
			filter_table_col_widths[0], filter_table_col_widths[1],
            filter_table_col_widths[2], filter_table_col_widths[3]);
        fprintf(config, "%s = %u,%u,%u\n",
			keywords[k_widths_filter_filters],
			filter_filters_col_widths[0], filter_filters_col_widths[1],
            filter_filters_col_widths[2]);
       	fprintf(config, "%s = %u,%u,%u,%u\n", keywords[k_win_coords], 
            win_x, win_y, win_w, win_h);
        fprintf(config, "%s = %u,%u,%u,%u\n", keywords[k_filter_dlg_coords], 
            flt_dlg_x, flt_dlg_y, flt_dlg_w, flt_dlg_h);
    }

    CONFIG_SECTION("Network settings") {
        CONFIG_SUBSECTION("non configurable") {
          	fprintf(config, "%s = \"%s\"\n", keywords[k_local_ip],
                    ip_to_gchar(local_ip));
        }

        CONFIG_SUBSECTION("IP settings") {
            CONFIG_WRITE_UINT(listen_port)
            CONFIG_WRITE_BOOL(force_local_ip)
            fprintf(config, "%s = \"%s\"\n", keywords[k_forced_local_ip],
                    ip_to_gchar(forced_local_ip));
        }

        CONFIG_SUBSECTION("Proxy settings") {
            CONFIG_WRITE_UINT(proxy_connections)
            CONFIG_WRITE_UINT(proxy_protocol)
            CONFIG_WRITE_STR(proxy_ip)
            CONFIG_WRITE_UINT(proxy_port)
            CONFIG_WRITE_BOOL(proxy_auth)
            CONFIG_WRITE_STR(socks_user)
            CONFIG_WRITE_STR(socks_pass)
        }
        
        CONFIG_SUBSECTION("Local networks") {
           	/* Mike Perry's netmask hack */
            CONFIG_WRITE_BOOL(use_netmasks)

          	if (local_netmasks_string)
                fprintf(config, "%s = %s\n", keywords[k_local_netmasks],
                        local_netmasks_string);
        }
    }

    CONFIG_SECTION("Bandwidth control") {
        CONFIG_SUBSECTION("gnutellaNet traffic") {
            CONFIG_WRITE_BOOL(bws_gin_enabled)
            CONFIG_WRITE_BOOL(bws_gout_enabled)
           	fprintf(config, "# Gnet output bandwidth, in bytes/sec "
                "[0=nolimit, max=2 MB/s]\n"
                "%s = %u\n", keywords[k_output_gnet_bandwidth], 
                bandwidth.goutput);

            fprintf(config, "# Gnet input bandwidth, in bytes/sec "
                "[0=nolimit, max=2 MB/s]\n"
                "%s = %u\n", keywords[k_input_gnet_bandwidth], 
                bandwidth.ginput);

        }

        CONFIG_SUBSECTION("HTTP traffic") {
            CONFIG_WRITE_BOOL(bws_in_enabled)
            CONFIG_WRITE_BOOL(bws_out_enabled)
            fprintf(config, "# Output bandwidth, in bytes/sec (Gnet excluded) "
                "[0=nolimit, max=2 MB/s]\n"
                "%s = %u\n", keywords[k_output_bandwidth], bandwidth.output);

            fprintf(config, "# Input bandwidth, in bytes/sec (Gnet excluded) "
                "[0=nolimit, max=2 MB/s]\n"
                "%s = %u\n", keywords[k_input_bandwidth], bandwidth.input);
        }
    }

    CONFIG_SECTION("GnutellaNet options") {
        CONFIG_SUBSECTION("non configurable") {
            fprintf(config, "%s = \"%s\"\n", keywords[k_guid], 
                    guid_hex_str(guid));

            fprintf(config, "# The following two variables work in concert:\n");
            fprintf(config, "# Minimum amount of dup messages to enable kicking, "
                "per node\n%s = %u\n",
                keywords[k_min_dup_msg], min_dup_msg);
            fprintf(config, "# Minimum ratio of dups on received messages, "
                "per node (between 0.0 and 100.0)\n%s = %.2f\n",
                keywords[k_min_dup_ratio], min_dup_ratio);

            CONFIG_COMMENT("Maximum size of the sendqueue for the nodes")
            CONFIG_COMMENT("(in bytes). Must be at least 150%% of max message")
            fprintf(config, "# size (currently %u bytes), which means minimal\n",(
                guint32) (1.5 * config_max_msg_size()) );
            fprintf(config, "# allowed value is %u bytes.\n", config_max_msg_size() );
            fprintf(config, "%s = %u\n",
                keywords[k_node_sendqueue_size], node_sendqueue_size);
        
            fprintf(config, "# Random factor for the hops field "
                "in search packets we send (between 0 and 3 inclusive)\n%s = %u\n",
                keywords[k_hops_random_factor], hops_random_factor);
        }

        CONFIG_SUBSECTION("General") {
            CONFIG_WRITE_UINT(up_connections)
            CONFIG_WRITE_UINT(max_connections)
            CONFIG_WRITE_UINT(connection_speed)
            CONFIG_WRITE_INT(search_max_items)
            CONFIG_WRITE_INT(ban_max_fds)
            CONFIG_WRITE_INT(ban_ratio_fds)
          	fprintf(config, "# Maximum amount of hosts to keep in cache "
                "(minimum 100)\n%s = %u\n",
                keywords[k_max_hosts_cached], max_hosts_cached);
            
        }
    
        CONFIG_SUBSECTION("Timeouts (all values in seconds)") {
            fprintf(config, "# Number of seconds before timeout "
                "for a connecting node\n%s = %u\n",
                keywords[k_node_connecting_timeout], node_connecting_timeout);
            fprintf(config, "# Number of seconds before timeout "
                "for a connected node\n%s = %u\n",
                keywords[k_node_connected_timeout], node_connected_timeout);
            fprintf(config, "# Maximum seconds node can remain in transmit "
                "flow control\n%s = %u\n",
                keywords[k_node_tx_flowc_timeout], node_tx_flowc_timeout);
        }

        CONFIG_SUBSECTION("TTL settings") {
            CONFIG_WRITE_UINT(max_ttl)
            CONFIG_WRITE_UINT(my_ttl)
            CONFIG_COMMENT("Max hard TTL limit (hop+ttl) on message (min 5)")
            fprintf(config, "%s = %u\n", keywords[k_hard_ttl_limit],
                hard_ttl_limit);

            fprintf(config, "# The following two variables work in concert:\n");
            CONFIG_COMMENT("Amount of tolerable messages above hard TTL limit")
            CONFIG_COMMENT("per node")
            CONFIG_WRITE_UINT(max_high_ttl_msg)

            fprintf(config, "# Hop radius for counting high TTL limit messages "
                "(#hops lower than...)\n%s = %u\n",
                keywords[k_max_high_ttl_radius], max_high_ttl_radius);
        }
    }

    CONFIG_SECTION("Download settings") {
        CONFIG_WRITE_UINT(max_downloads)
        CONFIG_WRITE_UINT(max_host_downloads)
        CONFIG_WRITE_BOOL(clear_downloads)
        CONFIG_WRITE_BOOL(download_delete_aborted)
        fprintf(config, "# Whether or not to send pushes.\n%s = %u\n",
			keywords[k_send_pushes], send_pushes);

        CONFIG_SUBSECTION("File storage") {
            CONFIG_WRITE_STR(save_file_path)
            CONFIG_WRITE_STR(move_file_path)
        }

        CONFIG_SUBSECTION("Resume and retry") {
          	fprintf(config, "# Maximum attempts to make, not counting HTTP busy "
                "indications\n%s = %u\n",
                keywords[k_download_max_retries], download_max_retries);
            fprintf(config, "# Amount of bytes to overlap when resuming download"
                "\n%s = %u\n",
                keywords[k_download_overlap_range], download_overlap_range);
        }

        CONFIG_SUBSECTION("Delays and timeouts (all values in seconds)") {
            CONFIG_COMMENT("Minimum seconds to wait on auto-retry timeouts")
            CONFIG_WRITE_UINT(download_retry_timeout_min)
            
            CONFIG_COMMENT("Maximum seconds to wait on auto-retry timeouts")
            CONFIG_WRITE_UINT(download_retry_timeout_max)

            CONFIG_COMMENT("Delay in seconds to wait after connection failure")
            CONFIG_WRITE_UINT(download_retry_timeout_delay)

            CONFIG_COMMENT("Delay in seconds to wait after HTTP busy indication")
            CONFIG_WRITE_UINT(download_retry_busy_delay)

            CONFIG_COMMENT("Delay in seconds to wait if connection is refused")
            CONFIG_WRITE_UINT(download_retry_refused_delay)

            CONFIG_COMMENT("Delay in seconds to wait when running download stops")
            CONFIG_WRITE_UINT(download_retry_stopped)

            CONFIG_COMMENT("Number of seconds before timeout for a")
            CONFIG_COMMENT("connecting download")
            CONFIG_WRITE_UINT(download_connecting_timeout)

            CONFIG_COMMENT("Number of seconds before timeout for a")
            CONFIG_COMMENT("'push sent' download")
            CONFIG_WRITE_UINT(download_push_sent_timeout)

            CONFIG_COMMENT("Number of seconds before timeout for a")
            CONFIG_COMMENT("connected download")
            CONFIG_WRITE_UINT(download_connected_timeout)
        }
    }

    CONFIG_SECTION("Upload settings") {
        CONFIG_WRITE_BOOL(clear_uploads)
        CONFIG_WRITE_UINT(max_uploads)
        fprintf(config, "# Maximum uploads per IP address\n"
            "%s = %u\n", keywords[k_max_uploads_ip], max_uploads_ip);

		CONFIG_WRITE_BOOL(bw_ul_usage_enabled)
		CONFIG_WRITE_UINT(ul_usage_min_percentage)

        CONFIG_SUBSECTION("Sharing") {
            fprintf(config, "%s = \"%s\"\n", keywords[k_shared_dirs],
                (shared_dirs_paths) ? shared_dirs_paths : "");
            fprintf(config, "%s = \"%s\"\n", keywords[k_scan_extensions],
                (scan_extensions) ? scan_extensions : "");
        }

        CONFIG_SUBSECTION("Timeouts (all values in seconds)") {
            fprintf(config, "# Number of seconds before timeout "
                "for a connecting upload\n%s = %u\n",
                keywords[k_upload_connecting_timeout],
                upload_connecting_timeout);
            fprintf(config, "# Number of seconds before timeout "
                "for a connected upload\n%s = %u\n",
                keywords[k_upload_connected_timeout],
                upload_connected_timeout);
        }
    }

    CONFIG_SECTION("Searches") {
        CONFIG_WRITE_UINT(minimum_speed)
        CONFIG_WRITE_UINT(search_reissue_timeout)
        CONFIG_WRITE_BOOL(search_results_show_tabs)
        CONFIG_WRITE_BOOL(search_remove_downloaded)
        CONFIG_WRITE_BOOL(search_autoselect_ident)
        CONFIG_WRITE_INT(filter_default_policy)
        fprintf(config, "# Whether or not to jump to the "
            "downloads screen when a new download is selected.\n"
			"%s = %u\n", keywords[k_jump_to_downloads],
			jump_to_downloads);  
        fprintf(config, "# Set to 1 to select all same filenames with "
            "greater or equal size\n"
			"%s = %u\n\n", keywords[k_search_pick_all], search_pick_all);


        CONFIG_SUBSECTION("non configurable") {
            fprintf(config, "# Max search results to show "
                "(avoids running out of memory in passive searches)\n%s = %u\n\n",
                keywords[k_search_max_results],
                search_max_results);
        }

        CONFIG_SUBSECTION("Search stats") {
            CONFIG_WRITE_BOOL(search_stats_enabled)
            CONFIG_WRITE_UINT(search_stats_update_interval)
            CONFIG_WRITE_UINT(search_stats_delcoef)
        }

        CONFIG_SUBSECTION("Monitor") {
            CONFIG_WRITE_BOOL(monitor_enabled)
            CONFIG_WRITE_UINT(monitor_max_items)
        }
    }

    CONFIG_SECTION("Debugging (for developers only)") {
        fprintf(config, "# Debug level, each one prints more detail "
            "(between 0 and 20)\n"
			"%s = %u\n\n", keywords[k_dbg], dbg);
        fprintf(config, "# Set to 1 to stop getting new hosts and "
            "stop timeout, manual connect only\n"
			"%s = %u\n\n", keywords[k_stop_host_get], stop_host_get);
        fprintf(config, "# Set to 1 to log network errors for later "
            "inspection, for developer improvements\n"
			"%s = %u\n\n", keywords[k_enable_err_log], enable_err_log);
    }

	/* The following are useful if you want to tweak your node --RAM */
    CONFIG_SECTION("Expert settings") {
        fprintf(config, "# WARNING: *PLEASE* DO NOT MODIFY THE FOLLOWING\n"
            "# VALUES IF YOU DON'T KNOW WHAT YOU'RE DOING\n\n");

        fprintf(config, "# Maximum size of search queries messages "
            "we forward to others (in bytes)\n%s = %u\n\n",
			keywords[k_search_queries_forward_size],
			search_queries_forward_size);
        fprintf(config, "# Maximum size of search queries messages "
            "we allow, otherwise close the\n"
            "# connection (in bytes)\n%s = %u\n\n",
			keywords[k_search_queries_kick_size],
			search_queries_kick_size);
        fprintf(config, "# Maximum size of search answers messages "
            "we forward to others (in bytes)\n%s = %u\n\n",
			keywords[k_search_answers_forward_size],
			search_answers_forward_size);
        fprintf(config, "# Maximum size of search answers messages "
            "we allow, otherwise close the\n"
            "# connection (in bytes)\n%s = %u\n\n",
			keywords[k_search_answers_kick_size],
			search_answers_kick_size);
        fprintf(config, "# Maximum size of unknown messages we allow, "
            "otherwise close the\n"
            "# connection (in bytes)\n%s = %u\n\n",
			keywords[k_other_messages_kick_size],
			other_messages_kick_size);
    }
    
    fprintf(config, "### End of configuration file ###\n");

	/*
	 * Rename saved configuration file on success.
	 */

	if (0 == fclose(config)) {
		if (-1 == rename(newfile, filename))
			g_warning("could not rename %s as %s: %s",
				newfile, filename, g_strerror(errno));
	} else
		g_warning("could not flush %s: %s", newfile, g_strerror(errno));

end:
	g_free(newfile);
}

void config_hostcache_save(void)
{
	/* Save the catched hosts & upload history */

	if (hosts_idle_func) {
		g_warning("exit() while still reading the hosts file, "
			"catched hosts not saved !\n");
	} else {
		g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", config_dir, host_file);
		hosts_write_to_file(cfg_tmp);
	}
}

/*
 * config_upload_stats_save
 *
 * Save upload statistics.
 */
static void config_upload_stats_save(void)
{
	g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", config_dir, ul_stats_file);
	ul_stats_dump_history(cfg_tmp, TRUE);
}

/*
 * config_remove_pidfile
 *
 * Remove pidfile.
 */
static void config_remove_pidfile(void)
{
	g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", config_dir, pidfile);

	if (-1 == unlink(cfg_tmp))
		g_warning("could not remove pidfile \"%s\": %s",
			cfg_tmp, g_strerror(errno));
}

/*
 * config_ip_changed
 *
 * This routine is called when we determined that our IP was no longer the
 * one we computed.  We base this on some headers sent back when we handshake
 * with other nodes, and as a result, cannot trust the information.
 *
 * What we do henceforth is trust 3 successive indication that our IP changed,
 * provided we get the same information each time.
 *
 *		--RAM, 13/01/2002
 */
void config_ip_changed(guint32 new_ip)
{
	static guint32 last_ip_seen = 0;
	static gint same_ip_count = 0;

	g_assert(!force_local_ip);		/* Must be called when IP isn't forced */

	if (new_ip != last_ip_seen) {
		last_ip_seen = new_ip;
		same_ip_count = 1;
		return;
	}

	if (++same_ip_count < 3)
		return;

	last_ip_seen = 0;
	same_ip_count = 0;

	if (new_ip == local_ip)
		return;

	g_warning("Changing local IP to %s", ip_to_gchar(new_ip));

	local_ip = new_ip;
	gui_update_config_port(FALSE);
}

/*
 * config_max_msg_size
 *
 * Maximum message payload size we are configured to handle.
 */
guint32 config_max_msg_size(void)
{
	/*
	 * Today, they are fixed at config time, but they will be set via
	 * GUI tomorrow, so the max size is not fixed in time.
	 *				--RAM, 15/09/2001
	 */

	guint32 maxsize;

	maxsize = MAX(search_queries_kick_size, search_answers_kick_size);
	maxsize = MAX(maxsize, other_messages_kick_size);

	return maxsize;
}

void config_shutdown(void)
{
	config_save();
	config_hostcache_save();
	config_upload_stats_save();
	config_remove_pidfile();
}

void config_close(void)
{
	if (home_dir)
		g_free(home_dir);
	if (config_dir)
		g_free(config_dir);
	if (save_file_path)
		g_free(save_file_path);
	if (move_file_path)
		g_free(move_file_path);
	if (proxy_ip && proxy_ip != static_proxy_ip)
		g_free(proxy_ip);
	if (socks_user && socks_user != socks[SOCKS_USER])
		g_free(socks_user);
	if (socks_pass && socks_pass != socks[SOCKS_PASS])
		g_free(socks_pass);
}

/* vi: set ts=4: */
