
/* gtk-gnutella configuration */

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
#include "autodownload.h"
#include "search_stats.h"
#include "upload_stats.h"

static gchar *config_file = "config";
static gchar *host_file = "hosts";
static gchar *ul_stats_file = "upload_stats";

gboolean clear_uploads = FALSE;
gboolean clear_downloads = FALSE;
gboolean monitor_enabled = FALSE;
gboolean search_remove_downloaded = FALSE;
gboolean force_local_ip = TRUE;
gboolean toolbar_visible = FALSE;
gboolean statusbar_visible = TRUE;
gboolean progressbar_uploads_visible = TRUE;
gboolean progressbar_downloads_visible = TRUE;
gboolean progressbar_connections_visible = TRUE;
gboolean progressbar_bps_in_visible = TRUE;
gboolean progressbar_bps_out_visible = TRUE;
gboolean progressbar_bps_in_avg = FALSE;
gboolean progressbar_bps_out_avg = FALSE;
gboolean use_netmasks = FALSE;
gboolean download_delete_aborted = FALSE;
gboolean queue_regex_case = FALSE;

guint8 max_ttl = 7;
guint8 my_ttl = 5;
guint8 hard_ttl_limit = 15;

guint16 listen_port = 6346;

guint32 up_connections = 4;
guint32 max_connections = 10;
guint32 max_downloads = 10;
guint32 max_host_downloads = 4;
guint32 max_uploads = 5;
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
guint32 output_bandwidth = 0;				/* Output b/w limit (0=none) */
guint32 input_bandwidth = 0;				/* Input b/w limit (0=none) */
guint32 node_connected_timeout = 45;
guint32 node_connecting_timeout = 5;
guint32 node_sendqueue_size = 98304;		/* 150% of max msg size (64K) */
guint32 node_tx_flowc_timeout = 300;
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

gchar *local_netmasks_string = NULL;

gint dbg = 0;					// debug level, for development use
gint stop_host_get = 0;			// stop get new hosts, non activity ok (debug)
gint enable_err_log = 0;		// enable writing to log file for errors
gint search_strict_and = 0;		// search filter for strict AND of results
gint search_pick_all = 1;		// enable picking all files alike in search
gint max_uploads_ip = 2;		// maximum uploads per IP

time_t tab_update_time = 5;

gchar *scan_extensions = NULL;
gchar *save_file_path = NULL;
gchar *move_file_path = NULL;
gchar *shared_dirs_paths = NULL;
gchar *completed_file_path = NULL;
gchar *home_dir = NULL;
gchar *config_dir = NULL;


guint32 nodes_col_widths[] = { 130, 50, 120, 20, 80 };
guint32 dl_active_col_widths[] = { 240, 80, 80, 80 };
guint32 dl_queued_col_widths[] = { 320, 80, 80 };
guint32 uploads_col_widths[] = { 200, 120, 36, 80, 80 };
guint32 search_results_col_widths[] = { 210, 80, 50, 140, 140 };
guint32 search_stats_col_widths[] = { 200, 80, 80 };
guint32 ul_stats_col_widths[] = { 200, 80, 80, 80, 80 };

gboolean jump_to_downloads = TRUE;

gint w_x = 0, w_y = 0, w_w = 0, w_h = 0;

guint32 search_reissue_timeout = 600;	/* 10 minutes */

gboolean proxy_connections = FALSE;
gint proxy_protocol = 4;
static gchar *static_proxy_ip = "0.0.0.0";
gint proxy_port = 1080;
gchar *proxy_ip = NULL;

#define SOCKSV5_USER	0
#define SOCKSV5_PASS	1

gboolean proxy_auth = FALSE;
static gchar *socksv5[] = { "proxyuser", "proxypass" };
gchar *socksv5_user = NULL;
gchar *socksv5_pass = NULL;

enum {
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
	k_node_connected_timeout,
	k_node_connecting_timeout, k_node_sendqueue_size, k_node_tx_flowc_timeout,
	k_search_queries_forward_size,
	k_search_queries_kick_size, k_search_answers_forward_size,
	k_search_answers_kick_size,
	k_other_messages_kick_size, k_save_file_path, k_move_file_path,
	k_win_x, k_win_y, k_win_w, k_win_h, k_win_coords, k_widths_nodes,
	k_widths_uploads,
	k_widths_dl_active, k_widths_dl_queued, k_widths_search_results,
	k_widths_search_stats, k_widths_ul_stats, k_show_results_tabs,
	k_hops_random_factor, k_send_pushes, k_jump_to_downloads,
	k_max_connections, k_proxy_connections,
	k_proxy_protocol, k_proxy_ip, k_proxy_port, k_proxy_auth, k_socksv5_user,
	k_socksv5_pass, k_search_reissue_timeout,
	k_hard_ttl_limit,
	k_dbg, k_stop_host_get, k_enable_err_log, k_max_uploads_ip,
	k_search_strict_and, k_search_pick_all,
	k_max_high_ttl_msg, k_max_high_ttl_radius,
	k_min_dup_msg, k_min_dup_ratio, k_max_hosts_cached,
	k_use_auto_download, k_auto_download_file, 
	k_search_stats_update_interval, k_search_stats_delcoef,
	k_search_stats_enabled,
	k_toolbar_visible, k_statusbar_visible,
	k_progressbar_uploads_visible, k_progressbar_downloads_visible, 
	k_progressbar_connections_visible, 
	k_progressbar_bps_in_visible,
	k_progressbar_bps_out_visible,
	k_progressbar_bps_in_avg,
	k_progressbar_bps_out_avg,
	k_use_netmasks,
	k_local_netmasks,
	k_end
};

static gchar *keywords[] = {
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
	"show_results_tabs",		/* k_show_results_tabs */
	"hops_random_factor",		/* k_hops_random_factor */
	"send_pushes",				/* k_send_pushes */
	"jump_to_downloads",		/* k_jump_to_downloads */
	"max_connections",
	"proxy_connections",
	"proxy_protocol",
	"proxy_ip",
	"proxy_port",
	"proxy_auth",
	"socksv5_user",
	"socksv5_pass",
	"search_reissue_timeout",
	"hard_ttl_limit",			/* k_hard_ttl_limit */
	"dbg",
	"stop_host_get",
	"enable_err_log",
	"max_uploads_ip",
	"search_strict_and",
	"search_pick_all",
	"max_high_ttl_msg",
	"max_high_ttl_radius",
	"min_dup_msg",
	"min_dup_ratio",
	"max_hosts_cached",
	"use_auto_download",
	"auto_download_file",
	"search_stats_update_interval",
	"search_stats_delcoef",
	"search_stats_enabled",
	"toolbar_visible",
	"statusbar_visible",
	"progressbar_uploads_visible",
	"progressbar_downloads_visible",
	"progressbar_connections_visible",
	"progressbar_bps_in_visible",
	"progressbar_bps_out_visible",
	"progressbar_bps_in_avg",
	"progressbar_bps_out_avg",
	"use_netmasks",
	"local_netmasks",
	NULL
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
	gint i;
	struct passwd *pwd = NULL;

	config_dir = g_strdup(getenv("GTK_GNUTELLA_DIR"));
	socksv5_user = socksv5[SOCKSV5_USER];
	socksv5_pass = socksv5[SOCKSV5_PASS];
	proxy_ip = static_proxy_ip;
	memset(guid, 0, sizeof(guid));

	pwd = getpwuid(getuid());

	if (pwd && pwd->pw_dir)
		home_dir = g_strdup(pwd->pw_dir);
	else
		home_dir = g_strdup(getenv("HOME"));

	if (!home_dir)
		g_warning("can't find your home directory!");

	if (config_dir && !is_directory(config_dir)) {
		g_warning("'%s' does not exists or is not a directory!", config_dir);
		g_free(config_dir);
		config_dir = NULL;
	}

	if (!config_dir) {
		if (home_dir) {
			g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/.gtk-gnutella",
					   home_dir);
			config_dir = g_strdup(cfg_tmp);
		} else
			g_warning("no configuration directory: prefs will not be saved!");
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

	/* Okay, update the GUI with values loaded */

	gui_update_count_downloads();
	gui_update_count_uploads();

	gui_update_minimum_speed(minimum_speed);
	gui_update_up_connections();
	gui_update_max_connections();
	gui_update_config_port();
	gui_update_config_force_ip();

	gui_update_save_file_path();
	gui_update_move_file_path();

	gui_update_monitor_max_items();

	gui_update_max_ttl();
	gui_update_my_ttl();

	gui_update_max_downloads();
	gui_update_max_host_downloads();
	gui_update_max_uploads();
    gui_update_max_host_uploads();
	gui_update_files_scanned();

	gui_update_connection_speed();

	gui_update_search_max_items();
	/* PLACEHOLDER: gui_update_search_max_results(); */

	gui_update_search_reissue_timeout();

	gui_update_scan_extensions();
	gui_update_shared_dirs();

	gui_update_search_stats_delcoef();
	gui_update_search_stats_update_interval();

    gui_update_config_netmasks();

	gtk_toggle_button_set_active(
		GTK_TOGGLE_BUTTON(checkbutton_search_stats_enable),
		search_stats_enabled);

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(checkbutton_monitor_enable),
								 monitor_enabled);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_uploads_auto_clear),
								 clear_uploads);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_downloads_auto_clear),
								 clear_downloads);
   	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
							     (checkbutton_downloads_delete_aborted),
							     download_delete_aborted);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_config_force_ip),
								 force_local_ip);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(checkbutton_downloads_never_push),
								 !send_pushes);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_search_jump_to_downloads),
								 jump_to_downloads);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_autodownload),
								 use_autodownload);

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_config_proxy_connections),
								 proxy_connections);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_config_proxy_auth),
								 proxy_auth);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_config_http),
								 (proxy_protocol == 1) ? TRUE : FALSE);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_config_socksv4),
								 (proxy_protocol == 4) ? TRUE : FALSE);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_config_socksv5),
								 (proxy_protocol == 5) ? TRUE : FALSE);

	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_toolbar_visible),
								   toolbar_visible);
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_statusbar_visible),
								   statusbar_visible);
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_uploads_visible),
								   progressbar_uploads_visible);
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_downloads_visible),
								   progressbar_downloads_visible);
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_connections_visible),
								   progressbar_connections_visible);
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_bps_in_visible),
								   progressbar_bps_in_visible);
	gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_bps_out_visible),
								   progressbar_bps_out_visible);

	gui_update_socks_host();
	gui_update_socks_port();
	gui_update_socks_user();
	gui_update_socks_pass();

	gui_update_bandwidth_input();
	gui_update_bandwidth_output();

	if (w_w && w_h) {
		gtk_widget_set_uposition(main_window, w_x, w_y);
		gtk_window_set_default_size(GTK_WINDOW(main_window), w_w, w_h);
	}

	for (i = 0; i < 5; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_nodes), i,
								   nodes_col_widths[i]);
	for (i = 0; i < 4; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_downloads), i,
								   dl_active_col_widths[i]);
	for (i = 0; i < 3; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_downloads_queue), i,
								   dl_queued_col_widths[i]);
	for (i = 0; i < 5; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_uploads), i,
								   uploads_col_widths[i]);

	// as soon as this is corrected in Glade, you can do this
	// check the variable names and take out the stuff in
	// search.c that sets this up
	// for (i = 0; i < 5; i++)
	//    gtk_clist_set_column_width(GTK_CLIST(clist_search_results),
	//         i, search_results_col_widths[i]);

	for (i = 0; i < 3; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_search_stats), i,
								   search_stats_col_widths[i]);
	for (i = 0; i < 5; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_ul_stats), i,
								   ul_stats_col_widths[i]);

	/* Transition : HOME/.gtk-gnutella is now a directory */

	if (config_dir && !is_directory(config_dir)) {
		if (unlink(config_dir) == -1) {
			if (errno != ENOENT) {
				g_warning("unlink(%s) failed (%s) !\n", config_dir,
						  g_strerror(errno));
				g_free(config_dir);
				config_dir = NULL;
				return;
			}
		} else {
			/* We are replacing the old config file by a directory. */
			fprintf(stdout, "Creating configuration directory '%s'\n",
					config_dir);
		}

		if (mkdir(config_dir, 0755) == -1) {
			g_warning("mkdir(%s) failed (%s) !\n\n", config_dir,
					  g_strerror(errno));
			g_free(config_dir);
			config_dir = NULL;
			return;
		}
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

void config_set_param(guint32 keyword, gchar *value)
{
	gint32 i = atol(value);
	guint32 *a;

	switch (keyword) {
	case k_monitor_enabled:
		monitor_enabled = (gboolean) ! g_strcasecmp(value, "true");
		return;

	case k_monitor_max_items:
		if (i > 0 && i < 512) monitor_max_items = i;
		return;

	case k_clear_uploads:
		clear_uploads = (gboolean) ! g_strcasecmp(value, "true");
		return;

	case k_clear_downloads:
		clear_downloads = (gboolean) ! g_strcasecmp(value, "true");
		return;

    case k_download_delete_aborted:
        download_delete_aborted = (gboolean) ! g_strcasecmp(value, "true");
		return;

	case k_up_connections:
		if (i >= 0 && i < 512) up_connections = i;
		return;

	case k_max_downloads:
		if (i > 0 && i < 512) max_downloads = i;
		return;

	case k_max_host_downloads:
		if (i > 0 && i < 512) max_host_downloads = i;
		return;

	case k_max_uploads:
		if (i >= 0 && i < 512) max_uploads = i;
		return;

	case k_minimum_speed:
		minimum_speed = atol(value);
		return;

	case k_listen_port:
		listen_port = atoi(value);
		return;

	case k_hard_ttl_limit:
		if (i >= 5 && i < 255) hard_ttl_limit = i;
		return;

	case k_max_ttl:
		if (i > 0 && i < 255) max_ttl = i;
		return;

	case k_my_ttl:
		if (i > 0 && i < 255) my_ttl = i;
		return;

	case k_search_max_items:
		if (i >= -1 && i < 256) search_max_items = i;
		return;

	case k_search_max_results:
		if (i > 0) search_max_results = i;
		return;

	case k_connection_speed:
		if (i > 0 && i < 65535) connection_speed = i;
		return;

	case k_local_ip:
		local_ip = gchar_to_ip(value);
		return;

	case k_force_local_ip:
		force_local_ip = (gboolean) ! g_strcasecmp(value, "true");
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

	case k_node_sendqueue_size:
		if (i > 4096 && i < 1048576) node_sendqueue_size = i;
		return;

	case k_node_tx_flowc_timeout:
		node_tx_flowc_timeout = i;
		return;

	case k_node_connecting_timeout:
		if (i > 1 && i < 3600) node_connecting_timeout = i;
		return;

	case k_node_connected_timeout:
		if (i > 1 && i < 3600) node_connected_timeout = i;
		return;

	case k_download_connecting_timeout:
		if (i > 1 && i < 3600) download_connecting_timeout = i;
		return;

	case k_download_push_sent_timeout:
		if (i > 1 && i < 3600) download_push_sent_timeout = i;
		return;

	case k_download_connected_timeout:
		if (i > 1 && i < 3600) download_connected_timeout = i;
		return;

	case k_download_retry_timeout_min:
		if (i >= 0) download_retry_timeout_min = i;
		return;

	case k_download_retry_timeout_max:
		if (i >= 0) download_retry_timeout_max = i;
		return;

	case k_download_retry_timeout_delay:
		if (i >= 0) download_retry_timeout_delay = i;
		return;

	case k_download_retry_busy_delay:
		if (i >= 0) download_retry_busy_delay = i;
		return;

	case k_download_max_retries:
		if (i >= 0) download_max_retries = i;
		return;

	case k_download_overlap_range:
		if (i >= 0) download_overlap_range = i;
		return;

	case k_download_retry_refused_delay:
		if (i >= 0) download_retry_refused_delay = i;
		return;

	case k_download_retry_stopped:
		if (i >= 0) download_retry_stopped = i;
		return;

	case k_upload_connecting_timeout:
		if (i > 1 && i < 3600) upload_connecting_timeout = i;
		return;

	case k_upload_connected_timeout:
		if (i > 1 && i < 3600) upload_connected_timeout = i;
		return;

	case k_output_bandwidth:
		/* Limited to 2 MB/s since we multiply by 1000 in an unsigned 32-bit */
		if (i >= 0 && i < BS_BW_MAX) output_bandwidth = i;
		return;

	case k_input_bandwidth:
		/* Limited to 2 MB/s since we multiply by 1000 in an unsigned 32-bit */
		if (i >= 0 && i < BS_BW_MAX) input_bandwidth = i;
		return;

	case k_search_queries_forward_size:
		if (i > 64 && i < 65535) search_queries_forward_size = i;
		return;

	case k_search_queries_kick_size:
		if (i > 512 && i < 65535) search_queries_kick_size = i;
		return;

	case k_search_answers_forward_size:
		if (i > 512 && i < 1048576) search_answers_forward_size = i;
		return;

	case k_search_answers_kick_size:
		if (i > 512 && i < 1048576) search_answers_kick_size = i;
		return;

	case k_other_messages_kick_size:
		if (i > 0 && i < 1048576) other_messages_kick_size = i;
		return;

	case k_win_x:
		w_x = i;
		return;

	case k_win_y:
		w_y = i;
		return;

	case k_win_w:
		w_w = i;
		return;

	case k_win_h:
		w_h = i;
		return;
	case k_win_coords:
		if ((a = config_parse_array(value, 4))) {
			w_x = a[0];
			w_y = a[1];
			w_w = a[2];
			w_h = a[3];
		}
		return;

	case k_widths_nodes:
		if ((a = config_parse_array(value, 5)))
			for (i = 0; i < 5; i++)
				nodes_col_widths[i] = a[i];
		return;

	case k_widths_uploads:
		if ((a = config_parse_array(value, 5)))
			for (i = 0; i < 5; i++)
				uploads_col_widths[i] = a[i];
		return;

	case k_widths_dl_active:
		if ((a = config_parse_array(value, 4)))
			for (i = 0; i < 4; i++)
				dl_active_col_widths[i] = a[i];
		return;

	case k_widths_dl_queued:
		if ((a = config_parse_array(value, 3)))
			for (i = 0; i < 3; i++)
				dl_queued_col_widths[i] = a[i];
		return;

	case k_widths_search_results:
		if ((a = config_parse_array(value, 5)))
			for (i = 0; i < 5; i++)
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

	case k_show_results_tabs:
		search_results_show_tabs =
			(gboolean) ! g_strcasecmp(value, "true");
		return;

	case k_forced_local_ip:
		forced_local_ip = gchar_to_ip(value);
		return;

	case k_hops_random_factor:
		if (i >= 0 && i <= 3)
			hops_random_factor = i;
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

	case k_proxy_ip:
		proxy_ip = g_strdup(value);
		return;

	case k_proxy_port:
		proxy_port = i;
		return;

	case k_proxy_auth:
		proxy_auth = (gboolean) ! g_strcasecmp(value, "true");
		return;

	case k_socksv5_user:
		socksv5_user = g_strdup(value);
		return;

	case k_socksv5_pass:
		socksv5_pass = g_strdup(value);
		return;

	case k_max_connections:
		if (i >= 0 && i < 512) max_connections = i;
		return;

	case k_search_reissue_timeout:
		search_reissue_timeout = i;
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

	case k_max_uploads_ip:
		if (i >= 0 && i < 512)
			max_uploads_ip = i;
		return;

	case k_search_strict_and:
		search_strict_and = i;
		return;

	case k_search_pick_all:
		search_pick_all = i;
		return;

	case k_max_high_ttl_msg:
		max_high_ttl_msg = i;
		return;

	case k_max_high_ttl_radius:
		max_high_ttl_radius = i;
		return;

	case k_min_dup_msg:
		min_dup_msg = i;
		return;

	case k_min_dup_ratio:
		min_dup_ratio = atof(value);
		if (min_dup_ratio < 0.0)   min_dup_ratio = 0.0;
		if (min_dup_ratio > 100.0) min_dup_ratio = 100.0;
		return;

	case k_max_hosts_cached:
		if (i >= 100) max_hosts_cached = i;
		return;

	case k_use_auto_download:
		use_autodownload = i ? TRUE : FALSE;
		return;

	case k_auto_download_file:
		auto_download_file = g_strdup(value);
		return;

	case k_search_stats_enabled:
		search_stats_enabled = (gboolean) ! g_strcasecmp(value, "true");
		return;

	case k_search_stats_delcoef:
		if (i >= 0 && i <= 100)
			search_stats_delcoef = i;
		return;

	case k_search_stats_update_interval:
		if (i >= 0 && i <= 50000)
			search_stats_update_interval = i;
		return;

	case k_toolbar_visible:
		toolbar_visible = (gboolean) ! g_strcasecmp(value, "true");
		return;

	case k_statusbar_visible:
		statusbar_visible = (gboolean) ! g_strcasecmp(value, "true");
		return;

	case k_progressbar_uploads_visible:
		progressbar_uploads_visible = (gboolean) ! g_strcasecmp(value, "true");
		return;

	case k_progressbar_downloads_visible:
		progressbar_downloads_visible =
			(gboolean) ! g_strcasecmp(value, "true");
		return;

	case k_progressbar_connections_visible:
		progressbar_connections_visible =
			(gboolean) ! g_strcasecmp(value, "true");
		return;

	case k_progressbar_bps_in_visible:
		progressbar_bps_in_visible = (gboolean) ! g_strcasecmp(value, "true");
		return;

	case k_progressbar_bps_out_visible:
		progressbar_bps_out_visible = (gboolean) ! g_strcasecmp(value, "true");
 		return;

	case k_progressbar_bps_in_avg:
		progressbar_bps_in_avg = (gboolean) ! g_strcasecmp(value, "true");
		return;

	case k_progressbar_bps_out_avg:
		progressbar_bps_out_avg = (gboolean) ! g_strcasecmp(value, "true");
		return;

 	case k_local_netmasks:
 		local_netmasks_string = g_strdup(value);
 		parse_netmasks(value);
 		return;
 
 	case k_use_netmasks:
 		use_netmasks = (gboolean)!(g_strcasecmp(value, "true"));
 		return;
	}
}

static void config_read(void)
{
	FILE *config;
	gchar *s, *k, *v;
	guint32 i, n = 0;
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
	fprintf(config, "# This is Gtk-Gnutella configuration file - "
		"you may edit it if you're careful.\n");
	fprintf(config, "# (only when the program is not running: "
		"this file is saved on quit)\n#\n\n");
	fprintf(config, "%s = %u\n", keywords[k_up_connections], up_connections);
	fprintf(config, "\n");
	fprintf(config, "%s = %u\n", keywords[k_max_connections], max_connections);
	fprintf(config, "\n");
	fprintf(config, "%s = %s\n", keywords[k_clear_uploads],
			config_boolean(clear_uploads));
	fprintf(config, "\n");
	fprintf(config, "%s = %u\n", keywords[k_max_downloads], max_downloads);
	fprintf(config, "\n");
	fprintf(config, "%s = %u\n", keywords[k_max_host_downloads],
			max_host_downloads);
	fprintf(config, "\n");
	fprintf(config, "%s = %u\n", keywords[k_max_uploads], max_uploads);
	fprintf(config, "\n");
	fprintf(config, "%s = %s\n", keywords[k_clear_downloads],
			config_boolean(clear_downloads));
   	fprintf(config, "%s = %s\n", keywords[k_download_delete_aborted],
			config_boolean(download_delete_aborted));
	fprintf(config, "\n");
	fprintf(config, "%s = %u\n", keywords[k_minimum_speed], minimum_speed);
	fprintf(config, "\n");
	fprintf(config, "%s = %s\n", keywords[k_monitor_enabled],
			config_boolean(monitor_enabled));
	fprintf(config, "%s = %u\n", keywords[k_monitor_max_items],
			monitor_max_items);
	fprintf(config, "\n");
	fprintf(config, "%s = \"%s\"\n", keywords[k_save_file_path],
			save_file_path);
	fprintf(config, "%s = \"%s\"\n", keywords[k_move_file_path],
			move_file_path);
	fprintf(config, "\n");
	fprintf(config, "%s = \"%s\"\n", keywords[k_shared_dirs],
			(shared_dirs_paths) ? shared_dirs_paths : "");
	fprintf(config, "%s = \"%s\"\n", keywords[k_scan_extensions],
			(scan_extensions) ? scan_extensions : "");
	fprintf(config, "\n");
	fprintf(config, "%s = \"%s\"\n", keywords[k_local_ip],
			ip_to_gchar(local_ip));
	fprintf(config, "%s = %s\n", keywords[k_force_local_ip],
			config_boolean(force_local_ip));
	fprintf(config, "%s = \"%s\"\n", keywords[k_forced_local_ip],
			ip_to_gchar(forced_local_ip));
	fprintf(config, "%s = %u\n", keywords[k_listen_port], listen_port);
	fprintf(config, "%s = \"%s\"\n", keywords[k_guid], guid_hex_str(guid));
	fprintf(config, "\n");
	fprintf(config, "%s = %u\n", keywords[k_connection_speed],
			connection_speed);
	fprintf(config, "\n");
	fprintf(config, "%s = %d\n", keywords[k_search_max_items],
			search_max_items);
	fprintf(config, "\n");
	fprintf(config, "%s = %u\n", keywords[k_max_ttl], max_ttl);
	fprintf(config, "%s = %u\n\n", keywords[k_my_ttl], my_ttl);
	fprintf(config, "%s = %u\n\n", keywords[k_search_reissue_timeout],
			search_reissue_timeout);

	fprintf(config, "%s = %s\n", keywords[k_show_results_tabs],
			config_boolean(search_results_show_tabs));

	fprintf(config, "\n\n# GUI values\n\n");

	fprintf(config, "%s = %u,%u,%u,%u\n\n", keywords[k_win_coords], win_x,
			win_y, win_w, win_h);

	fprintf(config, "%s = %u,%u,%u,%u,%u\n", keywords[k_widths_nodes],
			nodes_col_widths[0], nodes_col_widths[1],
			nodes_col_widths[2], nodes_col_widths[3], nodes_col_widths[4]);
	fprintf(config, "%s = %u,%u,%u,%u,%u\n", keywords[k_widths_uploads],
			uploads_col_widths[0], uploads_col_widths[1],
			uploads_col_widths[2], uploads_col_widths[3],
			uploads_col_widths[4]);
	fprintf(config, "%s = %u,%u,%u,%u\n", keywords[k_widths_dl_active],
			dl_active_col_widths[0], dl_active_col_widths[1],
			dl_active_col_widths[2], dl_active_col_widths[3]);
	fprintf(config, "%s = %u,%u,%u\n", keywords[k_widths_dl_queued],
			dl_queued_col_widths[0], dl_queued_col_widths[1],
		dl_queued_col_widths[2]);
	fprintf(config, "%s = %u,%u,%u,%u,%u\n",
			keywords[k_widths_search_results],
			search_results_col_widths[0], search_results_col_widths[1],
			search_results_col_widths[2], search_results_col_widths[3],
			search_results_col_widths[4]);
	fprintf(config, "%s = %u,%u,%u\n",
			keywords[k_widths_search_stats],
			search_stats_col_widths[0], search_stats_col_widths[1],
			search_stats_col_widths[2]);
	fprintf(config, "%s = %u,%u,%u,%u,%u\n",
			keywords[k_widths_ul_stats],
			ul_stats_col_widths[0], ul_stats_col_widths[1],
			ul_stats_col_widths[2], ul_stats_col_widths[3],
				ul_stats_col_widths[4]);
	fprintf(config, "%s = %s\n", keywords[k_toolbar_visible],
			config_boolean(toolbar_visible));
	fprintf(config, "%s = %s\n", keywords[k_statusbar_visible],
			config_boolean(statusbar_visible));
	fprintf(config, "%s = %s\n", keywords[k_progressbar_uploads_visible],
			config_boolean(progressbar_uploads_visible));
	fprintf(config, "%s = %s\n", keywords[k_progressbar_downloads_visible],
			config_boolean(progressbar_downloads_visible));
	fprintf(config, "%s = %s\n", keywords[k_progressbar_connections_visible],
			config_boolean(progressbar_connections_visible));
	fprintf(config, "%s = %s\n", keywords[k_progressbar_bps_in_visible],
			config_boolean(progressbar_bps_in_visible));
	fprintf(config, "%s = %s\n", keywords[k_progressbar_bps_out_visible],
			config_boolean(progressbar_bps_out_visible));
	fprintf(config, "%s = %s\n", keywords[k_progressbar_bps_in_avg],
			config_boolean(progressbar_bps_in_avg));
	fprintf(config, "%s = %s\n", keywords[k_progressbar_bps_out_avg],
			config_boolean(progressbar_bps_out_avg));

 	/* Mike Perry's netmask hack */
 	fprintf(config, "%s = %s\n", keywords[k_use_netmasks],
 			config_boolean(use_netmasks));
 
 	if (local_netmasks_string)
 		fprintf(config, "%s = %s\n", keywords[k_local_netmasks],
 				local_netmasks_string);

	fprintf(config, "\n\n#\n# The following variables cannot "
		"yet be configured with the GUI.\n#\n\n");

	/* XXX Bandwidth management must be GUI-configurable */

	fprintf(config, "# Output bandwidth, in bytes/sec (Gnet excluded) "
		"[0=nolimit, max=2 MB/s]\n"
		"%s = %u\n\n", keywords[k_output_bandwidth], output_bandwidth);

	fprintf(config, "# Input bandwidth, in bytes/sec (Gnet excluded) "
		"[0=nolimit, max=2 MB/s]\n"
		"%s = %u\n\n", keywords[k_input_bandwidth], input_bandwidth);

	fprintf(config, "# Name of file with auto-download strings "
		"(relative is taken from launch dir)\n%s = \"%s\"\n\n",
			keywords[k_auto_download_file],
			auto_download_file);

	fprintf(config, "# Max search results to show "
		"(avoids running out of memory in passive searches)\n%s = %u\n\n",
			keywords[k_search_max_results],
			search_max_results);

	fprintf(config, "# Number of seconds before timeout "
		"for a connecting download\n%s = %u\n\n",
			keywords[k_download_connecting_timeout],
			download_connecting_timeout);
	fprintf(config, "# Number of seconds before timeout "
		"for a 'push sent' download\n%s = %u\n\n",
			keywords[k_download_push_sent_timeout],
			download_push_sent_timeout);
	fprintf(config, "# Number of seconds before timeout "
		"for a connected download\n%s = %u\n\n",
			keywords[k_download_connected_timeout],
			download_connected_timeout);
	fprintf(config, "# Number of seconds before timeout "
		"for a connecting upload\n%s = %u\n\n",
			keywords[k_upload_connecting_timeout],
			upload_connecting_timeout);
	fprintf(config, "# Number of seconds before timeout "
		"for a connected upload\n%s = %u\n\n",
			keywords[k_upload_connected_timeout],
			upload_connected_timeout);
	fprintf(config, "# Number of seconds before timeout "
		"for a connecting node\n%s = %u\n\n",
			keywords[k_node_connecting_timeout], node_connecting_timeout);
	fprintf(config, "# Number of seconds before timeout "
		"for a connected node\n%s = %u\n\n",
			keywords[k_node_connected_timeout], node_connected_timeout);
	fprintf(config, "# Maximum seconds node can remain in transmit "
		"flow control\n%s = %u\n\n",
			keywords[k_node_tx_flowc_timeout], node_tx_flowc_timeout);

	fprintf(config, "# Minimum seconds to wait on auto-retry timeouts"
		"\n%s = %u\n\n",
		keywords[k_download_retry_timeout_min], download_retry_timeout_min);
	fprintf(config, "# Maximum seconds to wait on auto-retry timeouts"
		"\n%s = %u\n\n",
		keywords[k_download_retry_timeout_max], download_retry_timeout_max);
	fprintf(config, "# Delay in seconds to wait after connection failure"
		"\n%s = %u\n\n",
		keywords[k_download_retry_timeout_delay], download_retry_timeout_delay);
	fprintf(config, "# Delay in seconds to wait after HTTP busy indication"
		"\n%s = %u\n\n",
		keywords[k_download_retry_busy_delay], download_retry_busy_delay);
	fprintf(config, "# Delay in seconds to wait if connection is refused "
		"\n%s = %u\n\n",
		keywords[k_download_retry_refused_delay], download_retry_refused_delay);
	fprintf(config, "# Delay in seconds to wait when running download stops"
		"\n%s = %u\n\n",
		keywords[k_download_retry_stopped], download_retry_stopped);
	fprintf(config, "# Maximum attempts to make, not counting HTTP busy "
		"indications\n%s = %u\n\n",
		keywords[k_download_max_retries], download_max_retries);
	fprintf(config, "# Amount of bytes to overlap when resuming download"
		"\n%s = %u\n\n",
		keywords[k_download_overlap_range], download_overlap_range);

	fprintf(config, "# Max hard TTL limit (hop+ttl) on message (minimum 5)\n");
	fprintf(config, "%s = %u\n\n", keywords[k_hard_ttl_limit],
			hard_ttl_limit);

	fprintf(config, "# The following two variables work in concert:\n");
	fprintf(config, "# Amount of tolerable messages above hard TTL limit "
		"per node\n%s = %u\n",
			keywords[k_max_high_ttl_msg], max_high_ttl_msg);
	fprintf(config, "# Hop radius for counting high TTL limit messages "
		"(#hops lower than...)\n%s = %u\n\n",
			keywords[k_max_high_ttl_radius], max_high_ttl_radius);

	fprintf(config, "# The following two variables work in concert:\n");
	fprintf(config, "# Minimum amount of dup messages to enable kicking, "
		"per node\n%s = %u\n",
			keywords[k_min_dup_msg], min_dup_msg);
	fprintf(config, "# Minimum ratio of dups on received messages, "
		"per node (between 0.0 and 100.0)\n%s = %.2f\n\n",
			keywords[k_min_dup_ratio], min_dup_ratio);

	fprintf(config, "# Maximum amount of hosts to keep in cache "
		"(minimum 100)\n%s = %u\n\n",
			keywords[k_max_hosts_cached], max_hosts_cached);

	fprintf(config, "# Maximum size of the sendqueue for the nodes (in bytes)\n"
		"# Must be at least 150%% of max message size (currently %u bytes),\n"
		"# which means minimal allowed value is %u bytes.\n"
		"%s = %u\n\n",
			config_max_msg_size(), (guint32) (1.5 * config_max_msg_size()),
			keywords[k_node_sendqueue_size], node_sendqueue_size);

	fprintf(config, "# Random factor for the hops field "
		"in search packets we send (between 0 and 3 inclusive)\n%s = %u\n\n",
			keywords[k_hops_random_factor], hops_random_factor);

	fprintf(config, "\n");
	fprintf(config, "# Whether or not to send pushes.\n%s = %u\n\n",
			keywords[k_send_pushes], send_pushes);

	fprintf(config, "# Whether or not to jump to the "
		"downloads screen when a new download is selected.\n"
			"%s = %u\n\n", keywords[k_jump_to_downloads],
			jump_to_downloads);

	fprintf(config, "# Whether auto downloading should be enabled.\n"
			"%s = %u\n\n", keywords[k_use_auto_download],
			use_autodownload);

	fprintf(config, "# Maximum uploads per IP address\n"
			"%s = %u\n\n", keywords[k_max_uploads_ip], max_uploads_ip);

	fprintf(config,
			"# Set to 1 to filter search results with a strict AND\n"
			"%s = %u\n\n", keywords[k_search_strict_and],
			search_strict_and);
	fprintf(config, "# Set to 1 to select all same filenames with "
		"greater or equal size\n"
			"%s = %u\n\n", keywords[k_search_pick_all], search_pick_all);

	fprintf(config, "# Proxy Info\n");
	fprintf(config, "%s = %u\n", keywords[k_proxy_connections],
			proxy_connections);
	fprintf(config, "%s = %u\n", keywords[k_proxy_protocol], proxy_protocol);
	fprintf(config, "%s = \"%s\"\n", keywords[k_proxy_ip], proxy_ip);
	fprintf(config, "%s = %u\n", keywords[k_proxy_port], proxy_port);
	fprintf(config, "%s = %s\n", keywords[k_proxy_auth],
			config_boolean(proxy_auth));
	fprintf(config, "%s = \"%s\"\n", keywords[k_socksv5_user], socksv5_user);
	fprintf(config, "%s = \"%s\"\n", keywords[k_socksv5_pass], socksv5_pass);
	fprintf(config, "\n");

	fprintf(config, "# For developers only, debugging stuff\n\n");
	fprintf(config, "# Debug level, each one prints more detail "
		"(between 0 and 20)\n"
			"%s = %u\n\n", keywords[k_dbg], dbg);
	fprintf(config, "# Set to 1 to stop getting new hosts and "
		"stop timeout, manual connect only\n"
			"%s = %u\n\n", keywords[k_stop_host_get], stop_host_get);
	fprintf(config, "# Set to 1 to log network errors for later "
		"inspection, for developer improvements\n"
			"%s = %u\n\n", keywords[k_enable_err_log], enable_err_log);

	fprintf(config, "# Search stats gathering parameters\n");
	fprintf(config, "%s = %s\n", keywords[k_search_stats_enabled],
			config_boolean(search_stats_enabled));
	fprintf(config, "%s = %u\n", keywords[k_search_stats_update_interval],
		search_stats_update_interval);
	fprintf(config, "%s = %u\n", keywords[k_search_stats_delcoef],
		search_stats_delcoef);
	fprintf(config, "\n");

	/* The following are useful if you want to tweak your node --RAM */

	fprintf(config, "#\n# WARNING: *PLEASE* DO NOT MODIFY THE FOLLOWING\n"
		"# VALUES IF YOU DON'T KNOW WHAT YOU'RE DOING\n#\n\n");

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
	gui_update_config_port();
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
	if (socksv5_user && socksv5_user != socksv5[SOCKSV5_USER])
		g_free(socksv5_user);
	if (socksv5_pass && socksv5_pass != socksv5[SOCKSV5_PASS])
		g_free(socksv5_pass);
}

/* vi: set ts=4: */
