
/* gtk-gnutella configuration */

#include <sys/stat.h>
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

static gchar *config_file = "config";
static gchar *host_file = "hosts";

gboolean clear_uploads = FALSE;
gboolean clear_downloads = FALSE;
gboolean monitor_enabled = FALSE;
gboolean force_local_ip = FALSE;

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
guint32 download_connecting_timeout = 30;
guint32 download_push_sent_timeout = 60;
guint32 download_connected_timeout = 60;
guint32 download_retry_timeout_min = 20;
guint32 download_retry_timeout_max = 120;
guint32 download_max_retries = 5;
guint32 upload_connecting_timeout = 60;		/* Receiving headers */
guint32 upload_connected_timeout = 180;		/* Sending data */
guint32 node_connected_timeout = 45;
guint32 node_connecting_timeout = 5;
guint32 node_sendqueue_size = 20480;	/* was 10240 */
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


guint32 nodes_col_widths[] = { 140, 80, 80 };
guint32 dl_active_col_widths[] = { 240, 80, 80, 80 };
guint32 dl_queued_col_widths[] = { 320, 80, 80 };
guint32 uploads_col_widths[] = { 200, 140, 80 };
guint32 search_results_col_widths[] = { 210, 80, 50, 140, 140 };

gboolean jump_to_downloads = TRUE;

gint w_x = 0, w_y = 0, w_w = 0, w_h = 0;

guint32 search_reissue_timeout = 600;	/* 10 minutes */

gboolean proxy_connections = FALSE;
gint socks_protocol = 4;
gchar *proxy_ip = "0.0.0.0";
gint proxy_port = 1080;

#define SOCKSV5_USER	0
#define SOCKSV5_PASS	1

static gchar *socksv5[] = { "proxyuser", "proxypass" };
gchar *socksv5_user = NULL;
gchar *socksv5_pass = NULL;

enum {
	k_up_connections = 0,
	k_clear_uploads, k_max_downloads, k_max_host_downloads,
	k_max_uploads, k_clear_downloads,
	k_minimum_speed, k_monitor_enabled, k_monitor_max_items,
	k_old_save_file_path, k_scan_extensions,
	k_listen_port, k_max_ttl, k_my_ttl, k_shared_dirs, k_forced_local_ip,
	k_connection_speed,
	k_search_max_items, k_search_max_results,
	k_force_local_ip, k_hosts_catched,
	k_download_connecting_timeout,
	k_download_push_sent_timeout, k_download_connected_timeout,
	k_upload_connecting_timeout, k_upload_connected_timeout,
	k_node_connected_timeout,
	k_node_connecting_timeout, k_node_sendqueue_size,
	k_search_queries_forward_size,
	k_search_queries_kick_size, k_search_answers_forward_size,
	k_search_answers_kick_size,
	k_other_messages_kick_size, k_save_file_path, k_move_file_path,
	k_win_x, k_win_y, k_win_w, k_win_h, k_win_coords, k_widths_nodes,
	k_widths_uploads,
	k_widths_dl_active, k_widths_dl_queued, k_widths_search_results,
	k_show_results_tabs,
	k_hops_random_factor, k_send_pushes, k_jump_to_downloads,
	k_max_connections, k_proxy_connections,
	k_socks_protocol, k_proxy_ip, k_proxy_port, k_socksv5_user,
	k_socksv5_pass, k_search_reissue_timeout,
	k_hard_ttl_limit,
	k_dbg, k_stop_host_get, k_enable_err_log, k_max_uploads_ip,
	k_search_strict_and, k_search_pick_all,
	k_max_high_ttl_msg, k_max_high_ttl_radius,
	k_min_dup_msg, k_min_dup_ratio, k_max_hosts_cached,
	k_use_auto_download, k_auto_download_file,
	k_end
};

gchar *keywords[] = {
	"up_connections",			/* k_up_connections */
	"auto_clear_completed_uploads",		/* k_clear_uploads */
	"max_simultaneous_downloads",		/* k_max_downloads */
	"max_simultaneous_host_downloads",	/* k_max_host_downloads */
	"max_simultaneous_uploads", /* k_max_uploads */
	"auto_clear_completed_downloads",	/* k_clear_downloads */
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
	"force_local_ip",			/* k_force_local_ip */
	"hc",						/* k_hosts_catched */
	"download_connecting_timeout",		/* k_download_connecting_timeout */
	"download_push_sent_timeout",		/* k_download_push_sent_timeout */
	"download_connected_timeout",		/* k_download_connected_timeout */
	"upload_connecting_timeout",		/* k_upload_connecting_timeout */
	"upload_connected_timeout",			/* k_upload_connected_timeout */
	"node_connected_timeout",	/* k_node_connected_timeout */
	"node_connecting_timeout",	/* k_node_connecting_timeout */
	"node_sendqueue_size",		/* k_node_sendqueue_size */
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
	"widths_nodes",				/* k_width_nodes */
	"widths_uploads",			/* k_width_uploads */
	"widths_dl_active",			/* k_width_dl_active */
	"widths_dl_queued",			/* k_width_dl_queued */
	"widths_search_results",	/* k_widths_search_results */
	"show_results_tabs",		/* k_show_results_tabs */
	"hops_random_factor",		/* k_hops_random_factor */
	"send_pushes",				/* k_send_pushes */
	"jump_to_downloads",		/* k_jump_to_downloads */
	"max_connections",
	"proxy_connections",
	"socks_protocol",
	"proxy_ip",
	"proxy_port",
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
	NULL
};

gchar cfg_tmp[4096];
gboolean cfg_use_local_file = FALSE;	// use config file in same dir

void config_read(void);

/* ----------------------------------------- */

void config_init(void)
{
	gint i;
	struct passwd *pwd = NULL;

	config_dir = g_strdup(getenv("GTK_GNUTELLA_DIR"));
	socksv5_user = socksv5[SOCKSV5_USER];
	socksv5_pass = socksv5[SOCKSV5_PASS];

	pwd = getpwuid(getuid());

	if (pwd && pwd->pw_dir)
		home_dir = g_strdup(pwd->pw_dir);
	else
		home_dir = g_strdup(getenv("HOME"));

	if (!home_dir)
		fprintf(stderr,
				"\nWARNING - Can't find your home directory !\n\n");

	if (config_dir && !is_directory(config_dir)) {
		fprintf(stderr,
				"\nWARNING - '%s' does not exists or is not a directory !\n\n",
				config_dir);
		g_free(config_dir);
		config_dir = NULL;
	}

	if (!config_dir) {
		if (home_dir) {
			g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/.gtk-gnutella",
					   home_dir);
			config_dir = g_strdup(cfg_tmp);
		} else
			fprintf(stderr, "\nWARNING - No configuration directory: "
				"Prefs will not be saved !\n\n");
	}

	if (config_dir) {
		/* Parse the configuration */

		config_read();

		/* Loads the catched hosts */

		if (cfg_use_local_file)
			hosts_read_from_file(host_file, TRUE);
		else {
			g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", config_dir,
					   host_file);
			hosts_read_from_file(cfg_tmp, TRUE);
		}
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
		parse_extensions
			("mp3;mp2;mp1;vqf;avi;mpg;mpeg;wav;mod;voc;it;xm;s3m;"
			 "stm;wma;mov;asf;zip;rar;txt;jpg;pdf");

	if (!scan_extensions)
		scan_extensions = g_strdup(
			"mp3;mp2;mp1;vqf;avi;mpg;mpeg;wav;mod;voc;"
			"it;xm;s3m;stm;wma;mov;asf;zip;rar");
	/* watch for filter_file defaults */

	/* XXX -- Why is this disabled? -- RAM */
	if (0 && !local_ip) {		/* We need our local address */
		char hostname[255];
		struct hostent *hostinfo;
		gethostname(hostname, 255);
		hostinfo = gethostbyname(hostname);
		local_ip =
			g_ntohl(((struct in_addr *) (hostinfo->h_addr))->s_addr);
	}

	if (hard_ttl_limit < max_ttl)
		hard_ttl_limit = max_ttl;

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
	gui_update_files_scanned();

	gui_update_connection_speed();

	gui_update_search_max_items();
	/* PLACEHOLDER: gui_update_search_max_results(); */

	gui_update_search_reissue_timeout();

	gui_update_scan_extensions();
	gui_update_shared_dirs();

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(checkbutton_monitor),
								 monitor_enabled);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_clear_uploads),
								 clear_uploads);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_clear_downloads),
								 clear_downloads);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_config_force_ip),
								 force_local_ip);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(checkbutton_never_push),
								 !send_pushes);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_jump_to_downloads),
								 jump_to_downloads);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_autodownload),
								 use_autodownload);

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON
								 (checkbutton_proxy_connections),
								 proxy_connections);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_socksv4),
								 (socks_protocol == 4) ? TRUE : FALSE);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_socksv5),
								 (socks_protocol == 5) ? TRUE : FALSE);

	gui_update_socks_host();
	gui_update_socks_port();
	gui_update_socks_user();
	gui_update_socks_pass();

	if (w_w && w_h) {
		gtk_widget_set_uposition(main_window, w_x, w_y);
		gtk_window_set_default_size(GTK_WINDOW(main_window), w_w, w_h);
	}

	for (i = 0; i < 3; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_nodes), i,
								   nodes_col_widths[i]);
	for (i = 0; i < 4; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_downloads), i,
								   dl_active_col_widths[i]);
	for (i = 0; i < 3; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_download_queue), i,
								   dl_queued_col_widths[i]);
	for (i = 0; i < 3; i++)
		gtk_clist_set_column_width(GTK_CLIST(clist_uploads), i,
								   uploads_col_widths[i]);

	// as soon as this is corrected in Glade, you can do this
	// check the variable names and take out the stuff in
	// search.c that sets this up
	// for (i = 0; i < 5; i++)
	//    gtk_clist_set_column_width(GTK_CLIST(clist_search_results),
	//         i, search_results_col_widths[i]);

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

void config_hosts_catched(gchar * str)
{
	gchar **h = g_strsplit(str, ",", 0);
	gint i = 0;
	gchar p[16];

	while (h[i] && *h[i]) {
		if (strlen(h[i]) == 8) {		/* This is a host with default port */
			host_add(strtoul(h[i], NULL, 16), 6346, FALSE);
		} else if (strlen(h[i]) == 12) {		/* This is a host with a port */
			strncpy(p, h[i] + 8, 4);
			h[i][8] = 0;
			host_add(strtoul(h[i], NULL, 16), strtoul(p, NULL, 16), FALSE);
		}

		i++;
	}

	g_strfreev(h);
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

	case k_force_local_ip:
		force_local_ip = (gboolean) ! g_strcasecmp(value, "true");
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

	case k_hosts_catched:
		config_hosts_catched(value);
		return;

	case k_node_sendqueue_size:
		if (i > 4096 && i < 1048576) node_sendqueue_size = i;
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

	case k_upload_connecting_timeout:
		if (i > 1 && i < 3600) upload_connecting_timeout = i;
		return;

	case k_upload_connected_timeout:
		if (i > 1 && i < 3600) upload_connected_timeout = i;
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
		if ((a = config_parse_array(value, 3)))
			for (i = 0; i < 3; i++)
				nodes_col_widths[i] = a[i];
		return;

	case k_widths_uploads:
		if ((a = config_parse_array(value, 3)))
			for (i = 0; i < 3; i++)
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

	case k_socks_protocol:
		socks_protocol = i;
		return;

	case k_proxy_ip:
		proxy_ip = g_strdup(value);
		return;

	case k_proxy_port:
		proxy_port = i;
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
	}
}

void config_read(void)
{
	FILE *config;
	gchar *s, *k, *v;
	guint32 i, n = 0;

	static gchar *err = "Bad line %u in config file, ignored\n";

	if (is_directory(config_dir))
		g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", config_dir,
				   config_file);
	else
		strncpy(cfg_tmp, config_dir, sizeof(cfg_tmp));

	config = fopen(cfg_tmp, "r");

	/* Try to open settings file in local directory first */
	if ((config = fopen(config_file, "r")) != NULL)
		cfg_use_local_file = 1; /* We're using a local config file */
	else
		config = fopen(cfg_tmp, "r");	/* The normal file */

	if (!config)
		return;

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

void config_save(void)
{
	FILE *config;
	gint win_x, win_y, win_w, win_h;

	if (!config_dir) {
		fprintf(stderr, "\nNo configuration directory !\n"
			"\nPreferences have not been saved.\n\n");
		return;
	}

	g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", config_dir, config_file);

	if (cfg_use_local_file)
		config = fopen(config_file, "w");
	else
		config = fopen(cfg_tmp, "w");

	if (!config) {
		fprintf(stderr, "\nfopen(): %s\n"
			"\nUnable to write your configuration in %s\n"
			"Preferences have not been saved.\n\n",
				g_strerror(errno), cfg_tmp);
		return;
	}

	gdk_window_get_root_origin(main_window->window, &win_x, &win_y);
	gdk_window_get_size(main_window->window, &win_w, &win_h);

#ifdef GTA_REVISION
	fprintf(config,
			"\n# Gtk-Gnutella %u.%u %s (%s) by Olrick & Co. - %s\n\n",
			GTA_VERSION, GTA_SUBVERSION, GTA_REVISION, GTA_RELEASE,
			GTA_WEBSITE);
#else
	fprintf(config, "\n# Gtk-Gnutella %u.%u (%s) by Olrick & Co. - %s\n\n",
			GTA_VERSION, GTA_SUBVERSION, GTA_RELEASE, GTA_WEBSITE);
#endif
	fprintf(config, "# This is Gtk-Gnutella configuration file - "
		"you may edit it if you're careful.\n");
	fprintf(config, "# (only when the program is not running: "
		"this file is saved on quit)\n\n");
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
	fprintf(config, "%s = %s\n", keywords[k_force_local_ip],
			config_boolean(force_local_ip));
	fprintf(config, "%s = \"%s\"\n", keywords[k_forced_local_ip],
			ip_to_gchar(forced_local_ip));
	fprintf(config, "%s = %u\n", keywords[k_listen_port], listen_port);
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

	fprintf(config, "%s = %u,%u,%u\n", keywords[k_widths_nodes],
			nodes_col_widths[0], nodes_col_widths[1], nodes_col_widths[2]);
	fprintf(config, "%s = %u,%u,%u\n", keywords[k_widths_uploads],
			uploads_col_widths[0], uploads_col_widths[1],
			uploads_col_widths[2]);
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

	fprintf(config, "\n\n# The following variables cannot "
		"yet be configured with the GUI.\n\n");

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

	fprintf(config, "# Maximum size of the sendqueue "
		"for the nodes (in bytes)\n%s = %u\n\n",
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
			"%s = %u\n", keywords[k_search_pick_all], search_pick_all);

	fprintf(config, "# Proxy Info\n\n");
	fprintf(config, "%s = %u\n\n", keywords[k_proxy_connections],
			proxy_connections);
	fprintf(config, "%s = %u\n\n", keywords[k_socks_protocol], socks_protocol);
	fprintf(config, "%s = \"%s\"\n\n", keywords[k_proxy_ip], proxy_ip);
	fprintf(config, "%s = %u\n\n", keywords[k_proxy_port], proxy_port);
	fprintf(config, "%s = \"%s\"\n\n", keywords[k_socksv5_user], socksv5_user);
	fprintf(config, "%s = \"%s\"\n\n", keywords[k_socksv5_pass], socksv5_pass);
	fprintf(config, "\n\n");

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

	fprintf(config, "\n\n");

	fclose(config);

	/* Save the catched hosts */

	if (hosts_idle_func) {
		g_warning("exit() while still reading the hosts file, "
			"catched hosts not saved !\n");
	} else {
		if (cfg_use_local_file)
			hosts_write_to_file(host_file);
		else {
			g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/%s", config_dir,
					   host_file);
			hosts_write_to_file(cfg_tmp);
		}
	}
}

/*
 * config_ip_changed
 *
 * This routine is called when we determined that our IP was no longer the
 * one we force.  We base this on some headers sent back when we handshake
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

	g_assert(force_local_ip);		/* Must only be called when IP is forced */

	if (new_ip != last_ip_seen) {
		last_ip_seen = new_ip;
		same_ip_count = 1;
		return;
	}

	if (++same_ip_count < 3)
		return;

	last_ip_seen = 0;
	same_ip_count = 0;

	if (new_ip == forced_local_ip)
		return;

	g_warning("Changing forced IP to %s", ip_to_gchar(new_ip));

	forced_local_ip = new_ip;
	gui_update_config_force_ip();
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
	if (proxy_ip)
		g_free(proxy_ip);
	if (socksv5_user && socksv5_user != socksv5[SOCKSV5_USER])
		g_free(socksv5_user);
	if (socksv5_pass && socksv5_pass != socksv5[SOCKSV5_PASS])
		g_free(socksv5_pass);
}

/* vi: set ts=4: */
