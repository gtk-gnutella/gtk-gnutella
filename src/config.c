
/* gtk-gnutella configuration */

#include "gnutella.h"
#include "interface.h"

#include <sys/stat.h>
#include <pwd.h>

gboolean clear_uploads					= FALSE;
gboolean clear_downloads				= FALSE;
gboolean monitor_enabled				= FALSE;
gboolean force_local_ip					= FALSE;

guint8 max_ttl								= 5;
guint8 my_ttl								= 5;

guint16 listen_port						= 6346;

guint32 up_connections					= 4;
guint32 max_downloads					= 10;
guint32 max_host_downloads				= 4;
guint32 minimum_speed					= 0;
guint32 monitor_max_items				= 25;
guint32 connection_speed				= 28;
guint32 search_max_items				= 30;
guint32 forced_local_ip					= 0;
guint32 download_connecting_timeout	= 60;
guint32 download_push_sent_timeout	= 60;
guint32 download_connected_timeout	= 60;
guint32 download_retry_timeout_min	= 10;
guint32 download_retry_timeout_max	= 120;
guint32 download_max_retries			= 3;
guint32 node_connected_timeout		= 45;
guint32 node_connecting_timeout		= 45;
guint32 node_sendqueue_size			= 10240;
guint32 search_queries_forward_size	= 256;
guint32 search_queries_kick_size		= 512;
guint32 search_answers_forward_size	= 32768;
guint32 search_answers_kick_size		= 40960;
guint32 other_messages_kick_size		= 40960;

gchar *scan_extensions					= NULL;
gchar *save_file_path					= NULL;
gchar *move_file_path					= NULL;
gchar *shared_dirs_paths				= NULL;
gchar *completed_file_path				= NULL;
gchar *home_dir		  					= NULL;
gchar *config_dir							= NULL;

guint32 nodes_col_widths[]          = { 140, 80, 80 };
guint32 dl_active_col_widths[]      = { 180, 80, 80 };
guint32 dl_queued_col_widths[]      = { 320, 80 };
guint32 uploads_col_widths[]        = { 200, 140, 80 };
guint32 search_results_col_widths[] = { 290, 80, 50, 140 };

gint w_x = 0, w_y = 0, w_w = 0, w_h = 0;

enum
{
	k_up_connections = 0, k_clear_uploads, k_max_downloads, k_max_host_downloads, k_clear_downloads, 
	k_minimum_speed, k_monitor_enabled, k_monitor_max_items, k_old_save_file_path, k_scan_extensions, 
	k_listen_port, k_max_ttl, k_my_ttl, k_shared_dirs, k_forced_local_ip, k_connection_speed, 
	k_search_max_items, k_force_local_ip, k_hosts_catched, k_download_connecting_timeout,
	k_download_push_sent_timeout, k_download_connected_timeout, k_node_connected_timeout,
	k_node_connecting_timeout, k_node_sendqueue_size, k_search_queries_forward_size,
	k_search_queries_kick_size, k_search_answers_forward_size, k_search_answers_kick_size,
	k_other_messages_kick_size, k_save_file_path, k_move_file_path,
	k_win_x, k_win_y, k_win_w, k_win_h, k_win_coords, k_widths_nodes, k_widths_uploads,
	k_widths_dl_active, k_widths_dl_queued, k_widths_search_results, k_show_results_tabs,
	k_end
};

gchar *keywords[] = 
{
	"up_connections",							/* k_up_connections					*/
	"auto_clear_completed_uploads",		/* k_clear_uploads					*/
	"max_simultaneous_downloads",			/* k_max_downloads					*/
	"max_simultaneous_host_downloads",	/* k_max_host_downloads				*/
	"auto_clear_completed_downloads",	/* k_clear_downloads					*/
	"search_minimum_speed",					/* k_minimum_speed					*/
	"monitor_enabled",						/* k_monitor_enabled					*/
	"monitor_max_items",						/* k_monitor_max_items				*/
	"save_downloaded_files_to",			/* k_old_save_file_path				*/
	"shared_files_extensions",				/* k_scan_extensions					*/
	"listen_port",								/* k_listen_port						*/
	"max_ttl",									/* k_max_ttl							*/
	"my_ttl",									/* k_my_ttl								*/
	"shared_dirs",								/* k_shared_dirs						*/
	"forced_local_ip",						/* k_forced_local_ip					*/
	"connection_speed",						/* k_connection_speed				*/
	"limit_search_results",					/* k_search_max_items				*/
	"force_local_ip",							/* k_force_local_ip					*/
	"hc",											/* k_hosts_catched					*/
	"download_connecting_timeout",		/* k_download_connecting_timeout	*/
	"download_push_sent_timeout",			/* k_download_push_sent_timeout	*/
	"download_connected_timeout",			/* k_download_connected_timeout	*/
	"node_connected_timeout",				/* k_node_connected_timeout		*/
	"node_connecting_timeout",				/* k_node_connecting_timeout		*/
	"node_sendqueue_size",					/* k_node_sendqueue_size			*/
	"search_queries_forward_size",		/* k_search_queries_forward_size	*/
	"search_queries_kick_size",			/* k_search_queries_kick_size		*/
	"search_answers_forward_size",		/* k_search_answers_forward_size	*/
	"search_answers_kick_size",			/* k_search_answers_kick_size		*/
	"other_messages_kick_size",			/* k_other_messages_kick_size		*/
	"store_downloading_files_to",			/* k_save_file_path					*/
	"move_downloaded_files_to",			/* k_move_file_path					*/
	"window_x",									/* k_win_x								*/
	"window_y",									/* k_win_y								*/
	"window_w",									/* k_win_w								*/
	"window_h",									/* k_win_h								*/
	"window_coords",							/* k_win_coords						*/
	"widths_nodes",							/* k_width_nodes						*/
	"widths_uploads",							/* k_width_uploads					*/
	"widths_dl_active",						/* k_width_dl_active					*/
	"widths_dl_queued",						/* k_width_dl_queued					*/
	"widths_search_results",				/* k_width_search_results			*/
	"show_results_tabs",						/* k_show_results_tabs				*/
	NULL
};

gchar cfg_tmp[4096];

void config_read(void);

/* ------------------------------------------------------------------------------------------------ */

void config_init(void)
{
	gint i;
	struct passwd *pwd = NULL;

	config_dir = g_strdup(getenv("GTK_GNUTELLA_DIR"));

	pwd = getpwuid(getuid());

	if (pwd && pwd->pw_dir) home_dir = g_strdup(pwd->pw_dir);
	else home_dir = g_strdup(getenv("HOME"));

	if (!home_dir) fprintf(stderr, "\nWARNING - Can't find your home directory !\n\n");

	if (config_dir && !is_directory(config_dir))
	{
		fprintf(stderr, "\nWARNING - '%s' does not exists or is not a directory !\n\n", config_dir);
		g_free(config_dir);
		config_dir = NULL;
	}

	if (!config_dir)
	{
		if (home_dir)
		{
			g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/.gtk-gnutella", home_dir);
			config_dir = g_strdup(cfg_tmp);
		}
		else fprintf(stderr, "\nWARNING - No configuration directory: Prefs will not be saved !\n\n");
	}

	if (config_dir)
	{
		/* Parse the configuration */

		config_read();

		/* Loads the catched hosts */

		g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/hosts", config_dir);
		hosts_read_from_file(cfg_tmp, TRUE);
	}

	if (!save_file_path || !is_directory(save_file_path))
		save_file_path = (home_dir)? g_strdup(home_dir) : g_strdup("/tmp");

	if (!move_file_path || !is_directory(move_file_path))
		move_file_path = g_strdup(save_file_path);

	if (!forced_local_ip) force_local_ip = FALSE;

	if (!shared_dirs_paths) shared_dirs_paths = g_strdup("");

	if (!scan_extensions) scan_extensions = g_strdup("mp3;mp2;mp1;vqf;avi;mpg;mpeg;wav;mod;voc;it;xm;s3m;stm;wma;mov;asf;zip;rar");

	/* Okay, update the GUI with values loaded */

	gui_update_count_downloads();
	gui_update_count_uploads();

	gui_update_minimum_speed(minimum_speed);
	gui_update_up_connections();
	gui_update_config_port();
	gui_update_config_force_ip();

	gui_update_save_file_path();
	gui_update_move_file_path();

	gui_update_monitor_max_items();

	gui_update_max_ttl();
	gui_update_my_ttl();

	gui_update_max_downloads();
	gui_update_max_host_downloads();
	gui_update_files_scanned();

	gui_update_connection_speed();

	gui_update_search_max_items();

	gui_update_scan_extensions();
	gui_update_shared_dirs();

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(checkbutton_monitor), monitor_enabled);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(checkbutton_clear_uploads), clear_uploads);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(checkbutton_clear_downloads), clear_downloads);
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(checkbutton_config_force_ip), force_local_ip);

	if (w_w && w_h)
	{
		gtk_widget_set_uposition(main_window, w_x, w_y);
		gtk_window_set_default_size(GTK_WINDOW(main_window), w_w, w_h);
	}

	for (i = 0; i < 3; i++) gtk_clist_set_column_width(GTK_CLIST(clist_nodes), i, nodes_col_widths[i]);
	for (i = 0; i < 4; i++) gtk_clist_set_column_width(GTK_CLIST(clist_downloads), i, dl_active_col_widths[i]);
	for (i = 0; i < 2; i++) gtk_clist_set_column_width(GTK_CLIST(clist_download_queue), i, dl_queued_col_widths[i]);
	for (i = 0; i < 3; i++) gtk_clist_set_column_width(GTK_CLIST(clist_uploads), i, uploads_col_widths[i]);

	/* Transition : HOME/.gtk-gnutella is now a directory */

	if (config_dir && !is_directory(config_dir))
	{
		if (unlink(config_dir) == -1)
		{
			if (errno != ENOENT)
			{
				g_warning("unlink(%s) failed (%s) !\n", config_dir, g_strerror(errno));
				g_free(config_dir); config_dir = NULL;
				return;
			}
		}
		else
		{
			/* We are replacing the old config file by a directory. */
			fprintf(stdout, "Creating configuration directory '%s'\n", config_dir);
		}

		if (mkdir(config_dir, 0755) == -1)
		{
			g_warning("mkdir(%s) failed (%s) !\n\n", config_dir, g_strerror(errno));
			g_free(config_dir); config_dir = NULL;
			return;
		}
	}
}

void config_hosts_catched(gchar *str)
{
	gchar **h = g_strsplit(str, ",", 0);
	gint i = 0;
	gchar p[16];

	while (h[i] && *h[i])
	{
		if (strlen(h[i]) == 8) /* This is a host with default port */
		{
			host_add(NULL, strtoul(h[i], NULL, 16), 6346, FALSE);
		}
		else if (strlen(h[i]) == 12) /* This is a host with a port */
		{
			strncpy(p, h[i] + 8, 4);
			h[i][8] = 0;
			host_add(NULL, strtoul(h[i], NULL, 16), strtoul(p, NULL, 16), FALSE);
		}

		i++;
	}

	g_strfreev(h);
}

guint32 *config_parse_array(gchar *str, guint32 n)
{
	static guint32 array[10];
	gchar **h  = g_strsplit(str, ",", n + 1);
	guint32 *r = array;
	gint i;

	for (i = 0; i < n; i++)
	{
		if (!h[i]) { r = NULL; break; }
		array[i] = atol(h[i]);
	}

	g_strfreev(h);
	return r;
}

void config_set_param(guint32 keyword, gchar *value)
{
	gint32 i = atol(value);
	guint32 *a;

	switch (keyword)
	{
		case k_monitor_enabled: { monitor_enabled = (gboolean) !g_strcasecmp(value, "true"); return; }
		case k_monitor_max_items: { if (i > 0 && i < 512) monitor_max_items = i; return; }
		case k_clear_uploads: { clear_uploads = (gboolean) !g_strcasecmp(value, "true"); return; }
		case k_clear_downloads: { clear_downloads = (gboolean) !g_strcasecmp(value, "true"); return; }
		case k_up_connections: { if (i > 0 && i < 512) up_connections = i; return; }
		case k_max_downloads: { if (i > 0 && i < 512) max_downloads = i; return; }
		case k_max_host_downloads: { if (i > 0 && i < 512) max_host_downloads = i; return; }
		case k_minimum_speed: { minimum_speed = atol(value); return; }
		case k_listen_port: { listen_port = atoi(value); return; }
		case k_max_ttl: { if (i > 0 && i < 255) max_ttl = i; return; }
		case k_my_ttl:  { if (i > 0 && i < 255) my_ttl = i; return; }
		case k_search_max_items: { if (i >= 0 && i < 65535) search_max_items = i; return; }
		case k_connection_speed: { if (i > 0 && i < 65535) connection_speed = i; return; }
		case k_force_local_ip: { force_local_ip = (gboolean) !g_strcasecmp(value, "true"); return; }
		case k_scan_extensions: { parse_extensions(value); return; }
		case k_old_save_file_path:
		case k_save_file_path: { save_file_path = g_strdup(value); return; }
		case k_move_file_path: { move_file_path = g_strdup(value); return; }
		case k_shared_dirs: { shared_dirs_parse(value); return; }
		case k_hosts_catched: { config_hosts_catched(value); return; }
		case k_node_sendqueue_size: { if (i > 4096 && i < 1048576) node_sendqueue_size = i; return; }
		case k_node_connecting_timeout: { if (i > 10 && i < 3600) node_connecting_timeout = i; return; }
		case k_node_connected_timeout: { if (i > 10 && i < 3600) node_connected_timeout = i; return; }
		case k_download_connecting_timeout: { if (i > 10 && i < 3600) download_connecting_timeout = i; return; }
		case k_download_push_sent_timeout: { if (i > 10 && i < 3600) download_push_sent_timeout = i; return; }
		case k_download_connected_timeout: { if (i > 10 && i < 3600) download_connected_timeout = i; return; }
		case k_search_queries_forward_size: { if (i > 512 && i < 65535) search_queries_forward_size = i; return; }
		case k_search_queries_kick_size: { if (i > 512 && i < 65535) search_queries_kick_size = i; return; }
		case k_search_answers_forward_size: { if (i > 512 && i < 1048576) search_answers_forward_size = i; return; }
		case k_search_answers_kick_size: { if (i > 512 && i < 1048576) search_answers_kick_size = i; return; }
		case k_other_messages_kick_size: { if (i > 0 && i < 1048576) other_messages_kick_size = i; return; }
		case k_win_x: { w_x = i; return; }
		case k_win_y: { w_y = i; return; }
		case k_win_w: { w_w = i; return; }
		case k_win_h: { w_h = i; return; }
		case k_win_coords: { if ((a = config_parse_array(value, 4))) { w_x = a[0]; w_y = a[1]; w_w = a[2]; w_h = a[3]; } return; }
		case k_widths_nodes: { if ((a = config_parse_array(value, 3))) for (i=0; i < 3; i++) nodes_col_widths[i] = a[i]; return; }
		case k_widths_uploads: { if ((a = config_parse_array(value, 3))) for (i=0; i < 3; i++) uploads_col_widths[i] = a[i]; return; }
		case k_widths_dl_active: { if ((a = config_parse_array(value, 3))) for (i=0; i < 3; i++) dl_active_col_widths[i] = a[i]; return; }
		case k_widths_dl_queued: { if ((a = config_parse_array(value, 2))) for (i=0; i < 3; i++) dl_queued_col_widths[i] = a[i]; return; }
		case k_widths_search_results: { if ((a = config_parse_array(value, 4))) for (i=0; i < 3; i++) search_results_col_widths[i] = a[i]; return; }
		case k_show_results_tabs: { search_results_show_tabs = (gboolean) !g_strcasecmp(value, "true"); return; }
		case k_forced_local_ip: { forced_local_ip = gchar_to_ip(value); return; }
	}
}

void config_read(void)
{
	FILE *config;
	gchar *s, *k, *v;
	guint32 i, n = 0;

	static gchar *err = "Bad line %u in config file, ignored\n";

	if (is_directory(config_dir))
		g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/gtk-gnutella", config_dir);
	else
		strncpy(cfg_tmp, config_dir, sizeof(cfg_tmp));

	config = fopen(cfg_tmp, "r");

	if (!config) return;

	gtk_clist_freeze(GTK_CLIST(clist_host_catcher));

	while (fgets(cfg_tmp, sizeof(cfg_tmp), config))
	{
		n++;
		s = cfg_tmp;
		while (*s && (*s == ' ' || *s == '\t')) s++;
		if (!((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z'))) continue;
		k = s;
		while (*s =='_' || (*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z')) s++;
		if (*s != '=' && *s != ' ' && *s != '\t') { fprintf(stderr, err, n); continue; }
		v = s;
		while (*s == ' ' || *s == '\t') s++;
		if (*s != '=') { fprintf(stderr, err, n); continue; }
		*v = 0; s++;
		while (*s == ' ' || *s == '\t') s++;
		if (*s == '"')
		{
			v = ++s;
			while (*s && *s != '\n' && *s != '"') s++;
			if (!*s || *s == '\n') { fprintf(stderr, err, n); continue; }
		}
		else { v = s; while (*s && *s != '\n' && *s != ' ' && *s != '\t') s++; }
		*s = 0;

		for (i = 0; i < k_end; i++) if (!g_strcasecmp(k, keywords[i])) { config_set_param(i, v); break; }

		if (i >= k_end) fprintf(stderr, "config file, line %u: unknown keyword '%s', ignored\n", n, k);
	}

	gtk_clist_thaw(GTK_CLIST(clist_host_catcher));

	fclose(config);
}

gchar *config_boolean(gboolean b)
{
	static gchar *b_true  = "TRUE";
	static gchar *b_false = "FALSE";
	return (b)? b_true : b_false;
}

void config_save(void)
{
	FILE *config;
	gint win_x, win_y, win_w, win_h;

	if (!config_dir)
	{
		fprintf(stderr, "\nNo configuration directory !\n\nPreferences have not been saved.\n\n");
		return;
	}

	g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/gtk-gnutella", config_dir);

	config = fopen(cfg_tmp, "w");

	if (!config)
	{
		fprintf(stderr, "\nfopen(): %s\n\nUnable to write your configuration in %s\nPreferences have not been saved.\n\n", g_strerror(errno), cfg_tmp);
		return;
	}

	gdk_window_get_root_origin(main_window->window, &win_x, &win_y);
	gdk_window_get_size(main_window->window, &win_w, &win_h);

	#ifdef GTA_REVISION
	fprintf(config, "\n# Gtk-Gnutella %u.%u %s (%s) by Olrick - %s\n\n", GTA_VERSION, GTA_SUBVERSION, GTA_REVISION, GTA_RELEASE, GTA_WEBSITE);
	#else
	fprintf(config, "\n# Gtk-Gnutella %u.%u (%s) by Olrick - %s\n\n", GTA_VERSION, GTA_SUBVERSION, GTA_RELEASE, GTA_WEBSITE);
	#endif
	fprintf(config, "# This is Gtk-Gnutella configuration file - you may edit it if you're careful.\n\n");

	fprintf(config, "%s = %u\n", keywords[k_up_connections], up_connections);
	fprintf(config, "\n");
	fprintf(config, "%s = %s\n", keywords[k_clear_uploads], config_boolean(clear_uploads));
	fprintf(config, "\n");
	fprintf(config, "%s = %u\n", keywords[k_max_downloads], max_downloads);
	fprintf(config, "\n");
	fprintf(config, "%s = %u\n", keywords[k_max_host_downloads], max_host_downloads);
	fprintf(config, "\n");
	fprintf(config, "%s = %s\n", keywords[k_clear_downloads], config_boolean(clear_downloads));
	fprintf(config, "\n");
	fprintf(config, "%s = %u\n", keywords[k_minimum_speed], minimum_speed);
	fprintf(config, "\n");
	fprintf(config, "%s = %s\n", keywords[k_monitor_enabled], config_boolean(monitor_enabled));
	fprintf(config, "%s = %u\n", keywords[k_monitor_max_items], monitor_max_items);
	fprintf(config, "\n");
	fprintf(config, "%s = \"%s\"\n", keywords[k_save_file_path], save_file_path);
	fprintf(config, "%s = \"%s\"\n", keywords[k_move_file_path], move_file_path);
	fprintf(config, "\n");
	fprintf(config, "%s = \"%s\"\n", keywords[k_shared_dirs], (shared_dirs_paths)? shared_dirs_paths : "");
	fprintf(config, "%s = \"%s\"\n", keywords[k_scan_extensions], (scan_extensions)? scan_extensions : "");
	fprintf(config, "\n");
	fprintf(config, "%s = %s\n", keywords[k_force_local_ip], config_boolean(force_local_ip));
	fprintf(config, "%s = \"%s\"\n", keywords[k_forced_local_ip], ip_to_gchar(forced_local_ip));
	fprintf(config, "%s = %u\n", keywords[k_listen_port], listen_port);
	fprintf(config, "\n");
	fprintf(config, "%s = %u\n", keywords[k_connection_speed], connection_speed);
	fprintf(config, "\n");
	fprintf(config, "%s = %u\n", keywords[k_search_max_items], search_max_items);
	fprintf(config, "\n");
	fprintf(config, "%s = %u\n", keywords[k_max_ttl], max_ttl);
	fprintf(config, "%s = %u\n\n", keywords[k_my_ttl], my_ttl);

	fprintf(config, "%s = %s\n", keywords[k_show_results_tabs], config_boolean(search_results_show_tabs));

	fprintf(config, "\n\n# GUI values\n\n");

	fprintf(config, "%s = %u,%u,%u,%u\n\n", keywords[k_win_coords], win_x, win_y, win_w, win_h);

	fprintf(config, "%s = %u,%u,%u\n", keywords[k_widths_nodes], nodes_col_widths[0], nodes_col_widths[1], nodes_col_widths[2]);
	fprintf(config, "%s = %u,%u,%u\n", keywords[k_widths_uploads], uploads_col_widths[0], uploads_col_widths[1], uploads_col_widths[2]);
	fprintf(config, "%s = %u,%u,%u\n", keywords[k_widths_dl_active], dl_active_col_widths[0], dl_active_col_widths[1], dl_active_col_widths[2]);
	fprintf(config, "%s = %u,%u\n", keywords[k_widths_dl_queued], dl_queued_col_widths[0], dl_queued_col_widths[1]);
	fprintf(config, "%s = %u,%u,%u,%u\n", keywords[k_widths_search_results], search_results_col_widths[0], search_results_col_widths[1], search_results_col_widths[2], search_results_col_widths[3]);

	fprintf(config, "\n\n# The following variables cannot yet be configured with the GUI.\n\n"); 

	fprintf(config, "# Number of seconds before timeout for a connecting download\n%s = %u\n\n", keywords[k_download_connecting_timeout], download_connecting_timeout);
	fprintf(config, "# Number of seconds before timeout for a 'push sent' download\n%s = %u\n\n", keywords[k_download_push_sent_timeout], download_push_sent_timeout);
	fprintf(config, "# Number of seconds before timeout for a connected download\n%s = %u\n\n", keywords[k_download_connected_timeout], download_connected_timeout);
	fprintf(config, "# Number of seconds before timeout for a connecting node\n%s = %u\n\n", keywords[k_node_connecting_timeout], node_connecting_timeout);
	fprintf(config, "# Number of seconds before timeout for a connected node\n%s = %u\n\n", keywords[k_node_connected_timeout], node_connected_timeout);

	fprintf(config, "\n");

	fprintf(config, "# Maximum size of the sendqueue for the nodes (in bytes)\n%s = %u\n\n", keywords[k_node_sendqueue_size], node_sendqueue_size);

	/* I'm not sure yet that the following variables are really useful...

	fprintf(config, "# WARNING: *PLEASE* DO NOT MODIFY THE FOLLOWING VALUES IF YOU DON'T KNOW WHAT YOU'RE DOING\n\n"); 

	fprintf(config, "# [NOT IMPLEMENTED] Maximum size of search queries messages we forward to others (in bytes)\n%s = %u\n\n", keywords[k_search_queries_forward_size], search_queries_forward_size);
	fprintf(config, "# [NOT IMPLEMENTED] Maximum size of search queries messages we allow before closing the connection (in bytes)\n%s = %u\n\n", keywords[k_search_queries_kick_size], search_queries_kick_size);
	fprintf(config, "# [NOT IMPLEMENTED] Maximum size of search answers messages we forward to others (in bytes)\n%s = %u\n\n", keywords[k_search_answers_forward_size], search_answers_forward_size);
	fprintf(config, "# [NOT IMPLEMENTED] Maximum size of search answers messages we allow before closing the connection (in bytes)\n%s = %u\n\n", keywords[k_search_answers_kick_size], search_answers_kick_size);
	fprintf(config, "# [NOT IMPLEMENTED] Maximum size of unknown messages we allow before closing the connection (in bytes)\n%s = %u\n\n", keywords[k_other_messages_kick_size], other_messages_kick_size);

	*/
	
	fprintf(config, "\n\n");

	fclose(config);

	/* Save the catched hosts */

	if (hosts_idle_func)
	{
		g_warning("exit() while reading a hosts file, catched hosts not saved !\n");
	}
	else
	{
		g_snprintf(cfg_tmp, sizeof(cfg_tmp), "%s/hosts", config_dir);
		hosts_write_to_file(cfg_tmp);
	}
}

/* vi: set ts=3: */

