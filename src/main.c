/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#include "gnutella.h"

#include <pwd.h>
#include <signal.h>
#include <locale.h>

#include "gui.h"
#include "search.h"
#include "share.h"
#include "sockets.h"
#include "routing.h"
#include "downloads.h"
#include "hosts.h"
#include "misc.h"
#include "gmsg.h"
#include "bsched.h"
#include "search_stats.h"
#include "upload_stats.h"
#include "pcache.h"
#include "gtk-missing.h"
#include "filter.h"
#include "cq.h"
#include "ban.h"
#include "atoms.h"
#include "dmesh.h"
#include "filter_cb.h"
#include "version.h"
#include "matching.h"
#include "walloc.h"
#include "nodes.h"

#include "gnet_property_priv.h"
#include "main_gui.h"
#include "settings.h"
#include "oldconfig.h"
#include "fileinfo.h"

#define SLOW_UPDATE_PERIOD		20	/* Updating period for `main_slow_update' */
#define EXIT_GRACE				30	/* Seconds to wait before exiting */
#define CALLOUT_PERIOD			100	/* milliseconds */

/* */

struct gnutella_socket *s_listen = NULL;
time_t start_time;
gchar *start_rfc822_date = NULL;		/* RFC822 format of start_time */
cqueue_t *callout_queue;

static guint main_slow_update = 0;
static gboolean exiting = FALSE;

/* */

/*
 * gtk_gnutella_exit
 *
 * Exit program, return status `n' to parent process.
 *
 * Shutdown systems, so we can track memory leaks, and wait for EXIT_GRACE
 * seconds so that BYE messages can be sent to other nodes.
 */
void gtk_gnutella_exit(gint n)
{
	time_t now = time((time_t *) NULL);
	time_t tick;
	gchar tmp[256];
    GtkLabel *label_shutdown_count;

	if (exiting)
		return;			/* Already exiting, must be in loop below */

	exiting = TRUE;

	node_bye_all();
	upload_close();		/* Done before settings_close() for stats update */
	download_close();
    filter_cb_close();

	/*
	 * Make sure the gui writes config variabes it owns but that can't 
	 * be updated via callbacks.
	 *      --BLUE, 16/05/2002
	 */

    main_gui_shutdown();

	gui_shutdown();

	if (hosts_idle_func)
		g_source_remove(hosts_idle_func);

	if (s_listen)
		socket_destroy(s_listen);
	socket_shutdown();
	search_shutdown(); /* must be done before filter_shutdown! */
	filter_shutdown();
	bsched_shutdown();
	settings_shutdown();

	/* 
	 * Wait at most EXIT_GRACE seconds, so that BYE messages can go through.
	 */

	gtk_widget_hide(main_window);
	gtk_widget_show(shutdown_window);

    label_shutdown_count = GTK_LABEL
        (lookup_widget(shutdown_window, "label_shutdown_count"));

	while (
		node_bye_pending() && 
		(tick = time((time_t *) NULL)) - now < EXIT_GRACE
	) {
		g_snprintf(tmp, sizeof(tmp), "%d seconds", 
			EXIT_GRACE - (gint)difftime(tick,now));

		gtk_label_set(label_shutdown_count,tmp);
        gtk_main_flush();

		usleep(200000);					/* 200 ms */
	}

	share_close();
	node_close();
	host_close();
	routing_close();
	bsched_close();
	gui_close();
	dmesh_close();
	settings_close();
	ban_close();
	cq_free(callout_queue);
	matching_close();
	pmsg_close();
	version_close();
	atom_str_free(start_rfc822_date);
	atoms_close();
	wdestroy();

	if (dbg)
		printf("gtk-gnutella shut down cleanly.\n\n");

	gtk_exit(n);
}

static void sig_terminate(int n)
{
	gtk_gnutella_exit(1);
}

/*
 * sig_ignore
 *
 * This routine is meant as a workaround for some systems where a single
 * setting to SIG_IGN just won't do (e.g. on linux kernel 2.4.19-pre8-ben0).
 * Doing this is a little suboptimal, but we're not going to get hundreds of
 * SIGPIPE per second either.
 *		--RAM, 08/07/2002 (should fix bug #578151)
 */
static void sig_ignore(int n)
{
	signal(n, sig_ignore);
	return;
}

static void init_constants(void)
{
	start_time = time((time_t *) NULL);
	start_rfc822_date = atom_str_get(date_to_rfc822_gchar(start_time));
}

static void slow_main_timer(time_t now)
{
	static gint i = 0;

	switch (i) {
	case 0:
		dmesh_store();
		break;
	case 1:
		search_store();
		break;
	case 2:
		ul_flush_stats_if_dirty();
		break;
	case 3:
		file_info_store_if_dirty();
		break;
	default:
		g_assert(0);
	}

	if (++i > 3)
		i = 0;
}

static gboolean main_timer(gpointer p)
{
	time_t now = time((time_t *) NULL);

	bsched_timer();					/* Scheduling update */
	host_timer();					/* Host connection */
	node_timer(now);				/* Node timeouts */
	if (!exiting) {
		download_timer(now);  	    /* Download timeouts */
		upload_timer(now);			/* Upload timeouts */
	}
	socket_timer(now);				/* Expire inactive sockets */
	pcache_possibly_expired(now);	/* Expire pong cache */

	/*
	 * GUI update
	 */

	if (!exiting) {
		gui_update_global();
        gui_update_traffic_stats();
        filter_timer(); /* Update the filter stats */

		/* Update for things that change slowly */
		if (main_slow_update++ > SLOW_UPDATE_PERIOD) {
			main_slow_update = 0;
			slow_main_timer(now);
		}
	}

	return TRUE;
}

/*
 * callout_timer
 *
 * Called every CALLOUT_PERIOD to heartbeat the callout queue.
 */
static gboolean callout_timer(gpointer p)
{
	static struct timeval last_period = { 0L, 0L };
	struct timezone tz;
	struct timeval tv;
	gint delay;

	(void) gettimeofday(&tv, &tz);

	/*
	 * How much elapsed since last call?
	 */

	delay = (gint) ((tv.tv_sec - last_period.tv_sec) * 1000 +
		(tv.tv_usec - last_period.tv_usec) / 1000);

	last_period = tv;		/* struct copy */

	/*
	 * If too much variation, or too little, maybe the clock was adjusted.
	 * Assume a single period then.
	 */

	if (delay < 0 || delay > 10*CALLOUT_PERIOD)
		delay = CALLOUT_PERIOD;

	cq_clock(callout_queue, delay);

	return TRUE;
}

/*
 * scan_files_once
 *
 * Scan files when the GUI is up.
 */
static gboolean scan_files_once(gpointer p)
{
	gui_allow_rescan_dir(FALSE);
	share_scan();
	gui_allow_rescan_dir(TRUE);

	return FALSE;
}

/*
 * load_legacy_settings:
 *
 * If no configuration files are found for frontend and core, it tries
 * to read in the old config file.
 * FIXME: This should be removed as soon as possible, probably for 1.0.
 */
void load_legacy_settings(void)
{
    struct passwd *pwd = getpwuid(getuid());
    gchar *config_dir;
    gchar *home_dir;
    gchar tmp[2000] = "";
    gchar core_config_file[2000] = "";
    gchar gui_config_file[2000] = "";

    config_dir = g_strdup(getenv("GTK_GNUTELLA_DIR"));
    if (pwd && pwd->pw_dir)
		home_dir = g_strdup(pwd->pw_dir);
	else
		home_dir = g_strdup(getenv("HOME"));

    if (!home_dir)
		g_warning("can't find your home directory!");
 
    if (!config_dir) {
		if (home_dir) {
			g_snprintf(tmp, sizeof(tmp),
				"%s/.gtk-gnutella", home_dir);
			config_dir = g_strdup(tmp);
		} else
			g_warning("no home directory: can't check legacy configuration!");
	}

    g_snprintf(core_config_file, sizeof(core_config_file), 
        "%s/%s", config_dir, "config_gnet");
    g_snprintf(gui_config_file, sizeof(gui_config_file), 
        "%s/%s", config_dir, "config_gui");

    if (!file_exists(core_config_file) && !file_exists(gui_config_file)) {
        g_warning("No configuration found, trying legacy config file");
        config_init();
    }

    g_free(config_dir);
    g_free(home_dir);
}

gint main(gint argc, gchar ** argv)
{
	gint i;

	for (i = 3; i < 256; i++)
		close(i);				/* Just in case */

	setlocale(LC_TIME, "C");	/* strftime() must emit standard dates */

	/* Glade inits */

	gtk_set_locale();

	gtk_init(&argc, &argv);

	add_pixmap_directory(PACKAGE_DATA_DIR "/pixmaps");
	add_pixmap_directory(PACKAGE_SOURCE_DIR "/pixmaps");

    main_window = create_main_window();
    shutdown_window = create_shutdown_window();
    dlg_about = create_dlg_about();

	/* Our inits */

	random_init();
	atoms_init();
	version_init();
	callout_queue = cq_make(0);
	init_constants();
	settings_init();
	file_info_init();
    gui_init();
	matching_init();
	host_init();
	pmsg_init();
	gmsg_init();
	bsched_init();
	network_init();
	routing_init();
	filter_init();	/* Must come before search_init() for retrieval */
	search_init();
    filter_update_targets(); /* Make sure the default filters are ok */
	share_init();
	download_init();
	upload_init();
	ban_init();
	dmesh_init();

    main_gui_init();

    load_legacy_settings();

   	gui_update_all();

	/* Some signal handlers */

	signal(SIGTERM, sig_terminate);
	signal(SIGINT, sig_terminate);
	signal(SIGPIPE, sig_ignore);		/* Not SIG_IGN, see comment */

#ifdef SIGXFSZ
	signal(SIGXFSZ, SIG_IGN);
#endif

	/* Setup the main timers */

	(void) g_timeout_add(1000, main_timer, NULL);
	(void) g_timeout_add(CALLOUT_PERIOD, callout_timer, NULL);
	(void) g_timeout_add(1000, scan_files_once, NULL);

	/* Okay, here we go */

	bsched_enable_all();

	version_ancient_warn();

    main_gui_run();

	return 0;
}

/* vi: set ts=4: */
