/*
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

#include <signal.h>
#include <locale.h>
#include <sys/utsname.h>		/* For uname() */

#include "interface.h"
#include "gui.h"
#include "support.h"
#include "search.h"
#include "share.h"
#include "sockets.h"
#include "routing.h"
#include "downloads.h"
#include "hosts.h"
#include "misc.h"
#include "autodownload.h"
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

#define SLOW_UPDATE_PERIOD		20	/* Updating period for `main_slow_update' */
#define EXIT_GRACE				30	/* Seconds to wait before exiting */
#define CALLOUT_PERIOD			100	/* milliseconds */

/* */

struct gnutella_socket *s_listen = NULL;
gchar *version_string = NULL;
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

	if (exiting)
		return;			/* Already exiting, must be in loop below */

	exiting = TRUE;

	node_bye_all();
	upload_close();		/* Done before config_close() for stats update */
	download_close();

	/*
	 * Make sure the gui writes config variabes it owns but that can't 
	 * be updated via callbacks.
	 *      --BLUE, 16/05/2002
	 */

	gui_shutdown();

	if (hosts_idle_func)
		g_source_remove(hosts_idle_func);
	config_shutdown();

	if (s_listen)
		socket_destroy(s_listen);
	socket_shutdown();
	search_shutdown(); /* must be done before filter_shutdown! */
	filter_shutdown();
	bsched_shutdown();

	/* 
	 * Wait at most EXIT_GRACE seconds, so that BYE messages can go through.
	 */

	gtk_widget_hide(main_window);
	gtk_widget_show(shutdown_window);

	while (
		node_bye_pending() && 
		(tick = time((time_t *) NULL)) - now < EXIT_GRACE
	) {
		g_snprintf(tmp, sizeof(tmp), "%d seconds", 
			EXIT_GRACE - (gint)difftime(tick,now));

		gtk_label_set(GTK_LABEL(label_shutdown_count),tmp);
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
	config_close();
	ban_close();
	cq_free(callout_queue);
	atom_str_free(version_string);
	atom_str_free(start_rfc822_date);
	atoms_close();

	if (dbg)
		printf("gtk-gnutella shut down cleanly.\n\n");

	gtk_exit(n);
}

static void sig_terminate(int n)
{
	gtk_gnutella_exit(1);
}

static void init_constants(void)
{
	struct utsname un;
	gchar buf[128];

	(void) uname(&un);

	g_snprintf(buf, sizeof(buf) - 1,
		"gtk-gnutella/%u.%u%s (%s; %s; %s %s %s)",
		GTA_VERSION, GTA_SUBVERSION, GTA_REVCHAR, GTA_RELEASE,
		GTA_INTERFACE, un.sysname, un.release, un.machine);

	start_time = time((time_t *) NULL);

	version_string = atom_str_get(buf);
	start_rfc822_date = atom_str_get(date_to_rfc822_gchar(start_time));
}

static void slow_main_timer(time_t now)
{
	static gint i = 0;

	i++;

	if (i & 0x1)
		ul_flush_stats_if_dirty();
	else
		dmesh_store();
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
	socket_monitor_incoming();		/* Expire connecting sockets */
	pcache_possibly_expired(now);	/* Expire pong cache */

	/*
	 * GUI update
	 */

	if (!exiting) {
		gui_statusbar_clear_timeouts(now);
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

	/* Our inits */

	atoms_init();
	callout_queue = cq_make(0);
	gui_init();
	init_constants();
	config_init();
	host_init();
	gmsg_init();
	bsched_init();
	network_init();
	routing_init();
	filter_init();	/* Must come before search_init() for retrieval */
	search_init();
    filter_update_targets(); /* Make sure the default filters are ok */
	share_init();
	download_init();
	autodownload_init();
	ban_init();
	dmesh_init();

   	gui_update_all();

	/* Some signal handlers */

	signal(SIGTERM, sig_terminate);
	signal(SIGINT, sig_terminate);
	signal(SIGPIPE, SIG_IGN);

#ifdef SIGXFSZ
	signal(SIGXFSZ, SIG_IGN);
#endif

	/* Create the main listening socket */

	if (listen_port)
		s_listen = socket_listen(0, listen_port, GTA_TYPE_CONTROL);

    /* Final interface setup (setting of values read from config) */
    
	gui_update_global();

	gtk_widget_show(main_window);		/* Display the main window */

	/* Setup the main timers */

	(void) g_timeout_add(1000, main_timer, NULL);
	(void) g_timeout_add(CALLOUT_PERIOD, callout_timer, NULL);
	(void) g_timeout_add(1000, scan_files_once, NULL);

	/* Okay, here we go */

	bsched_enable_all();
	gtk_main();

	return 0;
}

/* vi: set ts=4: */
