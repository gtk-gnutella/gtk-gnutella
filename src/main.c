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
#include "gui.h"

#include <signal.h>
#include <locale.h>

#include "search.h"
#include "share.h"
#include "sockets.h"
#include "routing.h"
#include "downloads.h"
#include "hosts.h"
#include "gmsg.h"
#include "bsched.h"
#include "upload_stats.h"
#include "pcache.h"
#include "ban.h"
#include "dmesh.h"
#include "version.h"
#include "nodes.h"
#include "whitelist.h"
#include "ignore.h"
#include "guid.h"
#include "gnet_stats.h"
#include "http.h"
#include "gwcache.h"

#include "main_gui.h"
#include "settings.h"
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

	if (exiting)
		return;			/* Already exiting, must be in loop below */

	exiting = TRUE;

	node_bye_all();
	upload_close();		/* Done before settings_close() for stats update */
	download_close();
	http_close();
	gwc_close();

    main_gui_shutdown();

	if (hosts_idle_func)
		g_source_remove(hosts_idle_func);

	if (s_listen)
		socket_destroy(s_listen);
	socket_shutdown();
	search_shutdown(); 
	bsched_shutdown();
	settings_shutdown();

	/* 
	 * Wait at most EXIT_GRACE seconds, so that BYE messages can go through.
	 */

	while (
		node_bye_pending() && 
		(tick = time((time_t *) NULL)) - now < EXIT_GRACE
	) {
        main_gui_shutdown_tick(EXIT_GRACE - (gint)difftime(tick,now));
		usleep(200000);					/* 200 ms */
	}

	share_close();
	node_close();
	host_close();
	routing_close();
	bsched_close();
	dmesh_close();
	settings_close();
	ban_close();
    whitelist_close();
	cq_free(callout_queue);
	matching_close();
	pmsg_close();
	version_close();
	ignore_close();
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

// FIXME: this is declared in search_gui.c and should be called in the
//        main timer loop of the gui.
void search_gui_store_searches(void);
static void slow_main_timer(time_t now)
{
	static gint i = 0;

	switch (i) {
	case 0:
		dmesh_store();
		dmesh_ban_store();
		break;
	case 1:
		search_gui_store_searches();
		break;
	case 2:
		ul_flush_stats_if_dirty();
		break;
	case 3:
		file_info_store_if_dirty();
		break;
	case 4:
		gwc_store_if_dirty();
		break;
	default:
		g_assert(0);
	}

	ignore_timer(now);

	if (++i > 4)
		i = 0;
}

static gboolean main_timer(gpointer p)
{
	time_t now = time((time_t *) NULL);

	bsched_timer();					/* Scheduling update */
	host_timer();					/* Host connection */
	node_timer(now);				/* Node timeouts */
	http_timer(now);				/* HTTP request timeouts */
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
        main_gui_timer();

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


    gnet_stats_init();
    main_gui_early_init(argc, argv);
    
	/* Our inits */
	random_init();
	atoms_init();
	version_init();
	callout_queue = cq_make(0);
	init_constants();
	settings_init();
	guid_init();
	gwc_init();
	ignore_init();
	file_info_init();
	matching_init();
	host_init();
	pmsg_init();
	gmsg_init();
	bsched_init();
	network_init();
	routing_init();
	search_init();
	share_init();
	dmesh_init();			/* Muse be done BEFORE download_init() */
	download_init();
	upload_init();
	ban_init();
    whitelist_init();

    main_gui_init();

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
