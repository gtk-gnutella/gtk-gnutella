/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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
#include <ctype.h>
#include <setjmp.h>

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
#include "verify.h"
#include "move.h"
#include "extensions.h"
#include "inet.h"
#include "parq.h"
#include "adns.h"
#include "crc.h"
#include "icon.h"
#include "hostiles.h"
#include "clock.h"
#include "eval.h"
#include "pproxy.h"

#ifdef USE_REMOTE_CTRL
#include "shell.h"
#endif

#include "main_gui.h"
#include "settings.h"
#include "fileinfo.h"
#include "settings_gui.h"

RCSID("$Id$");

#define SLOW_UPDATE_PERIOD		20	/* Updating period for `main_slow_update' */
#define EXIT_GRACE				30	/* Seconds to wait before exiting */
#define CALLOUT_PERIOD			100	/* milliseconds */
#define ATEXIT_TIMEOUT			20	/* Final cleanup must not take longer */

/* */

struct gnutella_socket *s_listen = NULL;
gchar *start_rfc822_date = NULL;		/* RFC822 format of start_time */
cqueue_t *callout_queue;

static guint main_slow_update = 0;
static gboolean exiting = FALSE;
static gboolean from_atexit = FALSE;
static gint signal_received = 0;
static jmp_buf atexit_env;
static volatile gchar *exit_step = "gtk_gnutella_exit";

/*
 * sig_alarm
 *
 * Force immediate shutdown of SIGALRM reception.
 */
static void sig_alarm(int n)
{
	if (from_atexit) {
		g_warning("exit cleanup timed out -- forcing exit");
		longjmp(atexit_env, 1);
	}
}

/*
 * gtk_gnutella_atexit
 *
 * Invoked as an atexit() callback when someone does an exit().
 */
static void gtk_gnutella_atexit()
{
	/*
	 * There's no way the gtk_gnutella_exit() routine can have its signature
	 * changed, so we use the `from_atexit' global to indicate that we're
	 * coming from the atexit() callback, mainly to suppress the final
	 * gtk_exit() call, as well as the shutdown countdown.
	 */

	if (!exiting) {
		g_warning("trapped foreign exit(), cleaning up...");
		from_atexit = TRUE;
		signal(SIGALRM, sig_alarm);
		if (setjmp(atexit_env)) {
			g_warning("cleanup aborted while in %s().", exit_step);
			return;
		}
		alarm(ATEXIT_TIMEOUT);
		gtk_gnutella_exit(1);	/* Won't exit() since from_atexit is set */
		alarm(0);
		g_warning("cleanup all done.");
	}
}

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
	time_t exit_grace = EXIT_GRACE;

	if (exiting)
		return;			/* Already exiting, must be in loop below */

	exiting = TRUE;

#define DO(fn) 	do { exit_step = STRINGIFY(fn); fn(); } while (0)

#ifdef USE_REMOTE_CTRL
    DO(shell_close);
#endif

	DO(node_bye_all);
	DO(upload_close);	/* Done before upload_stats_close() for stats update */
	DO(upload_stats_close);
	DO(parq_close);
	DO(download_close);
	DO(pproxy_close);
	DO(http_close);
	DO(gwc_close);
	DO(verify_close);
	DO(move_close);

	/*
	 * When coming from atexit(), there is a sense of urgency.
	 * We have saved most of the dynamic data above, finish with
	 * the properties and exit.
	 */

	DO(settings_save_if_dirty);
	DO(settings_gui_save_if_dirty);

	if (from_atexit)
		return;

#undef DO

	main_gui_update_coords();
    main_gui_shutdown();

	settings_shutdown();
	socket_shutdown();
	search_shutdown(); 
	bsched_shutdown();
	settings_gui_shutdown();

	/* 
	 * Wait at most EXIT_GRACE seconds, so that BYE messages can go through.
	 * This amount of time is doubled when running in Ultra mode since we
	 * have more connections to flush.
	 */

	if (current_peermode == NODE_P_ULTRA)
		exit_grace *= 2;

	if (s_listen) {
		socket_free(s_listen);		/* No longer accept connections */
		s_listen = NULL;
	}

	while (
		node_bye_pending() && 
		(tick = time((time_t *) NULL)) - now < exit_grace
	) {
        main_gui_shutdown_tick(exit_grace - (gint) difftime(tick, now));
		usleep(200000);					/* 200 ms */
	}

	hostiles_close();
    file_info_close();
	ext_close();
	share_close();
	node_close();
	routing_close();	/* After node_close() */
	bsched_close();
	dmesh_close();
	host_close();
	hcache_close();		/* After host_close() */
	settings_close();	/* Must come after hcache_close() */
	ban_close();
    whitelist_close();
	header_features_close();
	clock_close();
	cq_free(callout_queue);
	matching_close();
	pmsg_close();
	version_close();
	ignore_close();
	bg_close();
	eval_close();
	atom_str_free(start_rfc822_date);
	adns_close();
	atoms_close();
	wdestroy();

	if (dbg)
		printf("gtk-gnutella shut down cleanly.\n\n");

	gtk_exit(n);
}

static void sig_terminate(int n)
{
	signal_received = n;		/* Terminate asynchronously in main_timer() */

	if (from_atexit)			/* Might be stuck in some cleanup callback */
		exit(1);				/* Terminate ASAP */
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
	time_t now = clock_loc2gmt(time(NULL));
	start_rfc822_date = atom_str_get(date_to_rfc822_gchar(now));
	gnet_prop_set_guint32_val(PROP_START_STAMP, (guint32) now);
}

/* FIXME: this is declared in search_gui.c and should be called in the
 *        main timer loop of the gui.
 */
void search_gui_store_searches(void);
static void slow_main_timer(time_t now)
{
	static gint i = 0;
	static time_t last_warn = 0;

	switch (i) {
	case 0:
		dmesh_store();
		dmesh_ban_store();
		break;
	case 1:
		search_gui_store_searches();
		break;
	case 2:
		upload_stats_flush_if_dirty();
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

	if (++i > 4)
		i = 0;

	download_store_if_dirty();		/* Important, so always attempt it */
	settings_save_if_dirty();		/* Nice to have, and file is small */
	settings_gui_save_if_dirty();	/* Ditto */
	node_slow_timer(now);
	ignore_timer(now);

	if (now - last_warn > 600) {
		version_ancient_warn();
		last_warn = now;
	}
}

static gboolean main_timer(gpointer p)
{
	void icon_timer(void);
	time_t now = time((time_t *) NULL);

	if (signal_received) {
		g_warning("caught signal #%d, exiting...", signal_received);
		gtk_gnutella_exit(1);
	}

	bsched_timer();					/* Scheduling update */
	host_timer();					/* Host connection */
	node_timer(now);				/* Node timeouts */
	http_timer(now);				/* HTTP request timeouts */
	if (!exiting) {
#ifdef USE_REMOTE_CTRL
        shell_timer(now);
#endif
		download_timer(now);  	    /* Download timeouts */
		parq_upload_timer(now);		/* PARQ upload timeouts/removal */
		upload_timer(now);			/* Upload timeouts */
        file_info_timer();          /* Notify about changes */
		pproxy_timer(now);			/* Push-proxy requests */
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
	
	icon_timer();
	bg_sched_timer();				/* Background tasks */

	return TRUE;
}

/*
 * callout_timer
 *
 * Called every CALLOUT_PERIOD to heartbeat the callout queue.
 */
static gboolean callout_timer(gpointer p)
{
	static GTimeVal last_period = { 0L, 0L };
	GTimeVal tv;
	gint delay;

	g_get_current_time(&tv);

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

static void log_handler(const gchar *log_domain, GLogLevelFlags log_level,
	const gchar *message, gpointer user_data)
{
	time_t now;
	struct tm *ct;
	const char *level;
	gchar *safer;

	now = time(NULL);
	ct = localtime(&now);

	switch (log_level) {
	case G_LOG_LEVEL_CRITICAL:
		level = "CRITICAL"; 
		break;
	case G_LOG_LEVEL_ERROR:
		level = "ERROR"; 
		break;
	case G_LOG_LEVEL_WARNING:
		level = "WARNING"; 
		break;
	case G_LOG_LEVEL_MESSAGE:
		level = "MESSAGE"; 
		break;
	case G_LOG_LEVEL_INFO:
		level = "INFO"; 
		break;
	case G_LOG_LEVEL_DEBUG:
		level = "DEBUG"; 
		break;
	default:
		level = "UNKNOWN";
	}

	safer = hex_escape(message, FALSE); /* non-strict escaping */

	fprintf(stderr, "%.2d/%.2d/%.2d %.2d:%.2d:%.2d (%s): %s\n",
		ct->tm_year % 100, ct->tm_mon + 1, ct->tm_mday,
		ct->tm_hour, ct->tm_min, ct->tm_sec, level, safer);

	if (safer != message)
		G_FREE_NULL(safer);
}
 
static void log_init(void)
{
	g_log_set_handler(G_LOG_DOMAIN,
		G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING |
		G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_INFO | G_LOG_LEVEL_DEBUG,
		log_handler, NULL);
}

gint main(gint argc, gchar **argv, gchar **env)
{
	gint i;

	if (0 == getuid() || 0 == geteuid()) {
		fprintf(stderr, "Never ever run this as root!\n");
		exit(EXIT_FAILURE); 
	}

	for (i = 3; i < 256; i++)
		close(i);				/* Just in case */

	signal(SIGINT, sig_ignore);		/* ignore SIGINT in adns (e.g. for gdb) */
	signal(SIGPIPE, sig_ignore);	/* Not SIG_IGN, see comment */

	gm_savemain(argc, argv, env);	/* For gm_setproctitle() */

	/* Our inits */
	log_init();
	locale_init();
	adns_init();
	atoms_init();
	eval_init();
	version_init();
	random_init();
    gnet_stats_init();
    main_gui_early_init(argc, argv);
	callout_queue = cq_make(0);
	hcache_init();
	settings_init();
	init_constants();
	guid_init();
	gwc_init();
	verify_init();
	move_init();
	ignore_init();
	file_info_init();
	matching_init();
	host_init();
	pmsg_init();
	gmsg_init();
	bsched_init();
	node_init();
	routing_init();
	search_init();
	share_init();
	dmesh_init();			/* Muse be done BEFORE download_init() */
	download_init();
	upload_init();
#ifdef USE_REMOTE_CTRL
    shell_init();
#endif
	ban_init();
    whitelist_init();
	ext_init();
	inet_init();
	crc_init();
	hostiles_init();
	parq_init();
	clock_init();

    main_gui_init();

    download_restore_state();

	/* Some signal handlers */

	signal(SIGTERM, sig_terminate);
	signal(SIGINT, sig_terminate);

#ifdef SIGXFSZ
	signal(SIGXFSZ, sig_ignore);
#endif

	/* Setup the main timers */

	(void) g_timeout_add(1000, main_timer, NULL);
	(void) g_timeout_add(CALLOUT_PERIOD, callout_timer, NULL);
	(void) g_timeout_add(1000, scan_files_once, NULL);

	/* Prepare against X connection losses -> exit() */

	atexit(gtk_gnutella_atexit);

	/* Okay, here we go */

	bsched_enable_all();
	version_ancient_warn();
    main_gui_run();

	return 0;
}

/* vi: set ts=4: */
