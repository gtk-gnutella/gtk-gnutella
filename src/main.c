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

#include "common.h"

#include <setjmp.h>

#define CORE_SOURCES

#include "core/ban.h"
#include "core/bitzi.h"
#include "core/bogons.h"
#include "core/bsched.h"
#include "core/clock.h"
#include "core/dh.h"
#include "core/dmesh.h"
#include "core/downloads.h"
#include "core/dq.h"
#include "core/extensions.h"
#include "core/features.h"
#include "core/fileinfo.h"
#include "core/geo_ip.h"
#include "core/gmsg.h"
#include "core/gnet_stats.h"
#include "core/gnutella.h"
#include "core/guid.h"
#include "core/gwcache.h"
#include "core/hcache.h"
#include "core/hostiles.h"
#include "core/hosts.h"
#include "core/hsep.h"
#include "core/http.h"
#include "core/ignore.h"
#include "core/inet.h"
#include "core/move.h"
#include "core/nodes.h"
#include "core/ntp.h"
#include "core/oob.h"
#include "core/parq.h"
#include "core/pcache.h"
#include "core/pproxy.h"
#include "core/routing.h"
#include "core/search.h"
#include "core/settings.h"
#include "core/share.h"
#include "core/sockets.h"
#include "core/sq.h"
#include "core/tsync.h"
#include "core/uhc.h"
#include "core/upload_stats.h"
#include "core/verify.h"
#include "core/version.h"
#include "core/whitelist.h"
#include "lib/adns.h"
#include "lib/atoms.h"
#include "lib/bg.h"
#include "lib/cq.h"
#include "lib/crc.h"
#include "lib/eval.h"
#include "lib/glib-missing.h"
#include "lib/iso3166.h"
#include "lib/pattern.h"
#include "lib/utf8.h"
#include "lib/walloc.h"
#include "lib/watcher.h"
#include "lib/wordvec.h"
#include "ui/gtk/drop.h"
#include "ui/gtk/gui.h"
#include "ui/gtk/icon.h"
#include "ui/gtk/main.h"
#include "ui/gtk/settings.h"
#include "ui/gtk/upload_stats.h"
#include "if/ui/gtk/search.h"
#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"

#ifdef USE_REMOTE_CTRL
#include "core/shell.h"
#endif

#include "lib/override.h"		/* Must be the last header included */

RCSID("$Id$");

#define SLOW_UPDATE_PERIOD		20	/* Updating period for `main_slow_update' */
#define EXIT_GRACE				30	/* Seconds to wait before exiting */
#define ATEXIT_TIMEOUT			20	/* Final cleanup must not take longer */

static guint main_slow_update = 0;
static gboolean exiting = FALSE;
static gboolean from_atexit = FALSE;
static gint signal_received = 0;
static jmp_buf atexit_env;
static volatile gchar *exit_step = "gtk_gnutella_exit";

void gtk_gnutella_exit(gint n);

/*
 * sig_alarm
 *
 * Force immediate shutdown of SIGALRM reception.
 */
static void sig_alarm(int n)
{
	(void) n;
	if (from_atexit) {
		g_warning("exit cleanup timed out -- forcing exit");
		longjmp(atexit_env, 1);
	}
}

#ifdef MALLOC_STATS
static gint signal_malloc = 0;

/*
 * sig_malloc
 *
 * Record USR1 or USR2 signal in `signal_malloc'.
 */
static void sig_malloc(int n)
{
	switch (n) {
	case SIGUSR1: signal_malloc = 1; break;
	case SIGUSR2: signal_malloc = 2; break;
	default: break;
	}
}
#endif /* MALLOC_STATS */

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
		set_signal(SIGALRM, sig_alarm);
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
	time_t exit_time = time((time_t *) NULL);
	gint exit_grace = EXIT_GRACE;

	if (exiting)
		return;			/* Already exiting, must be in loop below */

	exiting = TRUE;

#define DO(fn) 	do { exit_step = STRINGIFY(fn); fn(); } while (0)

#ifdef USE_REMOTE_CTRL
	DO(shell_close);
#endif

	DO(file_info_close_pre);
	DO(node_bye_all);
	DO(upload_close);	/* Done before upload_stats_close() for stats update */
	DO(upload_stats_close);
	DO(parq_close);
	DO(download_close);
	DO(pproxy_close);
	DO(http_close);
	DO(gwc_close);
	DO(uhc_close);
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

    hcache_shutdown();		/* Save host caches to disk */
	settings_shutdown();
	oob_shutdown();			/* No longer deliver outstanding OOB hits */
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

	while (node_bye_pending()) {
		time_t now = time(NULL);
		gint d;

		if ((d = delta_time(now, exit_time)) >= exit_grace)
			break;
		main_gui_shutdown_tick(exit_grace - d);
		sleep(1);
	}

	ntp_close();
	sq_close();
	dh_close();
	dq_close();
	hsep_close();
	drop_close();
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
	bogons_close();		/* Idem, since host_close() can touch the cache */
	hostiles_close();
	gip_close();
	ban_close();
	inet_close();
	whitelist_close();
	features_close();
	clock_close();
	watcher_close();
	tsync_close();
	cq_close();
	word_vec_close();
	pattern_close();
	pmsg_close();
	version_close();
	ignore_close();
	bg_close();
	eval_close();
	iso3166_close();
	atom_str_free(start_rfc822_date);
	adns_close();
	atoms_close();
	wdestroy();
	locale_close();
#ifdef TRACK_MALLOC
	malloc_close();
#endif


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
		hcache_store_if_dirty(HOST_ANY);
		break;
	case 2:
		upload_stats_flush_if_dirty();
		break;
	case 3:
		file_info_store_if_dirty();
		break;
	case 4:
		gwc_store_if_dirty();
		hcache_store_if_dirty(HOST_ULTRA);
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

	if (delta_time(now, last_warn) > 600) {
		version_ancient_warn();
		last_warn = now;
	}
}

static gboolean main_timer(gpointer p)
{
	void icon_timer(void);
	time_t now = time((time_t *) NULL);

	(void) p;
	if (signal_received) {
		g_warning("caught signal #%d, exiting...", signal_received);
		gtk_gnutella_exit(1);
	}

#ifdef MALLOC_STATS
	if (signal_malloc) {
		if (signal_malloc == 1)
			alloc_dump(stdout, FALSE);
		else if (signal_malloc == 2)
			alloc_reset(stdout, FALSE);
		signal_malloc = 0;
	}
#endif

	bsched_timer();					/* Scheduling update */
	host_timer();					/* Host connection */
    hcache_timer();
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
		hsep_timer(now);			/* HSEP notify message timer */
		pproxy_timer(now);			/* Push-proxy requests */
		dh_timer(now);				/* Monitoring of query hits */
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
 * scan_files_once
 *
 * Scan files when the GUI is up.
 */
static gboolean scan_files_once(gpointer p)
{
	(void) p;
	guc_allow_rescan_dir(FALSE);
	share_scan();
	guc_allow_rescan_dir(TRUE);

	return FALSE;
}

static void log_handler(const gchar *log_domain, GLogLevelFlags log_level,
	const gchar *message, gpointer user_data)
{
	gint saved_errno = errno;
	time_t now;
	struct tm *ct;
	const char *level;
	gchar *safer;

	(void) log_domain;
	(void) user_data;
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

#if 0
	/* Define to debug Glib or Gtk problems */
	if (log_domain &&
		(!strcmp(log_domain, "Gtk") || !strcmp(log_domain, "GLib"))
	) {
		raise(SIGTRAP);
	}
#endif

	errno = saved_errno;
}

static void log_init(void)
{
	const gchar *domains[] = { G_LOG_DOMAIN, "Gtk", "GLib" };
	guint i;

	for (i = 0; i < G_N_ELEMENTS(domains); i++) {
		g_log_set_handler(domains[i],
			G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING |
			G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_INFO | G_LOG_LEVEL_DEBUG,
			log_handler, NULL);
	}
}

extern char **environ;

int
main(int argc, char **argv)
{
	gint i;

	if (0 == getuid() || 0 == geteuid()) {
		fprintf(stderr, "Never ever run this as root!\n");
		exit(EXIT_FAILURE);
	}

	for (i = 3; i < 256; i++)
		close(i);				/* Just in case */

	set_signal(SIGINT, SIG_IGN);	/* ignore SIGINT in adns (e.g. for gdb) */
	set_signal(SIGPIPE, SIG_IGN);

#ifdef MALLOC_STATS
	set_signal(SIGUSR1, sig_malloc);
	set_signal(SIGUSR2, sig_malloc);
#endif

	gm_savemain(argc, argv, environ);	/* For gm_setproctitle() */

	/* Our inits */
	log_init();
#ifndef OFFICIAL_BUILD
	g_warning("%s \"%s\"",
		_("This is an unofficial build which accesses "
			"files in this directory:"),
		PACKAGE_SOURCE_DIR);
#endif

	random_init();
	locale_init();
	adns_init();
	atoms_init();
	eval_init();
	version_init();
	socket_init();
	gnet_stats_init();
	iso3166_init();
	main_gui_early_init(argc, argv);
	cq_init();
	tsync_init();
	watcher_init();
	hcache_init(); /* before settings_init() */
	settings_init();
    hcache_retrieve_all(); /* after settings_init() */
	hostiles_init();
	bogons_init();
	gip_init();
	guid_init();
	gwc_init();
	uhc_init();
	verify_init();
	move_init();
	ignore_init();
	file_info_init();
	pattern_init();
	word_vec_init();
	host_init();
	pmsg_init();
	gmsg_init();
	bsched_init();
	node_init();
	routing_init();
	search_init();
	share_init();
	dmesh_init();			/* MUST be done BEFORE download_init() */
	download_init();		/* MUST be done AFTER file_info_init() */
	upload_init();
#ifdef USE_REMOTE_CTRL
	shell_init();
#endif
	ban_init();
	whitelist_init();
	ext_init();
	inet_init();
	crc_init();
	parq_init();
	hsep_init();
	clock_init();
	dq_init();
	dh_init();
	bitzi_init();
	sq_init();
	file_info_init_post();

	main_gui_init();
	node_post_init();

	drop_init();
	download_restore_state();
	ntp_init();

	/* Some signal handlers */

	set_signal(SIGTERM, sig_terminate);
	set_signal(SIGINT, sig_terminate);

#ifdef SIGXFSZ
	set_signal(SIGXFSZ, SIG_IGN);
#endif

	/* Setup the main timers */

	(void) g_timeout_add(1000, main_timer, NULL);
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
