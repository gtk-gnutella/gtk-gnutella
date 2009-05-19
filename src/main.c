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

/**
 * @ingroup core
 * @file
 *
 * Main functions for gtk-gnutella.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#include "common.h"
#include "revision.h"

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
#include "core/dump.h"
#include "core/extensions.h"
#include "core/features.h"
#include "core/fileinfo.h"
#include "core/file_object.h"
#include "core/gdht.h"
#include "core/geo_ip.h"
#include "core/gmsg.h"
#include "core/gnet_stats.h"
#include "core/gnutella.h"
#include "core/guid.h"
#include "core/hcache.h"
#include "core/hostiles.h"
#include "core/hosts.h"
#include "core/hsep.h"
#include "core/http.h"
#include "core/ignore.h"
#include "core/inet.h"
#include "core/ipp_cache.h"
#include "core/local_shell.h"
#include "core/move.h"
#include "core/nodes.h"
#include "core/ntp.h"
#include "core/oob.h"
#include "core/parq.h"
#include "core/pcache.h"
#include "core/pproxy.h"
#include "core/routing.h"
#include "core/rx.h"
#include "core/search.h"
#include "core/settings.h"
#include "core/share.h"
#include "core/sockets.h"
#include "core/spam.h"
#include "core/sq.h"
#include "core/tls_common.h"
#include "core/topless.h"
#include "core/tsync.h"
#include "core/tx.h"
#include "core/udp.h"
#include "core/uhc.h"
#include "core/upload_stats.h"
#include "core/verify_sha1.h"
#include "core/verify_tth.h"
#include "core/version.h"
#include "core/vmsg.h"
#include "core/whitelist.h"
#include "if/dht/kmsg.h"
#include "if/dht/dht.h"
#include "lib/adns.h"
#include "lib/atoms.h"
#include "lib/bg.h"
#include "lib/cq.h"
#include "lib/crash.h"
#include "lib/crc.h"
#include "lib/debug.h"
#include "lib/dbus_util.h"
#include "lib/eval.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/iso3166.h"
#include "lib/map.h"
#include "lib/mime_type.h"
#include "lib/patricia.h"
#include "lib/pattern.h"
#include "lib/socket.h"
#include "lib/strtok.h"
#include "lib/tea.h"
#include "lib/tiger.h"
#include "lib/tigertree.h"
#include "lib/tm.h"
#include "lib/utf8.h"
#include "lib/vendors.h"
#include "lib/walloc.h"
#include "lib/watcher.h"
#include "lib/wordvec.h"
#include "lib/zalloc.h"
#include "shell/shell.h"

#include "ui/gtk/gui.h"

#if defined(USE_GTK1) || defined(USE_GTK2)
#include "ui/gtk/main.h"
#include "ui/gtk/settings.h"
#include "ui/gtk/upload_stats.h"
#endif /* GTK */

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"
#include "if/core/main.h"

#include "lib/override.h"		/* Must be the last header included */

RCSID("$Id$")

#define SLOW_UPDATE_PERIOD		20	/**< Update period for `main_slow_update' */
#define EXIT_GRACE				30	/**< Seconds to wait before exiting */
#define ATEXIT_TIMEOUT			20	/**< Final cleanup must not take longer */

#define LOAD_HIGH_WATERMARK		90	/**< % amount over which we're overloaded */
#define LOAD_LOW_WATERMARK		55	/**< lower threshold to clear condition */

static guint main_slow_update = 0;
static gboolean exiting = FALSE;
static volatile sig_atomic_t from_atexit = FALSE;
static volatile sig_atomic_t signal_received = 0;
static volatile sig_atomic_t shutdown_requested = 0;
static volatile sig_atomic_t sig_hup_received = 0;
static jmp_buf atexit_env;
static volatile const gchar *exit_step = "gtk_gnutella_exit";
static tm_t start_time;

void gtk_gnutella_exit(gint n);
static gint reopen_log_files(void);
static gboolean stderr_disabled;

/**
 * Force immediate shutdown of SIGALRM reception.
 */
static void
sig_alarm(int n)
{
	(void) n;
	if (from_atexit) {
		g_warning("exit cleanup timed out -- forcing exit");
		longjmp(atexit_env, 1);
	}
}

static void
sig_hup(int n)
{
	(void) n;
	sig_hup_received = 1;
}

static void
sig_chld(int n)
{
	int saved_errno = errno;
	(void) n;
	while (waitpid(-1, NULL, WNOHANG) > 0)
		continue;
	errno = saved_errno;
}

#if defined(FRAGCHECK) || defined(MALLOC_STATS)
static volatile sig_atomic_t signal_malloc = 0;

/**
 * Record USR1 or USR2 signal in `signal_malloc'.
 */
static void
sig_malloc(int n)
{
	switch (n) {
	case SIGUSR1: signal_malloc = 1; break;
	case SIGUSR2: signal_malloc = 2; break;
	default: break;
	}
}
#endif /* MALLOC_STATS */

/**
 * Get build number.
 */
guint32
main_get_build(void)
{
	static guint32 build;
	static int initialized;

	if (build)
		return build;

	if (!initialized) {
		const char *p;

		initialized = TRUE;
		p = is_strprefix(GTA_BUILD, "$Revision: ");
		if (p) {
			int error;
			build = parse_uint32(p, NULL, 10, &error);
		}
	}
	return build;
}

/**
 * Are we debugging anything at a level greater than some threshold "t"?
 */
gboolean
debugging(guint t)
{
	return
		GNET_PROPERTY(ban_debug) > t ||
		GNET_PROPERTY(bitzi_debug) > t ||
		GNET_PROPERTY(bootstrap_debug) > t ||
		GNET_PROPERTY(dbg) > t ||
		GNET_PROPERTY(dh_debug) > t ||
		GNET_PROPERTY(dht_debug) > t ||
		GNET_PROPERTY(dmesh_debug) > t ||
		GNET_PROPERTY(download_debug) > t ||
		GNET_PROPERTY(dq_debug) > t ||
		GNET_PROPERTY(fileinfo_debug) > t ||
		GNET_PROPERTY(ggep_debug) > t ||
		GNET_PROPERTY(gmsg_debug) > t ||
		GNET_PROPERTY(hsep_debug) > t ||
		GNET_PROPERTY(http_debug) > t ||
		GNET_PROPERTY(lib_debug) > t ||
		GNET_PROPERTY(node_debug) > t ||
		GNET_PROPERTY(oob_proxy_debug) > t ||
		GNET_PROPERTY(parq_debug) > t ||
		GNET_PROPERTY(pcache_debug) > t ||
		GNET_PROPERTY(qrp_debug) > t ||
		GNET_PROPERTY(query_debug) > t ||
		GNET_PROPERTY(routing_debug) > t ||
		GNET_PROPERTY(rudp_debug) > t ||
		GNET_PROPERTY(search_debug) > t ||
		GNET_PROPERTY(share_debug) > t ||
		GNET_PROPERTY(socket_debug) > t ||
		GNET_PROPERTY(tls_debug) > t ||
		GNET_PROPERTY(udp_debug) > t ||
		GNET_PROPERTY(upload_debug) > t ||
		GNET_PROPERTY(url_debug) > t ||
		GNET_PROPERTY(vmsg_debug) > t ||

		/* Above line left blank for easy "!}sort" under vi */
		0;
}

const char *
gtk_gnutella_interface(void)
{
	return running_topless ? "Topless" : GTA_INTERFACE;
}

/**
 * Invoked as an atexit() callback when someone does an exit().
 */
static void
gtk_gnutella_atexit(void)
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

#ifdef SIGALRM
		set_signal(SIGALRM, sig_alarm);
#endif
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

/**
 * Log cpu used since last time.
 *
 * @param since_time	time at which the measurement period started, updated
 * @param prev_user		previous total user time, updated if not NULL
 * @param prev_sys		previous total system time, updated if not NULL
 */
static void
log_cpu_usage(tm_t *since_time, gdouble *prev_user, gdouble *prev_sys)
{
	gdouble user;
	gdouble sys;
	gdouble total;
	tm_t cur_time;
	gdouble elapsed;

	tm_now_exact(&cur_time);
	total = tm_cputime(&user, &sys);
	if (prev_user) {
		gdouble v = *prev_user;
		*prev_user = user;
		user -= v;
		total -= v;
	}
	if (prev_sys) {
		gdouble v = *prev_sys;
		*prev_sys = sys;
		sys -= v;
		total -= v;
	}

	elapsed = tm_elapsed_f(&cur_time, since_time);
	*since_time = cur_time;

	g_message("average CPU used: %.3f%% over %.2f secs",
		100.0 * total / elapsed, elapsed);
	g_message("CPU usage: total: %.2fs (user: %.2f, sys: %.2f)",
		total, user, sys);
}

void
gtk_gnutella_request_shutdown(void)
{
	shutdown_requested = 1;
}

/**
 * Exit program, return status `n' to parent process.
 *
 * Shutdown systems, so we can track memory leaks, and wait for EXIT_GRACE
 * seconds so that BYE messages can be sent to other nodes.
 */
void
gtk_gnutella_exit(gint n)
{
	time_t exit_time = time(NULL);
	time_delta_t exit_grace = EXIT_GRACE;
	static gboolean safe_to_exit = FALSE;

	if (exiting) {
		if (safe_to_exit) {
			g_warning("forced exit(%d), good bye.", n);
			exit(n);
		}
		g_warning("ignoring re-entrant exit(%d), unsafe now (in %s)",
			n, exit_step);
		return;
	}

	exiting = TRUE;

#define DO(fn) 	do { exit_step = #fn; fn(); } while (0)

	DO(shell_close);
	DO(file_info_store_if_dirty);
	DO(file_info_close_pre);
	DO(node_bye_all);
	DO(upload_close);	/* Done before upload_stats_close() for stats update */
	DO(upload_stats_close);
	DO(parq_close_pre);
	DO(verify_sha1_close);
	DO(verify_tth_close);
	DO(download_close);
	DO(parq_close);
	DO(pproxy_close);
	DO(http_close);
	DO(uhc_close);
	DO(move_close);
	DO(dht_close);
	DO(ipp_cache_save_all);

	/*
	 * When coming from atexit(), there is a sense of urgency.
	 * We have saved most of the dynamic data above, finish with
	 * the properties and exit.
	 */

	DO(settings_save_if_dirty);

	safe_to_exit = TRUE;	/* Will immediately exit if re-entered */

	if (debugging(0) || signal_received || shutdown_requested)
		g_message("context files and settings closed properly");

	if (from_atexit)
		return;

#undef DO

	if (!running_topless) {
		settings_gui_save_if_dirty();
		main_gui_shutdown();

		if (debugging(0) || signal_received || shutdown_requested)
			g_message("GUI shutdown completed");
	}

	cq_halt();				/* No more callbacks, with everything shutdown */
	hcache_shutdown();		/* Save host caches to disk */
	settings_shutdown();
	oob_shutdown();			/* No longer deliver outstanding OOB hits */
	socket_shutdown();
	bsched_shutdown();

	if (!running_topless) {
		settings_gui_shutdown();
	}

	/*
	 * Show total CPU used, and the amount spent in user / kernel, before
	 * we start the grace period...
	 */

	if (debugging(0)) {
		tm_t since = start_time;
		log_cpu_usage(&since, NULL, NULL);
	}

	/*
	 * Wait at most EXIT_GRACE seconds, so that BYE messages can go through.
	 * This amount of time is doubled when running in Ultra mode since we
	 * have more connections to flush.
	 */

	if (GNET_PROPERTY(current_peermode) == NODE_P_ULTRA)
		exit_grace *= 2;

	if (debugging(0) || signal_received || shutdown_requested) {
		g_message("waiting at most %s for BYE messages",
			short_time(exit_grace));
	}

	while (node_bye_pending()) {
		time_t now = time(NULL);
		time_delta_t d;

		if (signal_received)
			break;

		if ((d = delta_time(now, exit_time)) >= exit_grace)
			break;

		if (!running_topless) {
			main_gui_shutdown_tick(exit_grace - d);
		}
		compat_sleep_ms(50);
	}

	if (debugging(0) || signal_received || shutdown_requested)
		g_message("running final shutdown sequence...");

	search_shutdown();		/* Disable now, since we can get queries above */

	bitzi_close();
	ntp_close();
	gdht_close();
	sq_close();
	dh_close();
	dq_close();
	hsep_close();
	file_info_close();
	ext_close();
	share_close();
	node_close();
	udp_close();
	routing_close();	/* After node_close() */
	bsched_close();
	dmesh_close();
	host_close();
	hcache_close();		/* After host_close() */
	bogons_close();		/* Idem, since host_close() can touch the cache */
	tx_collect();		/* Prevent spurious leak notifications */
	rx_collect();		/* Idem */
	hostiles_close();
	spam_close();
	gip_close();
	ban_close();
	inet_close();
	whitelist_close();
	features_close();
	clock_close();
	vmsg_close();
	watcher_close();
	tsync_close();
	word_vec_close();
	pattern_close();
	pmsg_close();
	version_close();
	ignore_close();
	bg_close();
	eval_close();
	iso3166_close();
	atom_str_free_null(&start_rfc822_date);
	adns_close();
	dbus_util_close();  /* After adns_close() to avoid strange crashes */
	ipp_cache_close();
	dump_close();
	file_object_close();
	settings_close();	/* Must come after hcache_close() */
	misc_close();
	inputevt_close();
	locale_close();
	cq_close();

	/*
	 * Memory shutdown must come last.
	 */

	atoms_close();
	wdestroy();
	zclose();
	malloc_close();

	if (debugging(0) || signal_received || shutdown_requested) {
		g_message("gtk-gnutella shut down cleanly.");
	}
	if (!running_topless) {
		main_gui_exit(n);
	}
	exit(n);
}

static void
sig_terminate(int n)
{
	signal_received = n;		/* Terminate asynchronously in main_timer() */

	if (from_atexit)			/* Might be stuck in some cleanup callback */
		exit(1);				/* Terminate ASAP */
}

static void
slow_main_timer(time_t now)
{
	static guint i = 0;

	if (GNET_PROPERTY(cpu_debug)) {
		static tm_t since = { 0, 0 };
		static gdouble user = 0.0;
		static gdouble sys = 0.0;

		if (since.tv_sec == 0)
			since = start_time;

		log_cpu_usage(&since, &user, &sys);
	}

	switch (i) {
	case 0:
		dmesh_store();
		dmesh_ban_store();
		version_ancient_warn();
		break;
	case 1:
		hcache_store_if_dirty(HOST_ANY);
		break;
	case 2:
		upload_stats_flush_if_dirty();
		dht_update_size_estimate();
		break;
	case 3:
		file_info_store_if_dirty();
		file_info_slow_timer();
		break;
	case 4:
		hcache_store_if_dirty(HOST_ULTRA);
		break;
	case 5:
		dht_route_store_if_dirty();
		break;
	default:
		g_assert_not_reached();
	}
	i = (i + 1) % 6;

	download_store_if_dirty();		/* Important, so always attempt it */
	settings_save_if_dirty();		/* Nice to have, and file is small */
	if (!running_topless) {
		settings_gui_save_if_dirty();	/* Ditto */
	}
	tx_collect();					/* Collect freed TX stacks */
	rx_collect();					/* Idem for freed RX stacks */
	prune_page_cache();

	download_slow_timer(now);
	node_slow_timer(now);
	ignore_timer(now);
}

/**
 * Check CPU usage.
 *
 * @return current (exact) system time.
 */
static time_t
check_cpu_usage(void)
{
	static tm_t last_tm;
	static gdouble last_cpu = 0.0;
	static gint ticks = 0;
	static gint load_avg = 0;		/* 100 * cpu% for integer arithmetic */
	static gint avg = 0;			/* cpu% */
	tm_t cur_tm;
	gint load = 0;
	gdouble cpu;
	gdouble elapsed;
	gdouble cpu_percent;
	gdouble coverage;

	/*
	 * Compute CPU time used this period.
	 */

	tm_now_exact(&cur_tm);
	cpu = tm_cputime(NULL, NULL);

	elapsed = tm_elapsed_f(&cur_tm, &last_tm);
	elapsed = MAX(elapsed, 0.000001);	/* Prevent division by zero */
	cpu_percent = 100.0 * (cpu - last_cpu) / elapsed;
	cpu_percent = MIN(cpu_percent, 100.0);

	coverage = callout_queue_coverage(ticks);
	coverage = MAX(coverage, 0.001);	/* Prevent division by zero */

	if (GNET_PROPERTY(cq_debug) > 2) {
		g_message("CQ: callout queue \"%s\" items=%d ticks=%d coverage=%d%%",
			cq_name(callout_queue), cq_count(callout_queue),
			cq_ticks(callout_queue), (int) (coverage * 100.0 + 0.5));
	}

	/*
	 * Correct the percentage of CPU that would have been actually used
	 * if we had had 100% of the CPU scheduling time.  We use the callout
	 * queue as a rough estimation of the CPU running time we had: the less
	 * ticks were received by the callout queue, the busier the CPU was
	 * running other things.  But we can be busy running our own code,
	 * not really because the CPU is used by other processes, so we cannot
	 * just divide by the coverage ratio.
	 *
	 * The average load is computed using a medium exponential moving average.
	 */

	if (coverage <= 0.1)
		cpu_percent *= 4;
	else if (coverage <= 0.2)
		cpu_percent *= 3;
	else if (coverage <= 0.5)
		cpu_percent *= 1.5;

	load = (gint) cpu_percent * 100;
	load_avg += (load >> 3) - (load_avg >> 3);
	avg = load_avg / 100;

	if (GNET_PROPERTY(cpu_debug) > 1 && last_cpu)
		g_message("CPU: %.3f secs in %.3f secs (~%.3f%% @ cover=%.2f) avg=%d%%",
			cpu - last_cpu, elapsed, cpu_percent, coverage, avg);

	/*
	 * Update for next time.
	 */

	last_cpu = cpu;
	last_tm = cur_tm;		/* Struct copy */
	ticks = cq_ticks(callout_queue);

	/*
	 * Check whether we're overloaded, or if we were, whether we decreased
	 * the average load enough to disable the "overloaded" condition.
	 */

	if (avg >= LOAD_HIGH_WATERMARK && !GNET_PROPERTY(overloaded_cpu)) {
		if (debugging(0))
			g_message("high average CPU load (%d%%), entering overloaded state",
				avg);
		gnet_prop_set_boolean_val(PROP_OVERLOADED_CPU, TRUE);
	} else if (GNET_PROPERTY(overloaded_cpu) && avg < LOAD_LOW_WATERMARK) {
		if (debugging(0))
			g_message("average CPU load (%d%%) low, leaving overloaded state",
				avg);
		gnet_prop_set_boolean_val(PROP_OVERLOADED_CPU, FALSE);
	}

	return tm_time();		/* Exact, since tm_now_exact() called on entry */
}

/**
 * Main timer routine, called once per second.
 */
static gboolean
main_timer(gpointer p)
{
	time_t now;

	(void) p;
	if (signal_received || shutdown_requested) {
		if (signal_received) {
			g_warning("caught signal #%d, exiting...", signal_received);
		}
		gtk_gnutella_exit(1);
	}

	now = check_cpu_usage();

#if defined(FRAGCHECK) || defined(MALLOC_STATS)
	switch (signal_malloc) {
	case 1: alloc_dump(stdout, FALSE); break;
	case 2: alloc_reset(stdout, FALSE); break;
	}
	signal_malloc = 0;
#endif

	if (sig_hup_received) {
		sig_hup_received = 0;
		reopen_log_files();
	}

	bsched_timer();					/* Scheduling update */
	host_timer();					/* Host connection */
    hcache_timer(now);
	node_timer(now);				/* Node timeouts */
	http_timer(now);				/* HTTP request timeouts */
	socket_timer(now);				/* Expire inactive sockets */
	pcache_possibly_expired(now);	/* Expire pong cache */

	if (exiting)
		return TRUE;

	shell_timer(now);
	download_timer(now);  	    /* Download timeouts */
	parq_upload_timer(now);		/* PARQ upload timeouts/removal */
	upload_timer(now);			/* Upload timeouts */
	file_info_timer();          /* Notify about changes */
	hsep_timer(now);			/* HSEP notify message timer */
	pproxy_timer(now);			/* Push-proxy requests */
	dh_timer(now);				/* Monitoring of query hits */

	/*
	 * GUI update
	 */

	if (!running_topless) {
		main_gui_timer(now);
	}

	/* Update for things that change slowly */
	if (main_slow_update++ > SLOW_UPDATE_PERIOD) {
		main_slow_update = 0;
		slow_main_timer(now);
	}

	bg_sched_timer(GNET_PROPERTY(overloaded_cpu));	/* Background tasks */

	return TRUE;
}

/**
 * Called when the main callout queue is idle.
 */
static gboolean
callout_queue_idle(gpointer unused_data)
{
	(void) unused_data;

	if (GNET_PROPERTY(cq_debug) > 1)
		g_message("CQ: callout queue is idle (CPU %s)",
			GNET_PROPERTY(overloaded_cpu) ? "OVERLOADED" : "available");

	/* Idle tasks always scheduled */
	zgc();

	if (!GNET_PROPERTY(overloaded_cpu)) {
		/* Idle tasks scheduled only when CPU is not overloaded */
		pgc();
	}

	return TRUE;		/* Keep scheduling this */
}

/**
 * Scan files when the GUI is up.
 */
static gboolean
scan_files_once(gpointer p)
{
	(void) p;
	share_scan();

	return FALSE;
}

static const gchar * const log_domains[] = {
	G_LOG_DOMAIN, "Gtk", "GLib", "Pango"
};

static void
log_handler(const gchar *domain, GLogLevelFlags level,
	const gchar *message, gpointer user_data)
{
	gint saved_errno = errno;
	time_t now;
	struct tm *ct;
	const char *prefix;
	gchar *safer;

	(void) domain;
	(void) user_data;

	if (stderr_disabled)
		return;

	now = tm_time_exact();
	ct = localtime(&now);

	switch (level) {
#define CASE(x) case CAT2(G_LOG_LEVEL_,x): prefix = #x; break;

	CASE(CRITICAL)
	CASE(ERROR)
	CASE(WARNING)
	CASE(MESSAGE)
	CASE(INFO)
	CASE(DEBUG)
#undef CASE
	default:
		prefix = "UNKNOWN";
	}

	safer = control_escape(message);

	fprintf(stderr, "%02d-%02d-%02d %.2d:%.2d:%.2d (%s): %s\n",
		(1900 + ct->tm_year) % 100, ct->tm_mon + 1, ct->tm_mday,
		ct->tm_hour, ct->tm_min, ct->tm_sec, prefix, safer);

	if (safer != message) {
		G_FREE_NULL(safer);
	}

#if 0
	/* Define to debug Glib or Gtk problems */
	if (domain) {
		guint i;

		for (i = 0; i < G_N_ELEMENTS(log_domains); i++) {
			const gchar *dom = log_domains[i];
			if (dom && 0 == strcmp(domain, dom)) {
				raise(SIGTRAP);
				break;
			}
		}
	}
#endif

	errno = saved_errno;
}

static void
log_init(void)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS(log_domains); i++) {
		g_log_set_handler(log_domains[i],
			G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING |
			G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_INFO | G_LOG_LEVEL_DEBUG,
			log_handler, NULL);
	}
}

extern char **environ;

enum main_arg {
	main_arg_daemonize,
	main_arg_exec_on_crash,
	main_arg_geometry,
	main_arg_help,
	main_arg_log_stderr,
	main_arg_log_stdout,
	main_arg_no_halloc,
	main_arg_no_xshm,
	main_arg_pause_on_crash,
	main_arg_ping,
	main_arg_shell,
	main_arg_topless,
	main_arg_version,

	/* Passed through for Gtk+/GDK/GLib */
	main_arg_class,
	main_arg_g_fatal_warnings,
	main_arg_gdk_debug,
	main_arg_gdk_no_debug,
	main_arg_gtk_debug,
	main_arg_gtk_no_debug,
	main_arg_gtk_module,
	main_arg_name,

	num_main_args
};

enum arg_type {
	ARG_TYPE_NONE,
	ARG_TYPE_TEXT,
	ARG_TYPE_PATH
};

static struct {
	const enum main_arg id;
	const gchar * const name;
	const gchar * const summary;
	const enum arg_type type;
	const gchar *arg;
	gboolean used;
} options[] = {
#define OPTION(name, type, summary) \
	{ main_arg_ ## name , #name, summary, ARG_TYPE_ ## type, NULL, FALSE }

	OPTION(daemonize, 		NONE, "Daemonize the process."),
	OPTION(exec_on_crash, 	PATH, "Execute a command on crash."),
	OPTION(geometry,		TEXT, "Placement of the main GUI window."),
	OPTION(help, 			NONE, "Print this message."),
	OPTION(log_stderr,		PATH, "Log standard output to a file."),
	OPTION(log_stdout,		PATH, "Log standard error output to a file."),
#ifdef USE_HALLOC
	OPTION(no_halloc,		NONE, "Disable malloc() replacement."),
#else
	OPTION(no_halloc,		NONE, NULL),	/* ignore silently */
#endif	/* USE_HALLOC */
	OPTION(no_xshm,			NONE, "Disable MIT shared memory extension."),
	OPTION(pause_on_crash, 	NONE, "Pause the process on crash."),
	OPTION(ping,			NONE, "Check whether gtk-gnutella is running."),
	OPTION(shell,			NONE, "Access the local shell interface."),
#ifdef USE_TOPLESS
	OPTION(topless,			NONE, NULL),	/* accept but hide */
#else
	OPTION(topless,			NONE, "Disable the graphical user-interface."),
#endif	/* USE_TOPLESS */
	OPTION(version,			NONE, "Show version information."),

	/* These are handled by Gtk+/GDK/GLib */
	OPTION(class,				TEXT, NULL),
	OPTION(g_fatal_warnings,	NONE, NULL),
	OPTION(gdk_debug,			TEXT, NULL),
	OPTION(gdk_no_debug,		TEXT, NULL),
	OPTION(gtk_debug,			TEXT, NULL),
	OPTION(gtk_no_debug,		TEXT, NULL),
	OPTION(gtk_module,			TEXT, NULL),
	OPTION(name,				TEXT, NULL),
#undef OPTION
};

static inline char
underscore_to_hyphen(char c)
{
	return '_' == c ? '-' : c;
}

/**
 * Checks whether two strings qualify as equivalent, the ASCII underscore
 * character and the ASCII hyphen character are considered equivalent.
 *
 * @return whether the two strings qualify as equivalent or not.
 */
static gboolean
option_match(const char *a, const char *b)
{
	g_assert(a);
	g_assert(b);

	for (;;) {	
		if (underscore_to_hyphen(*a) != underscore_to_hyphen(*b))
			return FALSE;
		if ('\0' == *a)
			break;
		a++;
		b++;
	}

	return TRUE;
}

/**
 * Copies the given option name to a static buffer replacing underscores
 * with hyphens.
 *
 * @return a pointer to a static buffer holding the pretty version of the
 *         option name. 
 */
static const gchar *
option_pretty_name(const gchar *name)
{
	static gchar buf[128];
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(buf) - 1; i++) {
		if ('\0' == name[i])
			break;
		buf[i] = underscore_to_hyphen(name[i]);
	}
	buf[i] = '\0';
	return buf;
}

static gint
reopen_log_files(void)
{
	gboolean failure = FALSE;

	if (options[main_arg_log_stdout].used) {
		if (freopen(options[main_arg_log_stdout].arg, "a", stdout)) {
			setvbuf(stdout, NULL, _IOLBF, 0);
		} else {
			fprintf(stderr, "freopen(..., \"a\", stdout) failed: %s",
				g_strerror(errno));
			failure = TRUE;
		}
	}
	if (options[main_arg_log_stderr].used) {
		const char *pathname = options[main_arg_log_stderr].arg;
		
		if (freopen(pathname, "a", stderr)) {
			stderr_disabled = 0 == strcmp(pathname, "/dev/null");
			setvbuf(stderr, NULL, _IOLBF, 0);
		} else {
			fprintf(stderr, "freopen(..., \"a\", stderr) failed: %s",
				g_strerror(errno));
			failure = TRUE;
			stderr_disabled = TRUE;
		}
	} else if (options[main_arg_daemonize].used) {
		stderr_disabled = TRUE;
	}

	return failure ? -1 : 0;
}

static void
usage(int exit_code)
{
	FILE *f;
	guint i;

	f = EXIT_SUCCESS == exit_code ? stdout : stderr;
	fprintf(f, "Usage: gtk-gnutella [ options ... ]\n");
	
	STATIC_ASSERT(G_N_ELEMENTS(options) == num_main_args);
	for (i = 0; i < G_N_ELEMENTS(options); i++) {
		g_assert(options[i].id == i);

		if (options[i].summary) {
			const gchar *arg, *name;
			size_t pad;

			arg = "";
			name = option_pretty_name(options[i].name);
			switch (options[i].type) {
			case ARG_TYPE_NONE:
				break;
			case ARG_TYPE_TEXT:
				arg = " <argument>";
				break;
			case ARG_TYPE_PATH:
				arg = " <path>";
				break;
			}
			
			pad = strlen(name) + strlen(arg);
			if (pad < 24) {
				pad = 24 - pad;
			} else {
				pad = 0;
			}

			fprintf(f, "  --%s%s%-*s%s\n",
				name, arg, (gint) pad, "", options[i].summary);
		}
	}
	
	exit(exit_code);
}

/* NOTE: This function must not allocate any memory. */
static void
prehandle_arguments(char **argv)
{
	argv++;

	while (argv[0]) {
		const gchar *s;
		guint i;

		s = is_strprefix(argv[0], "--");
		if (NULL == s || '\0' == s[0])
			break;

		argv++;

		for (i = 0; i < G_N_ELEMENTS(options); i++) {
			if (option_match(options[i].name, s))
				break;
		}
		if (G_N_ELEMENTS(options) == i)
			return;

		if (main_arg_no_halloc == i) {
			options[i].used = TRUE;
		}

		switch (options[i].type) {
		case ARG_TYPE_NONE:
			break;
		case ARG_TYPE_TEXT:
		case ARG_TYPE_PATH:
			if (NULL == argv[0] || '-' == argv[0][0])
				return;

			argv++;
			break;
		}
	}
}

/**
 * Parse arguments, but do not take any action (excepted re-opening log files).
 */
static void
parse_arguments(int argc, char **argv)
{
	const char *argv0;
	guint i;

	STATIC_ASSERT(G_N_ELEMENTS(options) == num_main_args);
	for (i = 0; i < G_N_ELEMENTS(options); i++) {
		g_assert(options[i].id == i);
	}

#ifdef USE_TOPLESS
	options[main_arg_topless].used = TRUE;
#endif	/* USE_TOPLESS */

	argv0 = argv[0];
	argv++;
	argc--;

	while (argc > 0) {
		const gchar *s;

		s = is_strprefix(argv[0], "--");
		if (!s)
			usage(EXIT_FAILURE);
		if ('\0' == s[0])
			break;

		argv++;
		argc--;

		for (i = 0; i < G_N_ELEMENTS(options); i++) {
			if (option_match(options[i].name, s))
				break;
		}
		if (G_N_ELEMENTS(options) == i) {
			fprintf(stderr, "Unknown option \"--%s\"\n", s);
			usage(EXIT_FAILURE);
		}

		options[i].used = TRUE;
		switch (options[i].type) {
		case ARG_TYPE_NONE:
			break;
		case ARG_TYPE_TEXT:
		case ARG_TYPE_PATH:
			if (argc < 0 || NULL == argv[0] || '-' == argv[0][0]) {
				fprintf(stderr, "Missing argument for \"--%s\"\n", s);
				usage(EXIT_FAILURE);
			}
			switch (options[i].type) {
			case ARG_TYPE_TEXT:
				options[i].arg = NOT_LEAKING(g_strdup(argv[0]));
				break;
			case ARG_TYPE_PATH:
				options[i].arg = NOT_LEAKING(absolute_pathname(argv[0]));
				if (NULL == options[i].arg) {
					fprintf(stderr,
						"Could not determine absolute path for \"--%s\"\n", s);
					usage(EXIT_FAILURE);
				}
				break;
			case ARG_TYPE_NONE:
				g_assert_not_reached();
			}
			argv++;
			argc--;
			break;
		}
	}

	if (0 != reopen_log_files()) {
		exit(EXIT_FAILURE);
	}
}

/**
 * Act on the options we parsed.
 */
static void
handle_arguments(char *argv0)
{
	crash_init(options[main_arg_exec_on_crash].arg, argv0,
		options[main_arg_pause_on_crash].used);

	if (options[main_arg_help].used) {
		usage(EXIT_SUCCESS);
	}

#ifndef USE_TOPLESS
	if (options[main_arg_topless].used) {
		running_topless = TRUE;
	}
#endif	/* USE_TOPLESS */

	if (options[main_arg_version].used) {
		printf("%s\n", version_build_string());

#ifndef OFFICIAL_BUILD
		printf("(unofficial build, accessing \"%s\")\n", PACKAGE_SOURCE_DIR);
#endif

		printf("GLib %u.%u.%u",
			glib_major_version, glib_minor_version, glib_micro_version);
		if (
			GLIB_MAJOR_VERSION != glib_major_version ||
			GLIB_MINOR_VERSION != glib_minor_version ||
			GLIB_MICRO_VERSION != glib_micro_version
		) {
			printf(" (compiled against %u.%u.%u)",
				GLIB_MAJOR_VERSION, GLIB_MINOR_VERSION, GLIB_MICRO_VERSION);
		}
		printf("\n");

#if defined(GTK_MAJOR_VERSION) && defined(GTK_MINOR_VERSION)
		printf("Gtk+ %u.%u.%u",
			gtk_major_version, gtk_minor_version, gtk_micro_version);
		if (
			GTK_MAJOR_VERSION != gtk_major_version ||
			GTK_MINOR_VERSION != gtk_minor_version ||
			GTK_MICRO_VERSION != gtk_micro_version
		) {
			printf(" (compiled against %u.%u.%u)",
				GTK_MAJOR_VERSION, GTK_MINOR_VERSION, GTK_MICRO_VERSION);
		}
		printf("\n");
#endif	/* Gtk+ */

		if (tls_version_string()) {
			printf("%s\n", tls_version_string());
		}
		exit(EXIT_SUCCESS);
	}
	if (options[main_arg_ping].used) {
		if (settings_is_unique_instance()) {
			/* gtk-gnutella was running. */
			exit(EXIT_SUCCESS);
		} else {
			/* gtk-gnutella was not running or the PID file could
			 * not be created. */
			exit(EXIT_FAILURE);
		}
	}
	if (options[main_arg_shell].used) {
		local_shell(settings_local_socket_path());
		exit(EXIT_SUCCESS);
	}
	if (options[main_arg_daemonize].used) {
		if (0 != compat_daemonize(NULL)) {
			exit(EXIT_FAILURE);
		}
		/* compat_daemonize() assigned stdout and stderr to /dev/null */
		if (0 != reopen_log_files()) {
			exit(EXIT_FAILURE);
		}
	}
}

int
main(int argc, char **argv)
{
	if (compat_is_superuser()) {
		fprintf(stderr, "Never ever run this as root! You may use:\n\n");
		fprintf(stderr, "    su - username -c 'gtk-gnutella --daemonize'\n\n");
		fprintf(stderr, "where 'username' stands for a regular user name.\n");
		exit(EXIT_FAILURE);
	}

	tm_now_exact(&start_time);
	gm_savemain(argc, argv, environ);	/* For gm_setproctitle() */

	/*
	 * This must be run before we allocate memory because we might
	 * use mmap() with /dev/zero and then accidently close this
	 * file descriptor.
	 */
	close_file_descriptors(3); /* Just in case */
	if (reserve_standard_file_descriptors()) {
		exit(EXIT_FAILURE);
	}

	/* First inits -- initialize custom memory allocator, if needed */

	prehandle_arguments(argv);

	if (!options[main_arg_no_halloc].used) {
		halloc_init();
	}
	malloc_init_vtable();

	set_signal(SIGINT, SIG_IGN);	/* ignore SIGINT in adns (e.g. for gdb) */
	set_signal(SIGHUP, sig_hup);
#ifdef SIGCHLD
	set_signal(SIGCHLD, sig_chld);
#endif
#ifdef SIGPIPE
	set_signal(SIGPIPE, SIG_IGN);
#endif

#if defined(FRAGCHECK) || defined(MALLOC_STATS)
	set_signal(SIGUSR1, sig_malloc);
	set_signal(SIGUSR2, sig_malloc);
#endif

	/* Early inits */

	parse_arguments(argc, argv);
	log_init();
	malloc_init(argv[0]);
	atoms_init();
	eval_init();
	misc_init();
	settings_early_init();

	handle_arguments(argv[0]);

	/* Our regular inits */

#ifndef OFFICIAL_BUILD
	g_warning("%s \"%s\"",
		_("unofficial build, accessing files from"),
		PACKAGE_SOURCE_DIR);
#endif

	/*
	 * If one of the two below fails, the GLib installation is broken.
	 * Gtk+ 1.2 and GLib 1.2 are not 64-bit clean, thus must not be
	 * used on 64-bit architectures.
	 */
	STATIC_ASSERT(sizeof(size_t) == sizeof(gsize));
	STATIC_ASSERT(sizeof(ssize_t) == sizeof(gssize));

	STATIC_ASSERT(UNSIGNED(INT_MIN) > 0);
	STATIC_ASSERT(UNSIGNED(LONG_MIN) > 0);
	STATIC_ASSERT(UNSIGNED(-1) > 0);
	STATIC_ASSERT(IS_POWER_OF_2(MEM_ALIGNBYTES));

	inputevt_init();
	tiger_check();
	tt_check();
	random_init();
	tea_test();
	patricia_test();
	strtok_test();
	locale_init();
	adns_init();
	file_object_init();
	version_init();
	socket_init();
	gnet_stats_init();
	iso3166_init();
	dbus_util_init();
	vendor_init();
	mime_type_init();

	if (!running_topless) {
		main_gui_early_init(argc, argv, options[main_arg_no_xshm].used);
	}

	cq_init(callout_queue_idle, GNET_PROPERTY_PTR(cq_debug));
	vmsg_init();
	tsync_init();
	watcher_init();
	hcache_init();			/* before settings_init() */
	bsched_early_init();	/* before settings_init() */
	ipp_cache_init();		/* before settings_init() */
	settings_init();
	set_library_debug(GNET_PROPERTY(lib_debug));
	map_test();				/* after settings_init() */
	ipp_cache_load_all();	/* after settings_init() */
	tls_global_init();
	hostiles_init();
	spam_init();
	bogons_init();
	gip_init();
	guid_init();
	uhc_init();
	verify_sha1_init();
	verify_tth_init();
	move_init();
	ignore_init();
	pattern_init();
	word_vec_init();

	file_info_init();
	host_init();
	pmsg_init();
	gmsg_init();
	bsched_init();
	dump_init();
	node_init();
    hcache_retrieve_all();	/* after settings_init() and node_init() */
	routing_init();
	search_init();
	share_init();
	dmesh_init();			/* MUST be done BEFORE download_init() */
	download_init();		/* MUST be done AFTER file_info_init() */
	upload_init();
	shell_init();
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
	gdht_init();
	file_info_init_post();

	kmsg_init();			/* DHT */
	dht_init();

	if (!running_topless) {
		main_gui_init();
	}
	node_post_init();

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

	(void) tm_time_exact();
	bsched_enable_all();
	version_ancient_warn();
	if (dht_enabled())
		dht_attempt_bootstrap();

	if (running_topless) {
		topless_main_run();
	} else {
		main_gui_run(options[main_arg_geometry].arg);
	}

	return 0;
}

/* vi: set ts=4 sw=4 cindent: */
