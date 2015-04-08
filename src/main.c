/*
 * Copyright (c) 2001-2015 Raphael Manfredi
 * Copyright (c) 2005-2011 Christian Biere
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
 * @date 2001-2015
 * @author Christian Biere
 * @date 2005-2011
 */

#include "common.h"
#include "revision.h"
#include "gtk-gnutella.h"

#define CORE_SOURCES

#include "core/ban.h"
#include "core/bogons.h"
#include "core/bsched.h"
#include "core/clock.h"
#include "core/ctl.h"
#include "core/dh.h"
#include "core/dmesh.h"
#include "core/downloads.h"
#include "core/dq.h"
#include "core/dump.h"
#include "core/extensions.h"
#include "core/features.h"
#include "core/fileinfo.h"
#include "core/g2/build.h"
#include "core/g2/gwc.h"
#include "core/g2/node.h"
#include "core/g2/rpc.h"
#include "core/g2/tree.h"
#include "core/gdht.h"
#include "core/geo_ip.h"
#include "core/ghc.h"
#include "core/gmsg.h"
#include "core/gnet_stats.h"
#include "core/gnutella.h"
#include "core/guess.h"
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
#include "core/pdht.h"
#include "core/pproxy.h"
#include "core/publisher.h"
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
#include "core/urpc.h"
#include "core/verify_sha1.h"
#include "core/verify_tth.h"
#include "core/version.h"
#include "core/vmsg.h"
#include "core/whitelist.h"
#include "if/dht/dht.h"
#include "lib/adns.h"
#include "lib/atoms.h"
#include "lib/bg.h"
#include "lib/compat_misc.h"
#include "lib/cpufreq.h"
#include "lib/cq.h"
#include "lib/crash.h"
#include "lib/crc.h"
#include "lib/dbus_util.h"
#include "lib/debug.h"
#include "lib/eval.h"
#include "lib/evq.h"
#include "lib/exit.h"
#include "lib/fd.h"
#include "lib/file_object.h"
#include "lib/gentime.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/htable.h"
#include "lib/inputevt.h"
#include "lib/iso3166.h"
#include "lib/log.h"
#include "lib/map.h"
#include "lib/mime_type.h"
#include "lib/misc.h"
#include "lib/offtime.h"
#include "lib/omalloc.h"
#include "lib/palloc.h"
#include "lib/parse.h"
#include "lib/patricia.h"
#include "lib/pattern.h"
#include "lib/pow2.h"
#include "lib/product.h"
#include "lib/random.h"
#include "lib/sha1.h"
#include "lib/signal.h"
#include "lib/stacktrace.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/strtok.h"
#include "lib/symbols.h"
#include "lib/tea.h"
#include "lib/teq.h"
#include "lib/thread.h"
#include "lib/tiger.h"
#include "lib/tigertree.h"
#include "lib/tm.h"
#include "lib/tmalloc.h"
#include "lib/utf8.h"
#include "lib/vendors.h"
#include "lib/vmm.h"
#include "lib/vsort.h"
#include "lib/walloc.h"
#include "lib/watcher.h"
#include "lib/wordvec.h"
#include "lib/wq.h"
#include "lib/xmalloc.h"
#include "lib/xxtea.h"
#include "lib/zalloc.h"
#include "shell/shell.h"
#include "upnp/upnp.h"
#include "xml/vxml.h"

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

#define SLOW_UPDATE_PERIOD		20	/**< Update period for `main_slow_update' */
#define EXIT_GRACE				30	/**< Seconds to wait before exiting */
#define ATEXIT_TIMEOUT			20	/**< Final cleanup must not take longer */

#define LOAD_HIGH_WATERMARK		95	/**< % amount over which we're overloaded */
#define LOAD_LOW_WATERMARK		80	/**< lower threshold to clear condition */

static unsigned main_slow_update;
static volatile sig_atomic_t exiting;
static volatile sig_atomic_t from_atexit;
static volatile sig_atomic_t signal_received;
static volatile sig_atomic_t shutdown_requested;
static volatile sig_atomic_t sig_hup_received;
static bool asynchronous_exit;
static enum shutdown_mode shutdown_user_mode = GTKG_SHUTDOWN_NORMAL;
static unsigned shutdown_user_flags;
static jmp_buf atexit_env;
static volatile const char *exit_step = "gtk_gnutella_exit";

static bool main_timer(void *);

#ifdef SIGALRM
/**
 * Force immediate shutdown of SIGALRM reception.
 */
static void
sig_alarm(int n)
{
	(void) n;
	if (from_atexit) {
		s_warning("exit cleanup timed out -- forcing exit");
		longjmp(atexit_env, 1);
	}
}
#endif	/* SIGALRM */

#ifdef SIGHUP
static void
sig_hup(int n)
{
	(void) n;
	sig_hup_received = 1;
}
#endif	/* SIGHUP */

#ifdef SIGCHLD
static void
sig_chld(int n)
{
	(void) n;
}
#endif

#if defined(FRAGCHECK) || defined(MALLOC_STATS)
static volatile sig_atomic_t signal_malloc = 0;

/**
 * Record USR1 or USR2 signal in `signal_malloc'.
 */
static void
sig_malloc(int n)
{
	switch (n) {
#ifdef SIGUSR1
	case SIGUSR1: signal_malloc = 1; break;
#endif
#ifdef SIGUSR2
	case SIGUSR2: signal_malloc = 2; break;
#endif
	default: break;
	}
}
#endif /* MALLOC_STATS */

/**
 * Are we debugging anything at a level greater than some threshold "t"?
 */
bool
debugging(guint t)
{
	return
		GNET_PROPERTY(ban_debug) > t ||
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
		GNET_PROPERTY(xmalloc_debug) > t ||
		GNET_PROPERTY(vmm_debug) > t ||
		GNET_PROPERTY(vmsg_debug) > t ||
		GNET_PROPERTY(zalloc_debug) > t ||

		/* Above line left blank for easy "!}sort" under vi */
		0;
}

/**
 * @reeturn GTK version string, or NULL if not compiled with GTK.
 */
const char *
gtk_version_string(void)
{
#if defined(GTK_MAJOR_VERSION) && defined(GTK_MINOR_VERSION)
	static char buf[80];

	if ('\0' == buf[0]) {
		str_bprintf(buf, sizeof buf, "Gtk+ %u.%u.%u",
				gtk_major_version, gtk_minor_version, gtk_micro_version);
		if (
				GTK_MAJOR_VERSION != gtk_major_version ||
				GTK_MINOR_VERSION != gtk_minor_version ||
				GTK_MICRO_VERSION != gtk_micro_version
		   ) {
			str_bcatf(buf, sizeof buf, " (compiled against %u.%u.%u)",
					GTK_MAJOR_VERSION, GTK_MINOR_VERSION, GTK_MICRO_VERSION);
		}
	}

	return buf;
#else
	return NULL;
#endif	/* Gtk+ */
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
		g_critical("trapped foreign exit(), cleaning up...");
		from_atexit = TRUE;
#ifndef USE_TOPLESS
		running_topless = TRUE;		/* X connection may be broken, avoid GUI */
#endif
        
#ifdef SIGALRM
		signal_set(SIGALRM, sig_alarm);
#endif
		if (setjmp(atexit_env)) {
			g_warning("cleanup aborted while in %s().", exit_step);
			return;
		}
#ifdef HAS_ALARM
		alarm(ATEXIT_TIMEOUT);
#endif
		gtk_gnutella_exit(1);	/* Won't exit() since from_atexit is set */
#ifdef HAS_ALARM
		alarm(0);
#endif
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
log_cpu_usage(tm_t *since_time, double *prev_user, double *prev_sys)
{
	double user;
	double sys;
	double total;
	tm_t cur_time;
	double elapsed;

	tm_now_exact(&cur_time);
	total = tm_cputime(&user, &sys);
	if (prev_user) {
		double v = *prev_user;
		*prev_user = user;
		user -= v;
		total -= v;
	}
	if (prev_sys) {
		double v = *prev_sys;
		*prev_sys = sys;
		sys -= v;
		total -= v;
	}

	elapsed = tm_elapsed_f(&cur_time, since_time);
	*since_time = cur_time;

	g_debug("average CPU used: %.3f%% over %.2f secs",
		100.0 * total / elapsed, elapsed);
	g_debug("CPU usage: total: %.2fs (user: %.2f, sys: %.2f)",
		total, user, sys);
}

void
gtk_gnutella_request_shutdown(enum shutdown_mode mode, unsigned flags)
{
	shutdown_requested = 1;
	shutdown_user_mode = mode;
	shutdown_user_flags = flags;
}

/**
 * Crash restart callback to trigger a graceful asynchronous restart.
 */
static int
gtk_gnutella_request_restart(void)
{
	gtk_gnutella_request_shutdown(GTKG_SHUTDOWN_NORMAL,
		GTKG_SHUTDOWN_OFAST | GTKG_SHUTDOWN_ORESTART | GTKG_SHUTDOWN_OCRASH);

	return 1;	/* Any non-zero return signifies: async restart in progress */
}

/**
 * Manually dispatch events that are normally done from glib's main loop.
 */
static void
main_dispatch(void)
{
	/*
	 * Order is important: we dispatch I/Os first because callout queue
	 * events are mostly for monitoring timeouts at this stage.
	 * We don't want to think there was a timeout where in fact the I/O
	 * reply was pending.
	 */

	inputevt_dispatch();
	cq_main_dispatch();

	/*
	 * If gtk_gnutella_exit() was called from main_timer(), the callout
	 * queue will no longer schedule invocations (since the event callback
	 * has not returned yet), but we need them to be done each second.
	 */

	if (asynchronous_exit) {
		static time_t last_call;
		time_t now = time(NULL);

		if (last_call != now) {
			last_call = now;
			main_timer(NULL);
		}
	}
}

/*
 * If they requested abnormal termination after shutdown, comply now.
 */
static void G_GNUC_COLD
handle_user_shutdown_request(enum shutdown_mode mode)
{
	const char *msg = "crashing at your request";
	const char *trigger = "shutdown completed, triggering";
	volatile int *p = uint_to_pointer(0xdeadbeefU);

	switch (mode) {
	case GTKG_SHUTDOWN_NORMAL:
		break;
	case GTKG_SHUTDOWN_ASSERT:
		s_message("%s assertion failure", trigger);
		g_assert_log(FALSE, "%s", msg);
		/* NOTREACHED */
		break;
	case GTKG_SHUTDOWN_ERROR:
		s_message("%s error", trigger);
		s_error("%s", msg);
		/* NOTREACHED */
		break;
	case GTKG_SHUTDOWN_MEMORY:
		s_message("%s memory access error", trigger);
		*p = 0xc001;
		break;
	case GTKG_SHUTDOWN_SIGNAL:
		s_message("%s SIGILL", trigger);
		raise(SIGILL);
		/* NOTREACHED */
		break;
	}
}

/**
 * Exit program, return status `exit_code' to parent process.
 *
 * Shutdown systems, so we can track memory leaks, and wait for EXIT_GRACE
 * seconds so that BYE messages can be sent to other nodes.
 */
void G_GNUC_COLD
gtk_gnutella_exit(int exit_code)
{
	static volatile sig_atomic_t safe_to_exit;
	time_t exit_time = time(NULL);
	time_delta_t exit_grace = EXIT_GRACE;
	bool byeall =
		!(shutdown_requested && (shutdown_user_flags & GTKG_SHUTDOWN_OFAST));
	bool crashing =
		shutdown_requested && (shutdown_user_flags & GTKG_SHUTDOWN_OCRASH);

	/*
	 * In case this routine is part of an automatic restarting sequence,
	 * signal to the crashing layer that we are starting in order to cancel
	 * the automatic restart after some time.
	 */

	crash_restarting();

	if (exiting) {
		if (safe_to_exit) {
			g_warning("forced exit(%d), good bye.", exit_code);
			exit(exit_code);
		}
		g_warning("ignoring re-entrant exit(%d), unsafe now (in %s)",
			exit_code, exit_step);
		return;
	}

	exiting = TRUE;

#define DO(fn) 	do {					\
	exit_step = STRINGIFY(fn);			\
	if (GNET_PROPERTY(shutdown_debug))	\
		g_debug("SHUTDOWN calling %s", exit_step);	\
	fn();								\
} while (0)

#define DO_BOOL(fn, arg)	do {			\
	exit_step = STRINGIFY(fn);				\
	if (GNET_PROPERTY(shutdown_debug)) {	\
		g_debug("SHUTDOWN calling %s(%s)",	\
			exit_step, (arg) ? "TRUE" : "FALSE"); \
	}										\
	fn(arg);								\
} while (0)

	DO(shell_close);
	DO(file_info_store_if_dirty);	/* For safety, will run again below */
	DO(file_info_close_pre);
	DO_BOOL(node_bye_all, byeall);
	DO(upload_close);	/* Done before upload_stats_close() for stats update */
	DO(upload_stats_close);
	DO(parq_close_pre);
	DO(verify_sha1_close);
	DO(verify_tth_shutdown);
	DO(download_close);
	DO(file_info_store_if_dirty);	/* In case downloads had buffered data */
	DO(parq_close);
	DO(pproxy_close);
	DO(http_close);
	DO(uhc_close);
	DO(ghc_close);
	DO(gwc_close);
	DO(move_close);
	DO(publisher_close);
	DO(pdht_close);
	DO(guess_close);
	DO(guid_close);
	DO_BOOL(dht_close, TRUE);
	DO(ipp_cache_save_all);
	DO(bg_close);

	/*
	 * When coming from atexit(), there is a sense of urgency.
	 * We have saved most of the dynamic data above, finish with
	 * the properties and exit.
	 */

	gnet_prop_set_timestamp_val(PROP_SHUTDOWN_TIME, tm_time());
	DO(settings_save_if_dirty);

	safe_to_exit = TRUE;	/* Will immediately exit if re-entered */

	if (debugging(0) || signal_received || shutdown_requested)
		g_info("context files and settings closed properly");

	if (from_atexit)
		return;

	/*
	 * Before running final cleanup, show allocation statistics.
	 */

	if (debugging(0)) {
		DO(palloc_dump_stats);
		DO(tmalloc_dump_stats);
		DO(vmm_dump_stats);
		DO(xmalloc_dump_stats);
		DO(zalloc_dump_stats);
	}

	/*
	 * When halloc() is replacing malloc(), we need to make sure no memory
	 * allocated through halloc() is going to get invalidated because some
	 * GTK callbacks seem to access freed memory.
	 *
	 * Also, later on when we finally cleanup all the allocated memory, we may
	 * run into similar problems with glib if we don't take this precaution.
	 *
	 * Therefore, before starting the final shutdown routines, prevent any
	 * freeing.  We don't care much as we're now going to exit() anyway.
	 *
	 * Note that only the actual freeing is suppressed, but all internal
	 * data structures are still updated, meaning memory leak detection will
	 * still work correctly.
	 *
	 * Used to do that only when halloc_replaces_malloc() was true, but
	 * now doing it unconditionally because of problems with GTK1 callbacks.
	 * This may not be due to GTK and be a bug in our usage of callbacks,
	 * but it happens only with memory allocated through the VMM layer,
	 * i.e. impacting walloc() / zalloc() as well since their arena are
	 * now allocated through VMM.
	 *		--RAM, 2010-02-19
	 */

	DO(vmm_stop_freeing);		/* Also stops memusage monitoring */
	DO(xmalloc_stop_freeing);	/* Ditto */
	DO(zalloc_memusage_close);	/* No longer needed */

	if (!running_topless) {
		DO(settings_gui_save_if_dirty);
		DO(main_gui_shutdown);

		if (debugging(0) || signal_received || shutdown_requested)
			g_info("GUI shutdown completed");
	}

	DO(hcache_shutdown);	/* Save host caches to disk */
	DO(oob_shutdown);		/* No longer deliver outstanding OOB hits */
	DO(socket_shutdown);
	DO(bsched_shutdown);

	/*
	 * If auto-restart was requested, flag that in the properties so that
	 * we'll know about that request when we restart.
	 */

	if (shutdown_user_flags & GTKG_SHUTDOWN_ORESTART) {
		gnet_prop_set_boolean_val(PROP_USER_AUTO_RESTART, TRUE);
	}

	if (!running_topless)
		DO(settings_gui_shutdown);
	DO(settings_shutdown);

	/*
	 * Show total CPU used, and the amount spent in user / kernel, before
	 * we start the grace period...
	 */

	if (debugging(0)) {
		tm_t since = tm_start_time();
		log_cpu_usage(&since, NULL, NULL);
	}

	/*
	 * Skip gracetime for BYE message to go through when crashing, as well
	 * as most the final exit sequence whose aim is to properly clean memory
	 * to be able to trace leaks when debugging.
	 */

	if (crashing) {
		/* Accelerated shutdown */
		DO(settings_close);
		DO(cq_close);
		goto quick_restart;
	}

	/*
	 * Wait at most EXIT_GRACE seconds, so that BYE messages can go through.
	 * This amount of time is doubled when running in Ultra mode since we
	 * have more connections to flush.
	 */

	if (settings_is_ultra())
		exit_grace *= 2;

	if (debugging(0) || signal_received || shutdown_requested) {
		g_info("waiting at most %s for BYE messages",
			short_time(exit_grace));
	}

	/*
	 * We may no longer be going back to glib's main loop, so we need
	 * to dispatch the critical events (I/Os, callout queue) manually.
	 */

	main_dispatch();

	while (node_bye_pending() || upnp_delete_pending()) {
		time_t now = time(NULL);
		time_delta_t d;

		if (signal_received)
			break;

		if ((d = delta_time(now, exit_time)) >= exit_grace)
			break;

		if (!running_topless) {
			main_gui_shutdown_tick(exit_grace - d);
		}
		thread_sleep_ms(50);
		main_dispatch();
	}

	if (debugging(0) || signal_received || shutdown_requested)
		g_info("running final shutdown sequence...");

	/*
	 * The main thread may now have to perform thread_join(), so we
	 * tell the management layer that it is OK to block.
	 */

	thread_set_main(TRUE);				/* Main thread can now block */

	DO(settings_terminate);	/* Entering the final sequence */
	DO(cq_halt);			/* No more callbacks, with everything shutdown */
	DO(search_shutdown);	/* Disable now, since we can get queries above */

	DO(socket_closedown);
	DO(upnp_close);
	DO(ntp_close);
	DO(gdht_close);
	DO(sq_close);
	DO(dh_close);
	DO(dq_close);
	DO(hsep_close);
	DO(file_info_close);
	DO(ext_close);
	DO(node_close);
	DO(g2_node_close);
	DO(share_close);	/* After node_close() */
	DO(udp_close);
	DO(urpc_close);
	DO(g2_rpc_close);
	DO(routing_close);	/* After node_close() */
	DO(bsched_close);
	DO(dmesh_close);
	DO(host_close);
	DO(hcache_close);	/* After host_close() */
	DO(bogons_close);	/* Idem, since host_close() can touch the cache */
	DO(tx_collect);		/* Prevent spurious leak notifications */
	DO(rx_collect);		/* Idem */
	DO(hostiles_close);
	DO(spam_close);
	DO(gip_close);
	DO(ban_close);
	DO(inet_close);
	DO(ctl_close);
	DO(whitelist_close);
	DO(features_close);
	DO(clock_close);
	DO(vmsg_close);
	DO(watcher_close);
	DO(tsync_close);
	DO(word_vec_close);
	DO(pattern_close);
	DO(pmsg_close);
	DO(gmsg_close);
	DO(g2_build_close);
	DO(version_close);
	DO(ignore_close);
	DO(iso3166_close);
	atom_str_free_null(&start_rfc822_date);
	DO(adns_close);
	DO(dbus_util_close);  /* After adns_close() to avoid strange crashes */
	DO(ipp_cache_close);
	DO(dump_close);
	DO(tls_global_close);
	DO(misc_close);
	DO(mingw_close);
	DO(verify_tth_close);
	DO(inputevt_close);
	DO(locale_close);
	DO(wq_close);
	DO(log_close);		/* Does not disable logging */
	DO(gentime_close);

	/*
	 * Wait for pending messages from other threads.
	 */

	if (debugging(0))
		g_info("waiting for pending messages from other threads");

	exit_time = time(NULL);
	exit_grace = 10;

	while (0 != thread_pending_count()) {
		time_t now = time(NULL);
		time_delta_t d;

		if (signal_received)
			break;

		if ((d = delta_time(now, exit_time)) >= exit_grace)
			break;

		thread_yield();
	}

	/*
	 * While there are events to be processed in the TEQ, handle them
	 * and wait a little to see if more events are coming.
	 */

	if (debugging(0))
		g_info("waiting for TEQ events from closing threads");

	teq_set_throttle(0, 0);		/* No throttling */

	while (0 != teq_dispatch()) {
		int i;

		for (i = 0; i < 100; i++) {
			int n = teq_count(THREAD_MAIN);
			if (n != 0)
				break;
			thread_sleep_ms(1);
		}
	}

	/*
	 * Prepare memory shutdown.
	 *
	 * Note that evq_close() must be called AFTER vmm_pre_close() to let the
	 * periodic callbacks from the VMM layer be cleared and BEFORE we suspend
	 * the other threads, to be able to wait for the complete EVQ shutdown.
	 */

	DO(vmm_pre_close);
	DO(evq_close);				/* Can now dispose of the event queue */

	/*
	 * About to shutdown memory, suspend all the other running threads to
	 * avoid problems if they wake up suddenly and attempt to allocate memory.
	 */

	if (debugging(0)) {
		unsigned n = thread_count() - 1;
		if (n != 0)
			g_info("suspending other %u thread%s", n, plural(n));
	}

	thread_suspend_others(FALSE);

	if (debugging(0))
		DO(thread_dump_stats);

	/*
	 * Now we won't be dispatching any more TEQ events, which happen mostly
	 * when the TTH and SHA-1 threads are ended with a non-empty work queue.
	 *
	 * We can therefore close the property system completely, and the
	 * callout queue (required when exiting from detached threads to hold
	 * off the thread element for a while).
	 */

	DO(file_object_close);
	DO(settings_close);		/* Must come after hcache_close() */
	DO(cq_close);

	/*
	 * Memory shutdown must come last.
	 */

	gm_mem_set_safe_vtable();
	DO(atoms_close);
	DO(wdestroy);
	DO(zclose);
	DO(malloc_close);
	DO(hdestroy);
	DO(omalloc_close);
	DO(xmalloc_pre_close);
	DO(vmm_close);
	DO(signal_close);

quick_restart:
	g_info("gtk-gnutella shut down %s.", crashing ? "quickly" : "cleanly");

	if (shutdown_requested) {
		handle_user_shutdown_request(shutdown_user_mode);
		if (shutdown_user_flags & GTKG_SHUTDOWN_ORESTART) {
			g_info("gtk-gnutella will now restart itself...");
			crash_reexec();
		}
	}

	if (!running_topless) {
		main_gui_exit(exit_code);
	}

	exit(exit_code);

#undef DO
#undef DO_ARG
}

static void
sig_terminate(int n)
{
	signal_received = n;		/* Terminate asynchronously in main_timer() */

	if (from_atexit)			/* Might be stuck in some cleanup callback */
		exit(EXIT_FAILURE);		/* Terminate ASAP */
}

extern char **environ;

enum main_arg {
	main_arg_compile_info,
	main_arg_daemonize,
	main_arg_exec_on_crash,
	main_arg_gdb_on_crash,
	main_arg_geometry,
	main_arg_help,
	main_arg_log_stderr,
	main_arg_log_stdout,
	main_arg_minimized,
	main_arg_no_dbus,
	main_arg_no_halloc,
	main_arg_no_restart,
	main_arg_no_xshm,
	main_arg_pause_on_crash,
	main_arg_ping,
	main_arg_restart_on_crash,
	main_arg_shell,
	main_arg_topless,
	main_arg_use_poll,
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
	const char * const name;
	const char * const summary;
	const enum arg_type type;
	const char *arg;	/* memory will be allocated via halloc() */
	bool used;
} options[] = {
#define OPTION(name, type, summary) \
	{ main_arg_ ## name , #name, summary, ARG_TYPE_ ## type, NULL, FALSE }

	OPTION(compile_info,	NONE, "Display compile-time information."),
	OPTION(daemonize, 		NONE, "Daemonize the process."),
#ifdef HAS_FORK
	OPTION(exec_on_crash, 	PATH, "Path of \"program\" to run on crash."),
	OPTION(gdb_on_crash, 	NONE, "Execute gdb on crash."),
#else
	OPTION(exec_on_crash, 	NONE, NULL),
	OPTION(gdb_on_crash, 	NONE, NULL),	/* ignore silently, hide */
#endif	/* HAS_FORK */
	OPTION(geometry,		TEXT, "Placement of the main GUI window."),
	OPTION(help, 			NONE, "Print this message."),
	OPTION(log_stderr,		PATH, "Log standard output to a file."),
	OPTION(log_stdout,		PATH, "Log standard error output to a file."),
#ifdef USE_TOPLESS
	OPTION(minimized,		NONE, NULL),	/* accept but hide */
#else
	OPTION(minimized,		NONE, "Start with minimized main window."),
#endif	/* USE_TOPLESS */
	OPTION(no_dbus,			NONE, "Disable D-BUS notifications."),
#ifdef USE_HALLOC
	OPTION(no_halloc,		NONE, "Disable malloc() replacement."),
#else
	OPTION(no_halloc,		NONE, NULL),	/* ignore silently */
#endif	/* USE_HALLOC */
	OPTION(no_restart,		NONE, "Disable auto-restarts on crash."),
	OPTION(no_xshm,			NONE, "Disable MIT shared memory extension."),
	OPTION(pause_on_crash, 	NONE, "Pause the process on crash."),
	OPTION(ping,			NONE, "Check whether gtk-gnutella is running."),
	OPTION(restart_on_crash,NONE, "Force auto-restarts on crash."),
	OPTION(shell,			NONE, "Access the local shell interface."),
#ifdef USE_TOPLESS
	OPTION(topless,			NONE, NULL),	/* accept but hide */
#else
	OPTION(topless,			NONE, "Disable the graphical user-interface."),
#endif	/* USE_TOPLESS */
	OPTION(use_poll,		NONE, "Use poll() instead of epoll(), kqueue() etc."),
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
static bool
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
static const char *
option_pretty_name(const char *name)
{
	static char buf[128];
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(buf) - 1; i++) {
		if ('\0' == name[i])
			break;
		buf[i] = underscore_to_hyphen(name[i]);
	}
	buf[i] = '\0';
	return buf;
}

static void G_GNUC_NORETURN
usage(int exit_code)
{
	FILE *f;
	unsigned i;

	f = EXIT_SUCCESS == exit_code ? stdout : stderr;
	fprintf(f, "Usage: gtk-gnutella [ options ... ]\n");
	
	STATIC_ASSERT(G_N_ELEMENTS(options) == num_main_args);
	for (i = 0; i < G_N_ELEMENTS(options); i++) {
		g_assert(options[i].id == i);

		if (options[i].summary) {
			const char *arg, *name;
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
				name, arg, (int) MIN(pad, INT_MAX), "", options[i].summary);
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
		const char *s;
		unsigned i;

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
	unsigned i;

	STATIC_ASSERT(G_N_ELEMENTS(options) == num_main_args);
	for (i = 0; i < G_N_ELEMENTS(options); i++) {
		g_assert(options[i].id == i);
	}

#ifdef USE_TOPLESS
	options[main_arg_topless].used = TRUE;
#endif	/* USE_TOPLESS */

	argv++;		/* Skip argv[0] */
	argc--;

	while (argc > 0) {
		const char *s;

		s = is_strprefix(argv[0], "--");
		if (NULL == s) {
			fprintf(stderr, "Unexpected argument \"%s\"\n", argv[0]);
			usage(EXIT_FAILURE);
		}
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
				options[i].arg = NOT_LEAKING(h_strdup(argv[0]));
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
}

/**
 * Validate combination of arguments, rejecting those that do not make sense.
 */
static void
validate_arguments(void)
{
	if (
		options[main_arg_no_restart].used &&
		options[main_arg_restart_on_crash].used)
	{
		fputs("Say either --restart-on-crash or --no-restart\n", stderr);
		exit(EXIT_FAILURE);
	}
#ifndef HAS_FORK
	if (
		options[main_arg_restart_on_crash].used && !crash_coredumps_disabled()
	) {
		fputs("--restart-on-crash has no effect on this platform\n", stderr);
	}
#endif	/* !HAS_FORK */
}

static void
slow_main_timer(time_t now)
{
	static unsigned i = 0;

	if (GNET_PROPERTY(cpu_debug)) {
		static tm_t since = { 0, 0 };
		static double user = 0.0;
		static double sys = 0.0;

		if (since.tv_sec == 0)
			since = tm_start_time();

		log_cpu_usage(&since, &user, &sys);
	}

	switch (i) {
	case 0:
		dmesh_store();
		version_ancient_warn();
		break;
	case 1:
		dmesh_ban_store();
		gwc_store_if_dirty();
		break;
	case 2:
		upload_stats_flush_if_dirty();
		dht_update_size_estimate();
		break;
	case 3:
		file_info_store_if_dirty();
		break;
	case 4:
		file_info_slow_timer();
		break;
	case 5:
		dht_route_store_if_dirty();
		gnet_prop_set_timestamp_val(PROP_SHUTDOWN_TIME, tm_time());
		settings_random_save(FALSE);
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
	static double last_cpu = 0.0;
	static int ticks = 0;
	static int load_avg = 0;	/* 100 * cpu% for integer arithmetic */
	static int avg = 0;			/* cpu% */
	tm_t cur_tm;
	int load = 0;
	double cpu;
	double elapsed;
	double cpu_percent;
	double coverage;
	cqueue_t *cqm = cq_main();

	/*
	 * Compute CPU time used this period.
	 */

	tm_now_exact(&cur_tm);
	cpu = tm_cputime(NULL, NULL);

	elapsed = tm_elapsed_f(&cur_tm, &last_tm);
	elapsed = MAX(elapsed, 0.000001);	/* Prevent division by zero */
	cpu_percent = 100.0 * (cpu - last_cpu) / elapsed;
	cpu_percent = MIN(cpu_percent, 100.0);

	coverage = cq_main_coverage(ticks);
	coverage = MAX(coverage, 0.001);	/* Prevent division by zero */

	if (GNET_PROPERTY(cq_debug) > 2) {
		g_debug("CQ: callout queue \"%s\" items=%d ticks=%d coverage=%d%%",
			cq_name(cqm), cq_count(cqm),
			cq_ticks(cqm), (int) (coverage * 100.0 + 0.5));
	}

	/*
	 * Correct the percentage of CPU that would have been actually used
	 * if we had had 100% of the CPU scheduling time.  We use the callout
	 * queue as a rough estimation of the CPU running time we had: the less
	 * ticks were received by the callout queue, the busier the CPU was
	 * running other things.  But we can be busy running our own code,
	 * not really because the CPU is used by other processes, so we cannot
	 * just divide by the coverage ratio.
	 */

	if (coverage <= 0.1)
		cpu_percent *= 2;
	else if (coverage <= 0.2)
		cpu_percent *= 1.5;
	else if (coverage <= 0.5)
		cpu_percent *= 1.1;

	/*
	 * If CPU scaling is enabled, correct the percentage used accordingly.
	 * We want to consider what the CPU usage would be if we were running
	 * at full speed.
	 */

	{
		guint64 current_speed = cpufreq_current();

		if (current_speed) {
			guint64 full_speed = cpufreq_max();
			double fraction = current_speed /
				(double) ((0 == full_speed) ?  current_speed : full_speed);

			if (GNET_PROPERTY(cpu_debug) > 1) {
				g_debug("CPU: running at %.2f%% of the maximum %s frequency",
					100.0 * fraction, short_frequency(full_speed));
			}

			if (fraction < 1.0)
				cpu_percent *= fraction;
		}
	}

	/*
	 * The average load is computed using a medium exponential moving average.
	 */

	load = (unsigned) cpu_percent * 100;
	load_avg += (load >> 3) - (load_avg >> 3);
	avg = load_avg / 100;

	if (GNET_PROPERTY(cpu_debug) > 1 && last_cpu > 0.0)
		g_debug("CPU: %g secs in %g secs (~%.3f%% @ cover=%g) avg=%d%%",
			cpu - last_cpu, elapsed, cpu_percent, coverage, avg);

	/*
	 * Update for next time.
	 */

	last_cpu = cpu;
	last_tm = cur_tm;		/* Struct copy */
	ticks = cq_ticks(cqm);

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
static bool
main_timer(void *unused_data)
{
	time_t now;

	(void) unused_data;

	if G_UNLIKELY((signal_received || shutdown_requested) && !exiting) {
		if (signal_received) {
			g_warning("caught %s, exiting...", signal_name(signal_received));
		}
		asynchronous_exit = TRUE;
 		gtk_gnutella_exit(EXIT_SUCCESS);
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
		log_reopen_all(options[main_arg_daemonize].used);
	}

	bsched_timer();					/* Scheduling update */
	host_timer();					/* Host connection */
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

	return TRUE;
}

typedef void (*digest_collector_cb_t)(sha1_t *digest);

static digest_collector_cb_t random_source[] = {
	palloc_stats_digest,
	gnet_stats_tcp_digest,
	thread_stats_digest,
	gnet_stats_udp_digest,
	vmm_stats_digest,
	gnet_stats_general_digest,
	tmalloc_stats_digest,
	xmalloc_stats_digest,
	zalloc_stats_digest,
};

/**
 * Called when the main callout queue is idle.
 */
static bool
callout_queue_idle(void *unused_data)
{
	bool overloaded = GNET_PROPERTY(overloaded_cpu);
	sha1_t digest;
	static uint ridx = 0;
	static size_t counter = 0;

	(void) unused_data;

	if (GNET_PROPERTY(cq_debug) > 1)
		g_debug("CQ: callout queue is idle (CPU %s)",
			overloaded ? "OVERLOADED" : "available");

	/* Idle tasks always scheduled */
	random_collect();

	/* Idle tasks only scheduled once every over run */
	if (0 == (counter++ & 1)) {
		size_t n;

		/*
		 * Be un-predictable: use round-robin 50% of the time, or a random
		 * routine to call among the ones we have at our disposal.
		 */

		if (0 == random_value(1)) {
			n = ridx;
			ridx = (ridx + 1) % G_N_ELEMENTS(random_source);
		} else {
			n = random_value(G_N_ELEMENTS(random_source) - 1);
		}

		(*random_source[n])(&digest);
		random_pool_append(&digest, sizeof digest);
	}

	return TRUE;		/* Keep scheduling this */
}

/**
 * Scan files when the GUI is up.
 */
static void
scan_files_once(cqueue_t *unused_cq, void *unused_data)
{
	(void) unused_cq;
	(void) unused_data;

	share_scan();
}

/**
 * Initialize logging.
 */
static void
initialize_logfiles(void)
{
	if (options[main_arg_log_stdout].used)
		log_set(LOG_STDOUT, options[main_arg_log_stdout].arg);

	if (options[main_arg_log_stderr].used)
		log_set(LOG_STDERR, options[main_arg_log_stderr].arg);

	if (!log_reopen_all(options[main_arg_daemonize].used)) {
		exit(EXIT_FAILURE);
	}
}

static void
handle_version_argument(void)
{
	version_string_dump();
	exit(EXIT_SUCCESS);
}

static void
handle_compile_info_argument(void)
{
	/*
	 * The output should be easily parseable, not look beautiful.
	 */

	/*
	 * If you want quoted paths, you have to escape embedded quotes!
	 */
	printf("user-interface=%s\n", GTA_INTERFACE);
	printf("bindir=%s\n", BIN);
	printf("datadir=%s\n", PRIVLIB_EXP);
	printf("libdir=%s\n", ARCHLIB_EXP);
	printf("localedir=%s\n", LOCALE_EXP);

#if !defined(OFFICIAL_BUILD) && defined(PACKAGE_SOURCE_DIR)
	printf("sourcedir=%s\n", PACKAGE_SOURCE_DIR);
#endif	/* !OFFICIAL_BUILD  && PACKAGE_SOURCE_DIR */

	/*
	 * Maybe the following should rather be printed like this:
	 *
	 * features=ipv6,dbus,gnutls,...
	 */
#ifdef ENABLE_NLS
	printf("nls=enabled\n");
#else
	printf("nls=disabled\n");
#endif	/* ENABLE_NLS */

#ifdef HAS_DBUS
	printf("dbus=enabled\n");
#else
	printf("dbus=disabled\n");
#endif	/* HAS_DBUS */

#ifdef HAS_GNUTLS
	printf("gnutls=enabled\n");
#else
	printf("gnutls=disabled\n");
#endif	/* HAS_GNUTLS */

#ifdef HAS_SOCKER_GET
	printf("socker=enabled\n");
#else
	printf("socker=disabled\n");
#endif	/* HAS_SOCKER_GET */

#ifdef HAS_IPV6
	printf("ipv6=enabled\n");
#else
	printf("ipv6=disabled\n");
#endif	/* HAS_IPV6 */

	printf("largefile-support=%s\n",
		MAX_INT_VAL(fileoffset_t) > MAX_INT_VAL(guint32) ?
			"enabled" : "disabled");

	exit(EXIT_SUCCESS);
}

/* Handle certain arguments as soon as possible */
static void
handle_arguments_asap(void)
{
	if (options[main_arg_help].used) {
		usage(EXIT_SUCCESS);
	}

#ifndef USE_TOPLESS
	if (options[main_arg_topless].used) {
		running_topless = TRUE;
	}
#endif	/* USE_TOPLESS */

	if (options[main_arg_version].used) {
		handle_version_argument();
	}
	if (options[main_arg_compile_info].used) {
		handle_compile_info_argument();
	}
	if (options[main_arg_daemonize].used) {
		if (0 != compat_daemonize(NULL)) {
			exit(EXIT_FAILURE);
		}
		/* compat_daemonize() assigned stdout and stderr to /dev/null */
		if (!log_reopen_all(TRUE)) {
			exit(EXIT_FAILURE);
		}
	}
}

/**
 * Act on the options we parsed.
 */
static void
handle_arguments(void)
{
	if (options[main_arg_shell].used) {
		local_shell(settings_local_socket_path());
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
}

/*
 * Duplicated main() arguments, in read-only memory.
 */
static int main_argc;
static const char **main_argv;
static const char **main_env;

/**
 * Allocate new string containing the original command line that launched us.
 *
 * @return command line string, which must be freed with hfree().
 */
char *
main_command_line(void)
{
	str_t *s;
	int i;

	g_assert(main_argv != NULL);		/* gm_dupmain() called */

	s = str_new(1024);

	for (i = 0; i < main_argc; i++) {
		if (i != 0)
			str_putc(s, ' ');
		str_cat(s, main_argv[i]);
	}

	return str_s2c_null(&s);
}

#ifndef GTA_PATCHLEVEL
#define GTA_PATCHLEVEL 0
#endif
#ifndef GTA_REVISION
#define GTA_REVISION NULL
#endif

int
main(int argc, char **argv)
{
	size_t str_discrepancies;

	product_init(GTA_PRODUCT_NAME,
		GTA_VERSION, GTA_SUBVERSION, GTA_PATCHLEVEL, GTA_REVCHAR,
		GTA_RELEASE, GTA_VERSION_NUMBER, GTA_REVISION, GTA_BUILD);
	product_set_website(GTA_WEBSITE);
	product_set_interface(GTA_INTERFACE);

	mingw_early_init();
	thread_set_main(FALSE);				/* Main thread cannot block! */
	gm_savemain(argc, argv, environ);	/* For gm_setproctitle() */
	tm_init();

	if (compat_is_superuser()) {
		fprintf(stderr, "Never ever run this as root! You may use:\n\n");
		fprintf(stderr, "    su - username -c 'gtk-gnutella --daemonize'\n\n");
		fprintf(stderr, "where 'username' stands for a regular user name.\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * We can no longer do this: as soon as threads are created, they can
	 * use pipe() or socketpair() to create blocking resources and we cannot
	 * close the descriptors blindly because we have no way to know from here
	 * whether a descriptor was already created in the parent process and
	 * inherited or whether it was opened by the thread layer.
	 *
	 * Note that even moving this code up in main() is not good as our malloc()
	 * routine can be called during the C startup, and that will immediately
	 * create threads.
	 *
	 *		--RAM, 2014-01-02
	 */

#if 0
	/*
	 * This must be run before we allocate memory because we might
	 * use mmap() with /dev/zero and then accidently close this
	 * file descriptor.
	 *
	 * We rely on fd_first_available() to tell us the next file descriptor
	 * that will be used by open().  We used to hardwire the value 3 here,
	 * but this is wrong as we cannot assume that a low-level library will
	 * not request a file descriptor before we reach this point.
	 *		--RAM, 2012-06-03
	 */

	{
		int first_fd;

		first_fd = fd_first_available();
		first_fd = MAX(first_fd, 3);		/* Paranoid: always keep 0,1,2 */
		close_file_descriptors(first_fd);	/* Just in case */
	}
#endif

	if (reserve_standard_file_descriptors()) {
		fprintf(stderr, "unable to reserve standard file descriptors\n");
		exit(EXIT_FAILURE);
	}

	/* First inits -- no memory allocated */

	misc_init();
	prehandle_arguments(argv);

	/* Initialize memory allocators -- order is important */

	vmm_init();
	signal_init();
	halloc_init(!options[main_arg_no_halloc].used);
	malloc_init_vtable();
	vmm_malloc_inited();
	zinit();
	walloc_init();

	/* At this point, vmm_alloc(), halloc() and zalloc() are up */

	signal_set(SIGINT, SIG_IGN);	/* ignore SIGINT in adns (e.g. for gdb) */
#ifdef SIGHUP
	signal_set(SIGHUP, sig_hup);
#endif
#ifdef SIGCHLD
	signal_set(SIGCHLD, sig_chld);
#endif
#ifdef SIGPIPE
	signal_set(SIGPIPE, SIG_IGN);
#endif

#if defined(FRAGCHECK) || defined(MALLOC_STATS)
#ifdef SIGUSR1
	signal_set(SIGUSR1, sig_malloc);
#endif
#ifdef SIGUSR2
	signal_set(SIGUSR2, sig_malloc);
#endif
#endif

	/* Early inits */

	log_init();
	main_argc = gm_dupmain(&main_argv, &main_env);
	str_discrepancies = str_test(FALSE);
	parse_arguments(argc, argv);
	validate_arguments();
	initialize_logfiles();
	{
		int flags = 0;

		flags |= options[main_arg_pause_on_crash].used ? CRASH_F_PAUSE : 0;
		flags |= options[main_arg_gdb_on_crash].used ? CRASH_F_GDB : 0;

		/*
		 * With no core dumps, we want to auto-restart by default, unless
		 * they say --no-restart.
		 *
		 * With core dumps enabled, we dump a core of course.
		 * To get an additional restart, users may say --restart-on-crash.
		 *
		 * Regardless of the core dumping condition, saying --no-restart will
		 * prevent restarts and saying --restart-on-crash will enable them,
		 * given that supplying both is forbidden.
		 */

		if (crash_coredumps_disabled()) {
			flags |= options[main_arg_no_restart].used ? 0 : CRASH_F_RESTART;
		} else {
			flags |=
				options[main_arg_restart_on_crash].used ? CRASH_F_RESTART : 0;
		}

		/*
		 * If core dumps are disabled, force gdb execution on crash
		 * to be able to get some information before the process
		 * disappears.
		 */

		flags |= crash_coredumps_disabled() ? CRASH_F_GDB : 0;

		crash_init(argv[0], product_get_name(),
			flags, options[main_arg_exec_on_crash].arg);
		crash_setnumbers(product_get_major(), product_get_minor(),
			product_get_patchlevel());
		crash_setbuild(product_get_build());
		crash_setmain(main_argc, main_argv, main_env);
		crash_set_restart(gtk_gnutella_request_restart);
	}	
	stacktrace_init(argv[0], TRUE);	/* Defer loading until needed */
	handle_arguments_asap();

	symbols_set_verbose(TRUE);
	mingw_init();
	atoms_init();
	settings_early_init();

	/*
	 * This MUST be called after handle_arguments_asap() in case the
	 * --daemonize switch is used.
	 *
	 * It can only be called after settings_early_init() since this
	 * is where the crash directory is initialized.
	 */
	crash_setdir(settings_crash_dir());

	handle_arguments();		/* Returning from here means we're good to go */
	stacktrace_post_init();	/* And for possibly (hopefully) a long time */

	/*
	 * Before using glib-1.2 routines, we absolutely need to tell the library
	 * that we are going to run multi-threaded.
	 */

#ifdef USE_GLIB1
	if (!g_thread_supported())
		g_thread_init(NULL);
#endif

	/*
	 * Continue with initializations.
	 */

	product_set_interface(running_topless ? "Topless" : GTA_INTERFACE);
	cq_init(callout_queue_idle, GNET_PROPERTY_PTR(cq_debug));
	vmm_memusage_init();	/* After callouut queue is up */
	zalloc_memusage_init();
	version_init();
	xmalloc_show_settings();
	malloc_show_settings();
	crash_setver(version_get_string());
	crash_post_init();		/* Done with crash initialization */

	/* Our regular inits */
	
#ifndef OFFICIAL_BUILD
	g_warning("%s \"%s\"",
		_("unofficial build, accessing files from"),
		PACKAGE_SOURCE_DIR);
#endif

	if (main_argc > 1) {
		char *cmd = main_command_line();

		g_info("running %s", cmd);
		HFREE_NULL(cmd);
	}

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

	random_init();
	vsort_init(1);
	htable_test();
	wq_init();
	inputevt_init(options[main_arg_use_poll].used);
	teq_io_create();
	teq_set_throttle(70, 50);	/* 70 ms max for TEQ events, every 50 ms */
	tiger_check();
	tt_check();
	tea_test();
	xxtea_test();
	patricia_test();
	strtok_test();
	locale_init();
	adns_init();
	file_object_init();
	socket_init();
	gnet_stats_init();
	iso3166_init();
	dbus_util_init(options[main_arg_no_dbus].used);
	vendor_init();
	mime_type_init();

	if (!running_topless) {
		main_gui_early_init(argc, argv, options[main_arg_no_xshm].used);
	}

	bg_init();
	upnp_init();
	udp_init();
	urpc_init();
	g2_rpc_init();
	vmsg_init();
	tsync_init();
	watcher_init();
	ctl_init();
	hcache_init();			/* before settings_init() */
	bsched_early_init();	/* before settings_init() */
	ipp_cache_init();		/* before settings_init() */
	settings_init();

	/*
	 * From now on, settings_init() was called so properties have been loaded.
	 * Routines requiring access to properties should therefore be put below.
	 */

	xmalloc_post_init();	/* after settings_init() */
	vmm_post_init();		/* after settings_init() */

	if (debugging(0) || is_running_on_mingw())
		stacktrace_load_symbols();

	if (str_discrepancies && debugging(0)) {
		g_info("found %zu discrepanc%s in string formatting:",
			str_discrepancies, 1 == str_discrepancies ? "y" : "ies");
		str_test(TRUE);
	}

	map_test();
	ipp_cache_load_all();
	tls_global_init();
	pmsg_init();
	hostiles_init();
	spam_init();
	bogons_init();
	gip_init();
	guid_init();
	uhc_init();
	ghc_init();
	gwc_init();
	verify_sha1_init();
	verify_tth_init();
	move_init();
	ignore_init();
	pattern_init();
	word_vec_init();

	file_info_init();
	host_init();
	gmsg_init();
	bsched_init();
	dump_init();
	node_init();
	g2_node_init();
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
	sq_init();
	gdht_init();
	pdht_init();
	publisher_init();
	guess_init();

	dht_init();
	upnp_post_init();

	if (!running_topless) {
		main_gui_init();
	}
	node_post_init();
	file_info_init_post();
	download_restore_state();
	ntp_init();
	random_added_listener_add(settings_add_randomness);

	/* Some signal handlers */

	signal_set(SIGTERM, sig_terminate);
	signal_set(SIGINT, sig_terminate);

#ifdef SIGXFSZ
	signal_set(SIGXFSZ, SIG_IGN);
#endif

	/* Setup the main timer */

	cq_periodic_main_add(1000, main_timer, NULL);

	/* Prepare against X connection losses -> exit() */

	atexit(gtk_gnutella_atexit);

	/* Okay, here we go */

	vmm_set_strategy(VMM_STRATEGY_LONG_TERM);

	(void) tm_time_exact();
	cq_main_insert(1000, scan_files_once, NULL);
	bsched_enable_all();
	version_ancient_warn();
	dht_attempt_bootstrap();
	http_test();
	vxml_test();
	g2_tree_test();

	if (running_topless) {
		topless_main_run();
	} else {
		main_gui_run(options[main_arg_geometry].arg,
			options[main_arg_minimized].used);
	}

	return 0;
}

/* vi: set ts=4 sw=4 cindent: */
