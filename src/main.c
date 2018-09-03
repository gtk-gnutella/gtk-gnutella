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
#include "lib/aging.h"
#include "lib/atoms.h"
#include "lib/bg.h"
#include "lib/bsearch.h"
#include "lib/compat_misc.h"
#include "lib/cpufreq.h"
#include "lib/cq.h"
#include "lib/crash.h"
#include "lib/crc.h"
#include "lib/dbus_util.h"
#include "lib/debug.h"
#include "lib/entropy.h"
#include "lib/eval.h"
#include "lib/evq.h"
#include "lib/exit.h"
#include "lib/exit2str.h"
#include "lib/fd.h"
#include "lib/file_object.h"
#include "lib/gentime.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/hstrfn.h"
#include "lib/htable.h"
#include "lib/inputevt.h"
#include "lib/iso3166.h"
#include "lib/launch.h"
#include "lib/log.h"
#include "lib/map.h"
#include "lib/mem.h"
#include "lib/mime_type.h"
#include "lib/misc.h"
#include "lib/mtwist.h"
#include "lib/offtime.h"
#include "lib/omalloc.h"
#include "lib/palloc.h"
#include "lib/parse.h"
#include "lib/patricia.h"
#include "lib/pattern.h"
#include "lib/pow2.h"
#include "lib/product.h"
#include "lib/progname.h"
#include "lib/random.h"
#include "lib/setproctitle.h"
#include "lib/sha1.h"
#include "lib/shuffle.h"
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
#include "lib/vmea.h"
#include "lib/vmm.h"
#include "lib/vsort.h"
#include "lib/walloc.h"
#include "lib/watcher.h"
#include "lib/wordvec.h"
#include "lib/wq.h"
#include "lib/xmalloc.h"
#include "lib/xsort.h"
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

/**
 * The emergency memory region is allocated at the beginning and not otherwise
 * used by the process until it runs out of memory.  We don't want to waste
 * too much from the virtual address space, but this memory will be swapped
 * out by the kernel as it remains totally unused.
 *
 * A size of 8 MiB does not waste too much of the total virtual memory a modern
 * system has (swap + RAM) given that we now reason in gigabytes.  This should
 * be less than 0.1% of the total virtual memory and therefore is reasonable.
 *		--RAM, 2015-12-12
 */
#define VMEA_SIZE	(8 * 1024 * 1024)	/**< Emergency region size: 8 MiB */

#define OPT(x)		options[main_arg_ ## x].used
#define OPTARG(x)	options[main_arg_ ## x].arg

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

extern char **environ;

enum main_arg {
	/* Order matters and must the same as in options[] below */
	main_arg_child,
	main_arg_cleanup,
	main_arg_compile_info,
	main_arg_daemonize,
	main_arg_exec_on_crash,
	main_arg_gdb_on_crash,
	main_arg_geometry,
	main_arg_help,
	main_arg_log_stderr,
	main_arg_log_stdout,
	main_arg_log_supervise,
	main_arg_minimized,
	main_arg_no_build_version,
	main_arg_no_dbus,
	main_arg_no_halloc,
	main_arg_no_restart,
	main_arg_no_supervise,
	main_arg_no_xshm,
	main_arg_pause_on_crash,
	main_arg_ping,
	main_arg_restart_on_crash,
	main_arg_resume_session,
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

static struct option {
	const enum main_arg id;
	const char * const name;
	const char * const summary;
	const enum arg_type type;
	const char *arg;	/* memory will be allocated via halloc() */
	bool used;
} options[] = {
#define OPTION(name, type, summary) \
	{ main_arg_ ## name , #name, summary, ARG_TYPE_ ## type, NULL, FALSE }

	OPTION(child,			NONE, NULL),	/* hidden option */
	OPTION(cleanup,			NONE, "Final cleanup to help detect memory leaks."),
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
	OPTION(log_supervise,	PATH, "Log for the supervisor process."),
#ifdef USE_TOPLESS
	OPTION(minimized,		NONE, NULL),	/* accept but hide */
#else
	OPTION(minimized,		NONE, "Start with minimized main window."),
#endif	/* USE_TOPLESS */
	OPTION(no_build_version,NONE, NULL),	/* hidden option */
	OPTION(no_dbus,			NONE, "Disable D-BUS notifications."),
#ifdef USE_HALLOC
	OPTION(no_halloc,		NONE, "Disable malloc() replacement."),
#else
	OPTION(no_halloc,		NONE, NULL),	/* ignore silently */
#endif	/* USE_HALLOC */
	OPTION(no_restart,		NONE, "Disable auto-restarts on crash."),
	OPTION(no_supervise,	NONE, "Disable supervision by a parent process."),
	OPTION(no_xshm,			NONE, "Disable MIT shared memory extension."),
	OPTION(pause_on_crash, 	NONE, "Pause the process on crash."),
	OPTION(ping,			NONE, "Check whether gtk-gnutella is running."),
	OPTION(restart_on_crash,NONE, "Force auto-restarts on crash."),
	OPTION(resume_session,	NONE, "Request resuming of previous session."),
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
		str_bprintf(ARYLEN(buf), "Gtk+ %u.%u.%u",
				gtk_major_version, gtk_minor_version, gtk_micro_version);
		if (
				GTK_MAJOR_VERSION != gtk_major_version ||
				GTK_MINOR_VERSION != gtk_minor_version ||
				GTK_MICRO_VERSION != gtk_micro_version
		   ) {
			str_bcatf(ARYLEN(buf), " (compiled against %u.%u.%u)",
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
	 * If we're in an exception, it means we're already crashing and
	 * we are now exiting, probably because we have a supervising parent
	 * process and do not need to re-exec() ourselves.
	 */

	if (signal_in_exception())
		return;

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
		if (Setjmp(atexit_env)) {
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
static void G_COLD
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
void G_COLD
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

	DO(socket_shutdowning);			/* We're about to shutdown for good */
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
	 * Before running final cleanup, show allocation and thread statistics.
	 */

	if (debugging(0)) {
		DO(random_dump_stats);
		DO(palloc_dump_stats);
		DO(tmalloc_dump_stats);
		DO(vmm_dump_stats);
		DO(xmalloc_dump_stats);
		DO(zalloc_dump_stats);
		DO(thread_dump_stats);
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
	 *
	 * A session extension (OEXTEND) works similarily to a restart (ORESTART),
	 * excepted that we do not re-launch immediately: the session will be
	 * continued the next time GTKG is launched.
	 *
	 * Continuing a session lets one resume seeding of files, for instance.
	 * In effect, crash_was_restarted() will return TRUE in the new process.
	 */

	if (
		shutdown_user_flags &
			(GTKG_SHUTDOWN_ORESTART | GTKG_SHUTDOWN_OEXTEND)
	) {
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
		tm_t since = progstart_time();
		log_cpu_usage(&since, NULL, NULL);
	}

	/*
	 * Skip gracetime for BYE message to go through when crashing, as well
	 * as most the final exit sequence whose aim is to properly clean memory
	 * to be able to trace leaks when debugging.
	 */

	if (crashing) {
		/* Accelerated shutdown */
		DO(cq_halt);
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
			short_time_ascii(exit_grace));
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

	/*
	 * From now on, we're mostly concerned about freeing memory that
	 * could be still used in the application to be able to identify
	 * possible memory leaks.
	 *
	 * This is somehow a risky operation because the destruction order
	 * is touchy due to dependencies, and may need to be adjusted to
	 * prevent crashes when these dependencies change.
	 *
	 * This is also a useless operation for most users, who could not
	 * care less about memory leak detection when they choose to stop
	 * the application.
	 *
	 * Therefore, unless we were invoked with --cleanup explicitly,
	 * skip this part.
	 *		--RAM, 2016-10-28
	 */

	if (debugging(0) || signal_received || shutdown_requested) {
		g_info("%s final shutdown sequence...",
			OPT(cleanup) ? "running" : "skipping");
	}

	if (!OPT(cleanup))
		goto quick_restart;

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
			int n = teq_count(THREAD_MAIN_ID);
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

	{
		size_t n = thread_suspend_others(FALSE);

		if (debugging(0))
			g_info("suspended %zu thread%s", n, plural(n));
	}

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
	DO(vmea_close);
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
			crash_restarting_done();
			crash_reexec();
		} else if (shutdown_user_flags & GTKG_SHUTDOWN_OEXTEND) {
			g_info("gtk-gnutella will resume current session next time.");
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

static inline char
underscore_to_hyphen(char c)
{
	return '_' == c ? '-' : c;
}

/**
 * Compare two strings, the ASCII underscore character and the ASCII hyphen
 * character being considered equivalent.
 *
 * @return 0 if strings are equal, the sign of the comparison otherwise.
 */
static int
option_strcmp(const char *a, const char *b)
{
	g_assert(a);
	g_assert(b);

	for (;;) {
		if (underscore_to_hyphen(*a) != underscore_to_hyphen(*b))
			return CMP(*a, *b);
		if ('\0' == *a) {
			if ('\0' == *b)
				return 0;
			return -1;
		} else if ('\0' == *b) {
			return +1;
		}
		a++;
		b++;
	}

	g_assert_not_reached();
}

/**
 * Check whether ``prefix'' is a prefix of ``str'', considering "-" and "_"
 * as identical characters.
 */
static bool
option_strprefix(const char *str, const char *prefix)
{
	const char *s, *p;
	int c;

	for (s = str, p = prefix; '\0' != (c = *p); p++) {
		if (underscore_to_hyphen(c) != underscore_to_hyphen(*s++))
			return FALSE;
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

	for (i = 0; i < N_ITEMS(buf) - 1; i++) {
		if ('\0' == name[i])
			break;
		buf[i] = underscore_to_hyphen(name[i]);
	}
	buf[i] = '\0';
	return buf;
}

/**
 * Pretty print option.
 *
 * @param f			where to print the formatted option name
 * @param o			the option to print
 */
static void
option_pretty_print(FILE *f, const struct option *o)
{
	const char *arg, *name;
	size_t pad;

	arg = "";
	name = option_pretty_name(o->name);
	switch (o->type) {
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

	if (o->summary != NULL) {
		fprintf(f, "  --%s%s%-*s%s\n",
			name, arg, (int) MIN(pad, INT_MAX), "", o->summary);
	} else {
		fprintf(f, "  --%s%s\n", name, arg);
	}
}

static int
option_id_cmp(const void *a, const void *b)
{
	const struct option *oa = a, *ob = b;

	return CMP(oa->id, ob->id);
}

static int
option_name_cmp(const void *a, const void *b)
{
	const struct option *oa = a, *ob = b;

	return option_strcmp(oa->name, ob->name);
}

static int
option_name_prefix(const void *key, const void *item)
{
	const char *name = key;
	const struct option *oi = item;

	if (option_strprefix(oi->name, name))
		return 0;

	return option_strcmp(name, oi->name);
}

static void G_NORETURN
option_ambiguous(const char *name, struct option *item)
{
	struct option *min = item, *max = item, *o;
	struct option *end = &options[N_ITEMS(options)];

	fprintf(stderr, "%s: ambiguous option --%s\n", getprogname(), name);
	fprintf(stderr, "Could mean either of:\n");

	for (o = item - 1; ptr_cmp(o, options) >= 0; o--) {
		if (option_strprefix(o->name, name))
			min = o;
		else
			break;
	}

	for (o = item + 1; ptr_cmp(o, end) < 0; o++) {
		if (option_strprefix(o->name, name))
			max = o;
		else
			break;
	}

	for (o = min; ptr_cmp(o, max) <= 0; o++) {
		option_pretty_print(stderr, o);
	}

	exit(EXIT_FAILURE);
}

/**
 * Lookup for option whose name starts with supplied name and which is
 * non-ambiguous
 *
 * @attention
 * The options[] array must be sorted by name, not by ID, at the time
 * this call is made.
 *
 * @param name		the option we're looking for
 * @param fatal		whether an ambiguous option means fatal error
 *
 * @return pointer within the options[] array if found and unique, or NULL.
 */
static struct option *
option_find(const char *name, bool fatal)
{
	struct option *item;

	item = bsearch(name,
		options, N_ITEMS(options), sizeof options[0], option_name_prefix);

	if (NULL == item)
		return NULL;

	if (ptr_cmp(item, options) > 0) {
		if (option_strprefix((item - 1)->name, name))
			goto ambiguous;
	}

	if (ptr_cmp(item, options + N_ITEMS(options) - 1) < 0) {
		if (option_strprefix((item + 1)->name, name))
			goto ambiguous;
	}

	return item;		/* Must be unique match since array is sorted */

ambiguous:
	if (!fatal)
		return NULL;

	option_ambiguous(name, item);
}

static void G_NORETURN
usage(int exit_code)
{
	FILE *f;
	unsigned i;

	f = EXIT_SUCCESS == exit_code ? stdout : stderr;
	fprintf(f, "Usage: %s [ options ... ]\n", getprogname());

	xqsort(options, N_ITEMS(options), sizeof options[0], option_id_cmp);

	STATIC_ASSERT(N_ITEMS(options) == num_main_args);
	for (i = 0; i < N_ITEMS(options); i++) {
		g_assert(options[i].id == i);

		if (options[i].summary) {
			option_pretty_print(f, &options[i]);
		}
	}

	exit(exit_code);
}

/* NOTE: This function must not allocate any memory. */
static void
prehandle_arguments(char **argv)
{
	unsigned i;

	argv++;

#ifdef USE_TOPLESS
	OPT(topless) = TRUE;
#endif	/* USE_TOPLESS */

	xqsort(options, N_ITEMS(options), sizeof options[0], option_name_cmp);

	while (argv[0]) {
		const char *s;
		struct option *o;

		s = is_strprefix(argv[0], "--");
		if (NULL == s || '\0' == s[0])
			break;

		argv++;

		o = option_find(s, FALSE);
		if (NULL == o)
			goto done;

		switch (o->id) {
		case main_arg_no_halloc:
		case main_arg_child:
		case main_arg_no_supervise:
		case main_arg_topless:
			o->used = TRUE;
			break;
		default:
			break;
		}

		switch (o->type) {
		case ARG_TYPE_NONE:
			break;
		case ARG_TYPE_TEXT:
		case ARG_TYPE_PATH:
			if (NULL == argv[0] || '-' == argv[0][0])
				goto done;

			argv++;
			break;
		}
	}

done:
	xqsort(options, N_ITEMS(options), sizeof options[0], option_id_cmp);

	for (i = 0; i < N_ITEMS(options); i++) {
		g_assert(options[i].id == i);
	}
}

/**
 * Log error, prefixing string with program name, then show usage and exit.
 */
static void G_PRINTF(1, 2) G_NORETURN
main_error(const char *fmt, ...)
{
	va_list args;

	fprintf(stderr, "%s: ", getprogname());

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	usage(EXIT_FAILURE);
}

/**
 * Parse arguments, but do not take any action (excepted re-opening log files).
 */
static void
parse_arguments(int argc, char **argv)
{
	unsigned i;

	STATIC_ASSERT(N_ITEMS(options) == num_main_args);
	for (i = 0; i < N_ITEMS(options); i++) {
		g_assert(options[i].id == i);
	}

	xqsort(options, N_ITEMS(options), sizeof options[0], option_name_cmp);

	argv++;		/* Skip argv[0] */
	argc--;

	while (argc > 0) {
		const char *s;
		struct option *o;

		s = is_strprefix(argv[0], "--");
		if (NULL == s)
			main_error("unexpected argument \"%s\"\n", argv[0]);
		if ('\0' == s[0])
			break;

		argv++;
		argc--;

		o = option_find(s, TRUE);
		if (NULL == o)
			main_error("unknown option \"--%s\"\n", s);

		o->used = TRUE;
		switch (o->type) {
		case ARG_TYPE_NONE:
			break;
		case ARG_TYPE_TEXT:
		case ARG_TYPE_PATH:
			if (argc < 0 || NULL == argv[0] || '-' == argv[0][0])
				main_error("missing argument for \"--%s\"\n", s);

			switch (o->type) {
			case ARG_TYPE_TEXT:
				o->arg = NOT_LEAKING(h_strdup(argv[0]));
				break;
			case ARG_TYPE_PATH:
				o->arg = NOT_LEAKING(absolute_pathname(argv[0]));
				if (NULL == o->arg) {
					main_error(
						"could not determine absolute path for \"--%s\"\n", s);
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

	xqsort(options, N_ITEMS(options), sizeof options[0], option_id_cmp);

	for (i = 0; i < N_ITEMS(options); i++) {
		g_assert(options[i].id == i);
	}
}

/**
 * Validate combination of arguments, rejecting those that do not make sense.
 */
static void
validate_arguments(void)
{
	if (OPT(no_restart) && OPT(restart_on_crash)) {
		fprintf(stderr, "%s: say either --restart-on-crash or --no-restart\n",
			getprogname());
		exit(EXIT_FAILURE);
	}
#ifndef HAS_FORK
	if (OPT(restart_on_crash) && !crash_coredumps_disabled()) {
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
			since = progstart_time();

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

	/*
	 * Unfortunately, Linux is not always correctly handling SO_REUSEADDR:
	 * a bind() can fail with errno set to EADDRINUSE despite the flag being
	 * requested on the socket descriptor prior to calling bind().
	 *
	 * So we have no other choice but to periodically re-attempt the creation
	 * when we end-up with no TCP listening socket.
	 *		--RAM, 2015-05-17
	 */

	if (GNET_PROPERTY(tcp_no_listening))
		settings_create_listening_sockets();
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
		log_reopen_all(OPT(daemonize));
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

static void
mtwist_randomness(sha1_t *digest)
{
	random_bytes_with(mt_thread_rand, PTRLEN(digest));
}

typedef void (*digest_collector_cb_t)(sha1_t *digest);

static digest_collector_cb_t random_source[] = {
	mtwist_randomness,
	random_stats_digest,
	halloc_stats_digest,
	palloc_stats_digest,
	gnet_stats_tcp_digest,
	thread_stats_digest,
	gnet_stats_udp_digest,
	vmm_stats_digest,
	gnet_stats_general_digest,
	tmalloc_stats_digest,
	xmalloc_stats_digest,
	zalloc_stats_digest,
	entropy_minimal_collect,
};

/**
 * Called when the main callout queue is idle.
 */
static bool
callout_queue_idle(void *unused_data)
{
	sha1_t digest;
	static uint ridx = 0;
	static size_t counter = 0;

	(void) unused_data;

	if (GNET_PROPERTY(cq_debug) > 1) {
		bool overloaded = GNET_PROPERTY(overloaded_cpu);
		g_debug("CQ: callout queue is idle (CPU %s)",
			overloaded ? "OVERLOADED" : "available");
	}

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
			ridx = (ridx + 1) % N_ITEMS(random_source);
		} else {
			n = random_value(N_ITEMS(random_source) - 1);
		}

		/*
		 * The digest we get is made of random bytes, normally, but we
		 * shuffle them to make the collected bits totally unpredictable.
		 */

		(*random_source[n])(&digest);
		shuffle(VARLEN(digest), 1);		/* Randomize digest bytes */
		random_pool_append(VARLEN(digest));
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
	if (OPT(log_stdout))
		log_set(LOG_STDOUT, OPTARG(log_stdout));

	if (OPT(log_stderr))
		log_set(LOG_STDERR, OPTARG(log_stderr));

	if (!log_reopen_all(OPT(daemonize))) {
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
	if (OPT(help))
		usage(EXIT_SUCCESS);

#ifndef USE_TOPLESS
	if (OPT(topless))
		running_topless = TRUE;
#endif	/* USE_TOPLESS */

	if (OPT(version))
		handle_version_argument();

	if (OPT(compile_info))
		handle_compile_info_argument();

	if (OPT(daemonize)) {
		if (0 != compat_daemonize(NULL)) {
			exit(EXIT_FAILURE);
		}
		/* compat_daemonize() assigned stdout and stderr to /dev/null */
		if (!log_reopen_all(TRUE)) {
			exit(EXIT_FAILURE);
		}
	}

	/*
	 * Don't launch GDB, pause the process, nor restart it when we are going
	 * to be running only for a short period of time.
	 */

	if (OPT(shell) || OPT(ping)) {
		crash_ctl(CRASH_FLAG_CLEAR,
			CRASH_F_RESTART | CRASH_F_PAUSE | CRASH_F_GDB);
	}
}

/**
 * Act on the options we parsed.
 */
static void
handle_arguments(void)
{
	if (OPT(shell)) {
		local_shell(settings_local_socket_path());
		exit(EXIT_SUCCESS);
	}
	if (OPT(ping)) {
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

#define MAIN_SUPERVISE_DELAY	3600	/* Monitor children launched per hour */
#define MAIN_SUPERVISE_CHILDREN	5		/* At most 5 launches per hour */

/**
 * Run as a supervisor.
 *
 * We're going to launch a child and monitor its exit status.
 * Each time the child exits abnormally, restart it with the same arguments
 * until we get more crashes per hour than we can withstand.
 *
 */
static void G_NORETURN
main_supervise(void)
{
	uint32 dbg = 0;			/* Debugging level for callout queue */
	aging_table_t *ag;		/* Used to monitor how often children die */
	ulong children = 0;		/* Amount of children launched */
	size_t child_argc;
	const char **child_argv;
	char *cmd, *path;
	int i;

	g_assert(!OPT(child));

	setproctitle("supervisor");

	thread_set_main(TRUE);				/* Main thread will block! */
	settings_unique_instance(TRUE);		/* Supervisor process */

	/*
	 * On Windows, when they launch us via the GUI (99% of the use cases)
	 * there is no opportunity to give a --log-supervise option unless
	 * they create a shortcut and add them on the command line.
	 *
	 * Therefore, if there is no --log-supervise set, force it for them
	 * so that supervisor logs get separated from regular logs used by the
	 * children.
	 */

#ifdef MINGW32
	if (!OPT(log_supervise)) {
		OPT(log_supervise) = TRUE;
		OPTARG(log_supervise) = mingw_get_supervisor_log_path();
		mingw_file_rotate(OPTARG(log_supervise), MINGW_TRACEFILE_KEEP);
	}
#endif	/* MINGW32 */

	if (OPT(log_supervise)) {
		log_set(LOG_STDOUT, OPTARG(log_supervise));
		log_set(LOG_STDERR, OPTARG(log_supervise));
		log_reopen_all(OPT(daemonize));
	} else {
		if (OPT(log_stdout))
			log_set(LOG_STDERR, OPTARG(log_stdout));
		else if (OPT(log_stderr))
			log_set(LOG_STDOUT, OPTARG(log_stderr));

		log_reopen_all(OPT(daemonize));
		log_show_pid(TRUE);
		s_warning("turning PID logging for supervisor process");
		s_message("use --log-supervise to redirect supervisor logs");
	}

	s_info("supervisor starting as PID %lu", (ulong) getpid());

	s_message("walloc() size limit set to %zu", walloc_size_threshold());
	if (!halloc_is_disabled())
		s_warning("halloc() could not be disabled");

	cq_init(NULL, &dbg);
	ag = aging_make(MAIN_SUPERVISE_DELAY, NULL, NULL, NULL);

	path = file_program_path(main_argv[0]);

	if (NULL == path) {
		s_warning("cannot locate \"%s\" in PATH", main_argv[0]);
		goto done;
	}

	s_info("program path is %s", path);

	/*
	 * Add --child as the first argument to make sure the child process
	 * is not going to recurse into being a supervisor, which would eat up
	 * all the system resources very quickly -- the infamous fork() bomb!
	 */

	child_argc = main_argc + 1;
	XMALLOC_ARRAY(child_argv, child_argc + 1);	/* +1 for trailing NULL */

	child_argv[0] = main_argv[0];
	child_argv[1] = "--child";
	for (i = 1; i <= main_argc; i++)
		child_argv[i+1] = main_argv[i];

	cmd = h_strjoinv(" ", (char **) child_argv);
	s_info("will be launching: %s", cmd);
	HFREE_NULL(cmd);

	while (aging_count(ag) < MAIN_SUPERVISE_CHILDREN) {
		pid_t pid;
		int status;
		time_t start, end;

		pid = launchve(path, (char **) child_argv, NULL);
		start = tm_time_exact();

		if ((pid_t) -1 == pid) {
			s_warning("cannot launch child #%lu: %m", children + 1);
			goto done;
		}

		children++;
		aging_record(ag, ulong_to_pointer(children));
		setproctitle("supervisor, %lu child%s launched",
			children, 1 == children ? "" : "ren");

		s_info("launched child #%lu as PID %lu", children, (ulong) pid);

		if ((pid_t) -1 == waitpid(pid, &status, 0)) {
			s_warning("cannot wait for child PID %lu: %m", (ulong) pid);
			goto done;
		}

		end = tm_time_exact();

		s_message("child #%lu (PID %lu) %s after %s",
			children, (ulong) pid, exit2str(status),
			short_time_ascii(delta_time(end, start)));

		if (0 == status) {
			s_info("supervisor exiting, launched %lu child%s over %s",
				children, 1 == children ? "" : "ren",
				short_time_ascii(delta_time(end, progstart_time().tv_sec)));
			exit(EXIT_SUCCESS);
		}
	}

	s_warning("%zu children were launched during last hour", aging_count(ag));

	/* FALL THROUGH */

done:
	s_info("supervisor exiting on failure, launched %lu child%s over %s",
		children, 1 == children ? "" : "ren",
		short_time_ascii(delta_time(tm_time_exact(), progstart_time().tv_sec)));

	exit(EXIT_FAILURE);
}

/**
 * Allocate new string containing the original command line that launched us.
 *
 * @return command line string, which must be freed with hfree().
 */
char *
main_command_line(void)
{
	g_assert(main_argv != NULL);		/* progstart_dup() called */

	return h_strjoinv(" ", (char **) main_argv);
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
	int dflt_pattern = PATTERN_INIT_PROGRESS | PATTERN_INIT_SELECTED;

	product_init(GTA_PRODUCT_NAME,
		GTA_VERSION, GTA_SUBVERSION, GTA_PATCHLEVEL, GTA_REVCHAR,
		GTA_RELEASE, GTA_VERSION_NUMBER, GTA_REVISION, GTA_BUILD);
	product_set_nickname(GTA_PRODUCT_NICK);
	product_set_website(GTA_WEBSITE);

	/*
	 * On Windows, the code path used for a GUI-launched application requires
	 * that the product information be filled, to be able to derive proper
	 * destination for log paths, since there is no console attached.
	 */

	progstart(argc, argv);
	prehandle_arguments(argv);
	product_set_interface(OPT(topless) ? "Topless" : GTA_INTERFACE);

	if (compat_is_superuser()) {
		fprintf(stderr,
			"Never ever run %s as root! You may use:\n\n", getprogname());
		fprintf(stderr,
			"    su - username -c '%s --daemonize'\n\n", getprogname());
		fprintf(stderr, "where 'username' stands for a regular user name.\n");
		exit(EXIT_FAILURE);
	}

	/* Disable walloc() and halloc() if we're going to supervise */

	if (!OPT(no_supervise) && !OPT(child)) {
		(void) walloc_active_limit();
		(void) halloc_disable();
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
		fd_close_from(first_fd);			/* Just in case */
	}
#endif

	if (reserve_standard_file_descriptors()) {
		fprintf(stderr, "%s: unable to reserve standard file descriptors\n",
			getprogname());
		exit(EXIT_FAILURE);
	}

	/* Initialize memory allocators -- order is important */

	vmm_init();
	signal_init();
	halloc_init(!OPT(no_halloc));
	malloc_init_vtable();
	vmm_malloc_inited();
	zinit();
	walloc_init();

	/* At this point, vmm_alloc(), halloc() and zalloc() are up */

	tm_init(TRUE);

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
	main_argc = progstart_dup(&main_argv, &main_env);
	str_discrepancies = str_test(FALSE);
	parse_arguments(argc, argv);
	validate_arguments();
	initialize_logfiles();
	{
		int flags = 0;

		flags |= OPT(pause_on_crash) ? CRASH_F_PAUSE : 0;
		flags |= OPT(gdb_on_crash) ? CRASH_F_GDB : 0;

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
			flags |= OPT(no_restart) ? 0 : CRASH_F_RESTART;
		} else {
			flags |= OPT(restart_on_crash) ? CRASH_F_RESTART : 0;
		}

		/*
		 * If core dumps are disabled, force gdb execution on crash
		 * to be able to get some information before the process
		 * disappears.
		 */

		flags |= crash_coredumps_disabled() ? CRASH_F_GDB : 0;

		/*
		 * If we're not running with --no-supervise, then we do supervise.
		 * However, only the child process (the one running with --child)
		 * is really supervised.
		 */

		flags |= (!OPT(no_supervise) && OPT(child)) ? CRASH_F_SUPERVISED : 0;

		crash_init(argv[0], product_name(), flags, OPTARG(exec_on_crash));
		crash_setnumbers(
			product_major(), product_minor(), product_patchlevel());
		crash_setbuild(product_build());
		crash_setmain();
		crash_set_restart(gtk_gnutella_request_restart);
	}

	handle_arguments_asap();

	/*
	 * This MUST be called after handle_arguments_asap() in case the
	 * --daemonize switch is used.
	 *
	 * It can only be called after settings_early_init() since this
	 * is where the crash directory is initialized.
	 */

	settings_early_init();
	crash_setdir(settings_crash_dir());
	handle_arguments();		/* Returning from here means we're good to go */
	stacktrace_post_init();	/* And for possibly (hopefully) a long time */

	/*
	 * If we are the supervisor process, go supervise and never return here.
	 */

	if (!OPT(no_supervise) && !OPT(child)) {
		main_supervise();
		g_assert_not_reached();
	}

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

	thread_set_main(FALSE);				/* Main thread cannot block! */

	mingw_init();
	atoms_init();
	cq_init(callout_queue_idle, GNET_PROPERTY_PTR(cq_debug));
	vmm_memusage_init();	/* After callouut queue is up */
	zalloc_memusage_init();
	version_init(OPT(no_build_version));
	xmalloc_show_settings();
	malloc_show_settings();
	zalloc_show_settings();
	crash_setver(version_build_string());	/* Wants true full version */
	crash_setccdate(__DATE__);
	crash_setcctime(__TIME__);
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

	symbols_set_verbose(TRUE);
	vmea_reserve(VMEA_SIZE, TRUE);

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

	STATIC_ASSERT(MAX_UINT_VALUE(uint64) == MAX_INT_VAL(uint64));
	STATIC_ASSERT(MAX_INT_VALUE(int64) == MAX_INT_VAL(int64));
	STATIC_ASSERT(MIN_INT_VALUE(int64) == MIN_INT_VAL(int64));

	STATIC_ASSERT(MAX_UINT_VALUE(uint32) == MAX_INT_VAL(uint32));
	STATIC_ASSERT(MAX_INT_VALUE(int32) == MAX_INT_VAL(int32));
	STATIC_ASSERT(MIN_INT_VALUE(int32) == MIN_INT_VAL(int32));

	mem_test();
	random_init();
	vsort_init(isatty(STDERR_FILENO) ? 0 : 1);
	pattern_init(isatty(STDERR_FILENO) ? 0 : dflt_pattern);
	htable_test();
	wq_init();
	inputevt_init(OPT(use_poll));
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
	dbus_util_init(OPT(no_dbus));
	vendor_init();
	mime_type_init();

	bg_init();
	upnp_init();
	udp_init();
	urpc_init();
	g2_rpc_init();
	vmsg_init();
	tsync_init();
	ctl_init();
	hcache_init();			/* before settings_init() */
	bsched_early_init();	/* before settings_init() */
	ipp_cache_init();		/* before settings_init() */
	settings_init(OPT(resume_session));

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

	/*
	 * Unfortunately we need to early-init the GUI, if any requested,
	 * before loading back the upload statistics.
	 */

	if (!running_topless) {
		main_gui_early_init(argc, argv, OPT(no_xshm));
	}

	upload_stats_load_history();	/* Loads the upload statistics */

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

	if (OPT(topless))
		gnet_prop_set_boolean_val(PROP_RUNNING_TOPLESS, TRUE);

	if (running_topless) {
		topless_main_run();
	} else {
		main_gui_run(OPTARG(geometry), OPT(minimized));
	}

	return 0;
}

/* vi: set ts=4 sw=4 cindent: */
