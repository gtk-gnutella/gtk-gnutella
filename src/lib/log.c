/*
 * $Id$
 *
 * Copyright (c) 2010, Raphael Manfredi
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
 * @ingroup lib
 * @file
 *
 * Logging support.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"

RCSID("$Id$")

#include "log.h"
#include "halloc.h"
#include "stacktrace.h"
#include "offtime.h"
#include "stringify.h"
#include "tm.h"
#include "override.h"		/* Must be the last header included */

static const char * const log_domains[] = {
	G_LOG_DOMAIN, "Gtk", "GLib", "Pango"
};

/**
 * This is used to protect critical sections of the log_handler() routine
 * so that routines we may call do not blindly log messages unless they
 * have checked with logging_would_recurse() that it will not cause recursion.
 */
static volatile sig_atomic_t in_log_handler;

/**
 * Whether we can write to stderr.
 */
static gboolean stderr_disabled;

/**
 * Prevent recursive logging messages, which are fatal.
 *
 * Routines called from our log handler must check for that before emitting
 * a log to prevent any fatal recursion.
 */
gboolean
log_would_recurse(void)
{
	return in_log_handler;
}

static void
log_handler(const char *unused_domain, GLogLevelFlags level,
	const char *message, void *unused_data)
{
	int saved_errno = errno;
	time_t now;
	struct tm *ct;
	const char *prefix;
	char *safer;
	GLogLevelFlags loglvl;

	(void) unused_domain;
	(void) unused_data;

	if (stderr_disabled)
		return;

	in_log_handler = TRUE;

	now = tm_time_exact();
	ct = localtime(&now);

	loglvl = level & ~(G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL);

	switch (loglvl) {
	case G_LOG_LEVEL_CRITICAL: prefix = "CRITICAL"; break;
	case G_LOG_LEVEL_ERROR:    prefix = "ERROR";    break;
	case G_LOG_LEVEL_WARNING:  prefix = "WARNING";  break;
	case G_LOG_LEVEL_MESSAGE:  prefix = "MESSAGE";  break;
	case G_LOG_LEVEL_INFO:     prefix = "INFO";     break;
	case G_LOG_LEVEL_DEBUG:    prefix = "DEBUG";    break;
	default:
		prefix = "UNKNOWN";
	}

	if (level & G_LOG_FLAG_RECURSION) {
		/* Probably logging from memory allocator, string should be safe */
		safer = deconstify_gpointer(message);
	} else {
		safer = control_escape(message);
	}

	fprintf(stderr, "%02d-%02d-%02d %.2d:%.2d:%.2d (%s)%s%s: %s\n",
		(TM_YEAR_ORIGIN + ct->tm_year) % 100, ct->tm_mon + 1, ct->tm_mday,
		ct->tm_hour, ct->tm_min, ct->tm_sec, prefix,
		(level & G_LOG_FLAG_RECURSION) ? " [RECURSIVE]" : "",
		(level & G_LOG_FLAG_FATAL) ? " [FATAL]" : "",
		safer);

	if (
		G_LOG_LEVEL_CRITICAL == loglvl ||
		G_LOG_LEVEL_ERROR == loglvl ||
		(level & (G_LOG_FLAG_RECURSION|G_LOG_FLAG_FATAL))
	) {
		stacktrace_where_print_offset(stderr, 3);
	}

	in_log_handler = FALSE;

	if (safer != message) {
		HFREE_NULL(safer);
	}

#if 0
	/* Define to debug Glib or Gtk problems */
	if (domain) {
		unsigned i;

		for (i = 0; i < G_N_ELEMENTS(log_domains); i++) {
			const char *dom = log_domains[i];
			if (dom && 0 == strcmp(domain, dom)) {
				raise(SIGTRAP);
				break;
			}
		}
	}
#endif

	errno = saved_errno;
}

/**
 * Reopen log file.
 *
 * @return TRUE on success.
 */
gboolean
log_reopen(FILE *f, const char *path)
{
	gboolean success = TRUE;

	if (freopen(path, "a", f)) {
		setvbuf(f, NULL, _IOLBF, 0);
		if (f == stderr)
			stderr_disabled = 0 == strcmp(path, "/dev/null");
	} else {
		fprintf(stderr, "freopen(\"%s\", \"a\", ...) failed: %s",
			path, g_strerror(errno));
		if (f == stderr)
			stderr_disabled = TRUE;
		success = FALSE;
	}

	return success;
}

/**
 * Enable or disable stderr output.
 */
void
log_disable_stderr(gboolean disable)
{
	stderr_disabled = disable;
}

/**
 * Initialization of logging layer.
 */
void
log_init(void)
{
	unsigned i;

	setvbuf(stderr, NULL, _IONBF, 0);	/* Windows buffers stderr by default */
	for (i = 0; i < G_N_ELEMENTS(log_domains); i++) {
		g_log_set_handler(log_domains[i],
			G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL |
			G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING |
			G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_INFO | G_LOG_LEVEL_DEBUG,
			log_handler, NULL);
	}
}

/* vi: set ts=4 sw=4 cindent: */
