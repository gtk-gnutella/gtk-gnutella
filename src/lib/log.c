/*
 * $Id$
 *
 * Copyright (c) 2010-2011, Raphael Manfredi
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
 * @date 2010-2011
 */

#include "common.h"

RCSID("$Id$")

#include "log.h"
#include "atoms.h"
#include "halloc.h"
#include "stacktrace.h"
#include "offtime.h"
#include "str.h"
#include "stringify.h"
#include "tm.h"
#include "override.h"		/* Must be the last header included */

static const char * const log_domains[] = {
	G_LOG_DOMAIN, "Gtk", "GLib", "Pango"
};

static gboolean atoms_are_inited;

/**
 * A Log file we manage.
 */
struct logfile {
	const char *name;		/**< Name (static string) */
	const char *path;		/**< File path (atom or static constant) */
	FILE *f;				/**< File descriptor */
	time_t otime;			/**< Opening time, for stats */
	unsigned disabled:1;	/**< Disabled when opened to /dev/null */
	unsigned changed:1;		/**< Logfile path was changed, pending reopen */
	unsigned path_is_atom:1;	/**< Path is an atom */
};

/**
 * Set of log files.
 */
static struct logfile logfile[LOG_MAX_FILES];

/**
 * This is used to protect critical sections of the log_handler() routine
 * so that routines we may call do not blindly log messages unless they
 * have checked with logging_would_recurse() that it will not cause recursion.
 */
static volatile sig_atomic_t in_log_handler;

static const char DEV_NULL[] = "/dev/null";

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

	if (logfile[LOG_STDERR].disabled)
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

	if (is_running_on_mingw())
		fflush(stderr);			/* Unbuffering does not work on Windows */

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
log_reopen(enum log_file which)
{
	gboolean success = TRUE;
	FILE *f;
	struct logfile *lf;

	g_assert(uint_is_non_negative(which) && which < LOG_MAX_FILES);
	g_assert(logfile[which].path != NULL);	/* log_set() called */

	lf = &logfile[which];
	f = lf->f;
	g_assert(f != NULL);

	if (freopen(lf->path, "a", f)) {
		setvbuf(f, NULL, _IOLBF, 0);
		lf->disabled = 0 == strcmp(lf->path, DEV_NULL);
		lf->otime = tm_time();
		lf->changed = FALSE;
	} else {
		fprintf(stderr, "freopen(\"%s\", \"a\", ...) failed: %s",
			lf->path, g_strerror(errno));
		lf->disabled = TRUE;
		lf->otime = 0;
		success = FALSE;
	}

	return success;
}

/**
 * Reopen log file, if managed.
 *
 * @return TRUE on success
 */
gboolean
log_reopen_if_managed(enum log_file which)
{
	g_assert(uint_is_non_negative(which) && which < LOG_MAX_FILES);

	if (NULL == logfile[which].path)
		return TRUE;		/* Unmanaged logfile */

	return log_reopen(which);
}

/**
 * Reopen all log files we manage.
 *
 * @return TRUE if OK.
 */
gboolean
log_reopen_all(gboolean daemonized)
{
	size_t i;
	gboolean success = TRUE;

	for (i = 0; i < G_N_ELEMENTS(logfile); i++) {
		struct logfile *lf = &logfile[i];

		if (NULL == lf->path) {
			if (daemonized)
				log_set_disabled(i, TRUE);
			continue;			/* Un-managed */
		}

		if (!log_reopen(i))
			success = FALSE;
	}

	return success;
}

/**
 * Enable or disable stderr output.
 */
void
log_set_disabled(enum log_file which, gboolean disabled)
{
	g_assert(uint_is_non_negative(which) && which < LOG_MAX_FILES);

	logfile[which].disabled = disabled;
}

/**
 * Set a managed log file.
 */
void
log_set(enum log_file which, const char *path)
{
	struct logfile *lf;

	g_assert(uint_is_non_negative(which) && which < LOG_MAX_FILES);
	g_assert(path != NULL);

	lf = &logfile[which];

	if (NULL == lf->path || strcmp(path, lf->path) != 0)
		lf->changed = TRUE;		/* Pending a reopen */

	if (atoms_are_inited) {
		if (lf->path_is_atom)
			atom_str_change(&logfile[which].path, path);
		else
			lf->path = atom_str_get(path);
		lf->path_is_atom = TRUE;
	} else {
		g_assert(!lf->path_is_atom);
		lf->path = path;		/* Must be a constant */
	}
}

/**
 * Rename current managed logfile, then re-opens it as the old name.
 *
 * @return TRUE on success, FALSE on errors with errno set.
 */
gboolean
log_rename(enum log_file which, const char *newname)
{
	struct logfile *lf;
	int saved_errno = 0;
	gboolean ok = TRUE;

	g_assert(uint_is_non_negative(which) && which < LOG_MAX_FILES);
	g_assert(newname != NULL);

	lf = &logfile[which];

	if (NULL == lf->path) {
		errno = EBADF;			/* File not managed, cannot rename */
		return FALSE;
	}

	if (lf->disabled) {
		errno = EIO;			/* File redirected to /dev/null */
		return FALSE;
	}

	/*
	 * On Windows, one cannot rename an opened file.
	 *
	 * So first re-open the file to some temporary file.  We don't want to
	 * close any of stderr or stdout because we may not be able to reopen them
	 * properly.  We don't reopen the file to /dev/null in case there is
	 * something wrong and we're renaming stderr: we would then be totally
	 * blind in case we cannot reopen again the file to its final destination.
	 * Reopening to /dev/null also seems to have nasty side effectson that
	 * platform: it closes the file and we cannot reopen it.
	 */

	fflush(lf->f);		/* Precaution, before renaming */

	if (is_running_on_mingw()) {
		const char *tmp = str_smsg("%s.__tmp__", lf->path);
		if (!freopen(tmp, "a", lf->f)) {
			errno = EIO;
			return FALSE;
		}
	}

	if (-1 == rename(lf->path, newname)) {
		saved_errno = errno;
		ok = FALSE;
	}

	/*
	 * Whether renaming succeeded or not, we need to restore the file
	 * to its original destination, and unlink the temporary file.
	 *
	 * We use the __tmp__ suffix to make sure there is no name collision
	 * with a user file that would happen to be there.
	 */

	if (is_running_on_mingw()) {
		const char *tmp = str_smsg("%s.__tmp__", lf->path);
		freopen(lf->path, "a", lf->f);
		if (-1 == unlink(tmp)) {
			g_warning("cannot unlink temporary log file \"%s\": %s",
				tmp, g_strerror(errno));
		}
	}

	if (!ok) {
		g_warning("could not rename \"%s\" as \"%s\": %s",
			lf->path, newname, g_strerror(saved_errno));
		errno = saved_errno;
		return FALSE;
	}

	/*
	 * On UNIX, renaming the file keeps the file descriptor pointing to the
	 * renamed entry, so we reopen the original log file.
	 *
	 * On Windows it has already been done above.  We call log_reopen()
	 * nonetheless, to reset the opening time.
	 */

	return log_reopen(which);
}

/**
 * Get statistics about managed log file, filling supplied structure.
 */
void
log_stat(enum log_file which, struct logstat *buf)
{
	struct logfile *lf;

	g_assert(uint_is_non_negative(which) && which < LOG_MAX_FILES);
	g_assert(buf != NULL);

	lf = &logfile[which];
	buf->name = lf->name;
	buf->path = lf->path;
	buf->otime = lf->otime;
	buf->disabled = lf->disabled;
	buf->need_reopen = lf->changed;

	{
		struct stat sbuf;

		fflush(lf->f);

		if (-1 == fstat(fileno(lf->f), &sbuf)) {
			g_warning("cannot stat logfile \"%s\" at \"%s\": %s",
				lf->name, lf->path, g_strerror(errno));
			buf->size = 0;
		} else
			buf->size = sbuf.st_size;
	}
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

	logfile[LOG_STDOUT].f = stdout;
	logfile[LOG_STDOUT].name = "out";
	logfile[LOG_STDOUT].otime = tm_time();

	logfile[LOG_STDERR].f = stderr;
	logfile[LOG_STDERR].name = "err";
	logfile[LOG_STDERR].otime = tm_time();
}

/**
 * Signals that the atom layer is up.
 */
void
log_atoms_inited(void)
{
	atoms_are_inited = TRUE;
}

/**
 * Shutdown the logging layer.
 */
void
log_close(void)
{
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(logfile); i++) {
		struct logfile *lf = &logfile[i];

		if (lf->path_is_atom)
			atom_str_free_null(&lf->path);
	}
}

/* vi: set ts=4 sw=4 cindent: */
