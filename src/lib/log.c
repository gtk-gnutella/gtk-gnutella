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
#include "ckalloc.h"
#include "crash.h"
#include "halloc.h"
#include "stacktrace.h"
#include "offtime.h"
#include "signal.h"
#include "str.h"
#include "stringify.h"
#include "tm.h"
#include "override.h"		/* Must be the last header included */

#define LOG_MSG_MAXLEN		512		/**< Maximum length within signal handler */

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
 * This is used to protect critical sections of the log_handler() routine.
 *
 * Routines that pose a risk of emitting a message recursively (e.g. routines
 * that can be called by log_handler(), or signal handlers) should use the
 * safe s_xxx() logging routines instead of the corresponding g_xxx().
 */
static volatile sig_atomic_t in_log_handler;

/**
 * This is used to detect recurstion in s_logv().
 */
static volatile sig_atomic_t in_safe_handler;

static const char DEV_NULL[] = "/dev/null";

/**
 * Safe logging to avoid recursion from the log handler, and safe to use
 * from a signal handler if needed.
 */
static void
s_logv(GLogLevelFlags level, const char *format, va_list args)
{
	gboolean in_signal_handler = signal_in_handler();
	GLogLevelFlags loglvl;

	if (!in_log_handler && !in_signal_handler) {
		g_logv(G_LOG_DOMAIN, level, format, args);
	} else {
		static str_t *cstr;
		const char *prefix;
		str_t *msg;
		ckhunk_t *ck = NULL;
		void *saved = NULL;

		/*
		 * An error is fatal, and indicates something is terribly wrong.
		 * Avoid allocating memory as much as possible, acting as if we
		 * were in a signal handler.
		 */

		if (G_LOG_LEVEL_ERROR == level)
			in_signal_handler = TRUE;

		/*
		 * Detect recursion, but don't make it fatal.
		 */

		if (in_safe_handler) {
			DECLARE_STR(6);
			char time_buf[18];

			crash_time(time_buf, sizeof time_buf);
			print_str(time_buf);	/* 0 */
			print_str(" (CRITICAL): recursion to format string \""); /* 1 */
			print_str(format);		/* 2 */
			print_str("\" from ");	/* 3 */
			print_str(stacktrace_caller_name(2));	/* 4 */
			print_str("\n");		/* 5 */
			flush_err_str();

			/*
			 * A recursion with an error message is always fatal.
			 */

			if (G_LOG_LEVEL_ERROR == level) {
				/*
				 * In case the error occurs within a critical section with
				 * all the signals blocked, make sure to unblock SIGBART.
				 */

				signal_unblock(SIGABRT);
				raise(SIGABRT);

				/*
				 * Back from raise(), that's bad.
				 *
				 * Either we don't have sigprocmask(), or it failed to
				 * unblock SIGBART.  Invoke the crash_handler() manually
				 * then so that we can pause() or exec() as configured
				 * in case of a crash.
				 */

				{
					rewind_str(0);

					crash_time(time_buf, sizeof time_buf);
					print_str(time_buf);	/* 0 */
					print_str(" (CRITICAL): back from raise(SIGBART)"); /* 1 */
					print_str(" -- invoking crash_handler()\n");		/* 2 */
					flush_err_str();

					crash_handler(SIGABRT);

					/*
					 * We can be back from crash_handler() if they haven't
					 * configured any pause() or exec() in case of a crash.
					 * Since SIGBART is blocked, there won't be any core.
					 */

					rewind_str(0);
					crash_time(time_buf, sizeof time_buf);
					print_str(time_buf);	/* 0 */
					print_str(" (CRITICAL): back from crash_handler()"); /* 1 */
					print_str(" -- exiting\n");		/* 2 */
					flush_err_str();

					exit(1);
				}
			}

			return;
		}

		/*
		 * OK, no recursion so far.  Emit log.
		 */

		in_safe_handler = TRUE;

		/*
		 * Within a signal handler, we can safely allocate memory to be
		 * able to format the log message by using the pre-allocated signal
		 * chunk and creating a string object out of it.
		 *
		 * When not from a signal handler, we use a static string object to
		 * perform the formatting.
		 */

		if (in_signal_handler) {
			ck = signal_chunk();
			saved = ck_save(ck);
			msg = str_new_in_chunk(ck, LOG_MSG_MAXLEN);

			if (NULL == msg) {
				DECLARE_STR(6);
				char time_buf[18];

				crash_time(time_buf, sizeof time_buf);
				print_str(time_buf);	/* 0 */
				print_str(" (CRITICAL): no memory to format string \""); /* 1 */
				print_str(format);		/* 2 */
				print_str("\" from ");	/* 3 */
				print_str(stacktrace_caller_name(2));	/* 4 */
				print_str("\n");		/* 5 */
				flush_err_str();
				ck_restore(ck, saved);
				return;
			}
		} else {
			if (NULL == cstr)
				cstr = str_new_not_leaking(0);
			msg = cstr;
		}

		/*
		 * The str_vprintf() routine is safe to use in signal handlers provided
		 * we do not attempt to format floating point numbers.
		 */

		str_vprintf(msg, format, args);

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

		/*
		 * Avoid stdio's fprintf() from within a signal handler since we
		 * don't know how the string will be formattted, nor whether
		 * re-entering fprintf() through a signal handler would be safe.
		 */

		if (in_signal_handler) {
			DECLARE_STR(9);
			char time_buf[18];

			crash_time(time_buf, sizeof time_buf);
			print_str(time_buf);	/* 0 */
			print_str(" (");		/* 1 */
			print_str(prefix);		/* 2 */
			print_str(")");			/* 3 */
			if (level & G_LOG_FLAG_RECURSION)
				print_str(" [RECURSIVE]");	/* 4 */
			if (level & G_LOG_FLAG_FATAL)
				print_str(" [FATAL]");		/* 5 */
			print_str(": ");		/* 6 */
			print_str(str_2c(msg));	/* 7 */
			print_str("\n");		/* 8 */
			flush_err_str();
		} else {
			time_t now = tm_time_exact();
			struct tm *ct = localtime(&now);

			fprintf(stderr, "%02d-%02d-%02d %.2d:%.2d:%.2d (%s)%s%s: %s\n",
				(TM_YEAR_ORIGIN + ct->tm_year) % 100,
				ct->tm_mon + 1, ct->tm_mday,
				ct->tm_hour, ct->tm_min, ct->tm_sec, prefix,
				(level & G_LOG_FLAG_RECURSION) ? " [RECURSIVE]" : "",
				(level & G_LOG_FLAG_FATAL) ? " [FATAL]" : "",
				str_2c(msg));
		}

		if (
			G_LOG_LEVEL_CRITICAL == level ||
			G_LOG_LEVEL_ERROR == level
		) {
			if (in_signal_handler)
				stacktrace_where_safe_print_offset(STDERR_FILENO, 2);
			else
				stacktrace_where_sym_print_offset(stderr, 2);
		}

		/*
		 * Free up the string memory by restoring the allocation context
		 * using the checkpoint we made before allocating that string.
		 *
		 * This allows signal handlers to log as many messages as they want,
		 * the only penalty being the critical section overhead for each
		 * message logged.
		 */

		if (in_signal_handler)
			ck_restore(ck, saved);

		if (is_running_on_mingw() && !in_signal_handler)
			fflush(stderr);		/* Unbuffering does not work on Windows */

		in_safe_handler = FALSE;
	}
}

/**
 * Safe fatal warning message, resulting in an exit with specified status.
 */
void
s_fatal_exit(int status, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_logv(G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL, format, args);
	va_end(args);
	exit(status);
}

/**
 * Safe critical message.
 */
void
s_critical(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_logv(G_LOG_LEVEL_CRITICAL, format, args);
	va_end(args);
}

/**
 * Safe error.
 */
void
s_error(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_logv(G_LOG_LEVEL_ERROR, format, args);
	va_end(args);

	raise(SIGABRT);		/* In case we did not enter g_logv() */
}

/**
 * Safe warning message.
 */
void
s_warning(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_logv(G_LOG_LEVEL_WARNING, format, args);
	va_end(args);
}

/**
 * Safe regular message.
 */
void
s_message(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_logv(G_LOG_LEVEL_MESSAGE, format, args);
	va_end(args);
}

/**
 * Safe info message.
 */
void
s_info(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_logv(G_LOG_LEVEL_INFO, format, args);
	va_end(args);
}

/**
 * Safe debug message.
 */
void
s_debug(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_logv(G_LOG_LEVEL_DEBUG, format, args);
	va_end(args);
}

/**
 * Regular log handler used for glib's logging routines (the g_xxx() ones).
 */
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
		stacktrace_where_sym_print_offset(stderr, 3);
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
		IGNORE_RESULT(freopen(lf->path, "a", lf->f));
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
