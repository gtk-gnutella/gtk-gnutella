/*
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

#include "log.h"
#include "atoms.h"
#include "ckalloc.h"
#include "crash.h"
#include "halloc.h"
#include "fd.h"				/* For is_valid_fd() */
#include "offtime.h"
#include "signal.h"
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"
#include "tm.h"
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

#define LOG_MSG_MAXLEN		512		/**< Maximum length within signal handler */
#define LOG_MSG_DEFAULT		4080	/**< Default string length for logger */
#define LOG_IOERR_GRACE		5		/**< Seconds between I/O errors */

static const char * const log_domains[] = {
	G_LOG_DOMAIN, "Gtk", "GLib", "Pango"
};

static gboolean atoms_are_inited;
static gboolean log_inited;
static str_t *log_str;

/**
 * A Log file we manage.
 */
struct logfile {
	const char *name;		/**< Name (static string) */
	const char *path;		/**< File path (atom or static constant) */
	FILE *f;				/**< File to log to */
	int fd;					/**< The kernel file descriptor */
	int crash_fd;			/**< When crashing, additional dump done there */
	time_t otime;			/**< Opening time, for stats */
	time_t etime;			/**< Time of last I/O error */
	unsigned disabled:1;	/**< Disabled when opened to /dev/null */
	unsigned changed:1;		/**< Logfile path was changed, pending reopen */
	unsigned path_is_atom:1;	/**< Path is an atom */
	unsigned ioerror:1;		/**< Recent I/O error occurred */
	unsigned crashing:1;	/**< Crashing mode, don't use stdio */
	unsigned duplicate:1;	/**< Duplicate logs to crash_fd without prefixing */
};

enum logthread_magic { LOGTHREAD_MAGIC = 0x72a32c36 };

/**
 * Thread private logging data.
 */
struct logthread {
	enum logthread_magic magic;
	volatile sig_atomic_t in_log_handler;	/**< Recursion detection */
	ckhunk_t *ck;			/**< Chunk from which we can allocate memory */
};

static inline void
logthread_check(const struct logthread * const lt)
{
	g_assert(lt != NULL);
	g_assert(LOGTHREAD_MAGIC == lt->magic);
	g_assert(lt->ck != NULL);
}

/**
 * Logging agent types.
 */
enum agent {
	LOG_A_STDERR,			/**< Log to stderr */
	LOG_A_STRING,			/**< Log to string */

	LOG_A_MAXTYPE
};

struct logagent;

enum logstring_magic { LOGSTRING_MAGIC = 0x3d65ee3b };

/**
 * String logging.
 */
struct logstring {
	enum logstring_magic magic;	/**< Magic number */
	str_t *buffer;				/**< Logging buffer */
	const char *prefix;			/**< Prefix to remove (static string) */
};

enum logagent_magic { LOGAGENT_MAGIC = 0x0e10380a };

static inline void
logstring_check(const struct logstring * const ls)
{
	g_assert(ls != NULL);
	g_assert(LOGSTRING_MAGIC == ls->magic);
}

/**
 * A logging agent.
 *
 * This is an abstraction used to perform polymorphic logging to either a
 * file or a string.
 */
struct logagent {
	enum logagent_magic magic;	/**< Magic number */
	enum agent type;			/**< Union discriminant */
	union {
		struct logfile *f;		/**< File logging */
		struct logstring *s;	/**< String logging */
	} u;
};

static inline void
logagent_check(const struct logagent * const la)
{
	g_assert(la != NULL);
	g_assert(LOGAGENT_MAGIC == la->magic);
}

/**
 * Set of log files.
 */
static struct logfile logfile[LOG_MAX_FILES];

#define log_flush_out()	\
	flush_str(G_LIKELY(log_inited) ? logfile[LOG_STDOUT].fd : STDOUT_FILENO)
#define log_flush_err()	\
	flush_str(G_LIKELY(log_inited) ? logfile[LOG_STDERR].fd : STDERR_FILENO)

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
 * @return pre-allocated chunk for allocating memory when no malloc() wanted.
 */
static ckhunk_t *
log_chunk(void)
{
	static ckhunk_t *ck;

	if G_UNLIKELY(NULL == ck) {
		ck = ck_init(LOG_MSG_MAXLEN * 4, LOG_MSG_MAXLEN);
	}

	return ck;
}

static void
log_file_check(enum log_file which)
{
	g_assert(uint_is_non_negative(which) && which < LOG_MAX_FILES);
}

/**
 * Get logging agent for stderr logging.
 *
 * @attention
 * There must not be any memory allocation done here in case this routine
 * is called during a crash, through a crashing hook.
 */
logagent_t *
log_agent_stderr_get(void)
{
	static logagent_t la;

	if G_UNLIKELY(la.magic != LOGAGENT_MAGIC) {
		struct logfile *lf = &logfile[LOG_STDERR];

		la.magic = LOGAGENT_MAGIC;
		la.type = LOG_A_STDERR;
		la.u.f = lf;
	}

	return &la;
}

/**
 * Create a string-logging logging driver.
 *
 * @param size			size hint for the string (0 for default)
 * @param prefix		constant prefix string to remove
 *
 * @return driver to log to a string through appending.
 */
static struct logstring *
log_driver_string_make(size_t size, const char *prefix)
{
	struct logstring *ls;

	WALLOC0(ls);
	ls->magic = LOGSTRING_MAGIC;
	ls->buffer = str_new(0 == size ? LOG_MSG_DEFAULT : size);
	ls->prefix = prefix;

	return ls;
}

/**
 * Free string-logging logging driver, along with the held string.
 */
static void
log_driver_string_free(struct logstring *ls)
{
	logstring_check(ls);

	str_destroy_null(&ls->buffer);
	ls->magic = 0;
	WFREE(ls);
}

/**
 * Create a new logging agent for string logging.
 *
 * @param size		size hint for the string (0 for default)
 * @param prefix	optional, prefix to eradicate from all lines
 *
 * @return a new logging agent that can be freed with log_agent_free_null().
 */
logagent_t *
log_agent_string_make(size_t size, const char *prefix)
{
	logagent_t *la;

	WALLOC0(la);
	la->magic = LOGAGENT_MAGIC;
	la->type = LOG_A_STRING;
	la->u.s = log_driver_string_make(size, prefix);

	return la;
}

/**
 * Extract logged string from string logger.
 */
const char *
log_agent_string_get(const logagent_t *la)
{
	logagent_check(la);
	g_assert(LOG_A_STRING == la->type);

	return str_2c(la->u.s->buffer);
}

/**
 * Reset string from string logger.
 */
void
log_agent_string_reset(logagent_t *la)
{
	logagent_check(la);
	g_assert(LOG_A_STRING == la->type);

	str_reset(la->u.s->buffer);
}

/**
 * Extract logged string from string logger and dispose of the logging agent,
 * nullifying its pointer.
 *
 * @return logged string which must be freed via hfree().
 */
char *
log_agent_string_get_null(logagent_t **la_ptr)
{
	logagent_t *la;
	char *result;

	g_assert(la_ptr != NULL);

	la = *la_ptr;

	logagent_check(la);
	g_assert(LOG_A_STRING == la->type);

	result = str_s2c_null(&la->u.s->buffer);
	log_agent_free_null(la_ptr);

	return result;
}

/**
 * Free logging agent structure.
 */
static void
log_agent_free(logagent_t *la)
{
	logagent_check(la);

	switch (la->type) {
	case LOG_A_STDERR:
		/* The logfile_t structure is static */
		goto freeing;
	case LOG_A_STRING:
		log_driver_string_free(la->u.s);
		goto freeing;
	case LOG_A_MAXTYPE:
		break;
	}
	g_assert_not_reached();

freeing:
	WFREE(la);
}

/**
 * Free logging agent structure, nullifying its pointer.
 */
void
log_agent_free_null(logagent_t **la_ptr)
{
	logagent_t *la = *la_ptr;

	if (la != NULL) {
		log_agent_free(la);
		*la_ptr = NULL;
	}
}

/**
 * Allocate a thread-private logging data descriptor.
 *
 * This must be done in the main thread before starting subsequent threads
 * since the memory allocation code is not thread-safe.
 */
logthread_t *
log_thread_alloc(void)
{
	logthread_t *lt;
	ckhunk_t *ck;

	ck = ck_init_not_leaking(2 * LOG_MSG_MAXLEN, 0);
	lt = ck_alloc(ck, sizeof *lt);
	lt->magic = LOGTHREAD_MAGIC;
	lt->ck = ck;
	lt->in_log_handler = FALSE;

	return lt;
}

/**
 * Get suitable thread-private logging data descriptor.
 *
 * If argument is non-NULL, use that one, otherwise use a private local one.
 * This allows non-threaded code to use the t_xxx() logging routines with a
 * NULL object and get safe logging with no call to malloc().
 *
 * @return valid logging data object.
 */
static logthread_t *
logthread_object(logthread_t *lt)
{
	if G_UNLIKELY(NULL == lt) {
		static logthread_t *ltp;

		if G_UNLIKELY(NULL == ltp)
			ltp = log_thread_alloc();

		return ltp;
	} else {
		return lt;
	}
}

/**
 * Is stdio file printable?
 */
gboolean
log_file_printable(const FILE *out)
{
	if (stderr == out)
		return log_printable(LOG_STDERR);
	else if (stdout == out)
		return log_printable(LOG_STDOUT);
	else
		return TRUE;
}

/**
 * Is log file printable?
 */
gboolean
log_printable(enum log_file which)
{
	struct logfile *lf;

	log_file_check(which);

	lf = &logfile[which];

	/*
	 * If an I/O error occurred recently for this logfile, do not emit anything
	 * for some short period.
	 */

	if G_UNLIKELY(lf->ioerror) {
		if (delta_time(tm_time(), lf->etime) < LOG_IOERR_GRACE)
			return FALSE;
		lf->ioerror = FALSE;
	}

	return TRUE;
}

/**
 * Emit log message.
 */
static void
log_fprint(enum log_file which, const struct tm *ct, GLogLevelFlags level,
	const char *prefix, const char *msg)
{
	struct logfile *lf;

#define FORMAT_STR	"%02d-%02d-%02d %.2d:%.2d:%.2d (%s)%s%s: %s\n"

	log_file_check(which);

	if (!log_printable(which))
		return;

	lf = &logfile[which];

	/*
	 * When crashing. we use a pre-allocated string object to format the
	 * message and the write() system call to log, bypassing any memory
	 * allocation and stdio.
	 */

	if G_UNLIKELY(log_str != NULL) {
		ssize_t w;

		str_printf(log_str, FORMAT_STR,
			(TM_YEAR_ORIGIN + ct->tm_year) % 100,
			ct->tm_mon + 1, ct->tm_mday,
			ct->tm_hour, ct->tm_min, ct->tm_sec, prefix,
			(level & G_LOG_FLAG_RECURSION) ? " [RECURSIVE]" : "",
			(level & G_LOG_FLAG_FATAL) ? " [FATAL]" : "",
			msg);

		w = write(fileno(lf->f), str_2c(log_str), str_len(log_str));

		if G_UNLIKELY((ssize_t) -1 == w) {
			lf->ioerror = TRUE;
			lf->etime = tm_time();
		}

		/*
		 * When duplication is configured, write a copy of the message
		 * without any timestamp and debug level tagging.
		 */

		if (lf->duplicate) {
			IGNORE_RESULT(write(lf->crash_fd, msg, strlen(msg)));
			IGNORE_RESULT(write(lf->crash_fd, "\n", 1));
		}
	} else {
		gboolean ioerr;

		ioerr = 0 > fprintf(lf->f, FORMAT_STR,
			(TM_YEAR_ORIGIN + ct->tm_year) % 100,
			ct->tm_mon + 1, ct->tm_mday,
			ct->tm_hour, ct->tm_min, ct->tm_sec, prefix,
			(level & G_LOG_FLAG_RECURSION) ? " [RECURSIVE]" : "",
			(level & G_LOG_FLAG_FATAL) ? " [FATAL]" : "",
			msg);

		if G_UNLIKELY(ioerr) {
			lf->ioerror = TRUE;
			lf->etime = tm_time();
		}
	}

#undef FORMAT_STR
}

/**
 * Safe logging to avoid recursion from the log handler, and safe to use
 * from a signal handler if needed, or from a concurrent thread with a
 * thread-private allocation chunk.
 *
 * @param lt		thread-private context (NULL if not in a concurrent thread)
 * @param level		glib-compatible log level flags
 * @param format	formatting string
 * @param args		variable argument list to format
 */
static void
s_logv(logthread_t *lt, GLogLevelFlags level, const char *format, va_list args)
{
	gboolean in_signal_handler = signal_in_handler();
	gboolean avoid_malloc;

	if (G_UNLIKELY(logfile[LOG_STDERR].disabled))
		return;

	/*
	 * Until the atom layer is up, consider it unsafe to call g_logv()
	 * because it could allocate memory and we have not fully initialized
	 * the memory layer yet (only the VMM layer can be assumed to be ready).
	 *
	 * When xmalloc() is remapped to malloc(), we don't want to enter g_logv()
	 * at all since we don't know how they will allocate memory, and recursion
	 * would not be detected easily.
	 *
	 * Therefore, avoid any general memory allocation by behaving as if
	 * we were in a signal handler.
	 *
	 * This allows the usage of s_xxx() logging routines very early in
	 * the process.
	 */

	avoid_malloc = lt != NULL || in_signal_handler ||
		!atoms_are_inited || log_str != NULL || xmalloc_is_malloc();

	if (!in_log_handler && !avoid_malloc) {
		g_logv(G_LOG_DOMAIN, level, format, args);
	} else {
		static str_t *cstr;
		const char *prefix;
		str_t *msg;
		ckhunk_t *ck = NULL;
		void *saved = NULL;
		gboolean recursing;
		GLogLevelFlags loglvl;

		/*
		 * An error is fatal, and indicates something is terribly wrong.
		 * Avoid allocating memory as much as possible, acting as if we
		 * were in a signal handler.
		 */

		if G_UNLIKELY(G_LOG_LEVEL_ERROR == level)
			avoid_malloc = TRUE;

		/*
		 * Detect recursion, but don't make it fatal.
		 */

		if (G_UNLIKELY(lt != NULL)) {
			recursing = lt->in_log_handler;
		} else {
			recursing = in_safe_handler;
		}

		if (recursing) {
			DECLARE_STR(6);
			char time_buf[18];

			crash_time(time_buf, sizeof time_buf);
			print_str(time_buf);	/* 0 */
			print_str(" (CRITICAL): recursion to format string \""); /* 1 */
			print_str(format);		/* 2 */
			print_str("\" from ");	/* 3 */
			print_str(stacktrace_caller_name(2));	/* 4 */
			print_str("\n");		/* 5 */
			log_flush_err();

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
					log_flush_err();
					if (log_stdout_is_distinct())
						log_flush_out();

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
					log_flush_err();
					if (log_stdout_is_distinct())
						log_flush_out();

					exit(1);
				}
			}

			return;
		}

		/*
		 * OK, no recursion so far.  Emit log.
		 */

		if (G_LIKELY(NULL == lt)) {
			in_safe_handler = TRUE;
		} else {
			lt->in_log_handler = TRUE;
		}

		/*
		 * Within a signal handler, we can safely allocate memory to be
		 * able to format the log message by using the pre-allocated signal
		 * chunk and creating a string object out of it.
		 *
		 * When not from a signal handler, we use a static string object to
		 * perform the formatting.
		 */

		if (avoid_malloc) {
			ck = (lt != NULL) ? lt->ck :
				in_signal_handler ? signal_chunk() : log_chunk();
			saved = ck_save(ck);
			msg = str_new_in_chunk(ck, LOG_MSG_MAXLEN);

			if G_UNLIKELY(NULL == msg) {
				DECLARE_STR(6);
				char time_buf[18];

				crash_time(time_buf, sizeof time_buf);
				print_str(time_buf);	/* 0 */
				print_str(" (CRITICAL): no memory to format string \""); /* 1 */
				print_str(format);		/* 2 */
				print_str("\" from ");	/* 3 */
				print_str(stacktrace_caller_name(2));	/* 4 */
				print_str("\n");		/* 5 */
				log_flush_err();
				ck_restore(ck, saved);
				return;
			}

			g_assert(ptr_diff(ck_save(ck), saved) > LOG_MSG_MAXLEN);
		} else {
			if G_UNLIKELY(NULL == cstr)
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

		if (avoid_malloc) {
			DECLARE_STR(9);
			char time_buf[18];

			crash_time(time_buf, sizeof time_buf);
			print_str(time_buf);	/* 0 */
			print_str(" (");		/* 1 */
			print_str(prefix);		/* 2 */
			print_str(")");			/* 3 */
			if G_UNLIKELY(level & G_LOG_FLAG_RECURSION)
				print_str(" [RECURSIVE]");	/* 4 */
			if G_UNLIKELY(level & G_LOG_FLAG_FATAL)
				print_str(" [FATAL]");		/* 5 */
			print_str(": ");		/* 6 */
			print_str(str_2c(msg));	/* 7 */
			print_str("\n");		/* 8 */
			log_flush_err();
			if G_UNLIKELY(level & G_LOG_FLAG_FATAL) {
				if (log_stdout_is_distinct())
					log_flush_out();
				crash_set_error(str_2c(msg));
			}
			/*
			 * When duplication is configured, write a copy of the message
			 * without any timestamp and debug level tagging.
			 */

			if G_UNLIKELY(logfile[LOG_STDERR].duplicate) {
				int fd = logfile[LOG_STDERR].crash_fd;
				IGNORE_RESULT(write(fd, str_2c(msg), str_len(msg)));
				IGNORE_RESULT(write(fd, "\n", 1));
			}
		} else {
			time_t now = tm_time_exact();
			struct tm *ct = localtime(&now);

			log_fprint(LOG_STDERR, ct, level, prefix, str_2c(msg));

			if G_UNLIKELY(level & G_LOG_FLAG_FATAL) {
				if (log_stdout_is_distinct())
					log_fprint(LOG_STDOUT, ct, level, prefix, str_2c(msg));
				crash_set_error(str_2c(msg));
			}
		}

		if G_UNLIKELY(
			G_LOG_LEVEL_CRITICAL == level ||
			G_LOG_LEVEL_ERROR == level
		) {
			if (avoid_malloc)
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

		if (avoid_malloc)
			ck_restore(ck, saved);

		if (is_running_on_mingw() && !avoid_malloc)
			fflush(stderr);		/* Unbuffering does not work on Windows */

		if (G_LIKELY(NULL == lt)) {
			in_safe_handler = FALSE;
		} else {
			lt->in_log_handler = FALSE;
		}
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
	s_logv(NULL, G_LOG_LEVEL_WARNING | G_LOG_FLAG_FATAL, format, args);
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
	s_logv(NULL, G_LOG_LEVEL_CRITICAL, format, args);
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
	s_logv(NULL, G_LOG_LEVEL_ERROR | G_LOG_FLAG_FATAL, format, args);
	va_end(args);

	raise(SIGABRT);		/* In case we did not enter g_logv() */
}

/*
 * Safe error, recording the source of the crash to allow crash hooks.
 */
void
s_error_from(const char *file, const char *format, ...)
{
	va_list args;

	crash_set_filename(file);

	va_start(args, format);
	s_logv(NULL, G_LOG_LEVEL_ERROR | G_LOG_FLAG_FATAL, format, args);
	va_end(args);

	raise(SIGABRT);		/* In case we did not enter g_logv() */
}

/**
 * Safe verbose warning message.
 */
void
s_carp(const char *format, ...)
{
	gboolean in_signal_handler = signal_in_handler();
	va_list args;

	va_start(args, format);
	s_logv(NULL, G_LOG_LEVEL_WARNING, format, args);
	va_end(args);

	if (in_signal_handler)
		stacktrace_where_safe_print_offset(STDERR_FILENO, 1);
	else
		stacktrace_where_sym_print_offset(stderr, 1);
}

/**
 * Safe warning message.
 */
void
s_warning(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_logv(NULL, G_LOG_LEVEL_WARNING, format, args);
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
	s_logv(NULL, G_LOG_LEVEL_MESSAGE, format, args);
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
	s_logv(NULL, G_LOG_LEVEL_INFO, format, args);
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
	s_logv(NULL, G_LOG_LEVEL_DEBUG, format, args);
	va_end(args);
}

/**
 * Thread-safe critical message.
 */
void
t_critical(logthread_t *lt, const char *format, ...)
{
	va_list args;

	lt = logthread_object(lt);
	logthread_check(lt);

	va_start(args, format);
	s_logv(lt, G_LOG_LEVEL_CRITICAL, format, args);
	va_end(args);
}

/**
 * Thread-safe error.
 */
void
t_error(logthread_t *lt, const char *format, ...)
{
	va_list args;

	lt = logthread_object(lt);
	logthread_check(lt);

	va_start(args, format);
	s_logv(lt, G_LOG_LEVEL_ERROR | G_LOG_FLAG_FATAL, format, args);
	va_end(args);

	raise(SIGABRT);		/* We did not enter g_logv() */
}

/**
 * Thread-safe error, recording the source of the crash to allow crash hooks.
 */
void
t_error_from(const char *file, logthread_t *lt, const char *format, ...)
{
	va_list args;

	lt = logthread_object(lt);
	logthread_check(lt);

	crash_set_filename(file);

	va_start(args, format);
	s_logv(lt, G_LOG_LEVEL_ERROR | G_LOG_FLAG_FATAL, format, args);
	va_end(args);

	raise(SIGABRT);		/* We did not enter g_logv() */
}

/**
 * Thread-safe verbose warning message.
 */
void
t_carp(logthread_t *lt, const char *format, ...)
{
	va_list args;

	lt = logthread_object(lt);
	logthread_check(lt);

	va_start(args, format);
	s_logv(lt, G_LOG_LEVEL_WARNING, format, args);
	va_end(args);

	stacktrace_where_safe_print_offset(STDERR_FILENO, 1);
}

/**
 * Thread-safe warning message.
 */
void
t_warning(logthread_t *lt, const char *format, ...)
{
	va_list args;

	lt = logthread_object(lt);
	logthread_check(lt);

	va_start(args, format);
	s_logv(lt, G_LOG_LEVEL_WARNING, format, args);
	va_end(args);
}

/**
 * Thread-safe regular message.
 */
void
t_message(logthread_t *lt, const char *format, ...)
{
	va_list args;

	lt = logthread_object(lt);
	logthread_check(lt);

	va_start(args, format);
	s_logv(lt, G_LOG_LEVEL_MESSAGE, format, args);
	va_end(args);
}

/**
 * Thread-safe info message.
 */
void
t_info(logthread_t *lt, const char *format, ...)
{
	va_list args;

	lt = logthread_object(lt);
	logthread_check(lt);

	va_start(args, format);
	s_logv(lt, G_LOG_LEVEL_INFO, format, args);
	va_end(args);
}

/**
 * Thread-safe debug message.
 */
void
t_debug(logthread_t *lt, const char *format, ...)
{
	va_list args;

	lt = logthread_object(lt);
	logthread_check(lt);

	va_start(args, format);
	s_logv(lt, G_LOG_LEVEL_DEBUG, format, args);
	va_end(args);
}

/**
 * Append log message to string.
 */
static void
log_str_logv(struct logstring *s,
	GLogLevelFlags level, const char *format, va_list args)
{
	const char *fmt;

	logstring_check(s);

	(void) level;		/* FIXME: what do we want to do with the level? */

	/*
	 * If there is a prefix, skip it at the start of the format string.
	 */

	fmt = (NULL == s->prefix) ? NULL : is_strprefix(format, s->prefix);
	if (NULL == fmt)
		fmt = format;

	str_vcatf(s->buffer, fmt, args);
	str_putc(s->buffer, '\n');
}

/**
 * Polymorphic logging dispatcher.
 *
 * @param la		logging agent
 * @param level		glib-compatible log level flags
 * @param format	formatting string
 * @param args		variable argument list to format
 */
static void
log_logv(logagent_t *la, GLogLevelFlags level, const char *format, va_list args)
{
	logagent_check(la);

	switch (la->type) {
	case LOG_A_STDERR:
		s_logv(logthread_object(NULL), level, format, args);
		return;
	case LOG_A_STRING:
		log_str_logv(la->u.s, level, format, args);
		return;
	case LOG_A_MAXTYPE:
		break;
	}
	g_assert_not_reached();
}

/**
 * Polymorphic logging of critical message.
 */
void
log_critical(logagent_t *la, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	log_logv(la, G_LOG_LEVEL_CRITICAL, format, args);
	va_end(args);
}

/**
 * Polymorphic logging of warning.
 */
void
log_warning(logagent_t *la, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	log_logv(la, G_LOG_LEVEL_WARNING, format, args);
	va_end(args);
}

/**
 * Polymorphic logging of message.
 */
void
log_message(logagent_t *la, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	log_logv(la, G_LOG_LEVEL_MESSAGE, format, args);
	va_end(args);
}

/**
 * Polymorphic logging of information.
 */
void
log_info(logagent_t *la, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	log_logv(la, G_LOG_LEVEL_INFO, format, args);
	va_end(args);
}

/**
 * Polymorphic logging of debugging information.
 */
void
log_debug(logagent_t *la, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	log_logv(la, G_LOG_LEVEL_DEBUG, format, args);
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

	if (G_UNLIKELY(logfile[LOG_STDERR].disabled))
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

	log_fprint(LOG_STDERR, ct, level, prefix, safer);

	if G_UNLIKELY(level & G_LOG_FLAG_FATAL) {
		if (log_stdout_is_distinct())
			log_fprint(LOG_STDOUT, ct, level, prefix, safer);
		crash_set_error(safer);
	}

	if (
		G_LOG_LEVEL_CRITICAL == loglvl ||
		G_LOG_LEVEL_ERROR == loglvl ||
		(level & (G_LOG_FLAG_RECURSION|G_LOG_FLAG_FATAL))
	) {
		stacktrace_where_sym_print_offset(stderr, 3);
		if (log_stdout_is_distinct()) {
			stacktrace_where_sym_print_offset(stdout, 3);
			if (is_running_on_mingw())
				fflush(stdout);		/* Unbuffering does not work on Windows */
		}
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

	log_file_check(which);
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
		s_critical("freopen(\"%s\", \"a\", ...) failed: %s",
			lf->path, g_strerror(errno));
		lf->disabled = TRUE;
		lf->otime = 0;
		success = FALSE;
	}

	return success;
}

/**
 * Is logfile managed?
 *
 * @return TRUE if we explicitly (re)opened the file
 */
gboolean
log_is_managed(enum log_file which)
{
	log_file_check(which);

	return logfile[which].path != NULL && !logfile[which].changed;
}

/**
 * Is logfile disabled?
 */
gboolean
log_is_disabled(enum log_file which)
{
	log_file_check(which);

	return logfile[which].disabled;
}

/**
 * Is stdout managed and different from stderr?
 *
 * Critical messages like assertion failures (soft or hard) can be emitted
 * to stdout as well so that they are not lost in the stderr logging volume.
 *
 * Hard assertion failures will be at the tail of stderr so they won't be
 * missed, but stderr could be disabled, so printing a copy on stdout will
 * at least give minimal feedback to the user.
 */
gboolean
log_stdout_is_distinct(void)
{
	return !log_is_disabled(LOG_STDOUT) && log_is_managed(LOG_STDOUT) &&
		(!log_is_managed(LOG_STDERR) ||
			0 != strcmp(logfile[LOG_STDOUT].path, logfile[LOG_STDERR].path));
}

/**
 * Reopen log file, if managed.
 *
 * @return TRUE on success
 */
gboolean
log_reopen_if_managed(enum log_file which)
{
	log_file_check(which);

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
	log_file_check(which);

	logfile[which].disabled = disabled;
}

/**
 * Record duplicate file descriptor where messages will also be written
 * albeit without any prefixing.
 *
 * Duplication is only triggered when the log layer is in crashing mode.
 */
void
log_set_duplicate(enum log_file which, int dupfd)
{
	log_file_check(which);
	g_assert(is_valid_fd(dupfd));

	logfile[which].duplicate = booleanize(TRUE);
	logfile[which].crash_fd = dupfd;
}

/**
 * Set a managed log file.
 */
void
log_set(enum log_file which, const char *path)
{
	struct logfile *lf;

	log_file_check(which);
	g_assert(path != NULL);

	lf = &logfile[which];

	if (NULL == lf->path || strcmp(path, lf->path) != 0)
		lf->changed = log_inited;	/* Pending a reopen when inited */

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

	log_file_check(which);
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
	 * Reopening to /dev/null also seems to have nasty side effects on that
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

	log_file_check(which);
	g_assert(buf != NULL);

	lf = &logfile[which];
	buf->name = lf->name;
	buf->path = lf->path;
	buf->otime = lf->otime;
	buf->disabled = lf->disabled;
	buf->need_reopen = lf->changed;

	{
		filestat_t sbuf;

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
G_GNUC_COLD void
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
	logfile[LOG_STDOUT].fd = fileno(stdout);
	logfile[LOG_STDOUT].name = "out";
	logfile[LOG_STDOUT].otime = tm_time();

	logfile[LOG_STDERR].f = stderr;
	logfile[LOG_STDERR].fd = fileno(stderr);
	logfile[LOG_STDERR].name = "err";
	logfile[LOG_STDERR].otime = tm_time();

	log_inited = TRUE;
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
 * Record formatting string to be used to format messages when crashing.
 */
void
log_crashing(struct str *str)
{
	g_assert(str != NULL);

	log_str = str;
}

/**
 * Force new file descriptor for given logfile.
 * Previous file is NOT closed.
 *
 * @attention
 * This is only meant to be used in the crash handler.
 */
void
log_force_fd(enum log_file which, int fd)
{
	struct logfile *lf;
	FILE *f;

	g_assert(is_valid_fd(fd));
	log_file_check(which);

	lf = &logfile[which];
	f = fdopen(fd, "a");
	if (f != NULL) {
		lf->f = f;
		lf->fd = fd;
	} else {
		s_critical("fdopen(\"%d\", \"a\") failed: %s", fd, g_strerror(errno));
	}
}

/**
 * Get file descriptor associated with a logfile.
 */
int
log_get_fd(enum log_file which)
{
	log_file_check(which);

	if G_LIKELY(log_inited) {
		return logfile[which].fd;
	}

	switch (which) {
	case LOG_STDOUT: return STDOUT_FILENO;
	case LOG_STDERR: return STDERR_FILENO;
	case LOG_MAX_FILES:
		break;
	}

	g_assert_not_reached();
}

/**
 * Shutdown the logging layer.
 */
G_GNUC_COLD void
log_close(void)
{
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(logfile); i++) {
		struct logfile *lf = &logfile[i];

		if (lf->path_is_atom)
			atom_str_free_null(&lf->path);
	}

	log_inited = FALSE;
}

/* vi: set ts=4 sw=4 cindent: */
