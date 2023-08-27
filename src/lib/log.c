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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Logging support.
 *
 * Routines that pose a risk of emitting a message recursively (e.g. routines
 * that can be called by log_handler(), or signal handlers) should use the
 * safe s_xxx() logging routines instead of the corresponding g_xxx().
 *
 * All s_xxx() routines also supports an enhanced %m formatting option which
 * displays both the symbolic errno and the error message string, plus %' to
 * format integers with groupped thousands separated with ",".
 * They guarantee that no malloc()-like routine will be used to log the message.
 *
 * There is also support for a polymorphic logging interface, through a
 * so-called "log agent" object.
 *
 * The log agent is a polymorphic dispatcher to allow transparent logging to
 * stderr or to a string.  This allows one to write a logging routine that can
 * be used to either write things to the log files or to generate a string
 * without any timestamp and logging level information.
 *
 * File loggging through log agent is guaranteed to not call malloc().
 *
 * @author Raphael Manfredi
 * @date 2010-2011
 */

#include "common.h"

#include "log.h"
#include "atio.h"
#include "atomic.h"
#include "atoms.h"
#include "ckalloc.h"
#include "crash.h"
#include "fd.h"				/* For is_valid_fd() */
#include "glog.h"
#include "halloc.h"
#include "hashing.h"		/* For string_mix_hash() and string_eq() */
#include "hashtable.h"
#include "misc.h"			/* For CONST_STRLEN() and english_strerror() */
#include "offtime.h"
#include "once.h"
#include "signal.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"
#include "thread.h"
#include "tm.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

#define LOG_MSG_MAXLEN		512		/**< Maximum length within signal handler */
#define LOG_MSG_REGULAR_LEN	3500	/**< Regular message length otherwise */
#define LOG_MSG_DEFAULT		4080	/**< Default string length for logger */
#define LOG_IOERR_GRACE		5		/**< Seconds between I/O errors */

/*
 * An internal log flag given to s_logv() to request explicit copy of the
 * message to stdout.  Since we're extending the GLogLevelFlags enum, we have
 * also to avoid using G_LOG_LEVEL_MASK to sort out the logging level out of
 * the flags...
 */
#define LOG_FLAG_COPY	(1 << G_LOG_LEVEL_USER_SHIFT)
#define LOG_LEVEL_MASK	(G_LOG_LEVEL_MASK & ~LOG_FLAG_COPY)

static const char * const log_domains[] = {
	G_LOG_DOMAIN, "Gtk", "Gdk", "GLib", "Pango"
};

static bool atoms_are_inited;
static bool log_inited;
static str_t *log_str;
static thread_key_t log_okey = THREAD_KEY_INIT;
static once_flag_t log_okey_inited;
static thread_key_t log_strkey = THREAD_KEY_INIT;
static once_flag_t log_strkey_inited;

/**
 * How large is the string holding the optional PID to log (e.g " [12345]").
 */
#define LOG_PIDLEN		(ULONG_DEC_BUFLEN + CONST_STRLEN(" []"))

/**
 * Length of a buffer able to hold the formatted time plus optionally
 * the PID of the process.
 */
#define LOG_TIME_BUFLEN	(CRASH_TIME_BUFLEN + LOG_PIDLEN)

static char logpid[LOG_PIDLEN];	/**< If non-empty, also log process PID */

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
typedef struct logthread {
	enum logthread_magic magic;
	volatile sig_atomic_t in_log_handler;	/**< Recursion detection */
	ckhunk_t *ck;			/**< Chunk from which we can allocate memory */
	unsigned stid;			/**< Thread small ID */
} logthread_t;

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
	LOG_A_STDOUT,			/**< Log to stdout */
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
static struct logfile logfile[LOG_MAX_FILES] = {
	/* LOG_STDOUT: */
	{
		.fd = STDOUT_FILENO,
		.name = "out",
	},
	/* LOG_STDERR: */
	{
		.fd = STDERR_FILENO,
		.name = "err",
	},
};

#define log_flush_out()			flush_str(logfile[LOG_STDOUT].fd)
#define log_flush_err()			flush_str(logfile[LOG_STDERR].fd)

#define log_flush_out_atomic()	flush_str_atomic(logfile[LOG_STDOUT].fd)
#define log_flush_err_atomic()	flush_str_atomic(logfile[LOG_STDERR].fd)

static bool log_crashing;
static const char DEV_NULL[] = "/dev/null";

/**
 * Make sure all logging routines are always using a raw log.
 *
 * Also a copy of all the logs is made to stdout automatically.
 *
 * This is used during emergency crashing conditions to ensure logging is
 * always going to use a safe logging mode.
 */
void G_COLD
log_crash_mode(void)
{
	log_crashing = TRUE;
}

/**
 * The global log chunk is used when we cannot use the per-thread chunk during
 * fatal errors.  There is little concurrency expected and very seldom use.
 *
 * We therefore provision enough space for about 2 messages, that would come
 * from 2 concurrent threads reporting a fatal error.
 *
 * @return pre-allocated chunk for allocating memory when no malloc() wanted.
 */
static ckhunk_t *
log_chunk(void)
{
	static ckhunk_t *ck;
	static spinlock_t chunk_slk = SPINLOCK_INIT;

	if G_UNLIKELY(NULL == ck) {
		spinlock_raw(&chunk_slk);
		if (NULL == ck)
			ck = ck_init(LOG_MSG_REGULAR_LEN * 2, LOG_MSG_MAXLEN);
		spinunlock_raw(&chunk_slk);
	}

	return ck;
}

static void
log_file_check(enum log_file which)
{
	g_assert(uint_is_non_negative(which) && which < LOG_MAX_FILES);
}

/**
 * Get logging agent for stdout logging.
 *
 * @attention
 * There must not be any memory allocation done here in case this routine
 * is called during a crash, through a crashing hook.
 */
logagent_t *
log_agent_stdout_get(void)
{
	static logagent_t la;
	static spinlock_t agent_lck = SPINLOCK_INIT;

	if G_UNLIKELY(la.magic != LOGAGENT_MAGIC) {
		spinlock(&agent_lck);
		if (la.magic != LOGAGENT_MAGIC) {
			struct logfile *lf = &logfile[LOG_STDOUT];

			la.magic = LOGAGENT_MAGIC;
			la.type = LOG_A_STDOUT;
			la.u.f = lf;
		}
		spinunlock(&agent_lck);
	}

	return &la;
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
	static spinlock_t agent_lck = SPINLOCK_INIT;

	if G_UNLIKELY(la.magic != LOGAGENT_MAGIC) {
		spinlock(&agent_lck);
		if (la.magic != LOGAGENT_MAGIC) {
			struct logfile *lf = &logfile[LOG_STDERR];

			la.magic = LOGAGENT_MAGIC;
			la.type = LOG_A_STDERR;
			la.u.f = lf;
		}
		spinunlock(&agent_lck);
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
 * Reserve room in the logging string.
 */
static void
log_driver_string_reserve(struct logstring *ls, size_t len)
{
	logstring_check(ls);

	str_reserve(ls->buffer, len);
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
 * Reserve room in the log agent to be able to safely append ``len'' bytes
 * of data without memory allocation.
 *
 * This routine does nothing if called on a logging agent not tied to
 * a string buffer.
 *
 * @param la		the log agent
 * @param len		amount of bytes we would like to reserve (pre-extension)
 */
void
log_agent_reserve(logagent_t *la, size_t len)
{
	logagent_check(la);

	switch (la->type) {
	case LOG_A_STDOUT:
	case LOG_A_STDERR:
		return;			/* Nothing we can do here */
	case LOG_A_STRING:
		log_driver_string_reserve(la->u.s, len);
		return;
	case LOG_A_MAXTYPE:
		break;
	}
	g_assert_not_reached();
}

/**
 * Free logging agent structure.
 */
static void
log_agent_free(logagent_t *la)
{
	logagent_check(la);

	switch (la->type) {
	case LOG_A_STDOUT:
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
 * @return newly created logging descriptor, NULL if we can't allocate memory.
 */
static logthread_t *
log_thread_alloc(void)
{
	logthread_t *lt;
	ckhunk_t *ck;

	if (signal_in_unsafe_handler())
		return NULL;	/* Can't allocate memory right now */

	ck = ck_init_not_leaking(LOG_MSG_REGULAR_LEN + sizeof(str_t), 0);
	lt = ck_alloc(ck, sizeof *lt);
	lt->magic = LOGTHREAD_MAGIC;
	lt->ck = ck;
	lt->in_log_handler = FALSE;
	lt->stid = thread_small_id();

	return lt;
}

/**
 * Create the log object key, once.
 */
static void
log_okey_init(void)
{
	if (-1 == thread_local_key_create(&log_okey, THREAD_LOCAL_KEEP))
		s_minierror("cannot initialize logthread object key: %m");
}

/**
 * Get suitable thread-local logging data descriptor.
 *
 * @param once		if TRUE, don't record the object as it will be used once
 *
 * @return valid logging data object for the current thread, NULL if we cannot
 * allocate one.
 */
static logthread_t *
logthread_object(bool once)
{
	logthread_t *lt;

	ONCE_FLAG_RUN(log_okey_inited, log_okey_init);

	lt = thread_local_get(log_okey);

	if G_UNLIKELY(NULL == lt) {
		lt = log_thread_alloc();
		if (NULL == lt)
			return NULL;
		if (!once)
			thread_local_set(log_okey, lt);
	}

	logthread_check(lt);
	return lt;
}

/**
 * Allocate local log formatting string object.
 */
static str_t *
log_string_alloc(void)
{
	/*
	 * We set a reasonable initial size, but this string can dynamically
	 * grow and has no upper limit.
	 */

	return str_new_not_leaking(LOG_MSG_MAXLEN);
}

/**
 * Create the log string key, once.
 */
static void
log_strkey_init(void)
{
	if (-1 == thread_local_key_create(&log_strkey, THREAD_LOCAL_KEEP))
		s_minierror("cannot initialize logstring object key: %m");
}

/**
 * Get suitable thread-local logging string.
 *
 * @return valid logging string object for the current thread.
 */
static str_t *
logstring_object(void)
{
	str_t *s;

	ONCE_FLAG_RUN(log_strkey_inited, log_strkey_init);

	s = thread_local_get(log_strkey);

	if G_UNLIKELY(NULL == s) {
		s = log_string_alloc();
		thread_local_set(log_strkey, s);
	}

	return s;
}

/**
 * Is stdio file printable?
 */
bool
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
bool
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
log_fprint(enum log_file which, const struct tm *ct, long usec,
	GLogLevelFlags level, const char *prefix, unsigned stid, const char *msg)
{
	struct logfile *lf;
	char buf[32];
	const char *tprefix;
	str_t *ls;
	ssize_t w;

#define FORMAT_STR	"%02d-%02d-%02d %.02d:%.02d:%.02d.%03ld%s (%s)%s%s: %s\n"

	log_file_check(which);

	if (!log_printable(which))
		return;

	lf = &logfile[which];

	if (stid != 0) {
		str_bprintf(ARYLEN(buf), "%s-%u", prefix, stid);
		tprefix = buf;
	} else {
		tprefix = prefix;
	}

	/*
	 * When crashing. we use a pre-allocated string object to format the
	 * message and the write() system call to log, bypassing any memory
	 * allocation and stdio.
	 */

	if G_UNLIKELY(log_str != NULL)
		ls = log_str;
	else
		ls = logstring_object();

	str_printf(ls, FORMAT_STR,
		(TM_YEAR_ORIGIN + ct->tm_year) % 100,
		ct->tm_mon + 1, ct->tm_mday,
		ct->tm_hour, ct->tm_min, ct->tm_sec, usec / 1000, logpid, tprefix,
		(level & G_LOG_FLAG_RECURSION) ? " [RECURSIVE]" : "",
		(level & G_LOG_FLAG_FATAL) ? " [FATAL]" : "",
		msg);

	/*
	 * Unfortunately, output made by two threads can intermix, i.e. the
	 * write() system call is not atomically flushing all the bytes to
	 * the file.  Hence use our own atio_write() routine.
	 */

	w = atio_write(fileno(lf->f), str_2c(ls), str_len(ls));

	if G_UNLIKELY((ssize_t) -1 == w) {
		lf->ioerror = TRUE;
		lf->etime = tm_time();
	}

	/*
	 * When duplication is configured, write a copy of the message
	 * without any timestamp and debug level tagging.
	 */

	if (lf->duplicate) {
		iovec_t iov[2];
		iovec_set(&iov[0], msg, vstrlen(msg));
		iovec_set(&iov[1], "\n", 1);
		atio_writev(lf->crash_fd, iov, N_ITEMS(iov));
	}

#undef FORMAT_STR
}

/**
 * Compute prefix based on glib's log level.
 *
 * @return pointer to static string.
 */
const char *
log_prefix(GLogLevelFlags level)
{
	/*
	 * Don't use G_LOG_LEVEL_MASK here: we need to clear our own LOG_FLAG_COPY
	 * flag as well
	 */

	switch (level & LOG_LEVEL_MASK) {
	case G_LOG_LEVEL_CRITICAL: return "CRITICAL";
	case G_LOG_LEVEL_ERROR:    return "ERROR";
	case G_LOG_LEVEL_WARNING:  return "WARNING";
	case G_LOG_LEVEL_MESSAGE:  return "MESSAGE";
	case G_LOG_LEVEL_INFO:     return "INFO";
	case G_LOG_LEVEL_DEBUG:    return "DEBUG";
	default:                   return "UNKNOWN";
	}
}

/**
 * Same as log_time(), albeit optionally use the raw time computation version.
 */
static void
log_time_careful(char *buf, size_t size, bool raw)
{
	if G_UNLIKELY(raw)
		crash_time_raw(buf, size);
	else
		crash_time(buf, size);

	clamp_strcat(buf, size, logpid);
}

/**
 * Fill supplied buffer with the current time formatted as yy-mm-dd HH:MM:SS.sss
 * and optionally the process PID, if configured to do so.
 *
 * The buffer should be at least LOG_TIME_BUFLEN bytes.
 *
 * @param buf		buffer where current time is formatted
 * @param size		length of buffer
 */
static void
log_time(char *buf, size_t size)
{
	log_time_careful(buf, size, FALSE);
}

/**
 * Same as log_time() but uses raw time, and therefore does not take locks.
 *
 * @param buf		buffer where current time is formatted
 * @param size		length of buffer
 */
static void
log_time_raw(char *buf, size_t size)
{
	log_time_careful(buf, size, TRUE);
}

/**
 * Abort and make sure we never return.
 */
void
log_abort(void)
{
	static void *log_stack[STACKTRACE_DEPTH_MAX];
	size_t count;

	/*
	 * If we have already generated a crash log and we are running supervised,
	 * it is time to exit: we're looping into errors.
	 */

	if (crash_is_logged() && crash_is_supervised()) {
		DECLARE_STR(3);
		char time_buf[LOG_TIME_BUFLEN];

		log_time(ARYLEN(time_buf));
		print_str(time_buf);							/* 0 */
		print_str(" (CRITICAL): crash log generated");	/* 1 */
		print_str(", good bye.\n");						/* 2 */

		log_flush_err_atomic();
		if (log_stdout_is_distinct())
			log_flush_out_atomic();

		_exit(EXIT_FAILURE);	/* Immediate exit */
	}

	/*
	 * It may be difficult to backtrace the stack past the signal handler
	 * which is going to be invoked by raise(), hence save a copy of the
	 * current stack before crashing.
	 */

	count = stacktrace_safe_unwind(log_stack, N_ITEMS(log_stack), 0);
	crash_save_stackframe(thread_safe_small_id(), log_stack, count);

	/*
	 * This is a synchronous error from the logging layer, so make sure we
	 * won't handle it as an asynchronous interrupt preventing symbol loading
	 * or fully decorated stack tracing if the crash handler has been
	 * installed.
	 */

	signal_abort();

	/*
	 * Back from raise(), that's bad.
	 *
	 * Either we don't have sigprocmask(), or it failed to
	 * unblock SIGBART.  Invoke the crash_handler() manually
	 * then so that we can pause() or exec() as configured
	 * in case of a crash.
	 */

	{
		DECLARE_STR(3);
		char time_buf[LOG_TIME_BUFLEN];

		log_time(ARYLEN(time_buf));
		print_str(time_buf);								/* 0 */
		print_str(" (CRITICAL): back from raise(SIGBART)"); /* 1 */
		print_str(" -- invoking crash_handler()\n");		/* 2 */
		log_flush_err_atomic();
		if (log_stdout_is_distinct())
			log_flush_out_atomic();

		crash_handler(SIGABRT);

		/*
		 * We can be back from crash_handler() if they haven't
		 * configured any pause() or exec() in case of a crash.
		 * Since SIGBART is blocked, there won't be any core.
		 */

		rewind_str(0);
		log_time(ARYLEN(time_buf));
		print_str(time_buf);			/* 0 */
		print_str(" (CRITICAL): back from crash_handler()"); /* 1 */
		print_str(" -- exiting\n");		/* 2 */
		log_flush_err_atomic();
		if (log_stdout_is_distinct())
			log_flush_out_atomic();

		_exit(EXIT_FAILURE);	/* Immediate exit */
	}
}

/**
 * Ensure the logged string was not truncated, and if it was, replace its
 * last 3 characters by a visual indication.
 *
 * @param s		the string holding the log message
 */
static void
log_check_truncated(str_t *s)
{
	/*
	 * If the string was truncated, replace its last 3 chars by "..."
	 * to give visual indication of the truncation.
	 *
	 * The string may have a trailing NUL already appended, or not, so
	 * we explicitly check for it to be able to skip the NUL character
	 * from the trailing replacement.
	 */

	if (str_is_truncated(s)) {
		static const char more[] = "+++";
		size_t n = CONST_STRLEN(more);
		int offset = -n;
		bool ok;

		if ('\0' == str_at(s, -1))
			offset--;	/* Go back one more character since we have a NUL */

		ok = str_replace(s, offset, n, more);
		g_soft_assert(ok);
	}
}

/*
 * A regular vsprintf() into a fix-sized buffer without fear of overflow...
 * If the log message is truncated, flag it as such visually.
 *
 * @return the length of the generated string.
 */
size_t
log_vbprintf(char *dst, size_t size, const char *fmt, va_list args)
{
	str_t str;

	str_new_buffer(&str, dst, size, 0);
	str_set_silent_truncation(&str, TRUE);
	str_vncatf(&str, size - 1, fmt, args);
	str_putc(&str, '\0');
	log_check_truncated(&str);

	return str_len(&str);
}

/**
 * Report no-memory condition to be able to properly format message!
 *
 * @param fmt		the formatting string
 * @param msglen	the max message length
 * @param stid		the current thread ID
 * @param caller	the caller routine
 * @param in_sigh	whether we are in a signal handler
 */
static void
log_no_memory(const char *fmt, size_t msglen, int stid,
	const char *caller, bool in_sigh)
{
	DECLARE_STR(11);
	char time_buf[LOG_TIME_BUFLEN];
	char stid_buf[ULONG_DEC_BUFLEN];
	char len_buf[ULONG_DEC_BUFLEN];

	log_time_careful(ARYLEN(time_buf), in_sigh);
	print_str(time_buf);		/* 0 */
	print_str(" (CRITICAL");	/* 1 */
	if (stid != 0) {
		const char *stid_str = PRINT_NUMBER(stid_buf, stid);
		print_str("-");			/* 2 */
		print_str(stid_str);	/* 3 */
	}
	print_str("): no ");		/* 4 */
	{
		const char *len_str = PRINT_NUMBER(len_buf, msglen);
		print_str(len_str);		/* 5 */
	}
	print_str(" bytes to format string \""); /* 6 */
	print_str(fmt);			/* 7 */
	print_str("\" from ");	/* 8 */
	print_str(caller);		/* 9 */
	print_str("()\n");		/* 10 */
	log_flush_err_atomic();
}

/**
 * Emit log message.
 *
 * @param level		the logging level
 * @param msg		the message string
 * @param prefix	the level prefix (NULL for none)
 * @param stid		the logging thread ID
 * @param in_sigh	whether we are in a signal handler
 * @param copy		whether to copy message to stdout as well
 * @param raw		whether we are in raw mode (avoid locks!)
 */
static void
log_emit(
	GLogLevelFlags level, str_t *msg, const char *prefix,
	unsigned stid, bool in_sigh, bool copy, bool raw)
{
	/*
	 * Avoid stdio's fprintf() from within a signal handler since we
	 * don't know how the string will be formattted, nor whether
	 * re-entering fprintf() through a signal handler would be safe.
	 */

	DECLARE_STR(11);
	char time_buf[LOG_TIME_BUFLEN];
	char stid_buf[ULONG_DEC_BUFLEN];

	log_time_careful(ARYLEN(time_buf), in_sigh || raw);
	print_str(time_buf);	/* 0 */
	print_str(" (");		/* 1 */
	print_str(prefix);		/* 2 */
	if (stid != 0) {
		const char *stid_str = PRINT_NUMBER(stid_buf, stid);
		print_str("-");			/* 3 */
		print_str(stid_str);	/* 4 */
	}
	print_str(")");			/* 5 */
	if G_UNLIKELY(level & G_LOG_FLAG_RECURSION)
		print_str(" [RECURSIVE]");	/* 6 */
	if G_UNLIKELY(level & G_LOG_FLAG_FATAL)
		print_str(" [FATAL]");		/* 7 */
	print_str(": ");		/* 8 */
	print_str(str_2c(msg));	/* 9 */
	print_str("\n");		/* 10 */

	/*
	 * In "raw" mode, use non-atomic flushes to avoid locks.
	 */

	if G_UNLIKELY(raw) {
		log_flush_err();
		if G_UNLIKELY(copy && log_stdout_is_distinct())
			log_flush_out();
	} else {
		log_flush_err_atomic();
		if G_UNLIKELY(copy && log_stdout_is_distinct())
			log_flush_out_atomic();
	}

	if G_UNLIKELY(level & G_LOG_FLAG_FATAL)
		crash_set_error(str_2c(msg));

	/*
	 * When duplication is configured, write a copy of the message
	 * without any timestamp and debug level tagging.
	 */

	if G_UNLIKELY(logfile[LOG_STDERR].duplicate) {
		int fd = logfile[LOG_STDERR].crash_fd;
		iovec_t iov[2];
		iovec_set(&iov[0], str_2c(msg), str_len(msg));
		iovec_set(&iov[1], "\n", 1);
		if (raw)
			IGNORE_RESULT(writev(fd, iov, N_ITEMS(iov)));
		else
			atio_writev(fd, iov, N_ITEMS(iov));
	}
}

/**
 * Raw logging service, in case of recursion or other drastic conditions.
 *
 * This routine never allocates memory, by-passes stdio and does NOT save
 * errno (since accessing errno in multi-threaded programs needs to access
 * some pthread-data that may not be accessible if we corrupted memory).
 *
 * When the ``raw'' argument is set, it also carefully avoids taking locks,
 * using a non-atomic log flushing, etc..
 *
 * It is suitable to be called (directly or through its wrappers) when we are
 * about to terminate the process anyway, so preserving errno is not critical.
 *
 * @param level		glib-compatible log level flags
 * @param raw		if TRUE, carefully avoid taking locks, use safe routines
 * @param copy		whether to copy message to stdout as well
 * @param fmt		formatting string
 * @param args		variable argument list to format
 *
 * @attention
 * This routine will clobber "errno" if an error occurs.
 */
void
s_rawlogv(GLogLevelFlags level, bool raw, bool copy,
	const char *fmt, va_list args)
{
	char data[LOG_MSG_MAXLEN];
	const char *prefix;
	unsigned stid;
	size_t len;
	str_t msg;

	if G_UNLIKELY(logfile[LOG_STDERR].disabled)
		return;

	/*
	 * Force emisison on stdout as well for fatal messages.
	 */

	if G_UNLIKELY(level & G_LOG_FLAG_FATAL)
		copy = TRUE;

	/*
	 * When ``copy'' is set, always emit message.
	 */

	if (!copy && !log_printable(LOG_STDERR))
		return;

	prefix = log_prefix(level);

	/*
	 * In a unsafe signal handler, always use "raw" mode.
	 *
	 * Note that we use this call to compute the (safe) small ID as a side
	 * effect, since checking for us running in a signal handler already
	 * requires the computation to be made.
	 */

	if (signal_in_unsafe_handler_stid(&stid))
		raw = TRUE;

	if G_UNLIKELY(raw) {
		if (THREAD_UNKNOWN_ID == stid)
			stid = 0;
	} else {
		if (THREAD_UNKNOWN_ID == stid)
			stid = thread_small_id();				/* New discovered thread! */
	}

	/*
	 * Because str_vncatf() is recursion-safe, we know we can't return
	 * to here through it.
	 */

	len = log_vbprintf(ARYLEN(data), fmt, args);	/* Uses str_vncatf() */
	str_new_buffer(&msg, ARYLEN(data), len);
	str_strip_trailing_nuls(&msg);

	log_emit(level, &msg, prefix, stid, TRUE, copy, raw);
}

/**
 * Minimal logging service, in case of recursion or other drastic conditions.
 *
 * This routine never allocates memory and by-passes stdio.
 *
 * @param level		glib-compatible log level flags
 * @param copy		whether to copy message to stdout as well
 * @param fmt		formatting string
 * @param args		variable argument list to format
 */
void
s_minilogv(GLogLevelFlags level, bool copy, const char *fmt, va_list args)
{
	int saved_errno;
	bool crashing = log_crashing;

	saved_errno = errno;
	s_rawlogv(level, crashing, copy || crashing, fmt, args);
	errno = saved_errno;
}

enum stacktrace_stack_level {
	STACKTRACE_NONE = 0,
	STACKTRACE_NORMAL,
	STACKTRACE_PLAIN
};

/**
 * Emit stacktrace to stderr and optionally stdout (if distinct from stderr).
 *
 * @param no_stdio		whether we must avoid stdio
 * @param copy			whether to copy stacktrace to stdout
 * @param offset		stack offset to apply to remove overhead from stack
 */
static void NO_INLINE
s_emit_stacktrace(bool no_stdio, bool copy, unsigned offset)
{
	static enum stacktrace_stack_level tracing[THREAD_MAX];
	static bool warned[THREAD_MAX];
	unsigned stid = thread_small_id();

	/*
	 * Protect thread, in case any of the tracing causes a recursion.
	 * Indeed, recursion would probably be fatal (endless) and would prevent
	 * further important debugging messages to be emitted by the thread.
	 *
	 * Initialally, the tracing level is STACKTRACE_NONE.  The first time
	 * we attempt a trace, we move to STACKTRACE_NORMAL.  If a recursion
	 * happens we raise to STACKTRACE_PLAIN, at which point a further recursion
	 * causes us to skip the tracing, warning once.
	 */

	if (STACKTRACE_NONE != tracing[stid]) {
		if (STACKTRACE_PLAIN == tracing[stid]) {
			if (!warned[stid]) {
				warned[stid] = TRUE;
				s_rawwarn("skipping trace for %s (already in progress)",
					thread_id_name(stid));
			}
			return;
		} else {
			tracing[stid] = STACKTRACE_PLAIN;
		}
	}

	/*
	 * If the process has entered "crash mode", then it is unsafe to emit
	 * a stacktrace here because memory allocation could do weird things
	 * with locks being disabled...  Only let the crashing thread continue.
	 */

	if (thread_in_crash_mode() && !thread_is_crashing()) {
		if (!warned[stid]) {
			warned[stid] = TRUE;
			s_rawwarn("skipping trace for %s (crash mode)",
				thread_safe_id_name(stid));
		}
		thread_check_suspended();		/* Probably was already suspended? */
		return;
	}

	if (STACKTRACE_NONE == tracing[stid])
		tracing[stid] = STACKTRACE_NORMAL;

	if (STACKTRACE_NORMAL == tracing[stid]) {
		if (no_stdio) {
			stacktrace_where_safe_print_offset(STDERR_FILENO, offset + 1);
			if (copy && log_stdout_is_distinct())
				stacktrace_where_safe_print_offset(STDOUT_FILENO, offset + 1);
		} else {
			stacktrace_where_sym_print_offset(stderr, offset + 1);
			if (copy && log_stdout_is_distinct())
				stacktrace_where_sym_print_offset(stdout, offset + 1);

			if (is_running_on_mingw()) {
				/* Unbuffering does not work on Windows, flush both */
				fflush(stderr);
				fflush(stdout);
			}
		}
	} else {
		stacktrace_where_plain_print_offset(STDERR_FILENO, offset + 1);
		if (copy && log_stdout_is_distinct())
			stacktrace_where_plain_print_offset(STDOUT_FILENO, offset + 1);
	}

	if (STACKTRACE_PLAIN == tracing[stid]) {
		tracing[stid] = STACKTRACE_NORMAL;
		warned[stid] = FALSE;
	} else {
		tracing[stid] = STACKTRACE_NONE;
	}
}

/**
 * Emit stacktrace to stderr and stdout (if distinct from stderr).
 *
 * @param no_stdio		whether we must avoid stdio
 * @param offset		stack offset to apply to remove overhead from stack
 */
void
s_stacktrace(bool no_stdio, unsigned offset)
{
	s_emit_stacktrace(no_stdio, TRUE, offset + 1);
}

/**
 * Emit stacktrace to stderr.
 *
 * @param offset		stack offset to apply to remove overhead from stack
 */
void
s_where(unsigned offset)
{
	s_emit_stacktrace(TRUE, FALSE, offset + 1);
}

/**
 * Safe logging to avoid recursion from the log handler, and safe to use
 * from a signal handler if needed, or from a concurrent thread with a
 * thread-private allocation chunk.
 *
 * This routine does not use malloc().
 *
 * @param lt		thread-private context (NULL if not in a concurrent thread)
 * @param level		glib-compatible log level flags
 * @param format	formatting string
 * @param args		variable argument list to format
 */
static void G_PRINTF(3, 0)
s_logv(logthread_t *lt, GLogLevelFlags level, const char *format, va_list args)
{
	static volatile sig_atomic_t logging[THREAD_MAX];
	int saved_errno = errno;
	bool in_signal_handler = signal_in_handler();
	const char *prefix;
	str_t *msg;
	ckhunk_t *ck;
	void *saved;
	bool recursing;
	unsigned stid;
	thread_sigsets_t set;
	size_t msglen;
	bool copy;

	if (G_UNLIKELY(logfile[LOG_STDERR].disabled))
		return;

	if G_UNLIKELY(log_crashing) {
		s_rawlogv(level, TRUE, TRUE, format, args);
		return;
	}

	/*
	 * The per-thread log object allows us to track recursion and contains
	 * our small thread-ID.  It is allocated once per thread.
	 *
	 * We don't attempt to grab a new one when logging a fatal condition
	 * because the state of the application may be corrupted and could
	 * fail the memory allocation.
	 */

	if G_UNLIKELY(NULL == lt && 0 == (level & G_LOG_FLAG_FATAL))
		lt = logthread_object(FALSE);

	/*
	 * Block all signals, to preserve the ability to log from a signal
	 * handler without causing recursions.
	 */

	thread_enter_critical(&set);

	/*
	 * Detect recursion, but don't make it fatal.
	 */

	if G_LIKELY(lt != NULL) {
		recursing = lt->in_log_handler;
	} else {
		recursing = logging[thread_small_id()];
	}

	copy = booleanize(
		level & (
			G_LOG_FLAG_FATAL  |	G_LOG_LEVEL_CRITICAL |
			G_LOG_LEVEL_ERROR |	LOG_FLAG_COPY
		)
	);

	if G_UNLIKELY(recursing) {
		DECLARE_STR(9);
		char time_buf[LOG_TIME_BUFLEN];
		const char *caller;

		stid = NULL == lt ? thread_small_id() : lt->stid;
		caller = stacktrace_caller_name(2);	/* Could log, so pre-compute */

		log_time_raw(ARYLEN(time_buf));
		print_str(time_buf);		/* 0 */
		print_str(" (CRITICAL");	/* 1 */
		if (0 != stid) {
			char stid_buf[UINT_DEC_BUFLEN];
			const char *snum = PRINT_NUMBER(stid_buf, stid);

			print_str("-");			/* 2 */
			print_str(snum);		/* 3 */
		}
		print_str("): recursion to format string \""); /* 4 */
		print_str(format);			/* 5 */
		print_str("\" from ");		/* 6 */
		print_str(caller);			/* 7 */
		print_str("()\n");			/* 8 */
		log_flush_err_atomic();

		/*
		 * A recursion with an error message is always fatal.
		 */

		if (G_LOG_LEVEL_ERROR & level)
			log_abort();

		/*
		 * Use minimal logging.
		 */

		s_minilogv(level | G_LOG_FLAG_RECURSION, copy, format, args);
		goto done;
	}

	/*
	 * OK, no recursion so far.  Emit log.
	 *
	 * Within a signal handler, we can safely allocate memory to be
	 * able to format the log message by using the pre-allocated signal
	 * chunk and creating a string object out of it.
	 *
	 * When not from a signal handler, we use a static chunk or a per-thread
	 * chunk, as supplied through the log-thread object.
	 */

	if G_UNLIKELY(NULL == lt) {
		stid = thread_small_id();
		logging[stid] = TRUE;
		if (in_signal_handler) {
			ck = signal_chunk();
			msglen = MAX(LOG_MSG_REGULAR_LEN / 2, LOG_MSG_MAXLEN);
		} else {
			ck = log_chunk();
			msglen = LOG_MSG_REGULAR_LEN;
		}
	} else {
		lt->in_log_handler = TRUE;
		stid = lt->stid;
		ck = lt->ck;
		msglen = LOG_MSG_REGULAR_LEN;
	}

	/*
	 * During early initializations, signal_chunk() can return NULL.
	 * Hence if we are crashing very early, we must take care of that.
	 */

	if G_UNLIKELY(NULL == ck) {
		s_rawlogv(level, TRUE, FALSE, format, args);	/* Lower size limit */
		goto log_done;
	}

	saved = ck_save(ck);
	msg = str_new_in_chunk(ck, msglen);

	/*
	 * When there is no room in the chunk to allocate enough space to format
	 * a message, report the fact and redirect to s_rawlogv() which can always
	 * log using stack space for the message buffer: the message could be
	 * truncated, but at least it will not be completely lost.
	 */

	if G_UNLIKELY(NULL == msg) {
		const char *caller = stacktrace_caller_name(2);
		log_no_memory(format, msglen, stid, caller, in_signal_handler);
		ck_restore(ck, saved);
		s_rawlogv(level, TRUE, FALSE, format, args);	/* Lower size limit */
		goto log_done;
	}

	g_assert(ptr_diff(ck_save(ck), saved) > msglen);

	/*
	 * The str_vprintf() routine is safe to use in signal handlers.
	 */

	str_set_silent_truncation(msg, TRUE);
	str_vprintf(msg, format, args);
	log_check_truncated(msg);
	prefix = log_prefix(level);

	/*
	 * Emit the log message.
	 */

	log_emit(level, msg, prefix, stid, in_signal_handler, copy, FALSE);

log_done:

	/*
	 * Free up the string memory by restoring the allocation context
	 * using the checkpoint we made before allocating that string.
	 *
	 * This allows signal handlers to log as many messages as they want,
	 * the only penalty being the critical section overhead for each
	 * message logged.
	 */

	if (ck != NULL)
		ck_restore(ck, saved);

	if (G_LIKELY(NULL == lt)) {
		logging[stid] = FALSE;
	} else {
		lt->in_log_handler = FALSE;
	}

	/*
	 * Now that we're done with the message logging, we can attempt to print
	 * a stack trace if we've been emitting a critical or error message.
	 *
	 * Because this can trigger symbol loading and possibly log errors when
	 * we can't find the executable or the symbol file, it's best to wait
	 * until the end to avoid recursion.
	 */

	if G_UNLIKELY(level & (G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR))
		s_stacktrace(TRUE, 2);		/* Copied to stdout if different */

done:
	thread_leave_critical(&set);
	errno = saved_errno;
}

/**
 * Make sure there is no recursive s_error() or t_error() calls.
 *
 * @return TRUE if are in recursion and can continue.
 */
static bool
log_check_recursive(const char *format, va_list ap)
{
	static int recursive;
	static char buf[LOG_MSG_MAXLEN];
	static int stid;
	int depth;

	depth = atomic_int_inc(&recursive);

	if (0 == depth) {
		log_vbprintf(ARYLEN(buf), format, ap);
		stid = thread_safe_small_id();
		return FALSE;
	} else if (1 == depth) {
		/*
		 * Ensure we're not losing previous error in case we did not go
		 * far enough, but flag the string as being from a previous error
		 * in case it was already logged, to avoid confusion.
		 */
		crash_set_error("previous error: ");
		crash_append_error(buf);
		s_miniwarn("error whilst processing error from thread #%d:", stid);
		s_miniinfo("previous error: %s", buf);
		return TRUE;
	} else if (2 == depth) {
		s_rawwarn("recursive or concurrent error, aborting");
		log_abort();
	} else if (3 == depth) {
		abort();
	} else {
		_exit(EXIT_FAILURE);
	}
}

/**
 * Wrapper over s_logv() to limit frequency of messages to once per period
 * for a given source location.
 *
 * This routine does not use malloc() but relies on the VMM layer.
 *
 * @param period	how often to emit message from origin (in seconds)
 * @param origin	orgin of the message (constant string expected)
 * @param lt		thread-private context (NULL if not in a concurrent thread)
 * @param level		glib-compatible log level flags
 * @param format	formatting string
 * @param args		variable argument list to format
 */
static void G_PRINTF(5, 0)
s_logv_once_per(long period, const char *origin,
	logthread_t *lt, GLogLevelFlags level, const char *format, va_list args)
{
	static spinlock_t logtime_slk = SPINLOCK_INIT;
	static hash_table_t *logtime;	/* origin -> time_t of last log */
	time_t lastlog, now;

	g_assert(origin != NULL);

	/*
	 * Don't use once_flag_run() to keep all the variables private to
	 * this routine.
	 */

	if G_UNLIKELY(NULL == logtime) {
		spinlock(&logtime_slk);
		if (NULL == logtime) {
			logtime =
				hash_table_new_full_not_leaking(string_mix_hash, string_eq);
			hash_table_thread_safe(logtime);
		}
		spinunlock(&logtime_slk);
	}

	lastlog = pointer_to_long(hash_table_lookup(logtime, origin));
	now = tm_time();

	/*
	 * Skip log if we already logged message within the period already.
	 */

	if (delta_time(now, lastlog) < period)
		return;

	/*
	 * OK, record current time and log message.
	 */

	hash_table_replace(logtime, origin, long_to_pointer(now));
	s_logv(lt, level, format, args);
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
	s_logv(logthread_object(FALSE), G_LOG_LEVEL_CRITICAL, format, args);
	va_end(args);
}

/**
 * Safe critical message, limited to one occurrence per origin per period.
 *
 * @note
 * This routine should not be called directly, use the s_critical_once_per()
 * macro instead.
 */
void
s_critical_once_per_from(long period, const char *origin,
	const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_logv_once_per(period, origin,
		logthread_object(FALSE), G_LOG_LEVEL_CRITICAL, format, args);
	va_end(args);
}

/**
 * Safe error.
 */
void
s_error(const char *format, ...)
{
	va_list args, acopy;
	unsigned flags = G_LOG_LEVEL_ERROR | G_LOG_FLAG_FATAL;

	va_start(args, format);
	VA_COPY(acopy, args);

	if (log_check_recursive(format, acopy)) {
		s_minilogv(flags | G_LOG_FLAG_RECURSION, TRUE, format, args);
	} else {
		s_logv(NULL /* take no risk */, flags, format, args);
	}

	va_end(acopy);
	va_end(args);

	log_abort();
}

/**
 * Safe error.
 *
 * This returns a value so that we can use it in comma expressions, but
 * the behaviour is really the same as s_error(), i.e. it aborts the
 * process.
 */
int
s_error_expr(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_logv(NULL /* take no risk */,
		G_LOG_LEVEL_ERROR | G_LOG_FLAG_FATAL, format, args);
	va_end(args);

	log_abort();
	return 0;
}

/*
 * Safe error, recording the source of the crash to allow crash hooks.
 */
void
s_error_from(const char *file, const char *format, ...)
{
	va_list args, acopy;
	unsigned flags = G_LOG_LEVEL_ERROR | G_LOG_FLAG_FATAL;

	crash_set_filename(file);

	va_start(args, format);
	VA_COPY(acopy, args);

	if (log_check_recursive(format, acopy)) {
		s_minilogv(flags | G_LOG_FLAG_RECURSION, TRUE, format, args);
	} else {
		s_logv(NULL /* take no risk */, flags, format, args);
	}

	va_end(acopy);
	va_end(args);

	log_abort();
}

/**
 * Safe verbose warning message, identifying a severe problem that could
 * indicate some malfunction or cause one later.
 *
 * Although only a warning, it is duplicated (along with the stacktrace)
 * to stdout if it is different from stderr.
 */
void
s_carp(const char *format, ...)
{
	bool in_signal_handler = signal_in_unsafe_handler();
	va_list args;

	thread_pending_add(+1);

	va_start(args, format);
	s_logv(logthread_object(FALSE),
		G_LOG_LEVEL_WARNING | LOG_FLAG_COPY, format, args);
	va_end(args);

	s_stacktrace(in_signal_handler, 1);		/* Copied to stdout if different */

	thread_pending_add(-1);
}

/**
 * Safe verbose warning message, emitted once per calling stack.
 */
void
s_carp_once(const char *format, ...)
{
	if (!stacktrace_caller_known(2))	{	/* Caller of our caller */
		va_list args;

		/*
		 * We use a CRITICAL level because "once" carping denotes a
		 * potentially dangerous situation something that we want to
		 * note loudly in case there is a problem later.
		 *
		 * This will automatically trigger stack tracing in s_logv()
		 * plus force a copy of the message to stdout, if distinct.
		 */

		va_start(args, format);
		s_logv(logthread_object(FALSE), G_LOG_LEVEL_CRITICAL, format, args);
		va_end(args);
	}
}

/**
 * Safe verbose warning message, with minimal resource consumption.
 *
 * This is intended to be used by the string formatting code to emit loud
 * warnings and avoid a recursion into the regular logging routine.
 */
void
s_minicarp(const char *format, ...)
{
	va_list args;

	/*
	 * This test duplicates the one in s_minilogv() but if we don't emit
	 * the message we don't want to emit the stacktrace afterwards either.
	 * Hence we need to know now.
	 */

	if G_UNLIKELY(logfile[LOG_STDERR].disabled)
		return;

	/*
	 * This routine is only called in exceptional conditions, so even if
	 * the LOG_STDERR file is not deemed printable for now, attempt to do
	 * that as well and copy the message to LOG_STDOUT anyway.
	 */

	va_start(args, format);
	s_minilogv(G_LOG_LEVEL_WARNING, TRUE, format, args);
	va_end(args);

	s_stacktrace(TRUE, 1);		/* Copied to stdout if different */
}

/**
 * Safe verbose minimal warning message, emitted once per calling stack.
 *
 * We guarantee no memory allocation during the check for known stacks
 * by relying on a circular buffer that will hold the stacks while we
 * are in a signal handler.
 */
void
s_minicarp_once(const char *format, ...)
{
	if G_UNLIKELY(logfile[LOG_STDERR].disabled)
		return;

	if (!stacktrace_caller_known(2))	{	/* Caller of our caller */
		va_list args;

		/*
		 * We use a CRITICAL level because "once" carping denotes a
		 * potentially dangerous situation something that we want to
		 * note loudly in case there is a problem later.
		 *
		 * This will NOT automatically trigger stack tracing in s_minilogv()
		 * so we need to do it explicitly.
		 */

		va_start(args, format);
		s_minilogv(G_LOG_LEVEL_CRITICAL, TRUE, format, args);
		va_end(args);

		s_stacktrace(TRUE, 0);		/* Copied to stdout if different */
	}
}

/**
 * Safe logging with minimal resource consumption.
 *
 * This is intended to be used in emergency situations when higher-level
 * logging mechanisms can't be used (recursion possibility, logging layer).
 */
void
s_minilog(GLogLevelFlags flags, const char *format, ...)
{
	va_list args;

	/*
	 * This routine is only called in exceptional conditions, so even if
	 * the LOG_STDERR file is not deemed printable for now, attempt to log
	 * anyway.
	 */

	va_start(args, format);
	s_minilogv(flags, FALSE, format, args);
	va_end(args);
}

/**
 * Safe termination with minimal resource consumption.
 *
 * This is intended to be used in emergency situations when higher-level
 * logging mechanisms can't be used (recursion possibility, logging layer,
 * deadlock condition).
 */
void
s_minierror(const char *format, ...)
{
	static int recursion;
	va_list args;
	char data[LOG_MSG_MAXLEN];
	char time_buf[LOG_TIME_BUFLEN];
	char sbuf[UINT_DEC_BUFLEN];
	DECLARE_STR(9);
	bool recursing;
	int stid = thread_safe_small_id();

	recursing = 0 != atomic_int_inc(&recursion);

	va_start(args, format);
	log_vbprintf(ARYLEN(data), format, args);
	va_end(args);

	crash_set_error(data);

	log_time(ARYLEN(time_buf));
	print_str(time_buf);					/* 0 */
	print_str(" (ERROR");					/* 1 */
	if (stid != 0) {
		print_str("-");						/* 2 */
		print_str(PRINT_NUMBER(sbuf, stid));/* 3 */
	}
	print_str(")");							/* 4 */
	if (recursing)
		print_str(" [RECURSIVE]");			/* 5 */
	print_str(": ");						/* 6 */
	print_str(data);						/* 7 */
	print_str("\n");						/* 8 */
	log_flush_err_atomic();
	if (log_stdout_is_distinct())
		log_flush_out_atomic();

	if (!recursing)
		s_stacktrace(TRUE, 1);

	abort();
}

/**
 * Safe logging of critical message with minimal resource consumption.
 *
 * This is intended to be used in emergency situations when higher-level
 * logging mechanisms can't be used (recursion possibility, logging layer).
 *
 * @attention
 * This routine can clobber "errno" if an error occurs.
 */
void
s_rawcrit(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_rawlogv(G_LOG_LEVEL_CRITICAL, TRUE, TRUE, format, args);
	va_end(args);

	s_stacktrace(TRUE, 1);	/* Copied to stdout if different */
}

/**
 * Safe logging of warning message with minimal resource consumption.
 *
 * This is intended to be used in emergency situations when higher-level
 * logging mechanisms can't be used (recursion possibility, logging layer).
 *
 * @attention
 * This routine can clobber "errno" if an error occurs.
 */
void
s_rawwarn(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_rawlogv(G_LOG_LEVEL_WARNING, TRUE, FALSE, format, args);
	va_end(args);
}

/**
 * Safe logging of message with minimal resource consumption.
 *
 * This is intended to be used in emergency situations when higher-level
 * logging mechanisms can't be used (recursion possibility, logging layer).
 *
 * @attention
 * This routine can clobber "errno" if an error occurs.
 */
void
s_rawmsg(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_rawlogv(G_LOG_LEVEL_MESSAGE, TRUE, FALSE, format, args);
	va_end(args);
}


/**
 * Safe logging of informational message with minimal resource consumption.
 *
 * This is intended to be used in emergency situations when higher-level
 * logging mechanisms can't be used (recursion possibility, logging layer).
 *
 * @attention
 * This routine can clobber "errno" if an error occurs.
 */
void
s_rawinfo(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_rawlogv(G_LOG_LEVEL_INFO, TRUE, FALSE, format, args);
	va_end(args);
}

/**
 * Safe logging of debugging message with minimal resource consumption.
 *
 * This is intended to be used in emergency situations when higher-level
 * logging mechanisms can't be used (recursion possibility, logging layer).
 *
 * @attention
 * This routine can clobber "errno" if an error occurs.
 */
void
s_rawdebug(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_rawlogv(G_LOG_LEVEL_DEBUG, TRUE, FALSE, format, args);
	va_end(args);
}

/**
 * Safe logging of critical message with minimal resource consumption.
 *
 * This is intended to be used in emergency situations when higher-level
 * logging mechanisms can't be used (recursion possibility, logging layer).
 */
void
s_minicrit(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_minilogv(G_LOG_LEVEL_CRITICAL, TRUE, format, args);
	va_end(args);

	s_stacktrace(TRUE, 1);		/* Copied to stdout if different */
}

/**
 * Safe logging of warning message with minimal resource consumption.
 *
 * This is intended to be used in emergency situations when higher-level
 * logging mechanisms can't be used (recursion possibility, logging layer).
 */
void
s_miniwarn(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_minilogv(G_LOG_LEVEL_WARNING, FALSE, format, args);
	va_end(args);
}

/**
 * Safe logging of regular message with minimal resource consumption.
 *
 * This is intended to be used in emergency situations when higher-level
 * logging mechanisms can't be used (recursion possibility, logging layer).
 */
void
s_minimsg(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_minilogv(G_LOG_LEVEL_MESSAGE, FALSE, format, args);
	va_end(args);
}

/**
 * Safe logging of information with minimal resource consumption.
 *
 * This is intended to be used in emergency situations when higher-level
 * logging mechanisms can't be used (recursion possibility, logging layer).
 */
void
s_miniinfo(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_minilogv(G_LOG_LEVEL_INFO, FALSE, format, args);
	va_end(args);
}

/**
 * Safe logging of debugging with minimal resource consumption.
 *
 * This is intended to be used in emergency situations when higher-level
 * logging mechanisms can't be used (recursion possibility, logging layer).
 */
void
s_minidbg(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_minilogv(G_LOG_LEVEL_DEBUG, FALSE, format, args);
	va_end(args);
}

/**
 * Safe warning message.
 */
void
s_warning(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_logv(logthread_object(FALSE), G_LOG_LEVEL_WARNING, format, args);
	va_end(args);
}

/**
 * Safe warning message, limited to one occurrence per origin per period.
 *
 * @note
 * This routine should not be called directly, use the s_warning_once_per()
 * macro instead.
 */
void
s_warning_once_per_from(long period, const char *origin,
	const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_logv_once_per(period, origin,
		logthread_object(FALSE), G_LOG_LEVEL_WARNING, format, args);
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
	s_logv(logthread_object(FALSE), G_LOG_LEVEL_MESSAGE, format, args);
	va_end(args);
}

/**
 * Safe regular message, limited to one occurrence per origin per period.
 *
 * @note
 * This routine should not be called directly, use the s_message_once_per()
 * macro instead.
 */
void
s_message_once_per_from(long period, const char *origin,
	const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_logv_once_per(period, origin,
		logthread_object(FALSE), G_LOG_LEVEL_MESSAGE, format, args);
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
	s_logv(logthread_object(FALSE), G_LOG_LEVEL_INFO, format, args);
	va_end(args);
}

/**
 * Safe info message, limited to one occurrence per origin per period.
 *
 * @note
 * This routine should not be called directly, use the s_info_once_per()
 * macro instead.
 */
void
s_info_once_per_from(long period, const char *origin,
	const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_logv_once_per(period, origin,
		logthread_object(FALSE), G_LOG_LEVEL_INFO, format, args);
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
	s_logv(logthread_object(FALSE), G_LOG_LEVEL_DEBUG, format, args);
	va_end(args);
}

/**
 * Safe debug message, limited to one occurrence per origin per period.
 *
 * @note
 * This routine should not be called directly, use the s_debug_once_per()
 * macro instead.
 */
void
s_debug_once_per_from(long period, const char *origin,
	const char *format, ...)
{
	va_list args;

	va_start(args, format);
	s_logv_once_per(period, origin,
		logthread_object(FALSE), G_LOG_LEVEL_DEBUG, format, args);
	va_end(args);
}

/**
 * Write formatted string to specified file descriptor.
 *
 * @note
 * This routine is very low-level and is meant to be used as a building block
 * for higher-level routines or when we are operating under dire circumstances.
 *
 * There is no leading timestamp nor thread indication prepended to the log.
 * A trailing "\n" is appended to the formatted string automatically though.
 *
 * The maximum message length is hardwired to LOG_MSG_MAXLEN (512 bytes).
 *
 * No memory allocation is performed by this routine and a direct system call
 * is issued to the specified file descriptor without any locking.
 *
 * @param fd		the file descriptor
 * @param fmt		the printf()-like formatting string
 * @param ...		the arguments to be formatted
 */
void G_PRINTF(2, 3)
s_line_writef(int fd, const char *fmt, ...)
{
	char buf[LOG_MSG_MAXLEN];
	str_t str;
	va_list args;
	iovec_t iov[2];

	str_new_buffer(&str, ARYLEN(buf), 0);
	str_set_silent_truncation(&str, TRUE);

	va_start(args, fmt);
	str_vprintf(&str, fmt, args);
	va_end(args);

	log_check_truncated(&str);

	iovec_set(&iov[0], str_2c(&str), str_len(&str));
	iovec_set(&iov[1], "\n", 1);

	IGNORE_RESULT(writev(fd, iov, N_ITEMS(iov)));
}

/**
 * Print message to stdout.
 */
static void
log_stdout_logv(const char *format, va_list args)
{
	char data[LOG_MSG_MAXLEN];
	DECLARE_STR(2);

	log_vbprintf(ARYLEN(data), format, args);	/* Uses str_vncatf() */

	print_str(data);			/* 0 */
	print_str("\n");			/* 1 */
	log_flush_out_atomic();
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
static void G_PRINTF(3, 0)
log_logv(logagent_t *la, GLogLevelFlags level, const char *format, va_list args)
{
	logagent_check(la);

	switch (la->type) {
	case LOG_A_STDOUT:
		log_stdout_logv(format, args);
		return;
	case LOG_A_STDERR:
		s_logv(logthread_object(FALSE), level, format, args);
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
log_handler(const char *domain, GLogLevelFlags level,
	const char *message, void *unused_data)
{
	int saved_errno = errno;
	time_t now;
	struct tm *ct;
	tm_t tv;
	const char *prefix;
	char *safer;
	unsigned stid;

	(void) unused_data;

	if (G_UNLIKELY(logfile[LOG_STDERR].disabled))
		return;

	tm_now_exact(&tv);
	now = tv.tv_sec;
	ct = localtime(&now);

	prefix = log_prefix(level);
	stid = thread_small_id();

	if (level & G_LOG_FLAG_RECURSION) {
		/* Probably logging from memory allocator, string should be safe */
		safer = deconstify_pointer(message);
	} else {
		safer = control_escape(message);
	}

	log_fprint(LOG_STDERR, ct, tv.tv_usec, level, prefix, stid, safer);

	if G_UNLIKELY(
		level &
			(G_LOG_FLAG_FATAL | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR)
	) {
		if (log_stdout_is_distinct())
			log_fprint(LOG_STDOUT, ct, tv.tv_usec, level, prefix, stid, safer);
		if (level & G_LOG_FLAG_FATAL)
			crash_set_error(safer);
	}

	/*
	 * For "foreign" domains (GTK, Pango, glib, ...), we will have a non-NULL
	 * domain passed (by default, G_LOG_DOMAIN is NULL).  In that case, since
	 * we do not expect these low-level libraries to emit any warning, we force
	 * a stacktrace as if they were actually "carping", which they really are...
	 *
	 * This help diagnose in our code what is the path leading to such an error
	 * message.  Note that we do not wish to emit a stacktrace everytime though,
	 * so we use a logic similar to that of s_carp_once() to actually record the
	 * event once per calling stack.
	 *
	 * We stick to G_LOG_LEVEL_WARNING here since anything more serious will
	 * trigger a stacktrace below.
	 *
	 * 	--RAM, 2018-04-16
	 */

	if G_UNLIKELY(domain != NULL && (level & G_LOG_LEVEL_WARNING)) {
		if (!stacktrace_caller_known(3))
			s_stacktrace(FALSE, 3);
	}

	if G_UNLIKELY(
		level & (
			G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION |
			G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR
		)
	) {
		s_stacktrace(FALSE, 3);
	}

	if G_UNLIKELY(safer != message) {
		HFREE_NULL(safer);
	}

	if (is_running_on_mingw())
		fflush(stderr);			/* Unbuffering does not work on Windows */

	/*
	 * If GTK or Glib is starting to emit critical messages and we're past
	 * the exit() point, abort.
	 */

	if G_UNLIKELY(domain != NULL) {
		if (crash_is_closed())
			crash_abort();
	}

#if 0
	/* Define to debug Glib or Gtk problems */
	if (domain) {
		unsigned i;

		for (i = 0; i < N_ITEMS(log_domains); i++) {
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
bool
log_reopen(enum log_file which)
{
	bool success = TRUE;
	FILE *f;
	struct logfile *lf;
	int fd = -1;

	log_file_check(which);
	g_assert(logfile[which].path != NULL);	/* log_set() called */

	lf = &logfile[which];
	f = lf->f;
	g_assert(f != NULL);

	/*
	 * Not being able to reopen stderr would be critical as further messages
	 * will be lost.  Therefore duplicate the file descriptor before calling
	 * freopen() to be able to log something in case we fail.
	 */

	if (LOG_STDERR == which) {
		fd = dup(fileno(f));

		if (!is_valid_fd(fd))
			s_warning("%s(): unable to dup(%d): %m", G_STRFUNC, fileno(f));
	}

	if (freopen(lf->path, "a", f)) {
		setvbuf(f, NULL, _IOLBF, 0);
		lf->disabled = 0 == strcmp(lf->path, DEV_NULL);
		lf->otime = tm_time();
		lf->changed = FALSE;
	} else {
		if (LOG_STDERR != which) {
			s_critical("freopen(\"%s\", \"a\", ...) failed: %m", lf->path);
		} else if (is_valid_fd(fd)) {
			DECLARE_STR(8);
			char time_buf[LOG_TIME_BUFLEN];

			log_time(ARYLEN(time_buf));
			print_str(time_buf);	/* 0 */
			print_str(" (CRITICAL): cannot freopen() stderr to "); /* 1 */
			print_str(lf->path);	/* 2 */
			print_str(": ");		/* 3 */
			print_str(symbolic_errno(errno));	/* 4 */
			print_str(" (");		/* 5 */
			print_str(english_strerror(errno));	/* 6 */
			print_str(")\n");		/* 7 */
			flush_str_atomic(fd);
			log_flush_out_atomic();
		}
		lf->disabled = TRUE;
		lf->otime = 0;
		success = FALSE;
	}

	if (LOG_STDERR == which && is_valid_fd(fd))
		close(fd);

	return success;
}

/**
 * Is logfile managed?
 *
 * @return TRUE if we explicitly (re)opened the file
 */
bool
log_is_managed(enum log_file which)
{
	log_file_check(which);

	return logfile[which].path != NULL && !logfile[which].changed;
}

/**
 * Is logfile disabled?
 */
bool
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
bool
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
bool
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
bool
log_reopen_all(bool daemonized)
{
	size_t i;
	bool success = TRUE;

	for (i = 0; i < N_ITEMS(logfile); i++) {
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
log_set_disabled(enum log_file which, bool disabled)
{
	log_file_check(which);

	logfile[which].disabled = disabled;
}

/**
 * Enable or disable PID logging.
 */
void
log_show_pid(bool enabled)
{
	if (enabled) {
		str_bprintf(ARYLEN(logpid), " [%lu]", (ulong) getpid());
	} else {
		logpid[0] = '\0';	/* Empty string, shows nothing */
	}
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
bool
log_rename(enum log_file which, const char *newname)
{
	struct logfile *lf;
	int saved_errno = 0;
	bool ok = TRUE;

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
			s_warning("cannot unlink temporary log file \"%s\": %m", tmp);
		}
	}

	if (!ok) {
		errno = saved_errno;
		s_warning("could not rename \"%s\" as \"%s\": %m", lf->path, newname);
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
			s_warning("cannot stat logfile \"%s\" at \"%s\": %m",
				lf->name, lf->path);
			buf->size = 0;
		} else
			buf->size = sbuf.st_size;
	}
}

/**
 * Initialization of logging layer.
 */
void G_COLD
log_init(void)
{
	unsigned i;

	for (i = 0; i < N_ITEMS(log_domains); i++) {
		g_log_set_handler(log_domains[i],
			G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL |
			G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING |
			G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_INFO | G_LOG_LEVEL_DEBUG,
			log_handler, NULL);
	}

	gl_log_set_handler(log_handler, NULL);

	logfile[LOG_STDOUT].f = stdout;
	logfile[LOG_STDOUT].fd = fileno(stdout);
	logfile[LOG_STDOUT].name = "out";
	logfile[LOG_STDOUT].otime = tm_time();

	logfile[LOG_STDERR].f = stderr;
	logfile[LOG_STDERR].fd = fileno(stderr);
	logfile[LOG_STDERR].name = "err";
	logfile[LOG_STDERR].otime = tm_time();

	(void) log_chunk();		/* Ensure log chunk is pre-allocated early */

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
log_crashing_str(struct str *str)
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
		s_critical("fdopen(\"%d\", \"a\") failed: %m", fd);
	}
}

/**
 * Get file descriptor associated with a logfile.
 */
int
log_get_fd(enum log_file which)
{
	log_file_check(which);

	return logfile[which].fd;
}

/**
 * Shutdown the logging layer.
 */
void G_COLD
log_close(void)
{
	size_t i;

	for (i = 0; i < N_ITEMS(logfile); i++) {
		struct logfile *lf = &logfile[i];

		if (lf->path_is_atom)
			atom_str_free_null(&lf->path);
	}

	log_inited = FALSE;
}

/* vi: set ts=4 sw=4 cindent: */
