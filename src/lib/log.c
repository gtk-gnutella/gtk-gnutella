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
 * Routines that pose a risk of emitting a message recursively (e.g. routines
 * that can be called by log_handler(), or signal handlers) should use the
 * safe s_xxx() logging routines instead of the corresponding g_xxx().
 *
 * All s_xxx() routines also supports an enhanced %m formatting option which
 * displays both the symbolic errno and the error message string, plus %' to
 * format integers with groupped thousands separated with ",".
 *
 * The t_xxx() routines are meant to be used in dedicate threads to avoid
 * concurrent memory allocation which is not otherwise supported.  They require
 * a thread-private logging object, which can be NULL to request a default
 * object for the main thread.
 *
 * A side effect of using t_xxx() or s_xxx() routines is that there is a
 * guarantee that no malloc()-like routine will be called to log the message.
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
#define LOG_MSG_DEFAULT		4080	/**< Default string length for logger */
#define LOG_IOERR_GRACE		5		/**< Seconds between I/O errors */

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
static struct logfile logfile[LOG_MAX_FILES];

#define log_flush_out_atomic()	\
	flush_str_atomic(			\
		G_LIKELY(log_inited) ? logfile[LOG_STDOUT].fd : STDOUT_FILENO)

#define log_flush_err_atomic()	\
	flush_str_atomic(			\
		G_LIKELY(log_inited) ? logfile[LOG_STDERR].fd : STDERR_FILENO)

/**
 * This is used to detect recurstions.
 */
static volatile sig_atomic_t in_safe_handler;	/* in s_logv() */

static const char DEV_NULL[] = "/dev/null";

/**
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
			ck = ck_init(LOG_MSG_MAXLEN * 4, LOG_MSG_MAXLEN);
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
 */
static logthread_t *
log_thread_alloc(void)
{
	logthread_t *lt;
	ckhunk_t *ck;

	ck = ck_init_not_leaking(2 * LOG_MSG_MAXLEN, 0);
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
 * @return valid logging data object for the current thread.
 */
static logthread_t *
logthread_object(bool once)
{
	logthread_t *lt;

	ONCE_FLAG_RUN(log_okey_inited, log_okey_init);

	lt = thread_local_get(log_okey);

	if G_UNLIKELY(NULL == lt) {
		lt = log_thread_alloc();
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

#define FORMAT_STR	"%02d-%02d-%02d %.02d:%.02d:%.02d.%03ld (%s)%s%s: %s\n"

	log_file_check(which);

	if (!log_printable(which))
		return;

	lf = &logfile[which];

	if (stid != 0) {
		str_bprintf(buf, sizeof buf, "%s-%u", prefix, stid);
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
		ct->tm_hour, ct->tm_min, ct->tm_sec, usec / 1000, tprefix,
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
		iovec_set(&iov[0], msg, strlen(msg));
		iovec_set(&iov[1], "\n", 1);
		atio_writev(lf->crash_fd, iov, G_N_ELEMENTS(iov));
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
	switch (level & G_LOG_LEVEL_MASK) {
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
 * Abort and make sure we never return.
 */
void
log_abort(void)
{
	static void *log_stack[STACKTRACE_DEPTH_MAX];
	size_t count;

	/*
	 * It may be difficult to backtrace the stack past the signal handler
	 * which is going to be invoked by raise(), hence save a copy of the
	 * current stack before crashing.
	 */

	count = stacktrace_safe_unwind(log_stack, G_N_ELEMENTS(log_stack), 0);
	crash_save_stackframe(log_stack, count);

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
		char time_buf[CRASH_TIME_BUFLEN];

		crash_time(time_buf, sizeof time_buf);
		print_str(time_buf);	/* 0 */
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
		crash_time(time_buf, sizeof time_buf);
		print_str(time_buf);	/* 0 */
		print_str(" (CRITICAL): back from crash_handler()"); /* 1 */
		print_str(" -- exiting\n");		/* 2 */
		log_flush_err_atomic();
		if (log_stdout_is_distinct())
			log_flush_out_atomic();

		_exit(EXIT_FAILURE);	/* Immediate exit */
	}
}

/**
 * Raw logging service, in case of recursion or other drastic conditions.
 *
 * This routine never allocates memory, by-passes stdio and does NOT save
 * errno (since accessing errno in multi-threaded programs needs to access
 * some pthread-data that may not be accessible if we corrupted memory).
 *
 * It is suitable to be called (directly or through its wrappers) when we are
 * about to terminate the process anyway, so preserving errno is not critical.
 *
 * @param level		glib-compatible log level flags
 * @param copy		whether to copy message to stdout as well
 * @param fmt		formatting string
 * @param args		variable argument list to format
 *
 * @attention
 * This routine will clobber "errno" if an error occurs.
 */
void
s_rawlogv(GLogLevelFlags level, bool copy, const char *fmt, va_list args)
{
	char data[LOG_MSG_MAXLEN];
	DECLARE_STR(11);
	char time_buf[CRASH_TIME_BUFLEN];
	const char *prefix;
	unsigned stid;

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
	stid = thread_small_id();

	/*
	 * Because str_vncatf() is recursion-safe, we know we can't return
	 * to here through it.
	 */

	str_vbprintf(data, sizeof data, fmt, args);		/* Uses str_vncatf() */

	crash_time(time_buf, sizeof time_buf);
	print_str(time_buf);		/* 0 */
	print_str(" (");			/* 1 */
	print_str(prefix);			/* 2 */
	if (stid != 0) {
		char stid_buf[ULONG_DEC_BUFLEN];
		const char *stid_str = PRINT_NUMBER(stid_buf, stid);
		print_str("-");			/* 3 */
		print_str(stid_str);	/* 4 */
	}
	print_str(")");				/* 5 */
	if G_UNLIKELY(level & G_LOG_FLAG_RECURSION)
		print_str(" [RECURSIVE]");	/* 6 */
	if G_UNLIKELY(level & G_LOG_FLAG_FATAL)
		print_str(" [FATAL]");		/* 7 */
	print_str(": ");			/* 8 */
	print_str(data);			/* 9 */
	print_str("\n");			/* 10 */
	log_flush_err_atomic();
	if (copy && log_stdout_is_distinct())
		log_flush_out_atomic();
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

	saved_errno = errno;
	s_rawlogv(level, copy, fmt, args);
	errno = saved_errno;
}

/**
 * Emit stacktrace to stderr and stdout (if distinct from stderr).
 *
 * @param no_stdio		whether we must avoid stdio
 * @param offset		stack offset to apply to remove overhead from stack
 */
static void NO_INLINE
s_stacktrace(bool no_stdio, unsigned offset)
{
	static bool tracing[THREAD_MAX];
	unsigned stid = thread_small_id();

	/*
	 * Protect thread, in case any of the tracing causes a recursion.
	 * Indeed, recursion would probably be fatal (endless) and would prevent
	 * further important debugging messages to be emitted by the thread.
	 */

	if (tracing[stid]) {
		s_rawwarn("skipping trace for %s (already in progress)",
			thread_id_name(stid));
		return;
	}

	/*
	 * If the process has entered "crash mode", then it is unsafe to emit
	 * a stacktrace here because memory allocation could do weird things
	 * with locks being disabled...  Only let the crashing thread continue.
	 */

	if (thread_in_crash_mode() && !thread_is_crashing()) {
		s_rawwarn("skipping trace for %s (crash mode)", thread_id_name(stid));
		thread_check_suspended();		/* Probably was already suspended? */
		return;
	}

	tracing[stid] = TRUE;

	if (no_stdio) {
		stacktrace_where_safe_print_offset(STDERR_FILENO, offset + 1);
		if (log_stdout_is_distinct())
			stacktrace_where_safe_print_offset(STDOUT_FILENO, offset + 1);
	} else {
		stacktrace_where_sym_print_offset(stderr, offset + 1);
		if (log_stdout_is_distinct())
			stacktrace_where_sym_print_offset(stdout, offset + 1);

		if (is_running_on_mingw()) {
			/* Unbuffering does not work on Windows, flush both */
			fflush(stderr);
			fflush(stdout);
		}
	}

	tracing[stid] = FALSE;
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
static void
s_logv(logthread_t *lt, GLogLevelFlags level, const char *format, va_list args)
{
	int saved_errno = errno;
	bool in_signal_handler = signal_in_handler();
	const char *prefix;
	str_t *msg;
	ckhunk_t *ck;
	void *saved;
	bool recursing;
	unsigned stid;

	if (G_UNLIKELY(logfile[LOG_STDERR].disabled))
		return;

	/*
	 * Detect recursion, but don't make it fatal.
	 */

	if G_UNLIKELY(NULL == lt && 0 == (level & G_LOG_FLAG_FATAL))
		lt = logthread_object(FALSE);

	if G_LIKELY(lt != NULL) {
		recursing = lt->in_log_handler;
	} else {
		recursing = in_safe_handler;
	}

	if G_UNLIKELY(recursing) {
		DECLARE_STR(9);
		char time_buf[CRASH_TIME_BUFLEN];
		const char *caller;
		bool copy;

		stid = NULL == lt ? thread_small_id() : lt->stid;
		caller = stacktrace_caller_name(2);	/* Could log, so pre-compute */

		crash_time(time_buf, sizeof time_buf);
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
		print_str("\n");			/* 8 */
		log_flush_err_atomic();

		/*
		 * A recursion with an error message is always fatal.
		 */

		if (G_LOG_LEVEL_ERROR & level)
			log_abort();

		/*
		 * Use minimal logging.
		 */

		copy = level & (G_LOG_FLAG_FATAL | G_LOG_LEVEL_CRITICAL);
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
		in_safe_handler = TRUE;
		stid = thread_small_id();
		ck = in_signal_handler ? signal_chunk() : log_chunk();
	} else {
		lt->in_log_handler = TRUE;
		stid = lt->stid;
		ck = lt->ck;
	}

	saved = ck_save(ck);
	msg = str_new_in_chunk(ck, LOG_MSG_MAXLEN);

	if G_UNLIKELY(NULL == msg) {
		DECLARE_STR(6);
		char time_buf[CRASH_TIME_BUFLEN];

		crash_time(time_buf, sizeof time_buf);
		print_str(time_buf);	/* 0 */
		print_str(" (CRITICAL): no memory to format string \""); /* 1 */
		print_str(format);		/* 2 */
		print_str("\" from ");	/* 3 */
		print_str(stacktrace_caller_name(2));	/* 4 */
		print_str("\n");		/* 5 */
		log_flush_err_atomic();
		ck_restore(ck, saved);
		goto done;
	}

	g_assert(ptr_diff(ck_save(ck), saved) > LOG_MSG_MAXLEN);

	/*
	 * The str_vprintf() routine is safe to use in signal handlers.
	 */

	str_vprintf(msg, format, args);
	prefix = log_prefix(level);

	/*
	 * Avoid stdio's fprintf() from within a signal handler since we
	 * don't know how the string will be formattted, nor whether
	 * re-entering fprintf() through a signal handler would be safe.
	 */

	{
		DECLARE_STR(11);
		char time_buf[CRASH_TIME_BUFLEN];

		crash_time(time_buf, sizeof time_buf);
		print_str(time_buf);	/* 0 */
		print_str(" (");		/* 1 */
		print_str(prefix);		/* 2 */
		if (stid != 0) {
			char stid_buf[ULONG_DEC_BUFLEN];
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
		log_flush_err_atomic();

		if G_UNLIKELY(
			level &
				(G_LOG_FLAG_FATAL | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR)
		) {
			if (log_stdout_is_distinct())
				log_flush_out_atomic();
			if (level & G_LOG_FLAG_FATAL)
				crash_set_error(str_2c(msg));
		}

		/*
		 * When duplication is configured, write a copy of the message
		 * without any timestamp and debug level tagging.
		 */

		if G_UNLIKELY(logfile[LOG_STDERR].duplicate) {
			int fd = logfile[LOG_STDERR].crash_fd;
			iovec_t iov[2];
			iovec_set(&iov[0], str_2c(msg), str_len(msg));
			iovec_set(&iov[1], "\n", 1);
			atio_writev(fd, iov, G_N_ELEMENTS(iov));
		}
	}

	/*
	 * Free up the string memory by restoring the allocation context
	 * using the checkpoint we made before allocating that string.
	 *
	 * This allows signal handlers to log as many messages as they want,
	 * the only penalty being the critical section overhead for each
	 * message logged.
	 */

	ck_restore(ck, saved);

	if (G_LIKELY(NULL == lt)) {
		in_safe_handler = FALSE;
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
		s_stacktrace(TRUE, 2);

done:
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

	atomic_int_inc(&recursive);

	if (1 == recursive) {
		str_vbprintf(buf, sizeof buf, format, ap);
		return FALSE;
	} else if (2 == recursive) {
		/*
		 * Ensure we're not losing previous error in case we did not go
		 * far enough, but flag the string as being from a previous error
		 * in case it was already logged, to avoid confusion.
		 */
		crash_set_error("previous error: ");
		crash_append_error(buf);
		s_minicrit("error occurred whilst processing former error:");
		s_miniinfo("previous error: %s", buf);
		return TRUE;
	} else if (3 == recursive) {
		s_minicrit("recursive or concurrent error, aborting");
		log_abort();
	} else if (4 == recursive) {
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
static void
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
 * Safe verbose warning message.
 */
void
s_carp(const char *format, ...)
{
	bool in_signal_handler = signal_in_handler();
	va_list args;

	thread_pending_add(+1);

	va_start(args, format);
	s_logv(logthread_object(FALSE), G_LOG_LEVEL_WARNING, format, args);
	va_end(args);

	s_stacktrace(in_signal_handler, 1);

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
	bool in_signal_handler = signal_in_handler();
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

	s_stacktrace(in_signal_handler, 1);
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
	char time_buf[CRASH_TIME_BUFLEN];
	DECLARE_STR(6);
	bool recursing;

	recursing = 0 != atomic_int_inc(&recursion);

	va_start(args, format);
	str_vbprintf(data, sizeof data, format, args);
	va_end(args);

	crash_time(time_buf, sizeof time_buf);
	print_str(time_buf);					/* 0 */
	print_str(" (ERROR)");					/* 1 */
	if (recursing)
		print_str(" [RECURSIVE]");			/* 2 */
	print_str(": ");						/* 3 */
	print_str(data);						/* 4 */
	print_str("\n");						/* 5 */
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
	bool in_signal_handler = signal_in_handler();
	va_list args;

	va_start(args, format);
	s_rawlogv(G_LOG_LEVEL_CRITICAL, TRUE, format, args);
	va_end(args);

	s_stacktrace(in_signal_handler, 1);
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
	s_rawlogv(G_LOG_LEVEL_WARNING, FALSE, format, args);
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
	bool in_signal_handler = signal_in_handler();
	va_list args;

	va_start(args, format);
	s_minilogv(G_LOG_LEVEL_CRITICAL, TRUE, format, args);
	va_end(args);

	s_stacktrace(in_signal_handler, 1);
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
 * Print message to stdout.
 */
static void
log_stdout_logv(const char *format, va_list args)
{
	char data[LOG_MSG_MAXLEN];
	DECLARE_STR(2);

	str_vbprintf(data, sizeof data, format, args);	/* Uses str_vncatf() */

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
static void
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

	if (LOG_STDERR == which)
		fd = dup(fileno(f));

	if (freopen(lf->path, "a", f)) {
		setvbuf(f, NULL, _IOLBF, 0);
		lf->disabled = 0 == strcmp(lf->path, DEV_NULL);
		lf->otime = tm_time();
		lf->changed = FALSE;
	} else {
		if (LOG_STDERR == which) {
			DECLARE_STR(8);
			char time_buf[CRASH_TIME_BUFLEN];

			crash_time(time_buf, sizeof time_buf);
			print_str(time_buf);	/* 0 */
			print_str(" (CRITICAL): cannot freopen() stderr to "); /* 1 */
			print_str(lf->path);	/* 2 */
			print_str(": ");		/* 3 */
			print_str(symbolic_errno(errno));	/* 4 */
			print_str(" (");		/* 5 */
			print_str(g_strerror(errno));		/* 6 */
			print_str(")\n");		/* 7 */
			flush_str_atomic(fd);
			log_flush_out_atomic();
		} else {
			s_critical("freopen(\"%s\", \"a\", ...) failed: %m", lf->path);
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
log_set_disabled(enum log_file which, bool disabled)
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
G_GNUC_COLD void
log_init(void)
{
	unsigned i;

	for (i = 0; i < G_N_ELEMENTS(log_domains); i++) {
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
