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
 * @author Raphael Manfredi
 * @date 2010-2011
 */

#ifndef _log_h_
#define _log_h_

#include "common.h"

#include "logfilter.h"
#include "pslist.h"

#define LOG_MSG_MAXLEN	512	/**< Maximum length in sigh, or mini/raw logs */

enum log_file {
	LOG_STDOUT = 0,
	LOG_STDERR,

	LOG_MAX_FILES
};

struct logstat {
	const char *name;		/**< Logfile name */
	const char *path;		/**< File path (NULL if not managed) */
	time_t otime;			/**< Opening time, for stats */
	filesize_t size;		/**< Current file size, in bytes */
	unsigned disabled:1;	/**< Whether logging is disabled */
	unsigned need_reopen:1;	/**< Logfile pending a reopen */
};

struct logagent;
typedef struct logagent logagent_t;

typedef struct logcolor {
	const char *initial;	/**< If non-NULL, need to reset default color */
	const char *leading;	/**< First escape sequence to establish new color */
	const char *closing;	/**< Final escape sequence to old color */
} logcolor_t;

/*
 * Public interface.
 */

struct str;

const char *log_prefix(GLogLevelFlags loglvl) G_CONST;
void log_abort(void) G_NORETURN;

void log_init(void);
void log_crash_mode(void);
void log_crashing_str(struct str *str);
void log_atoms_inited(void);
void log_close(void);
void log_show_pid(bool enabled);
void log_set_disabled(enum log_file which, bool disabled);
void log_set(enum log_file which, const char *path);
bool log_reopen(enum log_file which);
bool log_rename(enum log_file which, const char *newname);
bool log_reopen_if_managed(enum log_file which);
bool log_reopen_all(bool daemonized);
void log_stat(enum log_file which, struct logstat *buf);
bool log_is_managed(enum log_file which);
bool log_is_disabled(enum log_file which);
bool log_stdout_is_distinct(void);
bool log_printable(enum log_file which);
bool log_file_printable(const FILE *out);
void log_set_duplicate(enum log_file which, int dupfd);
void log_force_fd(enum log_file which, int fd);
int log_get_fd(enum log_file which);

/*
 * Safe logging interface (to avoid recursive logging, or from signal handlers).
 *
 * When logfilter is supported, trap the high-level messages that we can
 * possibly filter out or enrich dynamically at runtime.
 */

#if LOGFILTER_SUPPORTED

#define s_carp(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, LF_USR_CARP \
	}; \
	logfilter_log(G_LOG_LEVEL_WARNING, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_carp_once(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, LF_USR_CARP | LF_USR_ONCE \
	}; \
	logfilter_log(G_LOG_LEVEL_WARNING, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_critical(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, LF_USR_CARP \
	}; \
	logfilter_log(G_LOG_LEVEL_CRITICAL, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_warning(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, 0 \
	}; \
	logfilter_log(G_LOG_LEVEL_WARNING, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_message(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, 0 \
	}; \
	logfilter_log(G_LOG_LEVEL_MESSAGE, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_info(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, 0 \
	}; \
	logfilter_log(G_LOG_LEVEL_INFO, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_debug(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, 0 \
	}; \
	logfilter_log(G_LOG_LEVEL_DEBUG, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_minilog(flags, ...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, LF_USR_MINILOG \
	}; \
	logfilter_log((flags), &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_minicarp(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, LF_USR_CARP | LF_USR_MINILOG \
	}; \
	logfilter_log(G_LOG_LEVEL_WARNING, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_minicarp_once(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, LF_USR_CARP | LF_USR_ONCE | LF_USR_MINILOG \
	}; \
	logfilter_log(G_LOG_LEVEL_WARNING, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_minicrit(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, LF_USR_CARP | LF_USR_MINILOG \
	}; \
	logfilter_log(G_LOG_LEVEL_CRITICAL, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_miniwarn(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, LF_USR_MINILOG \
	}; \
	logfilter_log(G_LOG_LEVEL_WARNING, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_minimsg(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, LF_USR_MINILOG \
	}; \
	logfilter_log(G_LOG_LEVEL_MESSAGE, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_miniinfo(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, LF_USR_MINILOG \
	}; \
	logfilter_log(G_LOG_LEVEL_INFO, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_minidbg(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, LF_USR_MINILOG \
	}; \
	logfilter_log(G_LOG_LEVEL_DEBUG, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_rawcrit(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, \
		LF_USR_CARP | LF_USR_MINILOG | LF_USR_RAWLOG \
	}; \
	logfilter_log(G_LOG_LEVEL_CRITICAL, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_rawwarn(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, LF_USR_MINILOG | LF_USR_RAWLOG \
	}; \
	logfilter_log(G_LOG_LEVEL_WARNING, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_rawmsg(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, LF_USR_MINILOG | LF_USR_RAWLOG \
	}; \
	logfilter_log(G_LOG_LEVEL_MESSAGE, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_rawinfo(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, LF_USR_MINILOG | LF_USR_RAWLOG \
	}; \
	logfilter_log(G_LOG_LEVEL_INFO, &logdata_, __VA_ARGS__); \
} G_STMT_END

#define s_rawdebug(...) \
G_STMT_START { \
	static const logfilter_data_t logdata_ = { \
		_WHERE_, G_STRFUNC, __LINE__, LF_USR_MINILOG | LF_USR_RAWLOG \
	}; \
	logfilter_log(G_LOG_LEVEL_DEBUG, &logdata_, __VA_ARGS__); \
} G_STMT_END

#else	/* !LOGFILTER_SUPPORTED */
void s_carp(const char *format, ...) G_PRINTF(1, 2);
void s_carp_once(const char *format, ...) G_PRINTF(1, 2);
void s_critical(const char *format, ...) G_PRINTF(1, 2);
void s_warning(const char *format, ...) G_PRINTF(1, 2);
void s_message(const char *format, ...) G_PRINTF(1, 2);
void s_info(const char *format, ...) G_PRINTF(1, 2);
void s_debug(const char *format, ...) G_PRINTF(1, 2);

void s_minilog(GLogLevelFlags flags, const char *fmt, ...) G_PRINTF(2, 3);
void s_minicarp(const char *format, ...) G_PRINTF(1, 2);
void s_minicarp_once(const char *format, ...) G_PRINTF(1, 2);
void s_minicrit(const char *format, ...) G_PRINTF(1, 2);
void s_miniwarn(const char *format, ...) G_PRINTF(1, 2);
void s_minimsg(const char *format, ...) G_PRINTF(1, 2);
void s_miniinfo(const char *format, ...) G_PRINTF(1, 2);
void s_minidbg(const char *format, ...) G_PRINTF(1, 2);

void s_rawcrit(const char *format, ...) G_PRINTF(1, 2);
void s_rawwarn(const char *format, ...) G_PRINTF(1, 2);
void s_rawmsg(const char *format, ...) G_PRINTF(1, 2);
void s_rawinfo(const char *format, ...) G_PRINTF(1, 2);
void s_rawdebug(const char *format, ...) G_PRINTF(1, 2);
#endif	/* LOGFILTER_SUPPORTED */

void s_logv(GLogLevelFlags l, const char *fmt, va_list args) G_PRINTF(2, 0);
void s_error(const char *format, ...) G_PRINTF(1, 2) G_NORETURN;
int s_error_expr(const char *format, ...) G_PRINTF(1, 2);
void s_minierror(const char *format, ...) G_PRINTF(1, 2) G_NORETURN;

void s_fatal_exit(int status, const char *format, ...)
	G_PRINTF(2, 3) G_NORETURN;
void s_error_from(const char *file, const char *fmt, ...)
	G_PRINTF(2, 3) G_NORETURN;
void s_minilogv(GLogLevelFlags, bool copy, const char *fmt, va_list args)
	G_PRINTF(3, 0);
void s_rawlogv(GLogLevelFlags, bool raw, bool copy, const char *f, va_list a)
	G_PRINTF(4, 0);

void s_line_writef(int fd, const char *fmt, ...) G_PRINTF(2, 3);

void s_stacktrace(bool no_stdio, unsigned offset) NO_INLINE;
void s_where(unsigned offset) NO_INLINE;
void s_where_fd(int fd, unsigned offset) NO_INLINE;

/*
 * These routines should not be called directly, use the macros below.
 */
void s_critical_once_per_from(long period, const char *origin,
	const char *format, ...) G_PRINTF(3, 4);
void s_warning_once_per_from(long period, const char *origin,
	const char *format, ...) G_PRINTF(3, 4);
void s_message_once_per_from(long period, const char *origin,
	const char *format, ...) G_PRINTF(3, 4);
void s_info_once_per_from(long period, const char *origin,
	const char *format, ...) G_PRINTF(3, 4);
void s_debug_once_per_from(long period, const char *origin,
	const char *format, ...) G_PRINTF(3, 4);

#define s_critical_once_per(p,fmt,...) \
	s_critical_once_per_from((p), G_STRLOC, (fmt), __VA_ARGS__)

#define s_warning_once_per(p,fmt,...) \
	s_warning_once_per_from((p), G_STRLOC, (fmt), __VA_ARGS__)

#define s_message_once_per(p,fmt,...) \
	s_message_once_per_from((p), G_STRLOC, (fmt), __VA_ARGS__)

#define s_info_once_per(p,fmt,...) \
	s_info_once_per_from((p), G_STRLOC, (fmt), __VA_ARGS__)

#define s_debug_once_per(p,fmt,...) \
	s_debug_once_per_from((p), G_STRLOC, (fmt), __VA_ARGS__)

/*
 * Pre-defined logging periods for the xxx_once_per() logging routines.
 */

#define LOG_PERIOD_SECOND	1
#define LOG_PERIOD_MINUTE	60
#define LOG_PERIOD_HOUR		3600

/*
 * Polymorphic logging interface.
 */

logagent_t *log_agent_stdout_get(void);
logagent_t *log_agent_stderr_get(void);
logagent_t *log_agent_string_make(size_t size, const char *prefix);
void log_agent_reserve(logagent_t *la, size_t len);
void log_agent_string_reset(logagent_t *la);
const char *log_agent_string_get(const logagent_t *la);
char *log_agent_string_get_null(logagent_t **la_ptr);
void log_agent_free_null(logagent_t **la_ptr);

void log_critical(logagent_t *la, const char *format, ...) G_PRINTF(2, 3);
void log_warning(logagent_t *la, const char *format, ...) G_PRINTF(2, 3);
void log_message(logagent_t *la, const char *format, ...) G_PRINTF(2, 3);
void log_info(logagent_t *la, const char *format, ...) G_PRINTF(2, 3);
void log_debug(logagent_t *la, const char *format, ...) G_PRINTF(2, 3);

/*
 * Utilities.
 */

size_t log_vbprintf(char *dst, size_t size, const char *fmt, va_list args);

/*
 * These routines are only visible to the logfilter.
 */

#ifdef LOGFILTER_SOURCE
struct str;
void *log_string_get(const char *caller, const char *fmt, struct str **msg);
void log_string_release(void *saved);
void log_check_truncated(struct str *s);
void log_emit(
	GLogLevelFlags level, struct str *msg,
	const logcolor_t *color, const char *prefix,
	unsigned stid, bool in_sigh, bool copy, bool raw);
void
log_emit_fd(
	int fd,
	GLogLevelFlags level, struct str *msg,
	const logcolor_t *color, const char *prefix,
	unsigned stid, bool in_sigh, bool raw);
#endif	/* LOGFILTER_SOURCE */

/**
 * This macro can be used to send output to all the logfiles that the
 * logfilter would send a message to if it came from that routine and place.
 *
 * When the logfilter is not supported, it simply sends output to stderr.
 *
 * @param fd_		the int variable containing the file descriptor
 * @param code_		the code block using fd_ to send data to the logs
 */
#if LOGFILTER_SUPPORTED
#define LOG_FOREACH(fd_, code_)					\
G_STMT_START {									\
	static const logfilter_data_t logdata_ =	\
		{ _WHERE_, G_STRFUNC, __LINE__, 0 };	\
	pslist_t *list_ = logfilter_fds(&logdata_);	\
	pslist_t *l_ = list_;						\
	while (l_ != NULL)  {						\
		int fd_ = pointer_to_int(l_->data);		\
		l_ = l_->next;							\
		code_									\
	}											\
	logfilter_fds_cleanup(list_);				\
} G_STMT_END
#else	/* !LOGFILTER_SUPPORTED */
#define LOG_FOREACH(fd_, code_) \
G_STMT_START {					\
	fd_ = STDERR_FILENO;		\
	code_						\
} G_STMT_END
#endif	/* LOGFILTER_SUPPORTED */

#endif /* _log_h_ */

/* vi: set ts=4 sw=4 cindent: */
