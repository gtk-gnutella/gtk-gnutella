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

#ifndef _log_h_
#define _log_h_

#include "common.h"

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

/*
 * Public interface.
 */

struct str;

const char *log_prefix(GLogLevelFlags loglvl) G_GNUC_CONST;
void log_abort(void) G_GNUC_NORETURN;

void log_init(void);
void log_crashing(struct str *str);
void log_atoms_inited(void);
void log_close(void);
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
 */

void s_critical(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_error(const char *format, ...) G_GNUC_PRINTF(1, 2) G_GNUC_NORETURN;
int s_error_expr(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_carp(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_carp_once(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_minicarp(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_minilog(GLogLevelFlags flags, const char *fmt, ...) G_GNUC_PRINTF(2, 3);
void s_warning(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_message(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_info(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_debug(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_fatal_exit(int status, const char *format, ...)
	G_GNUC_PRINTF(2, 3) G_GNUC_NORETURN;
void s_error_from(const char *file, const char *fmt, ...)
	G_GNUC_PRINTF(2, 3) G_GNUC_NORETURN;
void s_minilogv(GLogLevelFlags, bool copy, const char *fmt, va_list args);
void s_minierror(const char *format, ...) G_GNUC_PRINTF(1, 2) G_GNUC_NORETURN;
void s_minicrit(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_miniwarn(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_minimsg(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_miniinfo(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_minidbg(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_rawlogv(GLogLevelFlags, bool copy, const char *fmt, va_list args);
void s_rawcrit(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_rawwarn(const char *format, ...) G_GNUC_PRINTF(1, 2);

/*
 * Thread-safe logging interface.
 */

void t_critical(const char *format, ...) G_GNUC_PRINTF(1, 2);
void t_error(const char *format, ...)
	G_GNUC_PRINTF(1, 2) G_GNUC_NORETURN;
void t_carp(const char *format, ...) G_GNUC_PRINTF(1, 2);
void t_carp_once(const char *format, ...) G_GNUC_PRINTF(1, 2);
void t_warning(const char *format, ...) G_GNUC_PRINTF(1, 2);
void t_message(const char *format, ...) G_GNUC_PRINTF(1, 2);
void t_info(const char *format, ...) G_GNUC_PRINTF(1, 2);
void t_debug(const char *format, ...) G_GNUC_PRINTF(1, 2);
void t_error_from(const char *file, const char *format, ...)
	G_GNUC_PRINTF(2, 3) G_GNUC_NORETURN;

/*
 * Polymorphic logging interface.
 */

logagent_t *log_agent_stdout_get(void);
logagent_t *log_agent_stderr_get(void);
logagent_t *log_agent_string_make(size_t size, const char *prefix);
void log_agent_string_reset(logagent_t *la);
const char *log_agent_string_get(const logagent_t *la);
char *log_agent_string_get_null(logagent_t **la_ptr);
void log_agent_free_null(logagent_t **la_ptr);

void log_critical(logagent_t *la, const char *format, ...) G_GNUC_PRINTF(2, 3);
void log_warning(logagent_t *la, const char *format, ...) G_GNUC_PRINTF(2, 3);
void log_message(logagent_t *la, const char *format, ...) G_GNUC_PRINTF(2, 3);
void log_info(logagent_t *la, const char *format, ...) G_GNUC_PRINTF(2, 3);
void log_debug(logagent_t *la, const char *format, ...) G_GNUC_PRINTF(2, 3);

#endif /* _log_h_ */

/* vi: set ts=4 sw=4 cindent: */
