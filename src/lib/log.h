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

struct logthread;
typedef struct logthread logthread_t;

/*
 * Public interface.
 */

logthread_t *log_thread_alloc(void);

void log_init(void);
void log_atoms_inited(void);
void log_close(void);
void log_set_disabled(enum log_file which, gboolean disabled);
void log_set(enum log_file which, const char *path);
gboolean log_reopen(enum log_file which);
gboolean log_rename(enum log_file which, const char *newname);
gboolean log_reopen_if_managed(enum log_file which);
gboolean log_reopen_all(gboolean daemonized);
void log_stat(enum log_file which, struct logstat *buf);
gboolean log_is_managed(enum log_file which);
gboolean log_is_disabled(enum log_file which);
gboolean log_stdout_is_distinct(void);
gboolean log_printable(enum log_file which);
gboolean log_file_printable(const FILE *out);

/*
 * Safe logging interface (to avoid recursive logging, or from signal handlers).
 */

void s_critical(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_error(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_carp(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_warning(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_message(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_info(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_debug(const char *format, ...) G_GNUC_PRINTF(1, 2);
void s_fatal_exit(int status, const char *format, ...) G_GNUC_PRINTF(2, 3);

/*
 * Thread-safe logging interface.
 */

void t_critical(logthread_t *lt, const char *format, ...) G_GNUC_PRINTF(2, 3);
void t_error(logthread_t *lt, const char *format, ...) G_GNUC_PRINTF(2, 3);
void t_carp(logthread_t *lt, const char *format, ...) G_GNUC_PRINTF(2, 3);
void t_warning(logthread_t *lt, const char *format, ...) G_GNUC_PRINTF(2, 3);
void t_message(logthread_t *lt, const char *format, ...) G_GNUC_PRINTF(2, 3);
void t_info(logthread_t *lt, const char *format, ...) G_GNUC_PRINTF(2, 3);
void t_debug(logthread_t *lt, const char *format, ...) G_GNUC_PRINTF(2, 3);

#endif /* _log_h_ */

/* vi: set ts=4 sw=4 cindent: */
