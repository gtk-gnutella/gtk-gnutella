/*
 * Copyright (c) 2018, Raphael Manfredi
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
 * Versatile logging filtering support.
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#ifndef _logfilter_h_
#define _logfilter_h_

#include "common.h"

#include "pslist.h"

/*
 * See whether we can usefully support the logfilter features, by remapping
 * all calls to g_xxx() and s_xxx() logging routines.
 *
 * For that to work, we need the ... support in the macro signatures, that will be
 * expanded through __VA_ARGS__ in the macro definition.
 */
#if defined (__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define LOGFILTER_SUPPORTED 1
#elif HAS_GCC(3, 0)
#define LOGFILTER_SUPPORTED 1
#else
#define LOGFILTER_NOT_SUPPORTED
#endif

#if LOGFILTER_SUPPORTED
#define logfilter_supported()	1
#else
#define logfilter_supported()	0
#endif

/**
 * logfilter_data_t flags.
 */

#define LF_USR_CARP			(1U << 0)	/**< Request carping */
#define LF_USR_ONCE			(1U << 1)	/**< Only log once per stack */
#define LF_USR_MINILOG		(1U << 2)	/**< Minimum usage of resources */
#define LF_USR_RAWLOG		(1U << 3)	/**< Raw logging, avoid locks! */
#define LF_USR_COMPUTED		(1U << 4)	/**< Data was computed (approximative) */

/**
 * Additional data supplied by the logging statement, possibly perused by the
 * logfilter rules to alter the logged message or filter it out.
 */
typedef struct logfilter_data {
	const char *file, *routine;
	unsigned line;
	unsigned flags;
} logfilter_data_t;

/*
 * Public interface.
 */

void logfilter_init(void);
void logfilter_close(void);

void logfilter_set_debug(uint32 level);
void logfilter_crash_mode(void);

bool logfilter_install(const char *file);
bool logfilter_is_active(void);

void NON_NULL_PARAM((2))
logfilter_log(GLogLevelFlags flags,
		const logfilter_data_t * const data,
		const char *fmt, ...) G_PRINTF(3, 4);

void NON_NULL_PARAM((2))
logfilter_logv(GLogLevelFlags flags,
		const logfilter_data_t * const data,
		size_t offset, const char *fmt, bool format, va_list args);

void NON_NULL_PARAM((2))
logfilter_logv_no_args(
	GLogLevelFlags flags, const logfilter_data_t * const data,
	size_t offset, const char *fmt, ...);

pslist_t *logfilter_fds(const logfilter_data_t *data);
void logfilter_fds_cleanup(pslist_t *);

#endif /* _logfilter_h_ */

/* vi: set ts=4 sw=4 cindent: */
