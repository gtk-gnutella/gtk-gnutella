/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * Glib logging remapping support.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "glog.h"
#include "log.h"
#include "str.h"
#include "thread.h"

#include "override.h"		/* Must be the last header included */

static gl_log_handler_t handler_cb;
static void *handler_data;

/**
 * Record logging handler.
 */
void
gl_log_set_handler(gl_log_handler_t handler, void *data)
{
	handler_cb = handler;
	handler_data = data;
}

/**
 * Log message.
 */
void
gl_logv(const char *domain, GLogLevelFlags flags, const char *fmt, va_list args)
{
	static str_t *msg[THREAD_MAX];
	static bool logging[THREAD_MAX];
	unsigned stid = thread_small_id();

	G_IGNORE_PUSH(-Wformat-nonliteral);		/* s_minilogv() call below */

	if (logging[stid]) {
		s_minilogv(flags | G_LOG_FLAG_RECURSION, FALSE, fmt, args);
		return;
	}

	G_IGNORE_POP;

	/*
	 * This call is thread-unsafe by construction, and supposed to be called
	 * only from the main thread.  This is why it's OK to have a global
	 * ``logging'' variable.
	 */

	logging[stid] = TRUE;

	if G_UNLIKELY(NULL == msg[stid])
		msg[stid] = str_new_not_leaking(0);

	str_vprintf(msg[stid], fmt, args);

	if (handler_cb != NULL)
		(*handler_cb)(domain, flags, str_2c(msg[stid]), handler_data);
	else
		s_minilog(flags, "%s", str_2c(msg[stid]));

	logging[stid] = FALSE;
}

/**
 * Log message.
 */
void gl_log(const char *domain, GLogLevelFlags flags, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	gl_logv(domain, flags, format, args);
	va_end(args);
}

/**
 * Log fata error.
 *
 * This routine does not return.
 */
void gl_error(const char *domain, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	gl_logv(domain, G_LOG_LEVEL_ERROR | G_LOG_FLAG_FATAL, format, args);
	va_end(args);

	log_abort();
}

/* vi: set ts=4 sw=4 cindent: */
