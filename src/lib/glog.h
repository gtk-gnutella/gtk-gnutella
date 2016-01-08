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

#ifndef _glog_h_
#define _glog_h_

#include "stacktrace.h"		/* For stacktrace_caller_known() */
#include "log.h"			/* For log_abort() */

/*
 * Trap all glib-defined logging and redirect them to our own.
 *
 * This was made necessary for two reasons:
 *
 * - The introduction of %m and %zu creates warnings with g_xxx() logging
 *   routines at compile-time since they are declared by glib as being
 *   printf()-like and not gnu_printf()-like.
 *
 * - Accidental use of %F in formats triggers a crash in glib 1.2 because
 *   their internal formatting routine cannot estimate the size of the field
 *   properly.
 *
 * By remapping we no longer have to bother whether we should call g_debug()
 * or s_debug() just because we're using a possibly unsupported formatting.
 */

#undef g_debug
#undef g_info
#undef g_message
#undef g_warning
#undef g_critical
#undef g_error

#if defined (__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define g_carp(...)					\
	G_STMT_START {					\
		gl_log(G_LOG_DOMAIN,		\
   			G_LOG_LEVEL_WARNING,	\
   			__VA_ARGS__);			\
		stacktrace_where_sym_print(stderr); \
	} G_STMT_END
#define g_carp_once(...) G_STMT_START {		\
	if (!stacktrace_caller_known(1)) {		\
		gl_log(G_LOG_DOMAIN,				\
   			G_LOG_LEVEL_WARNING,			\
   			__VA_ARGS__);					\
		stacktrace_where_sym_print(stderr); \
	}										\
} G_STMT_END
#define g_error(...)	gl_error(G_LOG_DOMAIN,  __VA_ARGS__)
#define g_critical(...)	gl_log(G_LOG_DOMAIN,		\
							   G_LOG_LEVEL_CRITICAL,\
							   __VA_ARGS__)
#define g_warning(...)	gl_log(G_LOG_DOMAIN,		\
							   G_LOG_LEVEL_WARNING,	\
							   __VA_ARGS__)
#define g_message(...)	gl_log(G_LOG_DOMAIN,		\
							   G_LOG_LEVEL_MESSAGE,	\
							   __VA_ARGS__)
#define g_info(...)		gl_log(G_LOG_DOMAIN,		\
							   G_LOG_LEVEL_INFO,	\
							   __VA_ARGS__)
#define g_debug(...)	gl_log(G_LOG_DOMAIN,		\
							   G_LOG_LEVEL_DEBUG,	\
							   __VA_ARGS__)
#elif defined (__GNUC__)
#define g_carp(format...)			\
	G_STMT_START {					\
		gl_log(G_LOG_DOMAIN,		\
   			G_LOG_LEVEL_WARNING,	\
   			format);				\
		stacktrace_where_sym_print(stderr); \
	} G_STMT_END
#define g_carp_once(format...) G_STMT_START {	\
	if (!stacktrace_caller_known(1)) {		\
		gl_log(G_LOG_DOMAIN,				\
   			G_LOG_LEVEL_WARNING,			\
   			format);						\
		stacktrace_where_sym_print(stderr); \
	}										\
} G_STMT_END
#define g_error(format...)		gl_error(G_LOG_DOMAIN, format)
#define g_critical(format...)	gl_log(G_LOG_DOMAIN,		\
								   G_LOG_LEVEL_CRITICAL,	\
								   	format)
#define g_warning(format...)	gl_log(G_LOG_DOMAIN,		\
								   G_LOG_LEVEL_WARNING,		\
								   format)
#define g_message(format...)	gl_log(G_LOG_DOMAIN,		\
								   G_LOG_LEVEL_MESSAGE,		\
								   format)
#define g_info(format...)		gl_log(G_LOG_DOMAIN,		\
									   G_LOG_LEVEL_INFO,	\
									   format)
#define g_debug(format...)		gl_log(G_LOG_DOMAIN,		\
									   G_LOG_LEVEL_DEBUG,	\
									   format)
#else	/* !__GNUC__ */
static inline G_GNUC_PRINTF(1, 2) void
g_carp(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  gl_logv(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, format, args);
  va_end(args);
  stacktrace_where_sym_print(stderr);
}

static inline G_GNUC_PRINTF(1, 2) void
g_carp_once(const char *format, ...)
{
  if (!stacktrace_caller_known(1)) {
	va_list args;
	va_start(args, format);
	gl_logv(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, format, args);
	va_end(args);
	stacktrace_where_sym_print(stderr);
  }
}

static inline G_GNUC_PRINTF(1, 2) void
g_error(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  gl_logv(G_LOG_DOMAIN, G_LOG_LEVEL_ERROR | G_LOG_FLAG_FATAL, format, args);
  va_end(args);
  log_abort();
}

static inline G_GNUC_PRINTF(1, 2) void
g_critical(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  gl_logv(G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL, format, args);
  va_end(args);
}

static inline G_GNUC_PRINTF(1, 2) void
g_warning(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  gl_logv(G_LOG_DOMAIN, G_LOG_LEVEL_WARNING, format, args);
  va_end(args);
}

static inline G_GNUC_PRINTF(1, 2) void
g_message(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  gl_logv(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, format, args);
  va_end(args);
}

static inline G_GNUC_PRINTF(1, 2) void
g_info(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  gl_logv(G_LOG_DOMAIN, G_LOG_LEVEL_INFO, format, args);
  va_end(args);
}

static inline G_GNUC_PRINTF(1, 2) void
g_debug(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  gl_logv(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, format, args);
  va_end(args);
}
#endif	/* !__GNUC__ */

/*
 * Public interface.
 */

typedef void (*gl_log_handler_t)(const char *, GLogLevelFlags,
	const char *, void *);

void gl_log_set_handler(gl_log_handler_t handler, void *data);
void gl_logv(const char *domain, GLogLevelFlags flags,
	const char *format, va_list args);
void gl_log(const char *domain, GLogLevelFlags flags,
	const char *format, ...) G_GNUC_PRINTF(3, 4);
void gl_error(const char *domain, const char *format, ...)
	G_GNUC_PRINTF(2, 3) G_NORETURN;

#endif /* _glog_h_ */

/* vi: set ts=4 sw=4 cindent: */
