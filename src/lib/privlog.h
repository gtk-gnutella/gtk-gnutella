/*
 * Copyright (c) 2018 Raphael Manfredi
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
 * Private logging, aimed at verbosely tracing and debugging code sections.
 *
 * To use this file, one needs to define PRIVLOG_PREFIX first, which has to
 * be a single identifier prefix. That will be used to prefix all the routines
 * defined by this logging layer.  It is therefore possible to include this
 * file several time in a single source file by simply chaning PRIVLOG_PREFIX
 * prior to its subsequent inclusions.
 *
 * Setting PRIVLOG_PREFIX to "foo" will define foo_debug(), foo_file, etc...
 * From here on, we will remove the prefix and talk about _debug(), _file
 * but keep in mind all these names will be prefxed.
 *
 * Another important define to set is PRIVLOG_ENABLED: if TRUE, then the
 * set of macros will be configured for emitting logs.  Otherwise, they will
 * be catch-up macros to prevent any code from being generated.
 *
 * When PRIVLOG_ENABLED is TRUE, it is also possible to set PRIVLOG_DYNAMIC.
 * This allows to turn off/on logging, even changing the default flags to
 * selectively trace parts of the code.  By default, logging will be off then.
 *
 * The PRIVLOG_TRACE_PATH is used to determine the logging path. It must be
 * either a manifest string, or the call to a routine that returns such a
 * "const char *" string, defining the directory where logfiles will be stored.
 *
 * Logfiles will be named "x.PRIVLOG_PREFIX.log" where "x" stands for the
 * value of product_nickname().
 *
 * Finally, PRIVLOG_FLAGS is the default set of user-defined flags, to be
 * able to initialize the _flags variable properly.
 *
 * Here are the functionality available for routines:
 *
 *   PRIVLOG_ENTRY				must be the first statement in traced routines
 *   PRIVLOG_RETURN(fmt, value)	return value, tracing it thanks to supplied fmt
 *   PRIVLOG_RETURN_VOID		return with no value to display
 *   PRIVLOG_DEBUG(flg, fmt, ...)	formatting message if flags match _flags
 *   PRIVLOG_LOG_LOCK			defines critical logging section, for atomicity
 *   PRIVLOG_LOG_UNLOCK			terminates critical logging section
 *
 *   _flags					variable holding the global runtime debug flags
 *   _debug()				evaluates to PRIVLOG_ENABLED, statically
 *   _log()					emit formatted log
 *   _file()				the private logfile descriptor
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#include "mutex.h"
#include "thread.h"

#ifndef _lib_privlog_h_
#define _lib_privlog_h_

typedef struct privlog_logdef {
	int level[THREAD_MAX];		/**< Indent level, per thread */
	const char *name;			/**< Logfile name */
	FILE *lf;					/**< Logfile */
	bool rotated;				/**< Did we rotate the old debug logfiles? */
	mutex_t lock;				/**< Protect concurrent writes */
} privlog_logdef_t;

void privlog_logv(privlog_logdef_t *pld, const char *fmt, va_list args);
void privlog_enter(privlog_logdef_t *pld, const char *routine);
void privlog_leavev(privlog_logdef_t *pld,
	const char *routine, const char *loc, const char *fmt, va_list args);

#endif /* _lib_privlog_h_ */

#ifdef PRIVLOG_PREFIX

/* Unfortunately, we cannot define them as PRIVLOG_PREFIX ## _XXX macros... */
#undef PRIVLOG_ENTRY
#undef PRIVLOG_RETURN
#undef PRIVLOG_RETURN_VOID
#undef PRIVLOG_DEBUG
#undef PRIVLOG_LOG_LOCK
#undef PRIVLOG_LOG_UNLOCK
#undef PRIVLOG_debug
#undef PRIVLOG_log
#undef PRIVLOG_flags
#undef PRIVLOG_lockvar
#undef PRIVLOG_enter
#undef PRIVLOG_leave

#define PRIVLOG_debug	CAT2(PRIVLOG_PREFIX,_debug)
#define PRIVLOG_log		CAT2(PRIVLOG_PREFIX,_log)
#define PRIVLOG_flags	CAT2(PRIVLOG_PREFIX,_flags)
#define PRIVLOG_leave	CAT2(PRIVLOG_PREFIX,_leave)
#define PRIVLOG_file	CAT2(PRIVLOG_PREFIX,_file)
#define PRIVLOG_struct	CAT2(PRIVLOG_PREFIX,_debuglog)
#define PRIVLOG_lockvar	PRIVLOG_struct.lock

#if PRIVLOG_ENABLED

#if defined(PRIVLOG_FLAGS) && !defined(PRIVLOG_DYNAMIC)
static uint32 PRIVLOG_flags = PRIVLOG_FLAGS;
#else
static uint32 PRIVLOG_flags;
#endif	/* PRIVLOG_FLAGS && !PRIVLOG_DYNAMIC */

static privlog_logdef_t PRIVLOG_struct = {
	.name = STRINGIFY(PRIVLOG_PREFIX),
	.lock = MUTEX_INIT,
};	

#define PRIVLOG_ENTRY									\
	G_STMT_START {										\
		if (PRIVLOG_debug())							\
		   	privlog_enter(&PRIVLOG_struct, G_STRFUNC);	\
	} G_STMT_END


#define PRIVLOG_DEBUG(flg, ...)							\
	G_STMT_START {										\
		if ((flg) & PRIVLOG_flags)						\
			PRIVLOG_log(__VA_ARGS__);					\
	} G_STMT_END

#define PRIVLOG_RETURN_VOID								\
	G_STMT_START {										\
		if (PRIVLOG_debug())							\
			PRIVLOG_leave(G_STRFUNC, G_STRLOC, "%s", "");\
		return;											\
	} G_STMT_END

#define PRIVLOG_RETURN(type, fmt, val)					\
	G_STMT_START {										\
		type v = (val);									\
		if (PRIVLOG_debug())							\
			PRIVLOG_leave(G_STRFUNC, G_STRLOC,			\
				(fmt), v);								\
		return v;										\
	} G_STMT_END

/* For Setjmp() / longjmp() support */
#define PRIVLOG_DECLARE_LEVEL(var)	volatile int var
#define PRIVLOG_SAVE_LEVEL(var)		var = PRIVLOG_level()
#define PRIVLOG_RESTORE_LEVEL(var)	PRIVLOG_set_level(var)

#define PRIVLOG_LOG_LOCK	mutex_lock(&PRIVLOG_lockvar)
#define PRIVLOG_LOG_UNLOCK	mutex_unlock(&PRIVLOG_lockvar)

static ALWAYS_INLINE inline bool
PRIVLOG_debug(void)
{
	return PRIVLOG_flags != 0;
}
static ALWAYS_INLINE inline FILE *
PRIVLOG_file(void)
{
	return PRIVLOG_struct.lf;
}
static ALWAYS_INLINE inline int
PRIVLOG_level(void)
{
	return PRIVLOG_struct.level[thread_small_id()];
}
static ALWAYS_INLINE inline void
PRIVLOG_set_level(int level)
{
	PRIVLOG_struct.level[thread_small_id()] = level;
}
static inline void G_PRINTF(1, 2)
PRIVLOG_log(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	privlog_logv(&PRIVLOG_struct, fmt, args);
	va_end(args);
}
static inline void G_PRINTF(3, 4)
PRIVLOG_leave(const char *routine, const char *loc, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	privlog_leavev(&PRIVLOG_struct, routine, loc, fmt, args);
	va_end(args);
}
#else	/* !PRIVLOG_ENABLED */
#define PRIVLOG_ENTRY
#define PRIVLOG_RETURN_VOID			return
#define PRIVLOG_RETURN(t, f, v)		return v
#define PRIVLOG_DEBUG(flg, ...)
#define PRIVLOG_DECLARE_LEVEL(var)
#define PRIVLOG_SAVE_LEVEL(var)
#define PRIVLOG_RESTORE_LEVEL(var)
#define PRIVLOG_LOG_LOCK
#define PRIVLOG_LOG_UNLOCK
static ALWAYS_INLINE inline bool PRIVLOG_debug(void)  { return 0; }
static ALWAYS_INLINE inline FILE *PRIVLOG_file(void)  { return stderr; }
static inline void G_PRINTF(1, 2)
PRIVLOG_log(const char *fmt, ...)
{
	(void) fmt;
}
#endif

#endif	/* PRIVLOG_PREFIX */

/* vi: set ts=4 sw=4 cindent: */
