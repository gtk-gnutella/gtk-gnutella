/*
 * $Id$
 *
 * Copyright (c) 2006, Christian Biere
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
 * Fast assertions.
 *
 * The following variant should be faster than the usual g_assert() because the
 * generated code is smaller which allows better optimization and is more
 * cache-friendly.
 *
 * Look at the generated code for functions which use assertion checks to see
 * the difference.
 *
 * Taking advantage of it may require using -momit-leaf-frame-pointer or
 * -fomit-frame-pointer for GCC and an appropriate -march option is also
 * recommended.
 *
 * @note This file should be included by override.h and assumes that
 *       common.h has been included.
 *
 * @author Christian Biere
 * @date 2006
 */

#ifndef _fast_assert_h_
#define _fast_assert_h_

#ifdef FAST_ASSERTIONS

struct eject_point {
	volatile const gchar *line, *file, *expr;
};

extern void G_GNUC_NORETURN REGPARM(1) assertion_failure(gulong addr);
extern volatile const struct eject_point *assert_point_;

/**
 * eject_() is the userland equivalent of panic(). Don't use it directly,
 * it should only used by assertion checks.
 */
static inline G_GNUC_NORETURN NON_NULL_PARAM((1)) void
eject_(const struct eject_point *eject_point_)
{
	assertion_failure((gulong) eject_point_);
}

#define fast_assert(x) \
G_STMT_START { \
	if (G_UNLIKELY(!(x))) { \
		static const struct eject_point eject_point_ = { \
			STRINGIFY(__LINE__), \
			__FILE__, \
			STRINGIFY(x) \
		}; \
		eject_(&eject_point_); \
	} \
} G_STMT_END

#define fast_assert_not_reached() \
G_STMT_START { \
	static const struct eject_point eject_point_ = { \
		STRINGIFY(__LINE__), \
		__FILE__, \
		NULL, \
	}; \
	eject_(&eject_point_); \
} G_STMT_END

#undef g_assert
#undef g_assert_not_reached

#define g_assert(x) fast_assert(x)
#define g_assert_not_reached() fast_assert_not_reached()

#define RUNTIME_ASSERT(x) fast_assert(x)
#define RUNTIME_UNREACHABLE(x) fast_assert_not_reached(x)

#else	/* !FAST_ASSERTIONS */
#define RUNTIME_ASSERT(x) assert(x)
#define RUNTIME_UNREACHABLE(x) assert(!"reached")
#endif /* FAST_ASSERTIONS */

#endif /* _fast_assert_h_ */
/* vi: set ts=4 sw=4 cindent: */
