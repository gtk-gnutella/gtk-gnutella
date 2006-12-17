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

typedef struct assertion_data {
	const char *file, *expr;
	unsigned line;
} assertion_data;

void G_GNUC_NORETURN NON_NULL_PARAM((1)) REGPARM(1)
assertion_failure(const assertion_data * const data);

void NON_NULL_PARAM((1)) REGPARM(1)
assertion_warning(const assertion_data * const data);

#define RUNTIME_ASSERT(expr) fast_assert(expr, #expr)
#define RUNTIME_UNREACHABLE() fast_assert_not_reached()

#define fast_assert(expr, expr_string) \
G_STMT_START { \
	if (G_UNLIKELY(!(expr))) { \
		static const struct assertion_data assertion_data_ = { \
			__FILE__, expr_string, __LINE__ \
		}; \
		assertion_failure(&assertion_data_); \
	} \
} G_STMT_END

#define fast_assert_not_reached() \
G_STMT_START { \
	static const struct assertion_data assertion_data_ = { \
		__FILE__, NULL, __LINE__ \
	}; \
	assertion_failure(&assertion_data_); \
} G_STMT_END

#define return_unless(expr) return_unless_intern((expr), #expr)

#define return_unless_intern(expr, expr_string) \
G_STMT_START { \
	if (G_UNLIKELY(!(expr))) { \
		static const struct assertion_data assertion_data_ = { \
			__FILE__, expr_string, __LINE__ \
		}; \
		assertion_warning(&assertion_data_); \
		return; \
	} \
} G_STMT_END

#define return_value_unless(expr, val) \
	return_value_unless_intern((expr), #expr, val)

#define return_value_unless_intern(expr, expr_string, val) \
G_STMT_START { \
	if (G_UNLIKELY(!(expr))) { \
		static const struct assertion_data assertion_data_ = { \
			__FILE__, expr_string, __LINE__ \
		}; \
		assertion_warning(&assertion_data_); \
		return (val); \
	} \
} G_STMT_END

#ifdef FAST_ASSERTIONS

#undef g_assert
#define g_assert(expr) fast_assert((expr), #expr)

#undef g_assert_not_reached
#define g_assert_not_reached() fast_assert_not_reached()

#undef g_return_if_fail
#define g_return_if_fail(expr) return_unless_intern((expr), #expr)

#undef g_return_val_if_fail
#define g_return_val_if_fail(expr, val) \
	return_value_unless_intern((expr), #expr, (val))

#endif /* FAST_ASSERTIONS */

#endif /* _fast_assert_h_ */
/* vi: set ts=4 sw=4 cindent: */
