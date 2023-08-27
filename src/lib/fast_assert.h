/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

/*
 * When expr is NULL, it means this is a "not-reached" type of assertion.
 *
 * As noted on 2013-10-28, we carry both the location and the routine name.
 * This can help debug situations where the assertion fails in code that has
 * been changed (e.g. from an old release) and the source location is not
 * enough to spot where the failure happens, especially when no symbolic stack
 * trace can be generated.
 */

typedef struct assertion_data {
	const char *file, *expr, *routine;
	unsigned line;
} assertion_data;

/*
 * Due to an optimizer bug in gcc 4.2.1 (and maybe later verions), avoid
 * specifying the REGPARM(1) attribute in the assertion_xxx() routines
 * or the pointer being passed will be garbage, causing a segmentation fault
 * in assertion_message().
 *		--RAM, 2009-10-31
 */

void G_NORETURN NON_NULL_PARAM((1)) /* REGPARM(1) */
assertion_failure(const assertion_data * const data);

void G_NORETURN NON_NULL_PARAM((1)) G_PRINTF(2,3)
assertion_failure_log(const assertion_data * const data, const char *fmt, ...);

void NON_NULL_PARAM((1)) /* REGPARM(1) */
assertion_warning(const assertion_data * const data);

void NON_NULL_PARAM((1)) G_PRINTF(2,3)
assertion_warning_log(const assertion_data * const data, const char *fmt, ...);

#define RUNTIME_ASSERT(expr) fast_assert(expr, #expr)
#define RUNTIME_UNREACHABLE() fast_assert_not_reached()

#define fast_assert(expr, expr_string) \
G_STMT_START { \
	if (G_UNLIKELY(!(expr))) { \
		static const struct assertion_data assertion_data_ = { \
			_WHERE_, expr_string, G_STRFUNC, __LINE__ \
		}; \
		assertion_failure(&assertion_data_); \
	} \
} G_STMT_END

#define fast_assert_log(expr, expr_string, ...) \
G_STMT_START { \
	if (G_UNLIKELY(!(expr))) { \
		static const struct assertion_data assertion_data_ = { \
			_WHERE_, expr_string, G_STRFUNC, __LINE__ \
		}; \
		assertion_failure_log(&assertion_data_, __VA_ARGS__); \
	} \
} G_STMT_END

#define fast_assert_not_reached() \
G_STMT_START { \
	static const struct assertion_data assertion_data_ = { \
		_WHERE_, NULL, G_STRFUNC, __LINE__ \
	}; \
	assertion_failure(&assertion_data_); \
} G_STMT_END

#define return_unless(expr) return_unless_intern((expr), #expr)

#define return_unless_log(expr, ...) \
	return_unless_intern_log((expr), #expr, __VA_ARGS__)

#define return_unless_intern(expr, expr_string) \
G_STMT_START { \
	if (G_UNLIKELY(!(expr))) { \
		static const struct assertion_data assertion_data_ = { \
			_WHERE_, expr_string, G_STRFUNC, __LINE__ \
		}; \
		assertion_warning(&assertion_data_); \
		return; \
	} \
} G_STMT_END

#define return_unless_intern_log(expr, expr_string, ...) \
G_STMT_START { \
	if (G_UNLIKELY(!(expr))) { \
		static const struct assertion_data assertion_data_ = { \
			_WHERE_, expr_string, G_STRFUNC, __LINE__ \
		}; \
		assertion_warning_log(&assertion_data_, __VA_ARGS__); \
		return; \
	} \
} G_STMT_END

#define return_value_unless(expr, val) \
	return_value_unless_intern((expr), #expr, val)

#define return_value_unless_intern(expr, expr_string, val) \
G_STMT_START { \
	if (G_UNLIKELY(!(expr))) { \
		static const struct assertion_data assertion_data_ = { \
			_WHERE_, expr_string, G_STRFUNC, __LINE__ \
		}; \
		assertion_warning(&assertion_data_); \
		return (val); \
	} \
} G_STMT_END

#define return_value_unless_intern_log(expr, expr_string, val, ...) \
G_STMT_START { \
	if (G_UNLIKELY(!(expr))) { \
		static const struct assertion_data assertion_data_ = { \
			_WHERE_, expr_string, G_STRFUNC, __LINE__ \
		}; \
		assertion_warning_log(&assertion_data_, __VA_ARGS__); \
		return (val); \
	} \
} G_STMT_END

#define warn_unless(expr, expr_string) \
G_STMT_START { \
	if (G_UNLIKELY(!(expr))) { \
		static const struct assertion_data assertion_data_ = { \
			_WHERE_, expr_string, G_STRFUNC, __LINE__ \
		}; \
		assertion_warning(&assertion_data_); \
	} \
} G_STMT_END

#define warn_unless_log(expr, expr_string, ...) \
G_STMT_START { \
	if (G_UNLIKELY(!(expr))) { \
		static const struct assertion_data assertion_data_ = { \
			_WHERE_, expr_string, G_STRFUNC, __LINE__ \
		}; \
		assertion_warning_log(&assertion_data_, __VA_ARGS__); \
	} \
} G_STMT_END

#define g_soft_assert(expr) warn_unless((expr), #expr)

#define g_soft_assert_log(expr, ...) \
	warn_unless_log((expr), #expr, __VA_ARGS__)

#define g_assert_log(expr, ...) \
	fast_assert_log((expr), #expr,  __VA_ARGS__)

#define g_return_if_fail_log(expr, ...) \
	return_unless_intern_log((expr), #expr, __VA_ARGS__)

#define g_return_val_if_fail_log(expr, val, ...) \
	return_value_unless_intern_log((expr), #expr, (val), __VA_ARGS__)

/* Aliases, for convenience */

#define g_return_unless(expr) return_unless_intern((expr), #expr)
#define g_return_unless_log(expr, ...) \
	return_unless_intern_log((expr), #expr, __VA_ARGS__)

#define g_return_val_unless(expr, val) \
	return_value_unless_intern((expr), #expr, (val))

#define g_return_val_unless_log(expr, val, ...) \
	return_value_unless_intern_log((expr), #expr, (val), __VA_ARGS__)

/* Superseding glib versions */

#undef g_assert
#define g_assert(expr) fast_assert((expr), #expr)

#undef g_assert_not_reached
#define g_assert_not_reached() fast_assert_not_reached()

#undef g_return_if_fail
#define g_return_if_fail(expr) return_unless_intern((expr), #expr)

#undef g_return_val_if_fail
#define g_return_val_if_fail(expr, val) \
	return_value_unless_intern((expr), #expr, (val))

#endif /* _fast_assert_h_ */

/* vi: set ts=4 sw=4 cindent: */
