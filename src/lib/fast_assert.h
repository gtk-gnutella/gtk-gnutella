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
 * The following variant should be faster than the usual g_assert() because
 * leaf functions stay leaf functions as it does not add function calls and the
 * generated code is smaller which allows better optimization and is more
 * cache-friendly. However, it abuses deferencing a null pointer to cause a
 * SIGSEGV or for x86 the "int 0x03" assembler opcode to cause a SIGTRAP which
 * is then caught by a signal handler. This provokes undefined behaviour and is
 * not portable but happens to work usually.
 *
 * Look at the generated code for functions which use assertion checks to see
 * the difference. It does not seem to make a significant difference in
 * performance overall though as it seems but that might be heavily
 * architecture-dependent.
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
	const gchar *line, *file, *expr;
};

/**
 * eject_() is the userland equivalent of panic(). Don't use it directly,
 * it should only used by assertion checks.
 */
static inline G_GNUC_NORETURN NON_NULL_PARAM((1)) void
eject_(const struct eject_point *eject_point_)
{
	extern const struct eject_point *assert_point_;

	assert_point_ = eject_point_;

	for (;;)	
#if defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
	{
		/* This should raise a SIGTRAP with minimum code */
		__asm__ __volatile__ ("int $03");
	}
#else
	{
		static volatile gint *assert_trigger_;
		*assert_trigger_ = 0;	/* ignite a SIGSEGV */
	}
#endif /* GCC/x86 */
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

#endif /* FAST_ASSERTIONS */

#endif /* _fast_assert_h_ */
/* vi: set ts=4 sw=4 cindent: */
