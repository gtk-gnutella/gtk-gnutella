/*
 * $Id$
 *
 * Copyright (c) 2004, Raphael Manfredi
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
 * Additional overrides.
 *
 * @note
 * This file should be the LAST one included.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _override_h_
#define _override_h_

#ifdef FAST_ASSERTIONS
/*
 * The following variant should be faster than the usual g_assert()
 * because leaf functions stay leaf functions as it does not add function
 * calls and the additional code is close to the possible minimum which
 * allows better optimization. However, it abuses deferencing a null pointer
 * to cause a SIGSEGV which is then caught by a signal handler. This is
 * provokes undefined behaviour but happens to work usually.
 *
 * Look at the generated code for hex2dec() to see the difference. It does
 * not seem to make difference overall though as it seems but that might
 * heavily architecture-dependent.
 *
 * Taking advantage of it may require using -momit-leaf-frame-pointer or
 * -fomit-frame-pointer for GCC.
 */
#undef g_assert
#undef g_assert_not_reached

extern const char *assert_msg_;

static inline G_GNUC_NORETURN void
raise_sigsegv(void)
{
	static char *assert_trigger_;
	*assert_trigger_ = 0;	/* ignite a SIGSEGV */
}

#define g_assert(x)														\
G_STMT_START {															\
	if (G_UNLIKELY(!(x))) {												\
		assert_msg_ = "\nAssertion failure \""							\
			StGiFy(x) "\" in " __FILE__ "(" STRINGIFY(__LINE__) ")\n";	\
		raise_sigsegv();												\
	}																	\
} G_STMT_END

#define g_assert_not_reached(x)							\
G_STMT_START {								  			\
	assert_msg_ = "\nCode should not be reached in "	\
			__FILE__ "(" STRINGIFY(__LINE__) ")\n";		\
	raise_sigsegv();									\
} G_STMT_END

#endif /* FAST_ASSERTIONS */

#include "malloc.h"		/* Must be the last header included */

#endif /* _override_h_ */
/* vi: set ts=4 sw=4 cindent: */
