/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
 *
 * Interface definition file.  One of the files that defines structures,
 * macros, etc. as part of the gui/core interface.
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

#ifndef _ui_core_interface_misc_defs_h_
#define _ui_core_interface_misc_defs_h_

#include "config.h"

#include <ctype.h>
#include <string.h>
#include <glib.h>


/* The RCS IDs can be looked up from the compiled binary with e.g. `what'  */
#ifdef __GNUC__
#define RCSID(x) \
	static const char rcsid[] __attribute__((__unused__)) = "@(#) " x
#else
#define RCSID(x) static const char rcsid[] = "@(#) " x
#endif

#define SIZE_FIELD_MAX 64		/* Max size of sprintf-ed size quantity */

/*
 * STATIC_ASSERT() can be used to verify conditions at compile-time e.g., that
 * an array has a minimum size. This is better than a run-time * assertion
 * because the condition is checked even if the code would seldomly or never
 * reached at run-time. However, this can only be used for static conditions
 * which can verified at compile-time.
 *
 * N.B.: The trick is declaring a negative sized array if the condition
 *	 is false - which is invalid C. This cannot be used outside a
 *	 function.
 */
#define STATIC_ASSERT(x) \
	do { (void) sizeof(char[((x) ? 1 : -23)]); } while(0)

/*
 * Needs to be defined if we are not using Glib 2
 */
#ifndef USE_GTK2

#ifndef HAVE_STRLCPY
size_t strlcpy(gchar *dst, const gchar *src, size_t dst_size);
#endif

#define g_ascii_strcasecmp g_strcasecmp
#define g_ascii_strncasecmp g_strncasecmp
#define g_string_printf g_string_sprintf
#define g_strlcpy strlcpy
#endif

/* Wrappers for ctype functions that allow only ASCII characters whereas
 * the locale would allow others. The parameter doesn't have to be casted
 * to (unsigned char) because isascii() is defined for all values so that
 * these macros return false for everything out of [0..127].
 *
 * GLib 2.x has similar macros/functions but defines only a subset.
 */
#define is_ascii_alnum(c) (isascii(c) && isalnum(c))
#define is_ascii_alpha(c) (isascii(c) && isalpha(c))
#ifdef isblank
#define is_ascii_blank(c) (isascii(c) && isblank(c))
#else /* !isblank */
#define is_ascii_blank(c) ((c) == ' ' || (c) == '\t')
#endif /* isblank */
#define is_ascii_cntrl(c) (isascii(c) && iscntrl(c))
#define is_ascii_digit(c) (isascii(c) && isdigit(c))
#define is_ascii_graph(c) (isascii(c) && isgraph(c))
#define is_ascii_lower(c) (isascii(c) && islower(c))
#define is_ascii_print(c) (isascii(c) && isprint(c))
#define is_ascii_punct(c) (isascii(c) && ispunct(c))
#define is_ascii_space(c) (isascii(c) && isspace(c))
#define is_ascii_upper(c) (isascii(c) && isupper(c))
#define is_ascii_xdigit(c) (isascii(c) && isxdigit(c))

static const char hex_alphabet_lower[] = "0123456789abcdef";

/*
 * Array size determination
 */
#ifndef G_N_ELEMENTS
#define G_N_ELEMENTS(arr) (sizeof (arr) / sizeof ((arr)[0]))
#endif

/* 
 * Set/clear binary flags 
 */
typedef guint16 flag_t;
#define set_flags(r,f) (r = r | (f))
#define clear_flags(r,f) (r = r & ~(f))

/*
 * Sorting constants
 */
#define SORT_ASC  1
#define SORT_DESC (-1)
#define SORT_NONE 0
#define SORT_NO_COL 0		/* On search creation, no column chosen for sort */

/* SIGN() returns whether a is smaller (-1), equal (0) or greater (1) than b */
#define SIGN(a, b) ((a) == (b) ? 0 : (a) > (b) ? 1 : (-1))


#endif
/* vi: set ts=4 sw=4 cindent: */
