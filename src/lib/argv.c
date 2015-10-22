/*
 * Copyright (c) 2015 Raphael Manfredi
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
 * Argument vector utilities.
 *
 * An argument vector is an array of strings terminated by a NULL pointer,
 * and can be represented by a single "char **argv" variable in its most
 * generic form, or "char *argv[]" at times, which is a "char * const *argv".
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#include "common.h"

#include "argv.h"

#include "halloc.h"

#include "override.h"			/* Must be the last header included */

/**
 * Create an argv[] array that must be later freed via argv_free_null().
 *
 * @param arg	the first mandatory item in the argv[] array
 * @param ap	the optional list of additional values
 *
 * @return a new vector of strings, NULL-terminated.
 */
char **
argv_create(const char *arg, va_list ap)
{
	const char **argv, **a;
	va_list ap2;
	const char *s;
	size_t cnt = 0;

	/*
	 * Count amount of additional arguments, past `arg'.
	 */

	VA_COPY(ap2, ap);
	while (NULL != va_arg(ap2, const char *))
		cnt++;
	va_end(ap2);

	/*
	 * Build argv[] dynamically.
	 */

	HALLOC_ARRAY(argv, cnt + 2);	/* +2 for arg and NULL */
	a = argv;

	*a++ = arg;		/* argv[0] */

	while (NULL != ((s = va_arg(ap, const char *)))) {
		*a++ = s;
	}

	g_assert(ptr_diff(a, argv) == (cnt + 1) * sizeof argv[0]);

	*a = NULL;		/* Last item is the argv[] sentinel */

	return deconstify_pointer(argv);
}

/**
 * Free memory allocated by argv_create() and nullify pointer.
 */
void
argv_free_null(char ***argv_ptr)
{
	char **argv = *argv_ptr;

	if (argv != NULL) {
		hfree(argv);
		*argv_ptr = NULL;
	}
}

/* vi: set ts=4 sw=4 cindent: */
