/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
 *
 * Functions that should be in glib-1.2 but are not.
 * They are all prefixed with "gm_" as in "Glib Missing".
 *
 * We also include FIXED versions of glib-1.2 routines that are broken
 * and make sure those glib versions are never called directly.
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

#include "common.h"
#include "glib-missing.h"

RCSID("$Id$");

/*
 * gm_slist_insert_after
 *
 * Insert `item' after `link' in list `list'.
 * If `link' is NULL, insertion happens at the head.
 *
 * Returns new list head.
 */
GSList *gm_slist_insert_after(GSList *list, GSList *link, gpointer data)
{
	GSList *new;

	g_assert(list != NULL || link == NULL);	/* (list = NULL) => (link = NULL) */

	if (link == NULL)
		return g_slist_prepend(list, data);

	new = g_slist_alloc();
	new->data = data;

	new->next = link->next;
	link->next = new;

	return list;
}

/*
 * gm_list_insert_after
 *
 * Insert `item' after `link' in list `list'.
 * If `link' is NULL, insertion happens at the head.
 *
 * Returns new list head.
 */
GList *gm_list_insert_after(GList *list, GList *link, gpointer data)
{
	GList *new;

	g_assert(list != NULL || link == NULL);	/* (list = NULL) => (link = NULL) */

	if (link == NULL)
		return g_list_prepend(list, data);

	new = g_list_alloc();
	new->data = data;

	new->prev = link;
	new->next = link->next;

	if (link->next)
		link->next->prev = new;

	link->next = new;

	return list;
}

/*
 * DO_VSNPRINTF
 *
 * Perform the vsnprintf() operation for the gm_vsnprintf() and gm_snprintf()
 * routines.
 *
 * We don't use macro arguments on purpose: instead, we hardwire the following
 * that must be provided by the context, to ensure this macro is not reused
 * out of its original intended context.
 *
 * `retval' is the returned value.
 * `str' is the string where printing is done.
 * `n' is the maximum amount of chars that can be held in `str'.
 * `fmt' is the format string.
 * `args' is the arguments to be printed.
 */

#ifdef	HAVE_VSNPRINTF
#define DO_VSNPRINTF() do {					\
	str[0] = '\0';							\
	retval = vsnprintf(str, n, fmt, args);	\
	if (retval < 0) {				/* Old versions of vsnprintf() */ \
		str[n - 1] = '\0';					\
		retval = strlen(str);				\
	} else if (retval >= n) {		/* New versions (compliant with C99) */ \
		str[n - 1] = '\0';					\
		retval = n - 1;						\
	}										\
} while (0)
#else	/* !HAVE_VSNPRINTF */
#define DO_VSNPRINTF() do {							\
	gchar *printed = g_strdup_vprintf(fmt, args);	\
	strncpy (str, printed, n);						\
	str[n - 1] = '\0';								\
	retval = strlen(str);							\
	g_free(printed);								\
} while (0)
#endif	/* HAVE_VSNPRINTF */


/*
 * gm_vsnprintf
 *
 * This version implements the correct FIXED semantics of the 1.2.10 glib:
 */
size_t gm_vsnprintf(gchar *str, size_t n, gchar const *fmt, va_list args)
{
	size_t retval;

	g_return_val_if_fail (str != NULL, 0);
	g_return_val_if_fail (fmt != NULL, 0);
	g_return_val_if_fail (n > 0, 0);
	g_return_val_if_fail (n <= INT_MAX, 0);

	DO_VSNPRINTF();

	g_assert(retval < n);

	return retval;
}

/*
 * gm_snprintf
 *
 * This version implements the correct FIXED semantics of the 1.2.10 glib:
 * It returns the length of the output string, and it is GUARANTEED to
 * be one less than `n' (last position occupied by the trailing NUL).
 */
size_t gm_snprintf(gchar *str, size_t n, gchar const *fmt, ...)
{
	va_list args;
	size_t retval;

	g_return_val_if_fail (str != NULL, 0);
	g_return_val_if_fail (fmt != NULL, 0);
	g_return_val_if_fail (n > 0, 0);
	g_return_val_if_fail (n <= INT_MAX, 0);

	va_start (args, fmt);
	DO_VSNPRINTF();
	va_end (args);

	g_assert(retval < n);

	return retval;
}

