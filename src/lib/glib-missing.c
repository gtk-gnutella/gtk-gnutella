/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
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
 * Missing functions in the Glib 1.2.
 *
 * Functions that should be in glib-1.2 but are not.
 * They are all prefixed with "gm_" as in "Glib Missing".
 *
 * We also include FIXED versions of glib-1.2 routines that are broken
 * and make sure those glib versions are never called directly.
 *
 * @author Raphael Manfredi
 * @date 2003
 */

#include "common.h"

RCSID("$Id$");

#include "glib-missing.h"
#include "utf8.h"
#include "misc.h"
#include "override.h"		/* Must be the last header included */

#ifndef TRACK_MALLOC

/**
 * Insert `item' after `lnk' in list `list'.
 * If `lnk' is NULL, insertion happens at the head.
 *
 * @return new list head.
 */
GSList *
gm_slist_insert_after(GSList *list, GSList *lnk, gpointer data)
{
	GSList *new;

	g_assert(list != NULL || lnk == NULL);	/* (list = NULL) => (lnk = NULL) */

	if (lnk == NULL)
		return g_slist_prepend(list, data);

	new = g_slist_alloc();
	new->data = data;

	new->next = lnk->next;
	lnk->next = new;

	return list;
}

/**
 * Insert `item' after `lnk' in list `list'.
 * If `lnk' is NULL, insertion happens at the head.
 *
 * @return new list head.
 */
GList *
gm_list_insert_after(GList *list, GList *lnk, gpointer data)
{
	GList *new;

	g_assert(list != NULL || lnk == NULL);	/* (list = NULL) => (lnk = NULL) */

	if (lnk == NULL)
		return g_list_prepend(list, data);

	new = g_list_alloc();
	new->data = data;

	new->prev = lnk;
	new->next = lnk->next;

	if (lnk->next)
		lnk->next->prev = new;

	lnk->next = new;

	return list;
}

#ifdef USE_GLIB1
#undef g_list_delete_link		/* Remaped under -DTRACK_MALLOC */
#undef g_slist_delete_link
GList *
g_list_delete_link(GList *l, GList *lnk)
{
	GList *head;

	head = g_list_remove_link(l, lnk);
	g_list_free_1(lnk);
	return head;
}

GSList *
g_slist_delete_link(GSList *sl, GSList *lnk)
{
	GSList *head;

	head = g_slist_remove_link(sl, lnk);
	g_slist_free_1(lnk);
	return head;
}
#endif /* USE_GLIB1 */

#endif /* !TRACK_MALLOC */

/**
 * Perform the vsnprintf() operation for the gm_vsnprintf() and gm_snprintf()
 * routines. The resulting string will not be larger than (size - 1)
 * and the returned value is always the length of this string. Thus it
 * will not be equal or greater than size either.
 *
 * @param dst The destination buffer to hold the resulting string.
 * @param size The size of the destination buffer.
 * @param fmt The printf-format string.
 * @param args The variable argument list.
 * @return The length of the resulting string.
 */
static inline size_t
buf_vprintf(gchar *dst, size_t size, const gchar *fmt, va_list args)
#ifdef	HAS_VSNPRINTF
{
	gint retval;	/* printf()-functions really return int, not size_t */
	
	g_assert(size > 0);	

	dst[0] = '\0';
	retval = vsnprintf(dst, size, fmt, args);
	if (retval < 0) {
		/* Old versions of vsnprintf() */
		dst[size - 1] = '\0';
		retval = strlen(dst);
	} else if ((size_t) retval >= size) {
		/* New versions (compliant with C99) */
		dst[size - 1] = '\0';
		retval = size - 1;
	}
	return retval;
}
#else	/* !HAS_VSNPRINTF */
{
	gchar *buf;
	size_t len;
  
	g_assert(size > 0);	
	buf	= g_strdup_vprintf(fmt, args);
	len = g_strlcpy(dst, buf, size);
	G_FREE_NULL(buf);
	return MIN((size - 1), len);
}
#endif	/* HAS_VSNPRINTF */

/**
 * This is the smallest common denominator between the g_vsnprintf() from
 * GLib 1.2 and the one from GLib 2.x. The older version has no defined
 * return value, it could be the resulting string length or the size of
 * the buffer minus one required to hold the resulting string. This
 * version always returns the length of the resulting string unlike the
 * vsnprintf() from ISO C99.
 *
 * @note:	The function name might be misleading. You cannot measure
 *			the required buffer size with this!
 *
 * @param dst The destination buffer to hold the resulting string.
 * @param size The size of the destination buffer. It must not exceed INT_MAX.
 * @param fmt The printf-format string.
 * @param args The variable argument list.
 * @return The length of the resulting string.
 */
size_t
gm_vsnprintf(gchar *dst, size_t size, const gchar *fmt, va_list args)
{
	size_t len;

	g_return_val_if_fail(dst != NULL, 0);
	g_return_val_if_fail(fmt != NULL, 0);
	g_return_val_if_fail((ssize_t) size > 0, 0);
	g_return_val_if_fail(size <= (size_t) INT_MAX, 0);

	len = buf_vprintf(dst, size, fmt, args);

	g_assert(len < size);

	return len;
}

/**
 * This is the smallest common denominator between the g_snprintf() from
 * GLib 1.2 and the one from GLib 2.x. The older version has no defined
 * return value, it could be the resulting string length or the size of
 * the buffer minus one required to hold the resulting string. This
 * version always returns the length of the resulting string unlike the
 * snprintf() from ISO C99.
 *
 * @note:	The function name might be misleading. You cannot measure
 *			the required buffer size with this!
 *
 * @param dst The destination buffer to hold the resulting string.
 * @param size The size of the destination buffer. It must not exceed INT_MAX.
 * @param fmt The printf-format string.
 * @return The length of the resulting string.
 */
size_t
gm_snprintf(gchar *dst, size_t size, const gchar *fmt, ...)
{
	va_list args;
	size_t len;

	g_return_val_if_fail(dst != NULL, 0);
	g_return_val_if_fail(fmt != NULL, 0);
	g_return_val_if_fail((ssize_t) size > 0, 0);
	g_return_val_if_fail(size <= (size_t) INT_MAX, 0);

	va_start(args, fmt);
	len = buf_vprintf(dst, size, fmt, args);
	va_end(args);

	g_assert(len < size);

	return len;
}

static gint orig_argc;
static gchar **orig_argv;
static gchar **orig_env;

/**
 * Save the original main() arguments.
 */
void
gm_savemain(gint argc, gchar **argv, gchar **env)
{
	orig_argc = argc;
	orig_argv = argv;
	orig_env = env;
}

/**
 * Change the process title as seen by "ps".
 */
void
gm_setproctitle(const gchar *title)
#if defined(HAS_SETPROCTITLE_WITHOUT_FORMAT)
{
	setproctitle(title)
}
#elif defined(HAS_SETPROCTITLE_WITH_FORMAT)
{
	setproctitle("%s", title)
}
#else /* !HAS_SETPROCTITLE && HAS_SETPROCTITLE_WITH_FORMAT */
{
	static size_t sysarglen = 0;	/* Length of the exec() arguments */
	size_t tlen;
	gint i;

	/*
	 * Compute the length of the exec() arguments that were given to us.
	 */

	if (sysarglen == 0) {
		gchar *s = orig_argv[0];

		s += strlen(s) + 1;			/* Go past trailing NUL */

		/*
		 * Let's see whether all the argv[] arguments were contiguous.
		 */

		for (i = 1; i < orig_argc; i++) {
			if (orig_argv[i] != s)
				break;
			s += strlen(s) + 1;		/* Yes, still contiguous */
		}

		/*
		 * Maybe the environment is contiguous as well...
		 */

		for (i = 0; orig_env[i] != NULL; i++) {
			if (orig_env[i] != s)
				break;
			s += strlen(s) + 1;		/* Yes, still contiguous */
		}

		sysarglen = s - orig_argv[0] - 1;	/* -1 for trailing NUL */

#if 0
		g_message("exec() args used %d contiguous bytes", sysarglen + 1);
#endif
	}

	tlen = strlen(title);

	if (tlen >= sysarglen) {		/* If too large, needs truncation */
		memcpy(orig_argv[0], title, sysarglen);
		(orig_argv[0])[sysarglen] = '\0';
	} else {
		memcpy(orig_argv[0], title, tlen + 1);	/* Copy trailing NUL */
		if (tlen + 1 < sysarglen)
			memset(orig_argv[0] + tlen + 1, ' ', sysarglen - tlen - 1);
	}

	/*
	 * Scrap references to the arguments.
	 */

	for (i = 1; i < orig_argc; i++)
		orig_argv[i] = NULL;
}
#endif /* HAS_SETPROCTITLE_WITHOUT_FORMAT */

#ifdef USE_GLIB1
#undef g_string_append_len		/* Macro when -DTRACK_MALLOC */
/**
 * Appends len bytes of val to string. Because len is provided, val may
 * contain embedded nuls and need not be nul-terminated.
 */
GString *
g_string_append_len(GString *gs, const gchar *val, gssize len)
{
	const gchar *p = val;

	while (len--)
		g_string_append_c(gs, *p++);

	return gs;
}
#endif	/* USE_GLIB1 */

/**
 * Creates a valid and sanitized filename from the supplied string. For most
 * Unix-like platforms anything goes but for security reasons, shell meta
 * characters are replaced by harmless characters.
 *
 * @param filename the suggested filename.
 * @param no_spaces if TRUE, spaces are replaced with underscores.
 * @param no_evil if TRUE, "evil" characters are replaced with underscores.
 *
 * @returns a newly allocated string or ``filename'' if it was a valid filename
 *		    already.
 */
gchar *
gm_sanitize_filename(const gchar *filename,
		gboolean no_spaces, gboolean no_evil)
{
	const gchar *s = filename;
	gchar *q = NULL;

	g_assert(filename);

/** Maximum bytes in filename i.e., including NUL */
#define	FILENAME_MAXBYTES 256

	/* Make sure the filename isn't too long */
	if (strlen(s) >= FILENAME_MAXBYTES) {
		size_t ext_size = 0;
		gchar *ext;

		q = g_malloc(FILENAME_MAXBYTES);

		/* Try to preserve the filename extension */
		ext = strrchr(s, '.');
		if (ext) {
			ext_size = strlen(ext) + 1;	/* Include NUL */
			if (ext_size >= FILENAME_MAXBYTES) {
				/*
				 * If it's too long, assume it's not extension at all.
				 * We must truncate the "extension" anyway and also
				 * preserve the UTF-8 encoding by all means.
				 */
				ext_size = 0;
				ext = NULL;
			}
		}

		g_assert(ext_size < FILENAME_MAXBYTES);
		utf8_strlcpy(q, s, FILENAME_MAXBYTES - ext_size);

		/* Append the filename extension */
		if (ext)
			g_strlcat(q, ext, FILENAME_MAXBYTES);

		g_assert(strlen(q) < FILENAME_MAXBYTES);
		s = q;
	}

	/* Replace shell meta characters and likely problematic characters */
	{
		static const gchar evil[] = "$&*\\`:;()'\"<>?|~\177";
		size_t i;
		guchar c;
		
		for (i = 0; '\0' != (c = s[i]); ++i) {
			if (
				c < 32
				|| is_ascii_cntrl(c)
				|| G_DIR_SEPARATOR == c
				|| '/' == c 
				|| (0 == i && '.' == c)
				|| (no_spaces && is_ascii_space(c))
				|| (no_evil && NULL != strchr(evil, c))
		   ) {
				if (!q)
					q = g_strdup(s);
				q[i] = '_';
			}
		}
	}

	return q ? q : deconstify_gchar(s);
}

/**
 * Frees the GString context but keeps the string data itself and returns
 * it. With Gtk+ 2.x g_string_free(gs, FALSE) would do the job but the
 * variant in Gtk+ 1.2 returns nothing.
 *
 * @return The string data.
 */
gchar *
gm_string_finalize(GString *gs)
{
	gchar *s;

	g_return_val_if_fail(gs, NULL);
	g_return_val_if_fail(gs->str, NULL);
	s = gs->str;
	g_string_free(gs, FALSE);
	return s;
}

/**
 * Detects a loop in a singly-linked list.
 *
 * @return TRUE if the given slist contains a loop; FALSE otherwise.
 */
gboolean
gm_slist_is_looping(const GSList *slist)
{
	const GSList *sl, *p;

	p = slist;
	sl = slist;
	for (sl = slist; /* NOTHING */; sl = g_slist_next(sl)) {
		p = g_slist_next(g_slist_next(p));
		if (p == sl || p == g_slist_next(sl)) {
			break;
		}
	}

	return NULL != p;
}

/* vi: set ts=4 sw=4 cindent: */
