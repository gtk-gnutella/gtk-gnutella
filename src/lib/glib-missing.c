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
 * Allocates an array of "struct iov" elements.
 * @param n The desired array length in elements.
 */
static inline struct iovec *
iov_alloc_n(size_t n)
{
	struct iovec *iov;

	if (n > (size_t) -1 / sizeof *iov) {
		g_assert_not_reached(); /* We don't want to handle failed allocations */
		return NULL;
	}
	iov = g_malloc(n * sizeof *iov);
	return iov;
}

static inline struct iovec
iov_get(gpointer base, size_t size)
{
	static const struct iovec zero_iov;
	struct iovec iov;

	iov = zero_iov;
	iov.iov_base = base;
	iov.iov_len = size;
	return iov;
}

/**
 * Resets an array of "struct iov" elements, so that iov_base is NULL
 * and iov_len is 0 for each element.
 *
 * @param iov The array base.
 * @param n The array length in elements.
 */
static inline void
iov_reset_n(struct iovec *iov, size_t n)
{
	size_t i;

	g_assert(iov);
	for (i = 0; i < n; i++) {
		static const struct iovec zero_iov;
		iov[i] = zero_iov;
	}
}

/**
 * Initializes the elements of an struct iovec array from an array of strings.
 * iov_len is set to string length plus one to include the trailing NUL.
 *
 * @param iov An array of writable initialized memory buffers.
 * @param iov_cnt The array length of iov.
 * @param src The source buffer to copy.
 * @param size The amount of bytes to copy from "src".
 * @return The amount of elements initialized. Thus, MIN(iov_cnt, argc).
 */
static inline size_t 
iov_init_from_string_vector(struct iovec *iov, size_t iov_cnt,
	gchar *argv[], size_t argc)
{
	size_t i, n;

	g_assert(iov);
	g_assert(iov_cnt >= argc);
	g_assert(argv);

	n = MIN(iov_cnt, argc);
	for (i = 0; i < n; i++) {
		iov[i].iov_base = argv[i];
		iov[i].iov_len = argv[i] ? (1 + strlen(argv[i])) : 0;
	}
	return n;
}

/**
 * Checks whether two given struct iovec point to contiguous memory.
 *
 * @return TRUE if b->iov_base directly follows after &a->iov_base[a->iov_len].
 */
static inline gboolean
iov_is_contiguous(const struct iovec * const a, const struct iovec * const b)
{
	g_assert(a);
	g_assert(b);

	return (size_t) a->iov_base + a->iov_len == (size_t) b->iov_base;
}

/**
 * Returns the size of contiguous memory buffers.
 *
 * @param iov An array of initialized memory buffers.
 * @param iov_cnt The array length of iov.
 * @return The amount contiguous bytes.
 */
static inline size_t 
iov_contiguous_size(const struct iovec *iov, size_t iov_cnt)
{
	struct iovec iov0;
	size_t i;

	g_assert(iov);

	iov0 = iov[0];

	for (i = 1; i < iov_cnt && iov_is_contiguous(&iov0, &iov[i]); i++) {
		size_t n = iov[i].iov_len;

		if (n >= (size_t) -1 - iov0.iov_len) {
			/* Abort if size would overflow */
			iov0.iov_len = (size_t) -1;
			break;
		}
		iov0.iov_len += n;
	}
	return iov0.iov_len;
}

/**
 * Clear all bytes in the buffer starting at the given offset. If the
 * offset is beyond iov->iov_len, nothing happens.
 *
 * @param iov An initialized struct iovec.
 * @param byte_offset The offset relative to iov->iov_base.
 */
static inline void
iov_clear(struct iovec *iov, size_t byte_offset)
{
	g_assert(iov);
	
	if (byte_offset < iov->iov_len) {
		gchar *p = iov->iov_base;
		memset(&p[byte_offset], 0, iov->iov_len - byte_offset);
	}
}

/**
 * Calculates the cumulative size of the memory buffers. This uses
 * saturation arithmetic, so the returned value can never overflow.
 *
 * @param iov An array of initialized memory buffers.
 * @param iov_cnt The array length of iov.
 * @return The sum of all buffer sizes.
 */
static inline size_t
iov_calculate_size(struct iovec *iov, size_t iov_cnt)
{
	size_t size = 0;
	size_t i;

	g_assert(iov);

	for (i = 0; i < iov_cnt; i++) {
		size_t n = iov[i].iov_len;

		if (n >= (size_t) -1 - size) {
			/* Abort if size would overflow */
			size = (size_t) -1;
			break;
		}
		size += n;
	}
	return size;
}

/**
 * Scatters a NUL-terminated string over an array of struct iovec buffers. The
 * trailing buffer space is zero-filled. If the string is too long, it is
 * truncated, so that there is a terminating NUL in any case, except if the
 * buffer space is zero.
 *
 * @param iov An array of initialized memory buffers.
 * @param iov_cnt The array length of iov.
 * @return The amount of bytes copied excluding the terminating NUL.
 */
static inline size_t
iov_scatter_string(struct iovec *iov, size_t iov_cnt, const gchar *s)
{
	size_t i, len, avail, size;

	g_assert(iov);
	g_assert(s);

	/* Reserve one byte for the trailing NUL */
	size = iov_calculate_size(iov, iov_cnt);
	len = strlen(s);
	if (len >= size) {
		len = size > 0 ? (size - 1) : 0;
	}
	avail = len;

	for (i = 0; i < iov_cnt; i++) {
		size_t n;

		n = MIN(iov[i].iov_len, avail);
		memmove(iov[i].iov_base, s, n);
		avail -= n;
		s += n;
		if (0 == avail) {
			iov_clear(&iov[i], n);
			i++;
			break;
		}
	}
	while (i < iov_cnt) {
		iov_clear(&iov[i], 0);
		i++;
	}
	return len;
}

static inline size_t
str_vec_count(gchar *strv[])
{
	size_t i = 0;

	while (strv[i]) {
		i++;
	}
	return i;
}

#if !defined(HAS_SETPROCTITLE)
/**
 * Compute the length of the exec() arguments that were given to us.
 *
 * @param argc The original ``argc'' argument from main().
 * @param argv The original ``argv'' argument from main().
 * @param env_ptr The original ``env'' variable.
 */
static struct iovec
gm_setproctitle_init(gint argc, gchar *argv[], gchar *env_ptr[])
{
	size_t env_count, n;
	struct iovec *iov;

	g_assert(argc > 0);
	g_assert(argv);
	g_assert(env_ptr);

	env_count = str_vec_count(env_ptr);
	n = argc + env_count;
	iov = iov_alloc_n(n);

	iov_reset_n(iov, n);

	iov_init_from_string_vector(&iov[0], n, argv, argc);
	iov_init_from_string_vector(&iov[argc], n - argc, env_ptr, env_count);

	/*
	 * Let's see how many argv[] arguments were contiguous.
	 */
	{
		size_t size;
		
		size = iov_contiguous_size(iov, n);
		g_message("%lu bytes available for gm_setproctitle().", (gulong) size);
	}

	/*
	 * Scrap references to the arguments.
	 */
	{
		gint i;

		for (i = 1; i < argc; i++)
			argv[i] = NULL;
	}
	
	
	return iov_get(iov, n);
}
#endif /* !HAS_SETPROCTITLE */

/**
 * Change the process title as seen by "ps".
 */
void
gm_setproctitle(const gchar *title)
#if defined(HAS_SETPROCTITLE)
{
	setproctitle("%s", title);
}
#else /* !HAS_SETPROCTITLE */
{
	static struct iovec *args;
	static size_t n;

	if (!args) {
		struct iovec iov;
		
		iov = gm_setproctitle_init(orig_argc, orig_argv, orig_env);
		args = iov.iov_base;
		n = iov.iov_len;
	}

	/* Scatter the title over the argv[] and env[] elements */
	iov_scatter_string(args, n, title);
}
#endif /* HAS_SETPROCTITLE */

/**
 * Return the process title as seen by "ps"
 */
const gchar *
gm_getproctitle(void)
{
	return orig_argv[0];
}

#ifdef USE_GLIB1
#undef g_string_append_len		/* Macro when -DTRACK_MALLOC */
#undef g_string_append_c		/* Macro when -DTRACK_MALLOC */
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
