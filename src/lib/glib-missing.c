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

RCSID("$Id$")

#include "glib-missing.h"
#include "ascii.h"
#include "iovec.h"
#include "misc.h"
#include "utf8.h"

#include "override.h"		/* Must be the last header included */

#if defined(USE_GLIB1) && \
	(defined(USE_HALLOC) || defined(TRACK_MALLOC) || defined(TRACK_ZALLOC) || \
		defined(REMAP_ZALLOC))

static GMemVTable gm_vtable;

#define GM_VTABLE_METHOD(method, params) \
	(gm_vtable.gmvt_ ## method \
	 ? (gm_vtable.gmvt_ ## method params) \
	 : (method params))

#undef malloc
static inline ALWAYS_INLINE gpointer
gm_malloc(gulong size)
{
	return GM_VTABLE_METHOD(malloc, (size));
}

#undef calloc
static inline ALWAYS_INLINE gpointer
gm_malloc0(gulong size)
{
	return GM_VTABLE_METHOD(calloc, (1, size));
}

#undef realloc
static inline ALWAYS_INLINE gpointer
gm_realloc(gpointer p, gulong size)
{
	return GM_VTABLE_METHOD(realloc, (p, size));
}

#undef free
static inline ALWAYS_INLINE void
gm_free(gpointer p)
{
	return GM_VTABLE_METHOD(free, (p));
}

#define try_malloc malloc
static inline ALWAYS_INLINE gpointer
gm_try_malloc(gulong size)
{
	return GM_VTABLE_METHOD(try_malloc, (size));
}
#undef try_malloc

#define try_realloc realloc
static inline ALWAYS_INLINE gpointer
gm_try_realloc(gpointer p, gulong size)
{
	return GM_VTABLE_METHOD(try_realloc, (p, size));
}
#undef try_realloc

/***
 *** Remap g_malloc() and friends to be able to emulate g_mem_set_vtable()
 *** with GTK1.  Fortunately, glib1.x placed the allocation routines in
 *** a dedicated mem.o file, so we may safely redefine them here.
 ***
 *** NOTE: This a hack and does not work on some platforms.
 ***/

#undef g_malloc
gpointer
g_malloc(gulong size)
{
	gpointer p;

	if (size == 0)
		return NULL;

	p = gm_malloc(size);

	if (p)
		return p;

	g_error("allocation of %lu bytes failed", size);
	return NULL;
}

#undef g_malloc0
gpointer
g_malloc0(gulong size)
{
	gpointer p;

	if (size == 0)
		return NULL;

	p = gm_malloc(size);

	if (p) {
		memset(p, 0, size);
		return p;
	}

	g_error("allocation of %lu bytes failed", size);
	return NULL;
}

#undef g_realloc
gpointer
g_realloc(gpointer p, gulong size)
{
	gpointer n;

	if (size == 0) {
		gm_free(p);
		return NULL;
	}

	n = gm_realloc(p, size);

	if (n)
		return n;

	g_error("re-allocation of %lu bytes failed", size);
	return NULL;
}

#undef g_free
void
g_free(gpointer p)
{
	gm_free(p);
}

#undef g_try_malloc
gpointer
g_try_malloc(gulong size)
{
	return size > 0 ? gm_try_malloc(size) : NULL;
}

#undef g_try_realloc
gpointer
g_try_realloc(gpointer p, gulong size)
{
	return size > 0 ? gm_try_realloc(p, size) : NULL;
}

/**
 * Emulates a calloc().
 */
static gpointer
emulate_calloc(gsize n, gsize m)
{
	gpointer p;

	if (n > 0 && m > 0 && m < ((size_t) -1) / n) {
		size_t size = n * m;
		p = gm_malloc(size);
		memset(p, 0, size);
	} else {
		p = NULL;
	}
	return p;
}

/**
 * Sets the GMemVTable to use for memory allocation.
 * This function must be called before using any other GLib functions.
 *
 * The vtable only needs to provide malloc(), realloc(), and free() functions;
 * GLib can provide default implementations of the others.
 * The malloc() and realloc() implementations should return NULL on failure, 
 */
void
g_mem_set_vtable(GMemVTable *vtable)
{
	gm_vtable.gmvt_malloc = vtable->gmvt_malloc;
	gm_vtable.gmvt_realloc = vtable->gmvt_realloc;
	gm_vtable.gmvt_free = vtable->gmvt_free;

	gm_vtable.gmvt_calloc = vtable->gmvt_calloc
		? vtable->gmvt_calloc
		: emulate_calloc;
	gm_vtable.gmvt_try_malloc = vtable->gmvt_try_malloc
		? vtable->gmvt_try_malloc
		: vtable->gmvt_malloc;
	gm_vtable.gmvt_try_realloc = vtable->gmvt_try_realloc
		? vtable->gmvt_try_realloc
		: vtable->gmvt_realloc;
}

/**
 * Are we using system's malloc?
 */
gboolean
g_mem_is_system_malloc(void)
{
	return NULL == gm_vtable.gmvt_malloc ||
		cast_pointer_to_func(gm_vtable.gmvt_malloc) ==
			cast_pointer_to_func(real_malloc) ||
		cast_pointer_to_func(gm_vtable.gmvt_malloc) ==
			cast_pointer_to_func(malloc);
}
#endif	/* USE_GLIB1 */

/**
 * Safe reallocation routine during final memory cleanup.
 */
static void *
safe_realloc(void *p, size_t len)
{
	if (NULL == p) {
		return malloc(len);
	} else if (0 == len) {
		/* NOTHING */
	} else {
		g_error("no realloc() allowed during final memory cleanup");
	}

	return NULL;
}

/**
 * Safe free routine during final memory cleanup.
 */
static void
safe_free(void *unused_p)
{
	(void) unused_p;
	/* NOTHING */
}

/**
 * Install safe memory vtable for final memory cleanup.
 *
 * When the memory vtable has been customized, redirecting g_malloc() to
 * some other routine like halloc(), we can't easily perform final shutdown
 * of the zalloc() and walloc() memory allocators because any call to
 * log something still present could allocate memory and reenter code that
 * is using the data structures being cleaned up.
 *
 * At this time though, we don't really care about freeing allocated memory
 * since we're about to exit, but we want to be able to allocate new one
 * safely.
 */
void
gm_mem_set_safe_vtable(void)
{
	static GMemVTable vtable;

#if defined(USE_HALLOC) || defined(TRACK_MALLOC) || defined(TRACK_ZALLOC) || \
		defined(REMAP_ZALLOC)

	if (g_mem_is_system_malloc())
		return;

#if GLIB_CHECK_VERSION(2,0,0)
	vtable.malloc = real_malloc;
	vtable.realloc = safe_realloc;
	vtable.free = safe_free;
#else	/* GLib < 2.0.0 */
	vtable.gmvt_malloc = real_malloc;
	vtable.gmvt_realloc = safe_realloc;
	vtable.gmvt_free = safe_free;
#endif	/* GLib >= 2.0.0 */

	g_mem_set_vtable(&vtable);

#endif	/* USE_HALLOC || TRACK_MALLOC || TRACK_ZALLOC || REMAP_ZALLOC */
}

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
#undef g_list_insert_before
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

GList *
g_list_insert_before(GList *l, GList *lk, gpointer data)
{
	GList *new;

	if (lk == NULL)
		return g_list_append(l, data);

	new = g_list_alloc();
	new->data = data;

	new->next = lk;
	new->prev = lk->prev;

	if (lk->prev)
		lk->prev->next = new;

	lk->prev = new;

	return lk == l ? new : l;
}
#endif /* USE_GLIB1 */
#endif	/* !TRACK_MALLOC */

#ifdef USE_GLIB1
void
g_hash_table_replace(GHashTable *ht, gpointer key, gpointer value)
{
	g_hash_table_remove(ht, key);
	g_hash_table_insert(ht, key, value);
}

gboolean
gm_hash_table_remove(GHashTable *ht, gconstpointer key)
{
	/* In glib 1.x, g_hash_table_remove() does not return anything */

	if (g_hash_table_lookup(ht, key)) {
		g_hash_table_remove(ht, key);
		return TRUE;
	}

	return FALSE;
}
#endif	/* USE_GLIB1 */

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
buf_vprintf(char *dst, size_t size, const char *fmt, va_list args)
#ifdef	HAS_VSNPRINTF
{
	int retval;	/* printf()-functions really return int, not size_t */
	
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
	char *buf;
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
gm_vsnprintf(char *dst, size_t size, const char *fmt, va_list args)
{
	size_t len;

	g_return_val_if_fail(dst != NULL, 0);
	g_return_val_if_fail(fmt != NULL, 0);
	g_return_val_if_fail(size_is_positive(size), 0);
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
gm_snprintf(char *dst, size_t size, const char *fmt, ...)
{
	va_list args;
	size_t len;

	g_return_val_if_fail(dst != NULL, 0);
	g_return_val_if_fail(fmt != NULL, 0);
	g_return_val_if_fail(size_is_positive(size), 0);
	g_return_val_if_fail(size <= (size_t) INT_MAX, 0);

	va_start(args, fmt);
	len = buf_vprintf(dst, size, fmt, args);
	va_end(args);

	g_assert(len < size);

	return len;
}

static int orig_argc;
static char **orig_argv;
static char **orig_env;

/**
 * Save the original main() arguments.
 */
void
gm_savemain(int argc, char **argv, char **env)
{
	orig_argc = argc;
	orig_argv = argv;
	orig_env = env;
}

static inline size_t
str_vec_count(char *strv[])
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
gm_setproctitle_init(int argc, char *argv[], char *env_ptr[])
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
		int i;

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
gm_setproctitle(const char *title)
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
		args = cast_to_gpointer(iov.iov_base); /* Solaris has caddr_t */
		n = iov.iov_len;
	}

	/* Scatter the title over the argv[] and env[] elements */
	iov_scatter_string(args, n, title);
}
#endif /* HAS_SETPROCTITLE */

/**
 * Return the process title as seen by "ps"
 */
const char *
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
g_string_append_len(GString *gs, const char *val, gssize len)
{
	const char *p = val;

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
char *
gm_sanitize_filename(const char *filename,
		gboolean no_spaces, gboolean no_evil)
{
	const char *s;
	char *q;

	g_assert(filename);

	/* Make sure the filename isn't too long */
	if (strlen(filename) >= FILENAME_MAXBYTES) {
		q = g_malloc(FILENAME_MAXBYTES);
		filename_shrink(filename, q, FILENAME_MAXBYTES);
		s = q;
	} else {
		s = filename;
		q = NULL;
	}

	/* Replace shell meta characters and likely problematic characters */
	{
		static const char evil[] = "$&*\\`:;()'\"<>?|~\177";
		size_t i;
		guchar c;
		
		for (i = 0; '\0' != (c = s[i]); i++) {
			if (
				c < 32
				|| is_ascii_cntrl(c)
				|| G_DIR_SEPARATOR == c
				|| '/' == c 
				|| (0 == i && ('.' == c || '-' == c))
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
 * Make filename prettier, by removing leading "_", making sure the filename
 * does not start with "-" or ".", and stripping consecutive "_" or "_" that
 * surround a punctuation character.
 *
 * Finally, ensure the filename is not completely empty, as this is
 * awkward to manipulate from a shell.
 *
 * @param filename	the filename to beautify
 *
 * @returns a newly allocated string holding the beautified filename, even if
 * it is a mere copy of the original.
 */
char *
gm_beautify_filename(const char *filename)
{
	const char *s;
	char *q;
	guchar c;
	size_t len;
	size_t j = 0;
	static const char punct[] = "_-+=.,<>{}[]";	/* 1st MUST be '_' */
	static const char strip[] = "_-.";
	static const char empty[] = "{empty}";

	g_assert(filename);

	s = filename;
	len = strlen(filename);
	q = g_malloc(len + 1);		/* Trailing NUL */

	while ((c = *s++)) {
		guchar d;

		/* Beautified filename cannot start with stripped characters */
		if (j == 0) {
			if (NULL == strchr(strip, c))
				q[j++] = c;
			continue;
		}

		g_assert(j > 0);

		d = q[j - 1];		/* Last char we've kept in beautified name */

		/* A "_" followed by a punctuation character, strip the "_" */
		if (d == '_' && NULL != strchr(punct, c)) {
			q[j - 1] = c;
			continue;
		}

		/* A punctuation character followed by "_", ignore that "_" */
		if (NULL != strchr(&punct[1], d) && c == '_')
			continue;

		q[j++] = c;
	}

	g_assert(j <= len);
	q[j] = '\0';

	/* Ensure we have no empty name */
	if (j == 0) {
		G_FREE_NULL(q);
		return g_strdup(empty);
	}

	/*
	 * If there was an extension following stripped chars (e.g. "_.ext"),
	 * then the filename kept will become "ext" (we assume a valid extension
	 * cannot contain "escaped" chars).  In which case we will prepend the
	 * string "{empty}." to it.
	 */

	if (NULL == strchr(q, '.') && j < len && '.' == filename[len - j]) {
		char *r = g_strconcat(empty, ".", q, (void *) 0);
		G_FREE_NULL(q);

		return r;
	}

	return q;
}

/**
 * Frees the GString context but keeps the string data itself and returns
 * it. With Gtk+ 2.x g_string_free(gs, FALSE) would do the job but the
 * variant in Gtk+ 1.2 returns nothing.
 *
 * @return The string data.
 */
char *
gm_string_finalize(GString *gs)
{
	char *s;

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

static void
gm_hash_table_all_keys_helper(gpointer key,
	gpointer unused_value, gpointer udata)
{
	GSList **sl_ptr = udata;
	
	(void) unused_value;
	*sl_ptr = g_slist_prepend(*sl_ptr, key);
}

/**
 * @return list of all the hash table keys.
 */
GSList *
gm_hash_table_all_keys(GHashTable *ht)
{
	GSList *keys = NULL;
	g_hash_table_foreach(ht, gm_hash_table_all_keys_helper, &keys);
	return keys;
}

struct gm_hash_table_foreach_keys_helper {
	GFunc func;			/* Function to call on each key */
	gpointer udata;		/* Original user data */
};

static void
gm_hash_table_foreach_keys_helper(gpointer key,
	gpointer unused_value, gpointer udata)
{
	struct gm_hash_table_foreach_keys_helper *hp = udata;
	
	(void) unused_value;
	(*hp->func)(key, hp->udata);
}


/**
 * Apply function to all the keys of the hash table.
 */
void
gm_hash_table_foreach_key(GHashTable *ht, GFunc func, gpointer user_data)
{
	struct gm_hash_table_foreach_keys_helper hp;

	hp.func = func;
	hp.udata = user_data;

	g_hash_table_foreach(ht, gm_hash_table_foreach_keys_helper, &hp);
}

#ifdef USE_GLIB1
/*
 * glib1 is missing g_list_sort_with_data().
 *
 * The following (adapted) code is:
 *
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 *
 * and was taken out of the glist.c file from glib 2.16.
 */

/**
 * Internal merging sort for g_list_sort_with_data().
 */
static GList *
g_list_sort_merge(
	GList *l1, GList *l2, GCompareDataFunc compare_func, gpointer user_data)
{
	GList list, *l, *lprev;

	l = &list; 
	lprev = NULL;

	while (l1 && l2) {
		int cmp = (*compare_func)(l1->data, l2->data, user_data);

		if (cmp <= 0) {
			l->next = l1;
			l1 = l1->next;
		} else {
			l->next = l2;
			l2 = l2->next;
		}
		l = l->next;
		l->prev = lprev; 
		lprev = l;
	}
	l->next = l1 ? l1 : l2;
	l->next->prev = l;

	return list.next;
}

/**
 * Like g_list_sort(), but the comparison function takes a user data argument.
 *
 * @return the new head of list
 */
GList *
g_list_sort_with_data(
	GList *list, GCompareDataFunc compare_func, gpointer user_data)
{
	GList *l1, *l2;
  
	if (!list) 
		return NULL;
	if (!list->next) 
		return list;
  
	l1 = list; 
	l2 = list->next;

	while ((l2 = l2->next)) {
		if (NULL == (l2 = l2->next)) 
			break;
		l1 = l1->next;
	}
	l2 = l1->next; 
	l1->next = NULL; 

	return g_list_sort_merge(
		g_list_sort_with_data(list, compare_func, user_data),
		g_list_sort_with_data(l2, compare_func, user_data),
		compare_func, user_data);
}
#endif	/* USE_GLIB1 */

/* vi: set ts=4 sw=4 cindent: */
