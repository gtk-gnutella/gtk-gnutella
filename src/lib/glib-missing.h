/*
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

#ifndef _glib_missing_h_
#define _glib_missing_h_

#include "common.h"
#include "stacktrace.h"		/* For stacktrace_where_sym_print() */

/* Suppress warnings when GCC is in -pedantic mode and not -std=c99 */
#if (__GNUC__ >= 3 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 96))
#pragma GCC system_header
#endif

#ifdef USE_GLIB1
typedef bool (*GEqualFunc)(const void *a, const void *b);

typedef struct GMemVTable {
	void *		(*malloc)		(gsize n_bytes);
	void *		(*realloc)		(void *mem, gsize n_bytes);
	void		(*free)			(void *mem);
	/* optional */
	void *		(*calloc)		(gsize n_blocks, gsize n_block_bytes);
	void *		(*try_malloc)	(gsize n_bytes);
	void *		(*try_realloc)	(void *mem, gsize n_bytes);
} GMemVTable;
#endif

/*
 * Public interface.
 */

void gm_mem_set_safe_vtable(void);

bool gm_slist_is_looping(const GSList *slist);
GSList *gm_slist_insert_after(GSList *list, GSList *lnk, void *data);

GList *gm_list_insert_after(GList *list, GList *lnk, void *data);

#ifdef USE_GLIB1
GList *g_list_delete_link(GList *l, GList *lnk);
GSList *g_slist_delete_link(GSList *sl, GSList *lnk);
GList *g_list_insert_before(GList *l, GList *lk, void *data);

void g_hash_table_replace(GHashTable *ht, void *key, void *value);
bool gm_hash_table_remove(GHashTable *ht, const void *key);

void g_mem_set_vtable(GMemVTable *vtable);
bool g_mem_is_system_malloc(void);

typedef int (*GCompareDataFunc)
	(const void *a, const void *b, void *user_data);

GList *g_list_sort_with_data(
	GList *l, GCompareDataFunc cmp, void *user_data);

typedef void *GMainContext;

GPollFunc g_main_context_get_poll_func(GMainContext *context);
void g_main_context_set_poll_func(GMainContext *context, GPollFunc func);
#endif	/* USE_GLIB1 */

#ifdef USE_GLIB2
#define gm_hash_table_remove	g_hash_table_remove
#endif

/**
 * Needs to be defined if we are not using Glib 2
 */
#ifndef USE_GLIB2

/*
 * (Copied from BSD man pages)
 *
 * NAME
 *
 *   strlcpy, strlcat -- size-bounded string copying and concatenation
 *
 * DESCRIPTION
 *
 *   The strlcpy() and strlcat() functions copy and concatenate strings
 *   respectively.  They are designed to be safer, more consistent, and less
 *   error prone replacements for strncpy(3) and strncat(3).  Unlike those
 *   functions, strlcpy() and strlcat() take the full size of the buffer (not
 *   just the length) and guarantee to NUL-terminate the result (as long as
 *   size is larger than 0 or, in the case of strlcat(), as long as there is
 *   at least one byte free in dst).  Note that a byte for the NUL should be
 *   included in size.  Also note that strlcpy() and strlcat() only operate on
 *   true ``C'' strings.  This means that for strlcpy() src must be NUL-termi-
 *   nated and for strlcat() both src and dst must be NUL-terminated.
 * 
 *   The strlcpy() function copies up to size - 1 characters from the NUL-ter-
 *   minated string src to dst, NUL-terminating the result.
 * 
 *   The strlcat() function appends the NUL-terminated string src to the end
 *   of dst.  It will append at most size - strlen(dst) - 1 bytes, NUL-termi-
 *   nating the result.
 * 
 *   The source and destination strings should not overlap, as the behavior is
 *   undefined.
 *
 * RETURN VALUES
 *
 *   The strlcpy() and strlcat() functions return the total length of the
 *   string they tried to create.  For strlcpy() that means the length of src.
 *   For strlcat() that means the initial length of dst plus the length of
 *   src.  While this may seem somewhat confusing, it was done to make trunca-
 *   tion detection simple.
 *
 *   Note however, that if strlcat() traverses size characters without finding
 *   a NUL, the length of the string is considered to be size and the destina-
 *   tion string will not be NUL-terminated (since there was no space for the
 *   NUL).  This keeps strlcat() from running off the end of a string.  In
 *   practice this should not happen (as it means that either size is incor-
 *   rect or that dst is not a proper ``C'' string).  The check exists to pre-
 *   vent potential security problems in incorrect code.
 */

#ifndef HAS_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t dst_size);
#endif /* HAS_STRLCPY */

#ifndef HAS_STRLCAT
size_t strlcat(char *dst, const char *src, size_t dst_size);
#endif /* HAS_STRLCAT */

#define g_strlcpy strlcpy
#define g_strlcat strlcat
#endif

void gm_slist_free_null(GSList **sl_ptr);
void gm_list_free_null(GList **l_ptr);
void gm_hash_table_destroy_null(GHashTable **h_ptr);

size_t gm_vsnprintf(char *str, size_t n, char const *fmt, va_list args);
size_t gm_snprintf(char *str, size_t n,
	char const *fmt, ...) G_GNUC_PRINTF(3, 4);
size_t gm_snprintf_unchecked(char *dst, size_t size,
	const char *fmt, ...); /* No G_GNUC_PRINTF here, on purpose! */

void gm_savemain(int argc, char **argv, char **env);
int gm_dupmain(const char ***argv_ptr, const char ***env_ptr);
const char *gm_getproctitle(void);
void gm_setproctitle(const char *title);

static inline bool
gm_hash_table_contains(GHashTable *ht, const void *key)
{
	return g_hash_table_lookup_extended(ht, key, NULL, NULL);
}

static inline void
gm_hash_table_insert_const(GHashTable *ht,
	const void *key, const void *value)
{
	g_hash_table_insert(ht, deconstify_pointer(key), deconstify_pointer(value));
}

static inline void
gm_hash_table_replace_const(GHashTable *ht,
	const void *key, const void *value)
{
	g_hash_table_replace(ht,
		deconstify_pointer(key), deconstify_pointer(value));
}

GSList *gm_hash_table_all_keys(GHashTable *ht);
void gm_hash_table_foreach_key(GHashTable *ht, GFunc func, void *user_data);

static inline GSList *
gm_slist_prepend_const(GSList *sl, const void *value)
{
	return g_slist_prepend(sl, deconstify_pointer(value));
}

/*
 * The G_*LIST_FOREACH_* macros are supposed to be used with ``func'' being
 * a function declared ``static inline'' whereas the protoype MUST match
 * ``GFunc''. ``func'' is not assigned to a variable so that the compiler
 * can prevent any function call overhead along with ``inline''.
 * These macros were rejected by the GLib maintainers so we can safely use
 * the G_ prefix.
 */

/* NB: Sub-statement func is evaluated more than once! */
#define G_LIST_FOREACH(list, func) \
	G_STMT_START { \
		GList *l_ = (list); \
		while (NULL != l_) { \
			func(l_->data); \
			l_ = g_list_next(l_); \
		} \
	} G_STMT_END

#define G_LIST_FOREACH_WITH_DATA(list, func, user_data) \
	G_STMT_START { \
		GList *l_ = (list); \
		void *user_data_ = (user_data); \
		while (NULL != l_) { \
			func(l_->data, user_data_); \
			l_ = g_list_next(l_); \
		} \
	} G_STMT_END

#define G_LIST_FOREACH_SWAPPED(list, func, user_data) \
	G_STMT_START { \
		GList *l_ = (list); \
		void *user_data_ = (user_data); \
		while (NULL != l_) { \
			func(user_data_, l_->data); \
			l_ = g_list_next(l_); \
		} \
	} G_STMT_END

/* NB: Sub-statement func is evaluated more than once! */
#define G_SLIST_FOREACH(slist, func) \
	G_STMT_START { \
		GSList *sl_ = (slist); \
		while (NULL != sl_) { \
			func(sl_->data); \
			sl_ = g_slist_next(sl_); \
		} \
	} G_STMT_END

/* NB: Sub-statement func is evaluated more than once! */
#define G_SLIST_FOREACH_WITH_DATA(slist, func, user_data) \
	G_STMT_START { \
		GSList *sl_ = (slist); \
		void *user_data_ = (user_data); \
		while (NULL != sl_) { \
			func(sl_->data, user_data_); \
			sl_ = g_slist_next(sl_); \
		} \
	} G_STMT_END


/* NB: Sub-statement func is evaluated more than once! */
#define G_SLIST_FOREACH_SWAPPED(slist, func, user_data) \
	G_STMT_START { \
		GSList *sl_ = (slist); \
		void *user_data_ = (user_data); \
		while (NULL != sl_) { \
			func(user_data_, sl_->data); \
			sl_ = g_slist_next(sl_); \
		} \
	} while(0)

#define GM_SLIST_FOREACH(slist, iter) \
	for ((iter) = (slist); NULL != (iter); (iter) = g_slist_next(iter))

#define GM_LIST_FOREACH(list, iter) \
	for ((iter) = (list); NULL != (iter); (iter) = g_list_next(iter))

#endif	/* _glib_missing_h_ */
/* vi: set ts=4 sw=4: */
