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
 * Needs brief description here.
 *
 * Debugging malloc, to supplant dmalloc which is not satisfactory for
 * leak detection.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _malloc_h_
#define _malloc_h_

/*
 * WARNING: this file must included AFTER all other include files since
 * it redefines commonly used routines as macros, and that would generate
 * a syntax error when including a file declaring them as function....
 */

/*
 * Under TRACK_MALLOC, we keep track of the allocation places.
 */

#if defined(USE_DMALLOC) && defined(TRACK_MALLOC)
#error "TRACK_MALLOC and USE_DMALLOC are mutually exclusive"
#endif

#ifdef MALLOC_STATS
#ifndef TRACK_MALLOC
#define TRACK_MALLOC
#endif
#endif

#if defined(TRACK_MALLOC) && !defined(MALLOC_SOURCE)

#include "hashlist.h"

#undef strdup			/**< Defined in <bits/string2.h> */

#define malloc(s)		malloc_track((s), _WHERE_, __LINE__)
#define calloc(n,s)		malloc0_track((n)*(s), _WHERE_, __LINE__)
#define free(o)			free_track(o, _WHERE_, __LINE__)
#define realloc(o,s)	realloc_track(o, (s), _WHERE_, __LINE__)
#define strdup(s)		strdup_track((s), _WHERE_, __LINE__)
#define strndup(s,n)	strndup_track((s), (n), _WHERE_, __LINE__)

#define g_malloc(s)		malloc_track((s), _WHERE_, __LINE__)
#define g_malloc0(s)	malloc0_track((s), _WHERE_, __LINE__)
#define g_free(o)		free_track(o, _WHERE_, __LINE__)
#define g_realloc(o,s)	realloc_track(o, (s), _WHERE_, __LINE__)
#define g_strdup(s)		((s) ? strdup_track(s, _WHERE_, __LINE__) : 0)
#define g_strndup(s,n)	((s) ? strndup_track(s, (n), _WHERE_, __LINE__) : 0)
#define g_strjoinv(s,v)	strjoinv_track(s, (v), _WHERE_, __LINE__)
#define g_memdup(p,s)	((p) ? memdup_track((p), (s), _WHERE_, __LINE__) : 0)
#define g_strfreev(v)	strfreev_track((v), _WHERE_, __LINE__)

#undef g_new
#undef g_new0
#undef g_renew

#define g_new(t,c)		(t*) malloc_track(sizeof(t)*(c), _WHERE_, __LINE__)
#define g_new0(t,c)		(t*) malloc0_track(sizeof(t)*(c), _WHERE_, __LINE__)
#define g_renew(t,m,c)	(t*) realloc_track((m),sizeof(t)*(c),_WHERE_,__LINE__)

#define g_strconcat(s, ...) \
	strconcat_track(_WHERE_, __LINE__, s, __VA_ARGS__)

#define g_strdup_printf(fmt, ...) \
	strdup_printf_track(_WHERE_, __LINE__, fmt, __VA_ARGS__)

#define g_strsplit(s,d,m)		strsplit_track((s),(d),(m), _WHERE_, __LINE__)

#define g_hash_table_new(x,y)	hashtable_new_track(x, y, _WHERE_, __LINE__)
#define g_hash_table_destroy(x)	hashtable_destroy_track(x, _WHERE_, __LINE__)

#define hash_list_new_(h,c)		hash_list_new_track((h),(c),_WHERE_, __LINE__)
#define hash_list_free(h)		hash_list_free_track((h), _WHERE_, __LINE__)

#define g_slist_alloc()			track_slist_alloc(_WHERE_, __LINE__)
#define g_slist_append(l,d)		track_slist_append((l),(d), _WHERE_, __LINE__)
#define g_slist_prepend(l,d)	track_slist_prepend((l),(d), _WHERE_, __LINE__)
#define g_slist_copy(l)			track_slist_copy((l), _WHERE_, __LINE__)
#define g_slist_free(l)			track_slist_free((l), _WHERE_, __LINE__)
#define g_slist_free_1(l)		track_slist_free1((l), _WHERE_, __LINE__)
#define g_slist_remove(l,d)		track_slist_remove((l),(d), _WHERE_, __LINE__)

#define g_slist_insert(l,d,p) \
	track_slist_insert((l),(d),(p), _WHERE_, __LINE__)
#define g_slist_insert_sorted(l,d,c) \
	track_slist_insert_sorted((l),(d),(c), _WHERE_, __LINE__)
#define g_slist_delete_link(l,x) \
	track_slist_delete_link((l),(x), _WHERE_, __LINE__)
#define gm_slist_insert_after(l,lk,d) \
	track_slist_insert_after((l),(lk),(d), _WHERE_, __LINE__)

#define g_list_alloc()			track_list_alloc(_WHERE_, __LINE__)
#define g_list_append(l,d)		track_list_append((l),(d), _WHERE_, __LINE__)
#define g_list_prepend(l,d)		track_list_prepend((l),(d), _WHERE_, __LINE__)
#define g_list_copy(l)			track_list_copy((l), _WHERE_, __LINE__)
#define g_list_free(l)			track_list_free((l), _WHERE_, __LINE__)
#define g_list_free_1(l)		track_list_free1((l), _WHERE_, __LINE__)
#define g_list_remove(l,d)		track_list_remove((l),(d), _WHERE_, __LINE__)

#define g_list_insert(l,d,p) \
	track_list_insert((l),(d),(p), _WHERE_, __LINE__)
#define g_list_insert_sorted(l,d,c) \
	track_list_insert_sorted((l),(d),(c), _WHERE_, __LINE__)
#define gm_list_insert_after(l,lk,d) \
	track_list_insert_after((l),(lk),(d), _WHERE_, __LINE__)
#define g_list_delete_link(l,lk) \
	track_list_delete_link((l),(lk), _WHERE_, __LINE__)

#define g_string_new(p)			string_new_track((p), _WHERE_, __LINE__)
#define g_string_sized_new(s)	string_sized_new_track((s), _WHERE_, __LINE__)
#define g_string_append(s,p)	string_append_track((s),(p),_WHERE_,__LINE__)
#undef g_string_append_c
#define g_string_append_c(s,c)	string_append_c_track((s),(c),_WHERE_,__LINE__)
#define g_string_assign(s,p)	string_assign_track((s),(p),_WHERE_,__LINE__)
#define g_string_free(s,b)		string_free_track((s),(b), _WHERE_, __LINE__)
#define g_string_prepend(s,p)	string_prepend_track((s),(p),_WHERE_,__LINE__)
#define g_string_prepend_c(s,c) string_prepend_c_track((s),(c),_WHERE_,__LINE__)

#define g_string_append_len(s,v,l) \
	string_append_len_track((s),(v),(l),_WHERE_,__LINE__)
#define g_string_insert(s,i,p)	\
	string_insert_track((s),(i),(p),_WHERE_,__LINE__)
#define g_string_insert_c(s,i,c) \
	string_insert_c_track((s),(i),(c),_WHERE_,__LINE__)

#ifdef USE_GTK2 /* Those are defined in gstring.h of GLib2 */
#undef g_string_sprintf
#undef g_string_sprintfa
#endif
#define g_string_sprintf(s,fmt,...) \
	string_sprintf_track((s),_WHERE_,__LINE__,(fmt), __VA_ARGS__)
#define g_string_sprintfa(s,fmt,...) \
	string_sprintf_tracka((s),_WHERE_,__LINE__,(fmt), __VA_ARGS__)


/*
 * Use STRTRACK() to track an allocated string by some obscure routine that
 * does not happen to be wrapped here, so that we can remember it is an
 * allocated block and correctly free() it later on when the time comes or
 * report it as a leak...
 *
 * Likewise, use MEMTRACK() to track some random memory buffer known to have
 * been allocated by a routine and not via any of the trapped calls.
 */
#define STRTRACK(s)		string_record((s), _WHERE_, __LINE__)
#define MEMTRACK(o,s)	malloc_record((o), (s), _WHERE_, __LINE__)

#else	/* !TRACK_MALLOC || MALLOC_SOURCE */

#define STRTRACK(s)		s
#define MEMTRACK(o,s)	o

#endif	/* TRACK_MALLOC && !MALLOC_SOURCE */

#if defined(TRACK_MALLOC) || defined(MALLOC_SOURCE)

gpointer string_record(const gchar *s, gchar *file, gint line);
gpointer malloc_record(gconstpointer o, size_t size, gchar *file, gint line);

gpointer malloc_track(size_t size, gchar *file, gint line);
gpointer malloc0_track(size_t size, gchar *file, gint line);
void free_track(gpointer o, gchar *file, gint line);
void strfreev_track(gchar **v, gchar *file, gint line);
gpointer realloc_track(gpointer o, size_t size, gchar *file, gint line);
gchar *strdup_track(const gchar *s, gchar *file, gint line);
gchar *strndup_track(const gchar *s, size_t n, gchar *file, gint line);
gpointer memdup_track(gconstpointer p, size_t size, gchar *file, gint line);
gchar *strjoinv_track(const gchar *s, gchar **vec, gchar *file, gint line);
gchar *strconcat_track(gchar *file, gint line, const gchar *s, ...);
gchar *strdup_printf_track(gchar *file, gint line, const gchar *fmt, ...)
	G_GNUC_PRINTF(3, 4);
gchar **strsplit_track(
	const gchar *s, const gchar *d, size_t m, gchar *file, gint line);

GHashTable *hashtable_new_track(
	GHashFunc h, GCompareFunc y, gchar *file, gint line);
void hashtable_destroy_track(GHashTable *h, gchar *file, gint line);

hash_list_t *hash_list_new_track(
	GHashFunc hash_func, GEqualFunc eq_func, gchar *file, gint line);
void hash_list_free_track(hash_list_t **hl_ptr, gchar *file, gint line);

GSList *track_slist_alloc(gchar *file, gint line);
GSList *track_slist_append(GSList *l, gpointer data, gchar *file, gint line);
GSList *track_slist_prepend(GSList *l, gpointer data, gchar *file, gint line);
GSList *track_slist_copy(GSList *l, gchar *file, gint line);
void track_slist_free(GSList *l, gchar *file, gint line);
void track_slist_free1(GSList *l, gchar *file, gint line);
GSList *track_slist_remove(GSList *l, gpointer data, gchar *file, gint line);
GSList *track_slist_insert(
	GSList *l, gpointer d, gint pos, gchar *file, gint line);
GSList *track_slist_insert_sorted(
	GSList *l, gpointer d, GCompareFunc c, gchar *file, gint line);
GSList *track_slist_insert_after(
	GSList *l, GSList *lk, gpointer data, gchar *file, gint line);
GSList *track_slist_delete_link(GSList *l, GSList *lk, gchar *file, gint line);

GList *track_list_alloc(gchar *file, gint line);
GList *track_list_append(GList *l, gpointer data, gchar *file, gint line);
GList *track_list_prepend(GList *l, gpointer data, gchar *file, gint line);
GList *track_list_copy(GList *l, gchar *file, gint line);
void track_list_free(GList *l, gchar *file, gint line);
void track_list_free1(GList *l, gchar *file, gint line);
GList *track_list_remove(GList *l, gpointer data, gchar *file, gint line);
GList *track_list_insert(
	GList *l, gpointer d, gint pos, gchar *file, gint line);
GList *track_list_insert_sorted(
	GList *l, gpointer d, GCompareFunc c, gchar *file, gint line);
GList *track_list_insert_after(
	GList *l, GList *lk, gpointer data, gchar *file, gint line);
GList *track_list_delete_link(GList *l, GList *lk, gchar *file, gint line);

GString *string_new_track(const gchar *p, gchar *file, gint line);
GString *string_sized_new_track(size_t size, gchar *file, gint line);
GString *string_append_track(
	GString *s, const gchar *p, gchar *file, gint line);
GString *string_append_c_track(
	GString *s, gchar c, gchar *file, gint line);
GString *string_append_len_track(
	GString *s, const gchar *val,  gssize len, gchar *file, gint line);
GString *string_assign_track(
	GString *s, const gchar *p, gchar *file, gint line);
void string_free_track(GString *s, gint freestr, gchar *file, gint line);
GString *string_prepend_track(
	GString *s, const gchar *p, gchar *file, gint line);
GString *string_prepend_c_track(
	GString *s, gchar c, gchar *file, gint line);
GString *string_insert_track(
	GString *s, gint pos, const gchar *p, gchar *file, gint line);
GString *string_insert_c_track(
	GString *s, gint pos, gchar c, gchar *file, gint line);
GString *string_sprintf_track(
	GString *s, gchar *file, gint line, const gchar *fmt, ...)
	G_GNUC_PRINTF(4, 5);
GString *string_sprintfa_track(
	GString *s, gchar *file, gint line, const gchar *fmt, ...)
	G_GNUC_PRINTF(4, 5);

#endif	/* TRACK_MALLOC || MALLOC_SOURCE */

#ifdef TRACK_MALLOC
void malloc_close(void);
#endif

#if defined(TRACK_MALLOC) || defined(TRACK_ZALLOC)

gpointer leak_init(void);
void leak_add(gpointer o, size_t size, gchar *file, gint line);
void leak_dump(gpointer o);
void leak_close(gpointer o);

#endif /* TRACK_MALLOC || TRACK_ZALLOC */

#ifdef MALLOC_STATS
void alloc_dump(FILE *f, gboolean total);
void alloc_reset(FILE *f, gboolean total);
#endif

#endif /* _malloc_h_ */

/* vi: set ts=4 sw=4 cindent:  */
