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
#undef strndup

#define malloc(s)		malloc_track((s), _WHERE_, __LINE__)
#define calloc(n,s)		malloc0_track((n)*(s), _WHERE_, __LINE__)
#define free(o)			free_track(o, _WHERE_, __LINE__)
#define realloc(o,s)	realloc_track(o, (s), _WHERE_, __LINE__)
#define strdup(s)		strdup_track((s), _WHERE_, __LINE__)
#define strndup(s,n)	strndup_track((s), (n), _WHERE_, __LINE__)

#define halloc(s)		malloc_track((s), _WHERE_, __LINE__)
#define hfree(s)		free_track((s), _WHERE_, __LINE__)
#define hrealloc(o,s)	realloc_track(o, (s), _WHERE_, __LINE__)

#define g_malloc(s)		malloc_track((s), _WHERE_, __LINE__)
#define g_malloc0(s)	malloc0_track((s), _WHERE_, __LINE__)
#define g_free(o)		free_track(o, _WHERE_, __LINE__)
#define g_realloc(o,s)	realloc_track(o, (s), _WHERE_, __LINE__)
#define g_strdup(s)		strdup_track(s, _WHERE_, __LINE__)
#define g_strndup(s,n)	strndup_track(s,(n),_WHERE_,__LINE__)
#define g_strjoinv(s,v)	strjoinv_track(s, (v), _WHERE_, __LINE__)
#define g_memdup(p,s)	memdup_track((p), (s), _WHERE_, __LINE__)
#define g_strfreev(v)	strfreev_track((v), _WHERE_, __LINE__)

#define h_strdup(s)		strdup_track(s,(n),_WHERE_,__LINE__)
#define h_strndup(s,n)	strndup_track(s,(n),_WHERE_,__LINE__)
#define h_strjoinv(s,v)	strjoinv_track(s, (v), _WHERE_, __LINE__)
#define h_strfreev(v)	strfreev_track((v), _WHERE_, __LINE__)

/* FIXME: This is only correct if xmlFree() is equivalent to free(). */
#define xmlFree(o)		free_track(o, _WHERE_, __LINE__)

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

#define hash_list_new(h,c)		hash_list_new_track((h),(c),_WHERE_, __LINE__)
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
#define g_list_insert_before(l,lk,d) \
	track_list_insert_before((l),(lk),(d), _WHERE_, __LINE__)

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

#define h_strdup_printf(fmt, ...) \
	strdup_printf_track(_WHERE_, __LINE__, fmt, __VA_ARGS__)

#define h_strconcat(s, ...) \
	strconcat_track(_WHERE_, __LINE__, s, __VA_ARGS__)

/*
 * Use STRTRACK() to track an allocated string by some obscure routine that
 * does not happen to be wrapped here, so that we can remember it is an
 * allocated block and correctly free() it later on when the time comes or
 * report it as a leak...
 *
 * Likewise, use MEMTRACK() to track some random memory buffer known to have
 * been allocated by a routine and not via any of the trapped calls.
 *
 * Use NOT_LEAKING() to remember the object as an exception: it will not
 * be flagged as a leak if it was not freed at the end.  This is intended
 * to be used in lazy-style functions that keep allocated data in a static
 * variable, which is freed at the next invocation, or for once functions that
 * compute data on the first call and then always return the same value.
 */
#define STRTRACK(o)		string_record((o), _WHERE_, __LINE__)
#define MEMTRACK(o,s)	malloc_record((o), (s), FALSE, _WHERE_, __LINE__)
#define GSLISTTRACK(o)	gslist_record((o), _WHERE_, __LINE__)
#define GLISTTRACK(o)	glist_record((o), _WHERE_, __LINE__)
#define NOT_LEAKING(o)	malloc_not_leaking(o, _WHERE_, __LINE__)

#else	/* !TRACK_MALLOC || MALLOC_SOURCE */

#define STRTRACK(o)		(o)
#define MEMTRACK(o,s)	(o)
#define GSLISTTRACK(o)	(o)
#define GLISTTRACK(o)	(o)
#define NOT_LEAKING(o)	(o)

#endif	/* TRACK_MALLOC && !MALLOC_SOURCE */

#if defined(TRACK_MALLOC) || defined(MALLOC_SOURCE)

char *string_record(const char *s, const char *file, int line);
gpointer malloc_record(gconstpointer o, size_t size, gboolean owned,
	const char *file, int line);
GSList *gslist_record(const GSList *, const char *file, int line);
GList *glist_record(const GList *, const char *file, int line);
gpointer malloc_not_leaking(gconstpointer o, const char *file, int line);

gpointer malloc_track(size_t size, const char *file, int line);
gpointer malloc0_track(size_t size, const char *file, int line);
void free_track(gpointer o, const char *file, int line);
void strfreev_track(char **v, const char *file, int line);
gpointer realloc_track(gpointer o, size_t size, const char *file, int line);
char *strdup_track(const char *s, const char *file, int line);
char *strndup_track(const char *s, size_t n, const char *file, int line);
gpointer memdup_track(gconstpointer p, size_t size, const char *file, int line);
char *strjoinv_track(const char *s, char **vec, const char *file, int line);
char *strconcat_track(const char *file, int line, const char *s, ...);
char *strdup_printf_track(const char *file, int line, const char *fmt, ...)
	G_GNUC_PRINTF(3, 4);
char **strsplit_track(
	const char *s, const char *d, size_t m, const char *file, int line);

GHashTable *hashtable_new_track(
	GHashFunc h, GCompareFunc y, const char *file, int line);
void hashtable_destroy_track(GHashTable *h, const char *file, int line);

hash_list_t *hash_list_new_track(
	GHashFunc hash_func, GEqualFunc eq_func, const char *file, int line);
void hash_list_free_track(hash_list_t **hl_ptr, const char *file, int line);

GSList *track_slist_alloc(const char *file, int line);
GSList *track_slist_append(GSList *l, gpointer data,
	const char *file, int line);
GSList *track_slist_prepend(GSList *l, gpointer data,
	const char *file, int line);
GSList *track_slist_copy(GSList *l, const char *file, int line);
void track_slist_free(GSList *l, const char *file, int line);
void track_slist_free1(GSList *l, const char *file, int line);
GSList *track_slist_remove(GSList *l, gpointer data,
	const char *file, int line);
GSList *track_slist_insert(
	GSList *l, gpointer d, int pos, const char *file, int line);
GSList *track_slist_insert_sorted(
	GSList *l, gpointer d, GCompareFunc c, const char *file, int line);
GSList *track_slist_insert_after(
	GSList *l, GSList *lk, gpointer data, const char *file, int line);
GSList *track_slist_delete_link(GSList *l, GSList *lk,
	const char *file, int line);

GList *track_list_alloc(const char *file, int line);
GList *track_list_append(GList *l, gpointer data, const char *file, int line);
GList *track_list_prepend(GList *l, gpointer data, const char *file, int line);
GList *track_list_copy(GList *l, const char *file, int line);
void track_list_free(GList *l, const char *file, int line);
void track_list_free1(GList *l, const char *file, int line);
GList *track_list_remove(GList *l, gpointer data, const char *file, int line);
GList *track_list_insert(
	GList *l, gpointer d, int pos, const char *file, int line);
GList *track_list_insert_sorted(
	GList *l, gpointer d, GCompareFunc c, const char *file, int line);
GList *track_list_insert_after(
	GList *l, GList *lk, gpointer data, const char *file, int line);
GList *track_list_insert_before(
	GList *l, GList *lk, gpointer data, const char *file, int line);
GList *track_list_delete_link(GList *l, GList *lk, const char *file, int line);

GString *string_new_track(const char *p, const char *file, int line);
GString *string_sized_new_track(size_t size, const char *file, int line);
GString *string_append_track(
	GString *s, const char *p, const char *file, int line);
GString *string_append_c_track(
	GString *s, char c, const char *file, int line);
GString *string_append_len_track(
	GString *s, const char *val,  gssize len, const char *file, int line);
GString *string_assign_track(
	GString *s, const char *p, const char *file, int line);
void string_free_track(GString *s, int freestr, const char *file, int line);
GString *string_prepend_track(
	GString *s, const char *p, const char *file, int line);
GString *string_prepend_c_track(
	GString *s, char c, const char *file, int line);
GString *string_insert_track(
	GString *s, int pos, const char *p, const char *file, int line);
GString *string_insert_c_track(
	GString *s, int pos, char c, const char *file, int line);
GString *string_sprintf_track(
	GString *s, const char *file, int line, const char *fmt, ...)
	G_GNUC_PRINTF(4, 5);
GString *string_sprintfa_track(
	GString *s, const char *file, int line, const char *fmt, ...)
	G_GNUC_PRINTF(4, 5);

#endif	/* TRACK_MALLOC || MALLOC_SOURCE */

#if defined(TRACK_MALLOC) || defined(TRACK_ZALLOC)

gpointer leak_init(void);
void leak_add(gpointer o, size_t size, const char *file, int line);
void leak_dump(gpointer o);
void leak_close(gpointer o);

#endif /* TRACK_MALLOC || TRACK_ZALLOC */

#ifdef MALLOC_STATS
void alloc_dump(FILE *f, gboolean total);
void alloc_reset(FILE *f, gboolean total);
#endif

/*
 * Public interface, available no matter which compile options are used.
 */

void malloc_init(const char *argv0);
void malloc_init_vtable(void);
void malloc_close(void);

#endif /* _malloc_h_ */

/* vi: set ts=4 sw=4 cindent:  */
