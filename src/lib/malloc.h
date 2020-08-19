/*
 * Copyright (c) 2004, 2020 Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Debugging malloc, to supplant dmalloc which is not satisfactory for
 * leak detection.
 *
 * @author Raphael Manfredi
 * @date 2004, 2020
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

#ifdef MALLOC_FRAMES
#include "hashtable.h"
#endif

#if defined(TRACK_MALLOC) && !defined(MALLOC_SOURCE)

#include "atomic.h"
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
#define halloc0(s)		malloc0_track((s), _WHERE_, __LINE__)
#define hfree(s)		free_track((s), _WHERE_, __LINE__)
#define hrealloc(o,s)	realloc_track(o, (s), _WHERE_, __LINE__)
#define hcopy(p,s)		memdup_track((p), (s), _WHERE_, __LINE__)

#define g_malloc(s)		malloc_track((s), _WHERE_, __LINE__)
#define g_malloc0(s)	malloc0_track((s), _WHERE_, __LINE__)
#define g_free(o)		free_track(o, _WHERE_, __LINE__)
#define g_realloc(o,s)	realloc_track(o, (s), _WHERE_, __LINE__)
#define g_strdup(s)		strdup_track(s, _WHERE_, __LINE__)
#define g_strndup(s,n)	strndup_track(s,(n),_WHERE_,__LINE__)
#define g_strjoinv(s,v)	strjoinv_track(s, (v), _WHERE_, __LINE__)
#define g_memdup(p,s)	memdup_track((p), (s), _WHERE_, __LINE__)
#define g_strfreev(v)	strfreev_track((v), _WHERE_, __LINE__)

#define h_strdup(s)		strdup_track(s,_WHERE_,__LINE__)
#define h_strndup(s,n)	strndup_track(s,(n),_WHERE_,__LINE__)
#define h_strjoinv(s,v)	strjoinv_track(s, (v), _WHERE_, __LINE__)
#define h_strfreev(v)	strfreev_track((v), _WHERE_, __LINE__)

#ifndef XMALLOC_SOURCE

#undef xmalloc
#undef xrealloc
#undef xfree
#undef xcalloc
#undef xstrdup
#undef xstrndup

#define xmalloc(s)		malloc_alloc_track(e_xmalloc, (s), _WHERE_, __LINE__)
#define xmalloc0(s)		malloc0_alloc_track(e_xmalloc, (s), _WHERE_, __LINE__)
#define xfree(p)		malloc_free_track(e_xfree, (p), _WHERE_, __LINE__)
#define xstrdup(s)		malloc_strdup_track(e_xmalloc, (s), _WHERE_, __LINE__)
#define xstrndup(s,n)	malloc_strndup_track(e_xmalloc, (s), (n), _WHERE_, __LINE__)
#define xpmalloc(s)		malloc_alloc_track(e_xmalloc, (s), _WHERE_, __LINE__)
#define xhmalloc(s)		malloc_alloc_track(e_xmalloc, (s), _WHERE_, __LINE__)

#define xrealloc(p,s)	\
	malloc_realloc_track(e_xrealloc, e_xmalloc, e_xfree,	\
		(p), (s), _WHERE_, __LINE__)

#define xprealloc(p,s)	\
	malloc_realloc_track(e_xrealloc, e_xmalloc, e_xfree,	\
		(p), (s), _WHERE_, __LINE__)

#define xcalloc(n,s) \
	malloc_alloc_track(e_xmalloc, (n) * (s), _WHERE_, __LINE__)

#endif	/* !XMALLOC_SOURCE */

#undef XCOPY
#define XCOPY(p)	malloc_copy_track(e_xmalloc, p, sizeof *p, _WHERE_, __LINE__)
#define xcopy(p,s)	malloc_copy_track(e_xmalloc, (p), (s), _WHERE_, __LINE__)

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

#ifndef REMAP_ZALLOC
#define hash_list_new(h,c)		hash_list_new_track((h),(c),_WHERE_, __LINE__)
#define hash_list_free(h)		hash_list_free_track((h), _WHERE_, __LINE__)
#endif	/* !REMAP_ZALLOC */

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
#define gm_slist_prepend_const(l,d) \
	track_slist_prepend_const((l),(d), _WHERE_, __LINE__)

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

#ifdef USE_GLIB2 /* Those are defined in gstring.h of GLib2 */
#undef g_string_sprintf
#undef g_string_sprintfa
#endif
#define g_string_sprintf(s,fmt,...) \
	string_sprintf_track((s),_WHERE_,__LINE__,(fmt), __VA_ARGS__)
#define g_string_sprintfa(s,fmt,...) \
	string_sprintf_tracka((s),_WHERE_,__LINE__,(fmt), __VA_ARGS__)

#define h_strdup_vprintf(fmt, ap) \
	strdup_vprintf_track(_WHERE_, __LINE__, (fmt), ap)
#define h_strdup_len_vprintf(fmt, ap, len) \
	strdup_len_vprintf_track(_WHERE_, __LINE__, (fmt), ap, len)
#define h_strdup_printf(fmt, ...) \
	strdup_printf_track(_WHERE_, __LINE__, (fmt), __VA_ARGS__)

#define h_strconcat(s, ...) \
	strconcat_track(_WHERE_, __LINE__, s, __VA_ARGS__)

#define h_strconcat_v(s, ap) strconcat_v_track(_WHERE_, __LINE__, s, ap)

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
#define NOT_LEAKING(o)	malloc_not_leaking(o)

#if defined(REMAP_ZALLOC)
#define NOT_LEAKING_Z(o)	malloc_not_leaking(o)
#elif defined(TRACK_ZALLOC) || defined(MALLOC_FRAMES)
#define NOT_LEAKING_Z(o)	zalloc_not_leaking(o)
void *zalloc_not_leaking(const void *o);
#else
#define NOT_LEAKING_Z(o)
#endif

#else	/* !TRACK_MALLOC || MALLOC_SOURCE */

#define STRTRACK(o)		(o)
#define MEMTRACK(o,s)	(o)
#define GSLISTTRACK(o)	(o)
#define GLISTTRACK(o)	(o)

#if defined(TRACK_ZALLOC) || defined(MALLOC_FRAMES)
#define NOT_LEAKING(o)		zalloc_not_leaking(o)
#define NOT_LEAKING_Z(o)	zalloc_not_leaking(o)
void *zalloc_not_leaking(const void *o);
#else
#define NOT_LEAKING(o)		(o)
#define NOT_LEAKING_Z(o)	(o)
#endif

#endif	/* TRACK_MALLOC && !MALLOC_SOURCE */

#if defined(TRACK_MALLOC) || defined(MALLOC_SOURCE)
void *malloc_alloc_track(alloc_fn_t, size_t, const char *, int);
void *malloc0_alloc_track(alloc_fn_t, size_t, const char *, int);
void *malloc_realloc_track(realloc_fn_t, alloc_fn_t, free_fn_t,
	void *, size_t, const char *, int);
void malloc_free_track(free_fn_t, void *, const char *, int);
void *malloc_copy_track(alloc_fn_t, const void *, size_t, const char *, int);
char *malloc_strdup_track(alloc_fn_t, const char *s, const char *, int);
char *malloc_strndup_track(alloc_fn_t, const char *s, size_t n, const char *, int);

char *string_record(const char *s, const char *file, int line);
void *malloc_record(const void *o, size_t size, bool owned,
	const char *file, int line);
void *realloc_record(void *o, void *n, size_t size, const char *file, int line);
bool free_record(const void *o, const char *file, int line);
GSList *gslist_record(const GSList *, const char *file, int line);
GList *glist_record(const GList *, const char *file, int line);
void *malloc_not_leaking(const void *o);

void *malloc_track(size_t size, const char *file, int line);
void *malloc0_track(size_t size, const char *file, int line);
void free_track(void *o, const char *file, int line);
void strfreev_track(char **v, const char *file, int line);
void *realloc_track(void *o, size_t size, const char *file, int line);
char *strdup_track(const char *s, const char *file, int line);
char *strndup_track(const char *s, size_t n, const char *file, int line);
void *memdup_track(const void *p, size_t size, const char *file, int line);
char *strjoinv_track(const char *s, char **vec, const char *file, int line);
char *strconcat_track(const char *file, int line, const char *s, ...);
char *strconcat_v_track(const char *file, int line, const char *s, va_list ap);
char *strdup_vprintf_track(const char *file, int line,
	const char *fmt, va_list ap);
char *strdup_len_vprintf_track(const char *file, int line,
	const char *fmt, va_list ap, size_t *len);
char *strdup_printf_track(const char *file, int line, const char *fmt, ...)
	G_PRINTF(3, 4);
char **strsplit_track(
	const char *s, const char *d, size_t m, const char *file, int line);

GHashTable *hashtable_new_track(
	GHashFunc h, GCompareFunc y, const char *file, int line);
void hashtable_destroy_track(GHashTable *h, const char *file, int line);

hash_list_t *hash_list_new_track(
	GHashFunc hash_func, GEqualFunc eq_func, const char *file, int line);
void hash_list_free_track(hash_list_t **hl_ptr, const char *file, int line);

GSList *track_slist_alloc(const char *file, int line);
GSList *track_slist_append(GSList *l, void *data,
	const char *file, int line);
GSList *track_slist_prepend(GSList *l, void *data,
	const char *file, int line);
GSList *track_slist_prepend_const(GSList *l, const void *data,
	const char *file, int line);
GSList *track_slist_copy(GSList *l, const char *file, int line);
void track_slist_free(GSList *l, const char *file, int line);
void track_slist_free1(GSList *l, const char *file, int line);
GSList *track_slist_remove(GSList *l, void *data,
	const char *file, int line);
GSList *track_slist_insert(
	GSList *l, void *d, int pos, const char *file, int line);
GSList *track_slist_insert_sorted(
	GSList *l, void *d, GCompareFunc c, const char *file, int line);
GSList *track_slist_insert_after(
	GSList *l, GSList *lk, void *data, const char *file, int line);
GSList *track_slist_delete_link(GSList *l, GSList *lk,
	const char *file, int line);

GList *track_list_alloc(const char *file, int line);
GList *track_list_append(GList *l, void *data, const char *file, int line);
GList *track_list_prepend(GList *l, void *data, const char *file, int line);
GList *track_list_copy(GList *l, const char *file, int line);
void track_list_free(GList *l, const char *file, int line);
void track_list_free1(GList *l, const char *file, int line);
GList *track_list_remove(GList *l, void *data, const char *file, int line);
GList *track_list_insert(
	GList *l, void *d, int pos, const char *file, int line);
GList *track_list_insert_sorted(
	GList *l, void *d, GCompareFunc c, const char *file, int line);
GList *track_list_insert_after(
	GList *l, GList *lk, void *data, const char *file, int line);
GList *track_list_insert_before(
	GList *l, GList *lk, void *data, const char *file, int line);
GList *track_list_delete_link(GList *l, GList *lk, const char *file, int line);

#endif	/* TRACK_MALLOC || MALLOC_SOURCE */

#ifdef MALLOC_STATS
void alloc_dump(FILE *f, bool total);
void alloc_reset(FILE *f, bool total);
#endif

#ifdef MALLOC_FRAMES

#define FRAME_DEPTH_MAX	128
#define FRAME_DEPTH		10	/**< Size of allocation frame we keep around */

struct stacktrace;
struct stackatom;

/**
 * Structure keeping track of the allocation/free stack frames.
 *
 * Counts are signed because for realloc() frames, we count algebric
 * quantities (in case the blocks are shrunk).
 */
struct frame {
	const struct stackatom *ast;	/**< Atomic stack frame */
	AU64(blocks);				/**< Blocks allocated from this stack frame */
	AU64(count);				/**< Bytes allocated/freed since reset */
	AU64(total_count);			/**< Grand total for this stack frame */
};

struct frame *get_frame_atom(hash_table_t **hptr, const struct stacktrace *st);

#endif /* MALLOC_FRAMES */

/*
 * Public interface, available no matter which compile options are used.
 */

struct logagent;

void malloc_show_settings_log(struct logagent *la);
void malloc_show_settings(void);
void malloc_init_vtable(void);
void malloc_close(void);
size_t malloc_memory_used(void);

void *real_malloc(size_t size);

/**
 * Calls g_free() and sets the pointer to NULL afterwards. You should use
 * this instead of a bare g_free() to prevent double-free bugs and dangling
 * pointers.
 */
#if defined(TRACK_MALLOC) && !defined(MALLOC_SOURCE)
#define G_FREE_NULL(p)	\
G_STMT_START {			\
	if (p) {			\
		free_track((p), _WHERE_, __LINE__);	\
		p = NULL;		\
	}					\
} G_STMT_END
#else
#define G_FREE_NULL(p)	\
G_STMT_START {			\
	if (p) {			\
		g_free(p);		\
		p = NULL;		\
	}					\
} G_STMT_END
#endif	/* TRACK_MALLOC && !MALLOC_SOURCE */

#if defined(TRACK_MALLOC) || defined(MALLOC_VTABLE)
void malloc_init_tracking(void);
#endif

#endif /* _malloc_h_ */

/* vi: set ts=4 sw=4 cindent:  */
