/*
 * $Id$
 *
 * Copyright (c) 2004, Raphael Manfredi
 *
 * Debugging malloc, to supplant dmalloc which is not satisfactory for
 * leak detection.
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

#if defined(TRACK_MALLOC) && !defined(MALLOC_SOURCE)

#define malloc(s)		malloc_track((s), __FILE__, __LINE__)
#define calloc(n,s)		malloc0_track((n)*(s), __FILE__, __LINE__)
#define free(o)			free_track(o, __FILE__, __LINE__)
#define realloc(o,s)	realloc_track(o, (s), __FILE__, __LINE__)
#define strdup(s)		strdup_track((s), __FILE__, __LINE__)
#define strndup(s,n)	strndup_track((s), (n), __FILE__, __LINE__)

#define g_malloc(s)		malloc_track((s), __FILE__, __LINE__)
#define g_malloc0(s)	malloc0_track((s), __FILE__, __LINE__)
#define g_free(o)		free_track(o, __FILE__, __LINE__)
#define g_realloc(o,s)	realloc_track(o, (s), __FILE__, __LINE__)
#define g_strdup(s)		((s) ? strdup_track(s, __FILE__, __LINE__) : 0)
#define g_strndup(s,n)	((s) ? strndup_track(s, (n), __FILE__, __LINE__) : 0)
#define g_strjoinv(s,v)	strjoinv_track(s, (v), __FILE__, __LINE__)
#define g_memdup(p,s)	((p) ? memdup_track((p), (s), __FILE__, __LINE__) : 0)
#define g_strfreev(v)	strfreev_track((v), __FILE__, __LINE__)

#undef g_new
#undef g_new0
#undef g_renew

#define g_new(t,c)		(t*) malloc_track(sizeof(t)*(c), __FILE__, __LINE__)
#define g_new0(t,c)		(t*) malloc0_track(sizeof(t)*(c), __FILE__, __LINE__)
#define g_renew(t,m,c)	(t*) realloc_track((m),sizeof(t)*(c),__FILE__,__LINE__)

#define g_strconcat(s, ...) \
	strconcat_track(__FILE__, __LINE__, s, __VA_ARGS__)

#define g_strdup_printf(fmt, ...) \
	strdup_printf_track(__FILE__, __LINE__, fmt, __VA_ARGS__)

#define g_strsplit(s,d,m)		strsplit_track((s),(d),(m), __FILE__, __LINE__)
#define g_hash_table_new(x,y)	hashtable_new_track(x, y, __FILE__, __LINE__)
#define g_hash_table_destroy(x)	hashtable_destroy_track(x, __FILE__, __LINE__)

/*
 * Use STRTRACK() to track an allocated string by some obscure routine that
 * does not happen to be wrapped here, so that we can remember it is an
 * allocated block and correctly free() it later on when the time comes or
 * report it as a leak...
 *
 * Likewise, use MEMTRACK() to track some random memory buffer known to have
 * been allocated by a routine and not via any of the trapped calls.
 */
#define STRTRACK(s)		string_record((s), __FILE__, __LINE__)
#define MEMTRACK(o,s)	malloc_record((o), (s), __FILE__, __LINE__)

#else	/* !TRACK_MALLOC || MALLOC_SOURCE */

#define STRTRACK(s)		s
#define MEMTRACK(o,s)	o

#endif	/* TRACK_MALLOC && !MALLOC_SOURCE */

#if defined(TRACK_MALLOC) || defined(MALLOC_SOURCE)

gpointer string_record(const gchar *s, gchar *file, gint line);
gpointer malloc_record(gpointer o, guint32 s, gchar *file, gint line);

gpointer malloc_track(guint32 s, gchar *file, gint line);
gpointer malloc0_track(guint32 s, gchar *file, gint line);
void free_track(gpointer o, gchar *file, gint line);
void strfreev_track(gchar **v, gchar *file, gint line);
gpointer realloc_track(gpointer o, guint32 s, gchar *file, gint line);
gchar *strdup_track(const gchar *s, gchar *file, gint line);
gchar *strndup_track(const gchar *s, gint n, gchar *file, gint line);
gpointer memdup_track(gconstpointer p, guint size, gchar *file, gint line);
gchar *strjoinv_track(const gchar *s, gchar **vec, gchar *file, gint line);
gchar *strconcat_track(gchar *file, gint line, const gchar *s, ...);
gchar *strdup_printf_track(gchar *file, gint line, const gchar *fmt, ...);
gchar **strsplit_track(
	const gchar *s, const gchar *d, gint m, gchar *file, gint line);
GHashTable *hashtable_new_track(
	GHashFunc h, GCompareFunc y, gchar *file, gint line);
void hashtable_destroy_track(GHashTable *h, gchar *file, gint line);

#endif	/* TRACK_MALLOC || MALLOC_SOURCE */

#ifdef TRACK_MALLOC
void malloc_close(void);
#endif

#if defined(TRACK_MALLOC) || defined(TRACK_ZALLOC)

gpointer leak_init(void);
void leak_add(gpointer o, guint32 size, gchar *file, gint line);
void leak_dump(gpointer o);
void leak_close(gpointer o);

#endif /* TRACK_MALLOC || TRACK_ZALLOC */

#endif /* _malloc_h_ */

