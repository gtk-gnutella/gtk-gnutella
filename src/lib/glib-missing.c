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

#include "common.h"

#include "glib-missing.h"

#include "ascii.h"
#include "compat_poll.h"
#include "iovec.h"
#include "log.h"			/* For s_minicarp() */
#include "misc.h"			/* For clamp_strcpy() */
#include "pslist.h"
#include "str.h"
#include "stringify.h"
#include "unsigned.h"
#include "utf8.h"

#include "override.h"		/* Must be the last header included */

#if !defined(HAS_STRLCPY) && !defined(USE_GLIB2)
size_t
strlcpy(char *dst, const char *src, size_t dst_size)
{
	char *d = dst;
	const char *s = src;

	g_assert(NULL != dst);
	g_assert(NULL != src);

	if (dst_size--) {
		size_t i = 0;

		while (i < dst_size) {
			if (!(*d++ = *s++))
				return i;
			i++;
		}
		dst[dst_size] = '\0';
	}
 	while (*s)
		s++;
	return s - src;
}
#endif /* HAS_STRLCPY */

#if !defined(HAS_STRLCAT) && !defined(USE_GLIB2)
size_t
strlcat(char *dst, const char *src, size_t dst_size)
{
	size_t n;
	
	g_assert(NULL != dst);
	g_assert(NULL != src);

	n = strlen(dst);	
	if (n < dst_size) {
		dst_size -= n;
	} else if (dst_size > 0) {
		dst[dst_size - 1] = '\0';
		dst_size = 0;
	}
	return n += g_strlcpy(&dst[n], src, dst_size);
}
#endif /* HAS_STRLCAT */

#ifndef TRACK_MALLOC
/**
 * Insert `item' after `lnk' in list `list'.
 * If `lnk' is NULL, insertion happens at the head.
 *
 * @return new list head.
 */
GSList *
gm_slist_insert_after(GSList *list, GSList *lnk, void *data)
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
gm_list_insert_after(GList *list, GList *lnk, void *data)
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
g_list_insert_before(GList *l, GList *lk, void *data)
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
g_hash_table_replace(GHashTable *ht, void *key, void *value)
{
	g_hash_table_remove(ht, key);
	g_hash_table_insert(ht, key, value);
}

bool
gm_hash_table_remove(GHashTable *ht, const void *key)
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
static inline size_t G_GNUC_PRINTF(3, 0)
buf_vprintf(char *dst, size_t size, const char *fmt, va_list args)
#ifdef HAS_VSNPRINTF
{
	int retval;	/* printf()-functions really return int, not size_t */
	int truncated = 0;

	g_assert(size_is_positive(size));	

	dst[0] = '\0';
	retval = vsnprintf(dst, size, fmt, args);
	if (retval < 0) {
		/* Old versions of vsnprintf() */
		dst[size - 1] = '\0';
		retval = strlen(dst);
		truncated = (size - 1 == (size_t) retval) ? 1 : 0;
	} else if ((size_t) retval >= size) {
		/* New versions (compliant with C99) */
		dst[size - 1] = '\0';
		truncated = retval - size + 1;
		retval = size - 1;
	}
	if G_UNLIKELY(truncated != 0) {
		s_minicarp("truncated %d byte%s when formatting into %zu-byte buffer "
			"with \"%s\"", truncated, plural(truncated),
			size, fmt);
	}
	return retval;
}
#else	/* !HAS_VSNPRINTF */
{
	static str_t *s;
  
	g_assert(size > 0);	

	if (NULL == s)
		s = str_new_not_leaking(0);

	str_vprintf(s, fmt, &args);
	return clamp_strcpy(dst, size, str_2c(s));
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

/**
 * Same as gm_snprintf() but with unchecked format string.
 *
 * @attention
 * Do not use unless ``fmt'' is a variable that cannot be used for
 * static argument list checking by gcc.
 */
size_t G_GNUC_PRINTF(3, 0)
gm_snprintf_unchecked(char *dst, size_t size, const char *fmt, ...)
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
string_vec_count(char *strv[])
{
	size_t i = 0;

	while (strv[i]) {
		i++;
	}
	return i;
}

static inline size_t
string_vec_size(char *strv[])
{
	size_t i = 0;
	size_t bytes = 0;

	while (strv[i]) {
		bytes += strlen(strv[i]) + 1;	/* Include trailing NUL */
		i++;
	}

	return bytes;
}

static void *
string_vec_strdup(char *orig[], int count, const char *dest[], void *mem)
{
	int i;

	for (i = 0; i < count; i++) {
		size_t len = strlen(orig[i]) + 1;
		void *p = mem;		/* Linearily increased allocation pointer */

		mem = ptr_add_offset(mem, len);
		clamp_strncpy(p, len, orig[i], len - 1);
		dest[i] = p;
	}

	dest[count] = NULL;
	return mem;
}

/**
 * Duplicate the original main() arguments + environment into read-only
 * memory, returning pointers to the argument vector, the environment and
 * the size of the argument vector.
 *
 * The gm_savemain() routine must be called first to record the original
 * argument pointers and gm_dupmain() must be called as soon as possible,
 * before alteration of the argument list or the passed environment.
 *
 * @param argv_ptr		where the allocated argment vector is returned
 * @param env_ptr		where the allocated environment is returned
 *
 * @return the amount of entries in the returned argv[]
 */
int
gm_dupmain(const char ***argv_ptr, const char ***env_ptr)
{
	size_t env_count, arg_count;
	size_t env_size, arg_size;
	size_t total_size;
	void *p, *q;
	const char **argv;
	const char **env;

	g_assert(orig_argv != NULL);	/* gm_savemain() was called */

	env_count = string_vec_count(orig_env);
	env_size = string_vec_size(orig_env);
	arg_count = orig_argc;
	arg_size = string_vec_size(orig_argv);

	total_size = (arg_count + env_count + 2) * sizeof(char *) +
		env_size + arg_size;

	p = vmm_alloc_not_leaking(total_size);
	argv = p;
	env = ptr_add_offset(argv, (arg_count + 1) * sizeof(char *));
	q = ptr_add_offset(env, (env_count + 1) * sizeof(char *));

	q = string_vec_strdup(orig_argv, arg_count, argv, q);
	q = string_vec_strdup(orig_env, env_count, env, q);

	g_assert(ptr_diff(q, p) == total_size);

	if (-1 == mprotect(p, total_size, PROT_READ))
		s_warning("%s(): cannot protect memory as read-only: %m", G_STRFUNC);

	*argv_ptr = argv;
	*env_ptr = env;

	return arg_count;
}

#if !defined(HAS_SETPROCTITLE)
/**
 * Compute the length of the exec() arguments that were given to us.
 *
 * @param argc The original ``argc'' argument from main().
 * @param argv The original ``argv'' argument from main().
 * @param env_ptr The original ``env'' variable.
 */
static iovec_t
gm_setproctitle_init(int argc, char *argv[], char *env_ptr[])
{
	size_t env_count, n;
	iovec_t *iov;

	g_assert(argc > 0);
	g_assert(argv);
	g_assert(env_ptr);

	env_count = string_vec_count(env_ptr);
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
		g_info("%zu bytes available for gm_setproctitle().", size);
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
	static iovec_t *args;
	static size_t n;

	if (!args) {
		iovec_t iov;
		
		iov = gm_setproctitle_init(orig_argc, orig_argv, orig_env);
		args = cast_to_pointer(iovec_base(&iov)); /* Solaris has caddr_t */
		n = iovec_len(&iov);
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
/*
 * Emulations for missing routines in glib 1.x to get/set glib's poll function.
 * They should be working substitutes given gtk-gnutella's usage pattern.
 */

static GPollFunc gpoll_func;

static gint
compat_poll_wrapper(GPollFD *ufds, uint nfsd, int timeout)
{
	return compat_poll((struct pollfd *) ufds, nfsd, timeout);
}

GPollFunc
g_main_context_get_poll_func(GMainContext *context)
{
	g_assert(NULL == context);

	if (NULL == gpoll_func) {
		gpoll_func = compat_poll_wrapper;
	}
	return gpoll_func;
}

void
g_main_context_set_poll_func(GMainContext *context, GPollFunc func)
{
	g_assert(NULL == context);

	gpoll_func = NULL == func ? compat_poll_wrapper : func;
	g_main_set_poll_func(gpoll_func);
}
#endif	/* USE_GLIB1 */

static void
gm_hash_table_all_keys_helper(void *key, void *unused_value, void *udata)
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
	void *udata;		/* Original user data */
};

static void
gm_hash_table_foreach_keys_helper(void *key, void *unused_value, void *udata)
{
	struct gm_hash_table_foreach_keys_helper *hp = udata;
	
	(void) unused_value;
	(*hp->func)(key, hp->udata);
}


/**
 * Apply function to all the keys of the hash table.
 */
void
gm_hash_table_foreach_key(GHashTable *ht, GFunc func, void *user_data)
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
	GList *l1, GList *l2, GCompareDataFunc compare_func, void *user_data)
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
	GList *list, GCompareDataFunc compare_func, void *user_data)
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

/**
 * Free GSList and nullify pointer holding it.
 */
void
gm_slist_free_null(GSList **sl_ptr)
{
	if (*sl_ptr != NULL) {
		g_slist_free(*sl_ptr);
		*sl_ptr = NULL;
	}
}

/**
 * Free GList and nullify pointer holding it.
 */
void
gm_list_free_null(GList **l_ptr)
{
	if (*l_ptr != NULL) {
		g_list_free(*l_ptr);
		*l_ptr = NULL;
	}
}

/**
 * Destroy GHashTable and nullify pointer holding it.
 */
void
gm_hash_table_destroy_null(GHashTable **h_ptr)
{
	if (*h_ptr != NULL) {
		g_hash_table_destroy(*h_ptr);
		*h_ptr = NULL;
	}
}

/***
 *** To ease the migration off GSList and GList (still used by the GUI layer).
 ***/

/**
 * Shallow cloning of a GSList into a pslist_t.
 */
pslist_t *
gm_slist_to_pslist(const GSList *list)
{
	const GSList *sl;
	pslist_t *pl = NULL;

	GM_SLIST_FOREACH(list, sl) {
		pl = pslist_prepend(pl, sl->data);
	}

	return pslist_reverse(pl);
}

/**
 * Shallow cloning of a pslist_t into a GSList.
 */
GSList *
gm_pslist_to_slist(const pslist_t *list)
{
	const pslist_t *pl;
	GSList *sl = NULL;

	PSLIST_FOREACH(list, pl) {
		sl = g_slist_prepend(sl, pl->data);
	}

	return g_slist_reverse(sl);
}

/***
 *** This set of routines must be kept at the tail of the file because they
 *** undefine malloc, g_malloc, etc... which are possibly set up by override.h.
 ***/

#ifdef USE_GLIB1
#if (defined(USE_HALLOC) || defined(TRACK_MALLOC) || defined(TRACK_ZALLOC) || \
		defined(REMAP_ZALLOC))

static GMemVTable gm_vtable;

#define GM_VTABLE_METHOD(method, params) \
	gm_vtable. method \
	 ? (gm_vtable. method params) \
	 : (method params)

#undef malloc
static inline ALWAYS_INLINE void *
gm_malloc(ulong size)
{
	return GM_VTABLE_METHOD(malloc, (size));
}

#undef calloc
static inline ALWAYS_INLINE void *
gm_malloc0(ulong size)
{
	return GM_VTABLE_METHOD(calloc, (1, size));
}

#undef realloc
static inline ALWAYS_INLINE void *
gm_realloc(void *p, ulong size)
{
	return GM_VTABLE_METHOD(realloc, (p, size));
}

#undef free
static inline ALWAYS_INLINE void
gm_free(void *p)
{
	return GM_VTABLE_METHOD(free, (p));
}

#define try_malloc malloc
static inline ALWAYS_INLINE void *
gm_try_malloc(ulong size)
{
	return GM_VTABLE_METHOD(try_malloc, (size));
}
#undef try_malloc

#define try_realloc realloc
static inline ALWAYS_INLINE void *
gm_try_realloc(void *p, ulong size)
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
void *
g_malloc(ulong size)
{
	if (G_LIKELY(size != 0)) {
		void *p = gm_malloc(size);

		if (p)
			return p;

		g_error("allocation of %lu bytes failed", size);
	}
	return NULL;
}

#undef g_malloc0
void *
g_malloc0(ulong size)
{

	if (G_LIKELY(size != 0)) {
		void *p = gm_malloc(size);

		if (p) {
			memset(p, 0, size);
			return p;
		}

		g_error("allocation of %lu bytes failed", size);
	}
	return NULL;
}

#undef g_realloc
void *
g_realloc(void *p, ulong size)
{
	void *n;

	if (G_UNLIKELY(0 == size)) {
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
g_free(void *p)
{
	gm_free(p);
}

#undef g_try_malloc
void *
g_try_malloc(ulong size)
{
	return size > 0 ? gm_try_malloc(size) : NULL;
}

#undef g_try_realloc
void *
g_try_realloc(void *p, ulong size)
{
	return size > 0 ? gm_try_realloc(p, size) : NULL;
}

/**
 * Emulates a calloc().
 */
static void *
emulate_calloc(gsize n, gsize m)
{
	void *p;

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
	gm_vtable.malloc = vtable->malloc;
	gm_vtable.realloc = vtable->realloc;
	gm_vtable.free = vtable->free;

	gm_vtable.calloc = vtable->calloc
		? vtable->calloc
		: emulate_calloc;
	gm_vtable.try_malloc = vtable->try_malloc
		? vtable->try_malloc
		: vtable->malloc;
	gm_vtable.try_realloc = vtable->try_realloc
		? vtable->try_realloc
		: vtable->realloc;
}

/**
 * Are we using system's malloc?
 */
bool
g_mem_is_system_malloc(void)
{
	return NULL == gm_vtable.malloc ||
		cast_pointer_to_func(gm_vtable.malloc) ==
			cast_pointer_to_func(real_malloc) ||
		cast_pointer_to_func(gm_vtable.malloc) ==
			cast_pointer_to_func(malloc);
}
#else
/**
 * Sets the GMemVTable to use for memory allocation.
 */
void
g_mem_set_vtable(GMemVTable *vtable)
{
	(void) vtable;

	g_error("%s() not supported in glib1", G_STRFUNC);
}

/**
 * Are we using system's malloc?
 */
bool
g_mem_is_system_malloc(void)
{
	return TRUE;		/* Remapping is not possible natively with glib1 */
}
#endif	/* USE_HALLOC || TRACK_MALLOC || TRACK_ZALLOC || REMAP_ZALLOC */
#endif	/* USE_GLIB1 */

/**
 * Safe reallocation routine during final memory cleanup.
 */
static inline void * G_GNUC_UNUSED
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
static inline void G_GNUC_UNUSED
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
#if defined(USE_HALLOC) || defined(TRACK_MALLOC) || defined(TRACK_ZALLOC) || \
		defined(REMAP_ZALLOC)
	static GMemVTable vtable;

	if (g_mem_is_system_malloc())
		return;

#undef malloc
#undef realloc
#undef free

	vtable.malloc = real_malloc;
	vtable.realloc = safe_realloc;
	vtable.free = safe_free;

	g_mem_set_vtable(&vtable);

#endif	/* USE_HALLOC || TRACK_MALLOC || TRACK_ZALLOC || REMAP_ZALLOC */
}

/* vi: set ts=4 sw=4 cindent: */
