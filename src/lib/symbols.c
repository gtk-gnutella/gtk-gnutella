/*
 * Copyright (c) 2004, 2010, 2012 Raphael Manfredi
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
 * Symbol address / name mapping.
 *
 * This structure allows the construction of symbolic stack traces.
 * It organizes symbols in a sorted array and allows quick mappings of
 * an address to a symbol.
 *
 * @author Raphael Manfredi
 * @date 2004, 2010, 2012
 */

#include "common.h"

#include "symbols.h"

#include "array_util.h"
#include "ascii.h"
#include "base16.h"
#include "bfd_util.h"
#include "constants.h"
#include "cstr.h"
#include "eslist.h"
#include "file.h"
#include "halloc.h"
#include "htable.h"
#include "log.h"
#include "misc.h"
#include "omalloc.h"
#include "parse.h"
#include "path.h"
#include "rwlock.h"
#include "sha1.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"
#include "tm.h"
#include "unsigned.h"
#include "vmm.h"
#include "xmalloc.h"
#include "xsort.h"

#include "override.h"			/* Must be the last header included */

#define SYMBOLS_SIZE_INCREMENT	1024	/**< # of entries added on resize */

enum symbols_magic { SYMBOLS_MAGIC = 0x546dd788 };

/**
 * The array of symbols.
 */
struct symbols {
	enum symbols_magic magic;	/**< Magic number */
	struct symbol *base;		/**< Array base */
	size_t size;				/**< Amount of entries allocated */
	size_t count;				/**< Amount of entries held */
	size_t offset;				/**< Symbol offset to apply */
	unsigned fresh:1;			/**< Symbols loaded via nm parsing */
	unsigned indirect:1;		/**< Symbols loaded via nm pre-computed file */
	unsigned stale:1;			/**< Pre-computed nm file was stale */
	unsigned mismatch:1;		/**< Symbol mismatches were identified */
	unsigned garbage:1;			/**< Symbols are probably pure garbage */
	unsigned sorted:1;			/**< Symbols were sorted */
	unsigned once:1;			/**< Whether symbol names are "once" atoms */
	rwlock_t lock;				/**< Thread-safe lock */
};

static inline void
symbols_check(const struct symbols * const s)
{
	g_assert(s != NULL);
	g_assert(SYMBOLS_MAGIC == s->magic);
}

#define SYMBOLS_READ_LOCK(x)	rwlock_rlock(deconstify_pointer(&(x)->lock))
#define SYMBOLS_READ_TRYLOCK(x)	rwlock_rlock_try(deconstify_pointer(&(x)->lock))
#define SYMBOLS_READ_UNLOCK(x)	rwlock_runlock(deconstify_pointer(&(x)->lock))

#define SYMBOLS_WRITE_LOCK(x)	rwlock_wlock(&(x)->lock)
#define SYMBOLS_WRITE_UNLOCK(x)	rwlock_wunlock(&(x)->lock)
#define SYMBOLS_WRITE_LOCKED(x)	rwlock_is_busy(&(x)->lock)

enum symbols_loadinfo_magic { SYMBOLS_LOADINFO_MAGIC = 0x4e1edc1d };

/**
 * This structure captures the symbol loading information if it happens early
 * and before symbols_set_verbose() is called.  It allows us to log what
 * happened after the fact.
 *
 * These structures are linked together to form a single list that will be
 * flushed to logs as soon as symbols_set_verbose() is called.
 */
struct symbols_loadinfo {
	enum symbols_loadinfo_magic magic;
	size_t count;
	size_t stripped;
	size_t offset;
	const char *path;
	const char *method;
	uint garbage:1;
	uint mismatch:1;
	double secs;
	tm_t when;
	slink_t list;				/* Embedded list */
};

static inline void
symbols_loadinfo_check(const struct symbols_loadinfo * const sli)
{
	g_assert(sli != NULL);
	g_assert(SYMBOLS_LOADINFO_MAGIC == sli->magic);
}

static const char NM_FILE[] = "gtk-gnutella.nm";
static bool symbols_verbose, symbols_verbose_set;
static eslist_t symbols_loaded =
	ESLIST_INIT(offsetof(struct symbols_loadinfo, list));
static spinlock_t symbols_loaded_slk = SPINLOCK_INIT;

#define SYMBOLS_LOADED_LOCK		spinlock(&symbols_loaded_slk)
#define SYMBOLS_LOADED_UNLOCK	spinunlock(&symbols_loaded_slk)

/**
 * Return string version of the self-assessed symbol quality.
 */
const char *
symbol_quality_string(const enum symbol_quality sq)
{
	switch (sq) {
	case SYMBOL_Q_GOOD:		return "good";
	case SYMBOL_Q_STALE:	return "stale";
	case SYMBOL_Q_MISMATCH:	return "mismatch";
	case SYMBOL_Q_GARBAGE:	return "garbage";
	case SYMBOL_Q_MAX:		break;
	}

	return "UNKNOWN";
}

/**
 * Export internal info from `sli' into user-visible `uli' structure.
 */
static void
symbols_export_info(
	struct symbol_load_info *uli,
	const struct symbols_loadinfo *sli)
{
#define UCP(x)	uli->x = sli->x

	UCP(count);
	UCP(stripped);
	UCP(offset);
	UCP(path);
	UCP(method);
	UCP(secs);
	UCP(when);

	if (sli->garbage)
		uli->quality = SYMBOL_Q_GARBAGE;
	else if (sli->mismatch)
		uli->quality = SYMBOL_Q_MISMATCH;
	else
		uli->quality = SYMBOL_Q_GOOD;

#undef UCP
}

/**
 * Iterate over the list of loaded symbols and invoke callback on each of
 * them.
 *
 * The callback will be invoked with a "struct symbol_load_info" data.
 *
 * @param cb	callback to invoke
 * @param udata	opaque user data supplied to callback
 */
void
symbols_load_foreach(cdata_fn_t cb, void *udata)
{
	const struct symbols_loadinfo *sli;

	SYMBOLS_LOADED_LOCK;

	ESLIST_FOREACH_DATA(&symbols_loaded, sli) {
		struct symbol_load_info uli;

		symbols_export_info(&uli, sli);
		(*cb)(&uli, udata);
	}

	SYMBOLS_LOADED_UNLOCK;
}

/**
 * Return information about the first symbol load operation, NULL if none.
 * This is a pointer to static data.
 */
const struct symbol_load_info *
symbols_load_first(void)
{
	const struct symbols_loadinfo *sli;
	static struct symbol_load_info uli;

	SYMBOLS_LOADED_LOCK;
	sli = eslist_head(&symbols_loaded);
	SYMBOLS_LOADED_UNLOCK;

	if (NULL == sli)
		return NULL;

	symbols_export_info(&uli, sli);

	return &uli;
}

/**
 * Log symbol loading if requested.
 */
static void
symbols_log_loaded(const struct symbols_loadinfo *sli)
{
	char buf[20];
	tm_t now;
	double ago;

	if (!symbols_verbose)
		return

	tm_now_exact(&now);
	ago = tm_elapsed_f(&now, &sli->when);

	buf[0] = '\0';
	if (ago != 0.0)
		str_bprintf(ARYLEN(buf), " %.3f secs ago", ago);

	s_info("loaded %zu symbol%s for \"%s\" via %s in %.3f secs%s",
		PLURAL(sli->count), sli->path, sli->method, sli->secs, buf);

	if (sli->stripped != 0)
		s_message("stripped %zu duplicate symbol%s", PLURAL(sli->stripped));
	if (sli->offset != 0) {
		s_message("will be offsetting symbol addresses by 0x%lx (%ld)",
			(unsigned long) sli->offset, (long) sli->offset);
	}
	if (sli->garbage) {
		s_warning("loaded symbols are pure garbage");
	} else if (sli->mismatch) {
		s_warning("loaded symbols are partially inaccurate");
	}
}

/**
 * Record loading of symbols unless symbols_set_verbose() was called already,
 * otherwise just log the information.
 */
static void
symbols_notify_loaded(const char *path,
	const char *method, size_t count, size_t stripped, size_t offset,
	bool garbage, bool mismatch, double secs)
{
	struct symbols_loadinfo *sli;

	/*
	 * This information is recorded and never gets freed.
	 *
	 * In case of a crash later, we'll peruse this information and propagate
	 * it into the crash log so that we know how confident we can be about
	 * the symbolic information we are logging.
	 *
	 * If everything goes well, there must be only one single loading of
	 * the symbols for each path, hence we can use omalloc() to allocate
	 * that structure.
	 */

	OMALLOC0(sli);
	sli->magic = SYMBOLS_LOADINFO_MAGIC;
	sli->path = ostrdup_readonly(path);
	sli->method = method;	/* Since `method' points to static string */
	sli->count = count;
	sli->stripped = stripped;
	sli->offset = offset;
	sli->garbage = booleanize(garbage);
	sli->mismatch = booleanize(mismatch);
	sli->secs = secs;
	tm_now_exact(&sli->when);

	SYMBOLS_LOADED_LOCK;
	eslist_append(&symbols_loaded, sli);
	SYMBOLS_LOADED_UNLOCK;

	if (!symbols_verbose_set)
		return;

	symbols_log_loaded(sli);
}

/**
 * eslist foreach callback to log and dispose of structure.
 */
static void
symbols_loaded_process(void *data, void *udata)
{
	struct symbols_loadinfo *sli = data;

	symbols_loadinfo_check(sli);
	(void) udata;

	symbols_log_loaded(sli);
}

/**
 * Should symbol loading be verbosely notified?
 */
void
symbols_set_verbose(bool verbose)
{
	symbols_verbose = verbose;

	SYMBOLS_LOADED_LOCK;

	if (!symbols_verbose_set) {
		symbols_verbose_set = TRUE;
		eslist_foreach(&symbols_loaded, symbols_loaded_process, NULL);
	}

	SYMBOLS_LOADED_UNLOCK;
}

/**
 * @return amount of symbols
 */
size_t
symbols_count(const symbols_t *st)
{
	symbols_check(st);

	/*
	 * This routine must not take any locks, so read the symbol count after
	 * issuing a memory barrier: another thread could be in the process of
	 * loading symbols, in which case the write-lock is taken and we'd block
	 * getting the read lock, risking a deadlock if we already hold locks.
	 */

	atomic_mb();
	return st->count;
}

/**
 * @return memory size used by symbols.
 */
size_t
symbols_memory_size(const symbols_t *st)
{
	size_t mem;

	symbols_check(st);

	SYMBOLS_READ_LOCK(st);
	mem = st->size * sizeof st->base[0];
	SYMBOLS_READ_UNLOCK(st);

	return mem;
}

/**
 * Mark symbols as being stale.
 */
void
symbols_mark_stale(symbols_t *st)
{
	symbols_check(st);

	SYMBOLS_WRITE_LOCK(st);
	st->stale = TRUE;
	SYMBOLS_WRITE_UNLOCK(st);
}

/**
 * Allocate a new table capable of holding the specified amount of entries.
 *
 * @param capacity		the projected size of the table (0 if unknown)
 * @param once			if TRUE, symbol names will be allocated via omalloc()
 *
 * @return new symbol table.
 */
symbols_t *
symbols_make(size_t capacity, bool once)
{
	symbols_t *s;
	size_t len;

	g_assert(size_is_non_negative(capacity));

	XMALLOC0(s);
	s->magic = SYMBOLS_MAGIC;
	s->once = booleanize(once);
	s->size = capacity;
	rwlock_init(&s->lock);

	len = capacity * sizeof s->base[0];

	if (len != 0)
		s->base = once ? vmm_alloc_not_leaking(len) : vmm_alloc(len);

	return s;
}

/**
 * Free symbol table.
 */
static void
symbols_free(symbols_t *st)
{
	symbols_check(st);

	vmm_free(st->base, st->size * sizeof st->base[0]);
	rwlock_destroy(&st->lock);
	st->magic = 0;
	xfree(st);
}

/**
 * Free symbol table and nullify its pointer.
 */
void
symbols_free_null(symbols_t **st_ptr)
{
	symbols_t *st = *st_ptr;

	if (st != NULL) {
		symbols_free(st);
		*st_ptr = NULL;
	}
}

/**
 * Normalize the symbol name.
 *
 * @param name		the origin name as reported by "nm" or similar means
 * @param atom		whether to create an atom
 *
 * @return atom string for the trace name (never freed) or a plain copy which
 * will need to be freed via xfree().
 */
static const char *
symbols_normalize(const char *name, bool atom)
{
	const char *result;
	const char *dot;
	char *tmp = NULL;

	/*
	 * On Windows and OS X, there is an obnoxious '_' prepended to all
	 * routine names.
	 */

	if ('_' == name[0])
		name++;

	/*
	 * gcc sometimes appends '.part' or other suffix to routine names.
	 */

	dot = vstrchr(name, '.');
	tmp = NULL == dot ? deconstify_char(name) : xstrndup(name, dot - name);

	/*
	 * On Windows, since the C calling convention used does not allow
	 * variable-length argument lists, the linker appends '@n' to the name
	 * where 'n' is the number of parameters expected.  This prevents a
	 * routine from being called with the wrong number of arguments, since
	 * the stack would be irremediably messed up if that happened.  If some
	 * code attempts to call the routine with the wrong number of arguments,
	 * the linker will report a name mismatch, preventing havoc.
	 *
	 * For symbol tracing purposes, the '@n' is just noise, so we remove it.
	 * on the fly.
	 */

	if (is_running_on_mingw() && tmp == name) {
		dot = vstrchr(name, '@');
		tmp = NULL == dot ? deconstify_char(name) : xstrndup(name, dot - name);
	}

	if (atom) {
		result = constant_str(tmp);
		if (tmp != name)
			xfree(tmp);
	} else {
		result = tmp == name ? xstrdup(name) : tmp;
	}

	return result;
}

/**
 * Append a new symbol to the table.
 *
 * @attention
 * This routine MUST be called with the symbol table write-locked
 *
 * @param st		the symbol table
 * @param addr		the address of the symbol
 * @param name		the name of the symbol
 */
void
symbols_append(symbols_t *st, const void *addr, const char *name)
{
	struct symbol *s;

	symbols_check(st);
	g_assert(name != NULL);
	g_assert(rwlock_is_owned(&st->lock));

	if (st->count >= st->size) {
		size_t osize, nsize;

		osize = st->size * sizeof st->base[0];
		st->size += SYMBOLS_SIZE_INCREMENT;
		nsize = st->size * sizeof st->base[0];

		if (0 == osize) {
			st->base = st->once ?
				vmm_alloc_not_leaking(nsize) : vmm_alloc(nsize);
		} else {
			st->base = st->once ?
				vmm_resize_not_leaking(st->base, osize, nsize) :
				vmm_resize(st->base, osize, nsize);
		}
	}

	s = &st->base[st->count++];
	s->addr = addr;
	s->name = symbols_normalize(name, st->once);
	st->sorted = FALSE;
}

/**
 * Compare two symbol entries -- qsort() callback.
 */
static int
symbol_cmp(const void *p, const void *q)
{
	struct symbol const *a = p;
	struct symbol const *b = q;

	return ptr_cmp(a->addr, b->addr);
}

/**
 * Remove duplicate entry in trace array at the specified index.
 */
static void
symbols_remove(symbols_t *st, size_t i)
{
	symbols_check(st);
	g_assert(size_is_non_negative(i));
	g_assert(rwlock_is_owned(&st->lock));

	if (!st->once)
		xfree(deconstify_pointer(st->base[i].name));

	ARRAY_REMOVE_DEC(st->base, i, st->count);
}

/**
 * Sort trace array, remove duplicate entries.
 *
 * @return amount of stripped duplicates.
 */
size_t
symbols_sort(symbols_t *st)
{
	size_t i = 0;
	size_t ocount;
	const void *last = NULL;
	size_t osize, nsize;

	symbols_check(st);

	SYMBOLS_WRITE_LOCK(st);

	ocount = st->count;

	if G_UNLIKELY(st->sorted || 0 == st->count)
		goto done;

	xqsort(st->base, st->count, sizeof st->base[0], symbol_cmp);

	while (i < st->count) {
		struct symbol *s = &st->base[i];
		if (last != NULL && s->addr == last) {
			symbols_remove(st, i);
		} else {
			last = s->addr;
			i++;
		}
	}

	/*
	 * Resize or free arena depending on how many symbols we have left.
	 */

	osize = st->size * sizeof st->base[0];
	nsize = st->count * sizeof st->base[0];

	if (nsize != 0) {
		st->base = st->once ?
			vmm_resize_not_leaking(st->base, osize, nsize) :
			vmm_resize(st->base, osize, nsize);
	} else {
		vmm_free(st->base, osize);
		st->base = NULL;
	}

	st->size = st->count;
	st->sorted = TRUE;

done:
	ocount -= st->count;
	SYMBOLS_WRITE_UNLOCK(st);

	return ocount;
}

/**
 * Lookup symbol structure encompassing given address.
 *
 * @return symbol structure if found, NULL otherwise.
 */
static struct symbol *
symbols_lookup(const symbols_t *st, const void *addr)
{
	struct symbol *low, *high, *mid;
	const void *laddr;

	symbols_check(st);

	if G_UNLIKELY(0 == st->count)
		return NULL;

	low = st->base,
	high = &st->base[st->count - 1],

	laddr = const_ptr_add_offset(addr, st->offset);

	while (low <= high) {
		mid = low + (high - low) / 2;
		if (laddr >= mid->addr && (mid == high || laddr < (mid+1)->addr))
			return mid;
		else if (laddr < mid->addr)
			high = mid - 1;		/* -1 OK, since pointers cannot reach page 0 */
		else
			low = mid + 1;
	}

	return NULL;	/* Not found */
}

/**
 * Find symbol, avoiding the last entry (supposed to be the end) and
 * ignoring garbage / stale symbol tables.
 *
 * @attention
 * This routine must be called with the symbols read-locked at least.
 *
 * @param st		the symbol table
 * @param pc		the PC within the routine
 *
 * @return symbol structure if found, NULL otherwise.
 */
static struct symbol *
symbols_find(const symbols_t *st, const void *pc)
{
	struct symbol *s;

	symbols_check(st);

	if G_UNLIKELY(!st->sorted || 0 == st->count)
		return NULL;

	if G_UNLIKELY(st->garbage || st->mismatch || st->stale)
		return NULL;

	s = symbols_lookup(st, pc);

	if (NULL == s || &st->base[st->count - 1] == s)
		return NULL;

	return s;
}

/**
 * Format pointer into specified buffer.
 *
 * This is equivalent to saying:
 *
 *    gm_snprintf(buf, buflen, "0x%lx", pointer_to_ulong(pc));
 *
 * but is safe to use in a signal handler.
 */
static void
symbols_fmt_pointer(char *buf, size_t buflen, const void *p)
{
	if (buflen < 4) {
		buf[0] = '\0';
		return;
	}

	pointer_to_string_buf(p, buf, buflen);
}

/**
 * Format "name+offset" into specified buffer.
 *
 * This is equivalent to saying:
 *
 *    gm_snprintf(buf, buflen, "%s+%u", name, offset);
 *
 * but is safe to use in a signal handler.
 */
static void
symbols_fmt_name(char *buf, size_t buflen, const char *name, size_t offset)
{
	size_t namelen;

	namelen = cstr_lcpy(buf, buflen, name);
	if (namelen >= buflen - 2)
		return;		/* No room for adding any offset */

	if (offset != 0) {
		buf[namelen] = '+';
		size_t_to_string_buf(offset, &buf[namelen+1], buflen - (namelen + 1));
	}
}

/*
 * Attempt to transform a PC (Program Counter) address into a symbolic name,
 * showing the function name and the offset within that routine.
 *
 * When the symbols are probable garbage, the name has a leading '?', and
 * the hexadecimal address follows the name between parenthesis.
 *
 * When the symbols may be inaccurate, the name has a leading '!'.
 *
 * When the symbols were loaded from a stale source, the name has a leading '~'.
 *
 * The way formatting is done allows this routine to be used from a
 * signal handler.
 *
 * @param st		the symbol table (may be NULL)
 * @param pc		the PC to translate into symbolic form
 * @param offset	whether decimal offset should be added, in symbolic form.
 *
 * @return symbolic name for given pc offset, if found, otherwise
 * the hexadecimal value.
 */
const char *
symbols_name(const symbols_t *st, const void *pc, bool offset)
{
	static char buf[THREAD_MAX][128];
	static char emergency[128];
	unsigned stid = thread_safe_small_id();
	char *b;

	STATIC_ASSERT(sizeof buf[0] == sizeof emergency);

	b = stid >= THREAD_MAX ? emergency : &buf[stid][0];

	if G_UNLIKELY(NULL == st) {
		symbols_fmt_pointer(b, sizeof buf[0], pc);
		return b;
	}

	symbols_check(st);

	if (!SYMBOLS_READ_TRYLOCK(st)) {
		symbols_fmt_pointer(b, sizeof buf[0], pc);
		goto done;
	} else if G_UNLIKELY(!st->sorted || 0 == st->count) {
		SYMBOLS_READ_UNLOCK(st);
		symbols_fmt_pointer(b, sizeof buf[0], pc);
	} else {
		struct symbol *s;

		s = symbols_lookup(st, pc);

		if (NULL == s || &st->base[st->count - 1] == s) {
			SYMBOLS_READ_UNLOCK(st);
			symbols_fmt_pointer(b, sizeof buf[0], pc);
		} else {
			size_t off = 0;
			const void *addr = const_ptr_add_offset(pc, st->offset);
			bool garbage;

			if ((garbage = st->garbage)) {
				b[0] = '?';
				off = 1;
			} else if (st->mismatch) {
				b[0] = '!';
				off = 1;
			} else if (st->stale) {
				b[0] = '~';
				off = 1;
			}

			symbols_fmt_name(&b[off], sizeof buf[0] - off, s->name,
				offset ? ptr_diff(addr, s->addr) : 0);

			SYMBOLS_READ_UNLOCK(st);

			/*
			 * If symbols are garbage, add the hexadecimal pointer to the
			 * name so that we have a little chance of figuring out what
			 * the routine was.
			 */

			if (garbage) {
				char ptr[POINTER_BUFLEN + CONST_STRLEN(" ()")];

				cstr_lcpy(ARYLEN(ptr), " (");
				pointer_to_string_buf(pc, ARYPOSLEN(ptr, 2));
				clamp_strcat(ARYLEN(ptr), ")");
				clamp_strcat(b, sizeof buf[0], ptr);
			}
		}
	}

	/* FALL THROUGH */

done:
	return b;
}

/**
 * Compute starting address of routine.
 *
 * @param st		the symbol table (may be NULL)
 * @param pc		the PC within the routine
 *
 * @return start of the routine, NULL if we cannot find it.
 */
const void *
symbols_addr(const symbols_t *st, const void *pc)
{
	struct symbol *s;
	const void *p;

	if G_UNLIKELY(NULL == st)
		return NULL;

	symbols_check(st);

	if (!SYMBOLS_READ_TRYLOCK(st))
		return NULL;	/* Avoid deadlocks if symbols still being loaded */

	s = symbols_find(st, pc);
	p = NULL == s ? NULL : const_ptr_add_offset(s->addr, st->offset);

	SYMBOLS_READ_UNLOCK(st);

	return p;
}

/**
 * Light version of the symbols_name_only() routine which attempts to minimize
 * the resources required to compute the information.
 *
 * This is light in that there is no need to format, and that we do not
 * attempt to lock the symbols, only bailing out when the symbols are
 * already write-locked.
 *
 * This can cause races and this routine should only be used during crashing,
 * to help translate information about PC and stack traces into digestable
 * names.
 *
 * @param st		the symbol table
 * @param pc		the PC to translate into symbolic form
 * @param offset	where offset is written, if non-NULL
 *
 * @return symbolic name for given pc offset, if found, NULL otherwise.
 */
const char *
symbols_name_light(const symbols_t *st, const void *pc, size_t *offset)
{
	struct symbol *s;

	symbols_check(st);

	if (SYMBOLS_WRITE_LOCKED(st))
		return NULL;		/* Already locked, symbols being loaded */

	s = symbols_find(st, pc);

	if (NULL == s)
		return NULL;

	if (offset != NULL)
		*offset = ptr_diff(const_ptr_add_offset(pc, st->offset), s->addr);

	return s->name;
}

/*
 * Lookup name of routine.
 *
 * @param st		the symbol table
 * @param pc		the PC to translate into symbolic form
 * @param offset	whether decimal offset should be added, if non-zero
 *
 * @return symbolic name for given pc offset, if found, NULL otherwise.
 */
const char *
symbols_name_only(const symbols_t *st, const void *pc, bool offset)
{
	static char buf[THREAD_MAX][128];
	static char emergency[128];
	unsigned stid = thread_safe_small_id();
	char *b;
	struct symbol *s;
	const void *addr;
	const char *name = NULL;

	STATIC_ASSERT(sizeof buf[0] == sizeof emergency);

	b = stid >= THREAD_MAX ? emergency : &buf[stid][0];

	symbols_check(st);

	if (!SYMBOLS_READ_TRYLOCK(st))
		return NULL;	/* Avoid deadlocks if symbols still being loaded */

	s = symbols_find(st, pc);

	if (NULL == s)
		goto done;

	if (offset) {
		/* Need to format string into a thread-private buffer */
		name = b;
		addr = const_ptr_add_offset(pc, st->offset);
		symbols_fmt_name(b, sizeof buf[0], s->name, ptr_diff(addr, s->addr));
	} else {
		name = s->name;		/* Already a constant string, is thread-safe */
	}

done:
	SYMBOLS_READ_UNLOCK(st);

	return name;
}

/**
 * Construct a hash table that maps back a symbol name to its address.
 *
 * The returned hash table can be freed up via htable_free_null().
 *
 * @return new hash table mapping a symbol name to its address.
 */
static htable_t *
symbols_by_name(const symbols_t *st)
{
	htable_t *ht;
	size_t i;

	symbols_check(st);

	ht = htable_create(HASH_KEY_STRING, 0);

	for (i = 0; i < st->count; i++) {
		struct symbol *s = &st->base[i];
		htable_insert_const(ht, s->name, s->addr);
	}

	return ht;
}

#define FN(x) \
	{ func_cast(func_ptr_t, x), STRINGIFY(x) }

/**
 * Known symbols that we want to check.
 */
static struct {
	func_ptr_t fn;				/**< Function address */
	const char *name;			/**< Function name */
} symbols_known[] = {
	FN(constant_str),
	FN(halloc_init),
	FN(htable_create),
	FN(is_strprefix),
	FN(log_abort),
	FN(make_pathname),
	FN(parse_pointer),
	FN(pointer_to_string_buf),
	FN(s_info),
	FN(short_size),
	FN(str_bprintf),
	FN(symbols_sort),
	FN(vmm_init),
	FN(xmalloc_is_malloc),
	FN(xsort),

	/* Above line intentionally left black for vi sorting */
};

#undef FN

/**
 * Check whether symbols that need to be defined in the program (either because
 * they are well-known like main() or used within this file) are consistent
 * with the symbols we loaded.
 *
 * Sets ``mismatch'' if we find at least 1 mismatch.
 * Sets ``garbage'' if we find more than half mismatches.
 */
static void
symbols_check_consistency(symbols_t *st)
{
	size_t matching = 0;
	size_t mismatches;
	size_t i;
	size_t offset = 0;
	htable_t *sym_pc;
	const void *main_pc;
	const char routine[] = "symbols_load_from";

	/*
	 * Reset the values we're computing since we can be called multiple
	 * times when we try to load symbols from multiple sources.
	 */

	st->garbage = FALSE;
	st->offset = 0;
	st->mismatch = FALSE;

	if (0 == st->count)
		return;

	/*
	 * On some systems, symbols are not mapped at absolute addresses but
	 * are relocated.
	 *
	 * To detect this: we locate the address of our probing routines and
	 * compare them with what we loaded from the symbols.  Of course,
	 * offsetting will only be working when the offset is the same for all
	 * the symbols.
	 */

	sym_pc = symbols_by_name(st);

	/*
	 * Compute the initial offset for symbols_load_from().
	 */

	main_pc = htable_lookup(sym_pc, routine);

	if (NULL == main_pc) {
		s_warning("cannot find %s() in the loaded symbols", routine);
		st->garbage = TRUE;
		goto done;
	}

	offset = ptr_diff(main_pc, func_to_pointer(symbols_load_from));

	/*
	 * Make sure the offset is constant among all our probed symbols.
	 */

	for (i = 0; i < N_ITEMS(symbols_known); i++) {
		const char *name = symbols_known[i].name;
		const void *pc = cast_func_to_pointer(symbols_known[i].fn);
		const void *loaded_pc = htable_lookup(sym_pc, name);
		size_t loaded_offset;

		if (NULL == loaded_pc) {
			s_warning("cannot find %s() in the loaded symbols", name);
			st->garbage = TRUE;
			goto done;
		}

		loaded_offset = ptr_diff(loaded_pc, pc);

		if (loaded_offset != offset) {
			s_warning("will not offset symbol addresses (loaded garbage?)");
			offset = 0;
			break;
		}
	}

	st->offset = offset;

	/*
	 * Now verify whether we can match symbols.
	 */

	for (i = 0; i < N_ITEMS(symbols_known); i++) {
		struct symbol *s;
		const void *pc = cast_func_to_pointer(symbols_known[i].fn);

		s = symbols_lookup(st, pc);

		if (s != NULL) {
			const char *name = symbols_known[i].name;
			if (0 == strcmp(name, s->name))
				matching++;
		}
	}

	g_assert(size_is_non_negative(matching));
	g_assert(matching <= N_ITEMS(symbols_known));

	mismatches = N_ITEMS(symbols_known) - matching;

	if (mismatches != 0) {
		if (mismatches >= N_ITEMS(symbols_known) / 2) {
			st->garbage = TRUE;
		} else {
			st->mismatch = TRUE;
		}
	}

	/*
	 * Note that our algorithm cannot find any mismatch if we successfully
	 * computed a valid offset above since by construction this means we were
	 * able to find a common offset between the loaded symbol addresses and
	 * the actual ones, meaning the lookup algorithm of trace_lookup() will
	 * find the proper symbols.
	 */

	g_soft_assert_log(0 == offset || 0 == mismatches,
		"offset=%zu, mismatches=%zu", offset, mismatches);

done:
	htable_free_null(&sym_pc);
}

/**
 * Parse the nm output line, recording symbol mapping for function entries.
 *
 * We're looking for lines like:
 *
 *	082bec77 T zget
 *	082be9d3 t zn_create
 *
 * We skip symbols starting with a ".", since this is not a valid C identifier
 * but rather an internal linker symbol (such as ".text").
 */
static void
symbols_parse_nm(symbols_t *st, char *line)
{
	int error;
	const char *ep;
	char *p = line;
	const void *addr;

	addr = parse_pointer(p, &ep, &error);
	if (error || NULL == addr)
		return;

	p = skip_ascii_blanks(ep);

	if ('t' == ascii_tolower(*p)) {
		p = skip_ascii_blanks(&p[1]);

		/*
		 * Pseudo-symbols such as ".text" can have the same address as a
		 * real symbol and could be the ones actually being kept when we
		 * strip duplicates.  Hence make sure these pseudo-symbols are skipped.
		 */

		if ('.' != *p) {
			strchomp(p, 0);
			symbols_append(st, addr, p);
		}
	}
}

/**
 * Computes the SHA1 of the specified file.
 *
 * @param file		the file for which we want to compute the SHA1
 * @param digest	where the digest is written
 *
 * @return TRUE if we successfully compute the SHA1.
 */
static bool
symbols_sha1(const char *file, struct sha1 *digest)
{
	int fd;
	SHA1_context ctx;

	fd = file_open(file, O_RDONLY, 0);
	if (-1 == fd)
		return FALSE;

	SHA1_reset(&ctx);

	for (;;) {
		char buf[512];
		int r;

		r = read(fd, ARYLEN(buf));

		if (-1 == r) {
			close(fd);
			return FALSE;
		}

		SHA1_input(&ctx, buf, r);

		if (r != sizeof buf)
			break;
	}

	close(fd);
	SHA1_result(&ctx, digest);

	return TRUE;
}

/**
 * Read line (or up to "size - 1" characters) from the file into the buffer.
 *
 * The line is NUL-terminated.
 *
 * @param f		the file we're reading from
 * @param buf	the buffer where we're storing the line
 * @param size	the size of the buffer
 *
 * @return TRUE if we read the whole line, FALSE if we did not reach the end
 * of the line before reaching the end of the buffer.
 */
static bool
symbols_read_line(FILE *f, char *buf, size_t size)
{
	size_t len = 0;

	while (len < size) {
		int c = getc(f);
		if (EOF == c)
			return FALSE;
		if ('\n' == c)
			break;
		buf[len++] = c;
	}

	if (len < size) {
		buf[len] = '\0';
		return TRUE;
	}

	return FALSE;
}

/**
 * Parse NM header from file and fill in nm[] with the two SHA1 header lines
 * we find (one for the executable's SHA1, one for the stripped version).
 *
 * @param f		opened file where we expect to read the NM HTTP-like header
 * @param nm	array where read SHA1s are stored.
 *
 * @return TRUE if we successfully parsed the header and found the two SHA1,
 * FALSE otherwise.
 * If successful, the file's read pointer is left after the header.
 */
static bool
symbols_extract_sha1(FILE *f, struct sha1 nm[2])
{
	char line[512];
	int i = 0;

	if (!symbols_read_line(f, ARYLEN(line)))
		return FALSE;

	/*
	 * Our NM header, if present, starts with "NM/1.0".
	 */

	if (0 != strcmp(line, "NM/1.0"))
		return FALSE;				/* Not a valid NM header */

	/*
	 * Minimal parsing of the header, looking for SHA1: lines only.
	 *
	 * We strive to use a little resources as possible, since this code
	 * can run during assertion failures.
	 *
	 * We expect exactly two SHA1 lines, each bearing an hexadecimal
	 * representataion of a SHA1.  One of the SHA1 is for the executable,
	 * the other is for the stripped executable, the order being unspecified.
	 *
	 * Embedding the NM header at the top of the pre-computed nm output allows
	 * to safely detect whether the symbols match the executable, without
	 * having to compare timestamps.
	 *		--RAM, 2013-10-03
	 */

	while (symbols_read_line(f, ARYLEN(line))) {
		char *p;

		if ('\0' == line[0])		/* Reached end of header */
			return 2 == i;			/* OK if we read the two SHA1 */

		if (!is_ascii_alnum(line[0]))
			return FALSE;			/* HTTP header starts with letter/digit */

		p = is_strcaseprefix(line, "SHA1");

		if (NULL == p) {
			if (NULL == vstrchr(line, ':'))
				return FALSE;		/* Not an HTTP header */
			continue;
		}

		/* Found a SHA1: header line */

		p = skip_ascii_spaces(p);
		if (*p != ':')
			return FALSE;

		p = skip_ascii_spaces(p + 1);

		/* Decode the hexadecimal representation of the SHA1 */

		if (i >= 2)
			return FALSE;

		if (
			SHA1_RAW_SIZE !=
				base16_decode(&nm[i++], SHA1_RAW_SIZE, p, vstrlen(p))
		)
			return FALSE;
	}

	return FALSE;
}

/**
 * Parse NM header of opened file to check whether it contains symbols for
 * the specified executable.
 *
 * We exepect an "NM" HTTP-like header with "SHA1:" lines stating the
 * hexadecimal SHA1 of the executable and that of its stripped version.
 *
 * @param f		opened symbol file
 * @param exe	the executable path
 *
 * @return TRUE if the executable matches the advertised SHA1, FALSE otherwise.
 * When we return TRUE, the file's read buffer is positionned right after the
 * end of the header, in order to hide the header from the processing logic
 * that will follow.
 */
static bool
symbols_header_check(FILE *f, const char *exe)
{
	struct sha1 digest;
	struct sha1 nm[2];

	if (!symbols_sha1(exe, &digest))
		return FALSE;

	if (!symbols_extract_sha1(f, nm))
		return FALSE;

	if (0 != sha1_cmp(&digest, &nm[0]) && 0 != sha1_cmp(&digest, &nm[1]))
		return FALSE;

	return TRUE;
}

/**
 * Open specified file containing code symbols.
 *
 * @param exe	the executable path, to assess freshness of nm file
 * @param nm	the path to the nm file, symbols from the executable
 *
 * @return opened file if successful, NULL on error with the error already
 * logged appropriately.
 */
static FILE *
symbols_open(symbols_t *st, const char *exe, const char *nm)
{
	FILE *f;

	st->stale = FALSE;

	f = fopen(nm, "r");

	if (NULL == f) {
		s_warning("can't open \"%s\": %m", nm);
	} else {
		if (!symbols_header_check(f, exe)) {
			s_warning("file \"%s\" not holding symbols for \"%s\"", nm, exe);
			fclose(f);
			f = NULL;
		}
	}

	/*
	 * If the file is still opened, the first unread character is the
	 * one after the NM header.
	 */

	return f;
}

/**
 * Load symbols from the executable we're running.
 *
 * Symbols are loaded even if the executable is not "fresh" or if the
 * "gtk-gnutella.nm" file is older than the executable.  The rationale is
 * that it is better to have some symbols than none, in the hope that the
 * ones we list will be roughly correct.
 *
 * In any case, stale or un-fresh symbols will be clearly marked in the
 * stack traces we emit, so that there cannot be any doubt later one when
 * we analyze stacks and they seem inconsistent or impossible.  The only
 * limitation is that we cannot know which symbols are correct, so all symbols
 * will be flagged as doubtful when we detect the slightest inconsistency.
 *
 * @param st			the symbol table into which symbols should be loaded
 * @param exe			the executable file
 * @param lpath			the executable name for logging purposes only
 */
void G_COLD
symbols_load_from(symbols_t *st, const char *exe, const  char *lpath)
{
	char tmp[MAX_PATH_LEN + 80];
	FILE *f;
	bool retried = FALSE;
	bool has_bfd = FALSE;
	size_t stripped;
	const char *method = "nothing";
	tm_t start, end;

	symbols_check(st);

	tm_now_exact(&start);

	SYMBOLS_WRITE_LOCK(st);

	/*
	 * If we are compiled with the BFD library, try to load symbols directly
	 * from the executable.
	 */

	has_bfd = bfd_util_load_text_symbols(st, exe);

	if (has_bfd && 0 != st->count) {
		method = "the BFD library";
		goto done;
	}

	/*
	 * Maybe we don't have the BFD library, or the executable was stripped.
	 *
	 * On Windows we'll try to open the companion file containing the computed
	 * "nm output" at build time.
	 *
	 * On UNIX we attempt to launch "nm -p" on the executable before falling
	 * back to the computed "nm output".
	 */

#ifdef MINGW32
	/*
	 * Open the "gtk-gnutella.nm" file nearby the executable.
	 */

	{
		const char *nm;

		nm = mingw_filename_nearby(NM_FILE);
		f = symbols_open(st, exe, nm);

		if (NULL == f)
			goto done;

		st->indirect = TRUE;
		method = "pre-computed nm output";
	}
#else	/* !MINGW32 */
	/*
	 * Launch "nm -p" on our executable to grab the symbols.
	 */

	if (!has_bfd) {
		size_t rw;
		const char meta[] = "$&`;()<>|";
		const char *p = exe;
		int c;

		/*
		 * Make sure there are no problematic shell meta-characters in the path.
		 */

		while ((c = *p++)) {
			if (vstrchr(meta, c)) {
				s_warning("found shell meta-character '%c' in path \"%s\", "
					"not loading symbols", c, exe);
				goto use_pre_computed;
			}
		}

		rw = str_bprintf(ARYLEN(tmp), "nm -p %s", exe);
		if (rw != vstrlen(exe) + CONST_STRLEN("nm -p ")) {
			s_warning("full path \"%s\" too long, cannot load symbols", exe);
			goto use_pre_computed;
		}

		f = popen(tmp, "r");

		if (NULL == f) {
			s_warning("can't run \"%s\": %m", tmp);
			goto use_pre_computed;
		}

		st->fresh = !st->stale;
		method = "nm output parsing";
	} else {
		goto use_pre_computed;
	}
#endif	/* MINGW32 */

retry:
	while (fgets(ARYLEN(tmp), f)) {
		symbols_parse_nm(st, tmp);
	}

	if (retried || is_running_on_mingw())
		fclose(f);
	else
		pclose(f);

	/*
	 * If we did not load any symbol, maybe the executable was stripped?
	 * Try to open the symbols from the installed nm file.
	 */

use_pre_computed:

	if (!retried && (0 == st->count || st->garbage)) {
		char *nm = make_pathname(ARCHLIB_EXP, NM_FILE);

		s_warning("%s, trying with pre-computed \"%s\"",
			0 == st->count ? "no symbols loaded" : "garbage symbols", nm);

		st->fresh = FALSE;
		f = symbols_open(st, exe, nm);
		retried = TRUE;
		HFREE_NULL(nm);

		if (f != NULL) {
			st->indirect = TRUE;
			method = "pre-computed nm output";
			goto retry;
		}

		if (st->garbage)
			goto unlock;		/* Already went through the "done" part */

		/* FALL THROUGH */
	}

done:
	stripped = symbols_sort(st);
	tm_now_exact(&end);

	symbols_check_consistency(st);

	symbols_notify_loaded(lpath, method, st->count, stripped,
		st->offset, st->garbage, st->mismatch,
		tm_elapsed_f(&end, &start));

	/*
	 * If symbols are garbage, retry with pre-computed symbol file.
	 *
	 * This usually happens when the executable has been stripped at
	 * installation time but the BFD library still manages to find a
	 * few symbols.
	 */

	if (!retried && !st->indirect && st->garbage)
		goto use_pre_computed;

unlock:
	SYMBOLS_WRITE_UNLOCK(st);
}

/**
 * Return self-assessed symbol quality.
 */
enum symbol_quality
symbols_quality(const symbols_t *st)
{
	symbols_check(st);

	if (st->garbage)
		return SYMBOL_Q_GARBAGE;
	else if (st->mismatch)
		return SYMBOL_Q_MISMATCH;
	else if (st->stale)
		return SYMBOL_Q_STALE;
	else
		return SYMBOL_Q_GOOD;
}

/**
 * Write-lock symbols.
 */
void
symbols_lock(symbols_t *st)
{
	symbols_check(st);
	SYMBOLS_WRITE_LOCK(st);
}

/**
 * Write-unlock symbols.
 */
void
symbols_unlock(symbols_t *st)
{
	symbols_check(st);
	SYMBOLS_WRITE_UNLOCK(st);
}

/* vi: set ts=4 sw=4 cindent: */
