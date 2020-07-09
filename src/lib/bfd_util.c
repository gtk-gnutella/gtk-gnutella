/*
 * Copyright (c) 2012 Raphael Manfredi
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
 * BFD library wrapper functions.
 *
 * This interface is a wrapping API on top of the BFD library which allows
 * to conveniently perform operations on a set of files within one execution
 * "environment".  All the resources are cleaned up when the environment is
 * released.
 *
 * Symbol resolution is typically a two-step operation:
 *
 * 1- Given a file where the symbol is supposedly located, get the BFD context
 *    for that file.
 *
 * 2- Query the BFD context for the address.
 *
 * The environment keeps all the underlying BFD files opened until it is
 * closed.  The environment of execution is typically the symbol extraction
 * from an executable to format a nice stack trace, for instance.
 *
 * Once the environment has been closed, all the BFD contexts are released
 * and any dangling reference to them becomes unusable.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#ifdef HAS_BFD_LIBRARY
/*
 * Starting with binutils 2.23, we need to define two symbols to be able
 * to compile with <bfd.h>.  It is a shame to have to go through contorsions
 * like that, but the BFD folks wish to keep their library unsuitable for
 * the general use.
 *
 * See https://sourceware.org/bugzilla/show_bug.cgi?id=15920
 *
 * Their mindset being what it is, let's be smarter and adapt.  There is no
 * way we are going to bloat our source tree by including a version of the BFD
 * sources, just to workaround a library design bug!
 *		--RAM, 2013-09-94
 *
 * There's no need to define the PACKAGE symbol: since it is present in a
 * comment, that metaconfig symbol will be automatically defined in config.h.
 */
#define PACKAGE_VERSION		/* PACKAGE is already a metaconfig symbol */

#include <bfd.h>

#undef PACKAGE_VERSION
#endif	/* HAS_BFD_LIBRARY */

#include "bfd_util.h"
#include "concat.h"
#include "mutex.h"
#include "once.h"
#include "path.h"
#include "symbols.h"
#include "vmm.h"			/* For vmm_page_start() */
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

#ifdef HAS_BFD_LIBRARY

/*
 * Deal with backward portability issue.
 *
 * The 'b' argument in bfd_get_section_vma() was ignored, so the
 * BFD library folks changed their macro definition to drop that
 * unused argument, causing a portability issue.
 *
 * Actually, the bfd_get_section_xxx() accessors are removed now
 * and only bfd_section_xxx() accessors exist, using only the section
 * as their sole parameter.
 * 		--RAM, 2020-03-16
 */
#ifdef HAS_BFD_SECTION_1ARG
/* New API, starting with BFD 2.34 */
#define BFD_UTIL_SECTION_FLAGS(b,s)	bfd_section_flags(s)
#define BFD_UTIL_SECTION_SIZE(s)	bfd_section_size(s)
#define BFD_UTIL_SECTION_VMA(b,s)	bfd_section_vma(s)
#else	/* !HAS_BFD_SECTION_1ARG */
/* Safe defaults, using the old API */
#define BFD_UTIL_SECTION_FLAGS(b,s)	bfd_get_section_flags((b),(s))
#define BFD_UTIL_SECTION_SIZE(s)	bfd_get_section_size(s)
#define BFD_UTIL_SECTION_VMA(b,s)	bfd_get_section_vma((b),(s))
#endif	/* HAS_BFD_SECTION_1ARG */

enum bfd_ctx_magic { BFD_CTX_MAGIC = 0x3bb7920e };

struct bfd_ctx {
	enum bfd_ctx_magic magic;	/* Magic number */
	bfd *handle;				/* Opened handle on binary file */
	asymbol **symbols;			/* Symbol table */
	size_t offset;				/* Memory mapping offset */
	symbols_t *text_symbols;	/* Text-only symbols */
	mutex_t lock;				/* Thread-safe access */
	unsigned symsize;			/* Symbol size in the symbols[] array */
	long count;					/* Amount of symbols in symbols[] */
	uint dynamic:1;				/* Whether symbols[] holds dynamic symbols */
	uint offseted:1;			/* Whether mapping offset was computed */
};

struct bfd_list {
	char *path;					/* Executable / library path */
	struct bfd_ctx *bc;			/* Opened binary context */
	struct bfd_list *next;		/* Next in list */
};

enum bfd_env_magic { BFD_ENV_MAGIC = 0x53378fa3 };

struct bfd_env {
	enum bfd_env_magic magic;	/* Magic number */
	struct bfd_list *head;		/* List of allocated contexts */
	mutex_t lock;				/* Lock for thread-safe access */
};

struct symbol_ctx {
	struct symbol_loc location;
	asymbol **symbols;
	bfd_vma addr;
};

static inline void
bfd_ctx_check(const struct bfd_ctx * const bc)
{
	g_assert(bc != NULL);
	g_assert(BFD_CTX_MAGIC == bc->magic);
}

static inline void
bfd_env_check(const struct bfd_env * const be)
{
	g_assert(be != NULL);
	g_assert(BFD_ENV_MAGIC == be->magic);
}

/**
 * Load text symbols from the file into supplied table.
 *
 * @param bc		the BFD context pointing to the file
 * @param st		the symbol table where symbols should be added
 */
static void
bfd_util_load_text(bfd_ctx_t *bc, symbols_t *st)
{
	long i;
	asymbol* empty;
	void *p;

	bfd_ctx_check(bc);
	g_assert(st != NULL);

	if (0 == bc->count)
		return;

	g_assert(bc->symbols != NULL);

	mutex_lock_fast(&bc->lock);
	empty = bfd_make_empty_symbol(bc->handle);
	mutex_unlock_fast(&bc->lock);

	symbols_lock(st);

	for (
		i = 0, p = bc->symbols;
		i < bc->count;
		i++, p = ptr_add_offset(p, bc->symsize)
	) {
		asymbol *sym;
		symbol_info syminfo;

		mutex_lock_fast(&bc->lock);
		sym = bfd_minisymbol_to_symbol(bc->handle, bc->dynamic, p, empty);
		bfd_get_symbol_info(bc->handle, sym, &syminfo);
		mutex_unlock_fast(&bc->lock);

		if ('T' == syminfo.type || 't' == syminfo.type) {
			const char *name = bfd_asymbol_name(sym);

			if (name != NULL && name[0] != '.') {
				void *addr = ulong_to_pointer(syminfo.value);
				symbols_append(st, addr, name);
			}
		}
	}

	symbols_unlock(st);
}

/**
 * Lookup callback.
 */
static void
bfd_util_lookup_section(bfd *b, asection *sec, void *data)
{
	struct symbol_ctx *sc = data;
	bfd_vma vma;

	if (sc->location.function != NULL)
		return;		/* Already found */

	if (0 == (BFD_UTIL_SECTION_FLAGS(b, sec) & SEC_ALLOC))
		return;

	vma = BFD_UTIL_SECTION_VMA(b, sec);

	if (sc->addr < vma || sc->addr >= BFD_UTIL_SECTION_SIZE(sec) + vma)
		return;

	bfd_find_nearest_line(b, sec, sc->symbols, sc->addr - vma,
		&sc->location.file, &sc->location.function, &sc->location.line);
}

/**
 * Locate a symbol at the given addres.
 *
 * @param bc		the BFD context retrieved by bfd_util_get_context()
 * @param addr		the address of the symbol
 * @param loc		where location information is returned
 *
 * @return TRUE if the symbol address was located.
 */
bool
bfd_util_locate(bfd_ctx_t *bc, const void *addr, struct symbol_loc *loc)
{
	struct symbol_ctx sc;
	const void *lookaddr;
	const char *name;

	g_assert(loc != NULL);

	if G_UNLIKELY(NULL == bc)
		return FALSE;

	bfd_ctx_check(bc);

	ZERO(&sc);
	lookaddr = const_ptr_add_offset(addr, bc->offset);
	sc.addr = pointer_to_ulong(lookaddr);
	sc.symbols = bc->symbols;

	bfd_map_over_sections(bc->handle, bfd_util_lookup_section, &sc);

	if (sc.location.function != NULL) {
		*loc = sc.location;		/* Struct copy */
		return TRUE;
	}

	/*
	 * For some reason the BFD library successfully loads symbols but is not
	 * able to locate them through bfd_map_over_sections().
	 *
	 * Load the symbol table ourselves and perform the lookup then.  We will
	 * only be able to fill the routine name, and not the source code
	 * information but that is better than nothing.
	 */

	mutex_lock_fast(&bc->lock);

	if (NULL == bc->text_symbols) {
		bc->text_symbols = symbols_make(bc->count, FALSE);
		mutex_unlock_fast(&bc->lock);

		bfd_util_load_text(bc, bc->text_symbols);
		symbols_sort(bc->text_symbols);
	} else {
		mutex_unlock_fast(&bc->lock);
	}

	name = symbols_name_only(bc->text_symbols, lookaddr, FALSE);
	if (name != NULL) {
		ZERO(loc);
		loc->function = name;
		return TRUE;
	}

	return FALSE;
}

/**
 * Check opened bfd for format.
 *
 * @return TRUE if it matches the format, FALSE otherwise.
 */
static bool
bfd_util_check_format(bfd *b, bfd_format fmt, const char *path)
{
	char **matching;
	unsigned i = 0;

	if (bfd_check_format(b, fmt))
		return TRUE;

	if (bfd_error_file_ambiguously_recognized != bfd_get_error())
		return FALSE;

	if (!bfd_check_format_matches(b, fmt, &matching))
		return FALSE;

	s_miniwarn("%s: ambiguous format matching for %s", G_STRFUNC, path);

	while (matching[i] != NULL) {
		s_miniwarn("%s: possible format is \"%s\"", G_STRFUNC, matching[i]);
		i++;
	}

	/* So we can use free() when TRACK_MALLOC is on */
	(void) MEMTRACK(matching, 1);

	free(matching);		/* Not xfree(), was allocated by bfd */
	return FALSE;
}

/**
 * Initialize the bfd context.
 *
 * @return TRUE if OK.
 */
static bool
bfd_util_open(bfd_ctx_t *bc, const char *path)
{
	static mutex_t bfd_library_mtx = MUTEX_INIT;
	bfd *b;
	void *symbols = NULL;
	unsigned size = 0;
	long count;
	int fd = -1;
	const char *libpath = path;

	/*
	 * On Debian systems, there is a debugging version of libraries held
	 * under /usr/lib/debug.  We'll get better symbol resolution by
	 * opening these instead of the usually stripped runtime versions
	 * that will only contain externally visible symbols.
	 */

	if (!is_running_on_mingw() && is_absolute_path(path)) {
		static char debugpath[MAX_PATH_LEN];
		const char *base = filepath_basename(path);

		concat_strings(ARYLEN(debugpath), "/usr/lib/debug/", base, NULL_PTR);

		fd = open(debugpath, O_RDONLY);
		if (-1 == fd) {
			concat_strings(ARYLEN(debugpath), "/usr/lib/debug", path, NULL_PTR);
			fd = open(debugpath, O_RDONLY);
		}
		if (-1 != fd)
			libpath = debugpath;
	}

	if (-1 == fd)
		fd = open(libpath, O_RDONLY);

	if (-1 == fd) {
		s_miniwarn("%s: can't open %s: %m", G_STRFUNC, libpath);
		return FALSE;
	}

	/*
	 * Protect calls to BFD opening: they don't appear to be fully
	 * thread-safe and we could enter here concurrently.
	 */

	mutex_lock_fast(&bfd_library_mtx);

	b = bfd_fdopenr(libpath, NULL, fd);
	if (NULL == b) {
		mutex_unlock_fast(&bfd_library_mtx);
		close(fd);
		return FALSE;
	}

	if (!bfd_util_check_format(b, bfd_object, libpath)) {
		s_miniwarn("%s: %s is not an object", G_STRFUNC, libpath);
		goto failed;
	}

	if (0 == (bfd_get_file_flags(b) & HAS_SYMS)) {
		s_miniwarn("%s: %s has no symbols", G_STRFUNC, libpath);
		goto failed;
	}

	count = bfd_read_minisymbols(b, FALSE, &symbols, &size);
	if (count <= 0) {
		bc->dynamic = TRUE;
		count = bfd_read_minisymbols(b, TRUE, &symbols, &size);
	}

	if (count >= 0)
		goto done;

	s_miniwarn("%s: unable to load symbols from %s ", G_STRFUNC, libpath);
	symbols = NULL;
	/* FALL THROUGH */

	/*
	 * We keep the context on errors to avoid logging them over and over
	 * each time we attempt to access the same file.  The BFD and system
	 * resources are released though.
	 */

failed:
	bfd_close(b);
	b = NULL;
	count = 0;
	/* FALL THROUGH */

done:
	mutex_unlock_fast(&bfd_library_mtx);

	bc->magic = BFD_CTX_MAGIC;
	bc->handle = b;
	bc->symbols = MEMTRACK(symbols, 1);		/* Allocated by the bfd library */
	bc->count = count;
	bc->symsize = size;
	mutex_init(&bc->lock);

	return TRUE;
}

/**
 * Close BFD context, releasing its resources and nullifying its pointer.
 */
static void
bfd_util_close_context_null(bfd_ctx_t **bc_ptr)
{
	bfd_ctx_t *bc = *bc_ptr;

	if (bc != NULL) {
		bfd_ctx_check(bc);

		mutex_lock(&bc->lock);	/* Not a fast mutex since we'll destroy it */

		if (bc->symbols != NULL)
			free(bc->symbols);	/* Not xfree(): created by the bfd library */

		/*
		 * On Windows, we apparently still need to avoid calling bfd_close()
		 * as this creates a SIGSEGV in the BFD library code.  Diagnosing
		 * such crashes on Windows is not easy, therefore using the fastpath
		 * of reverting to a known working solution, even though the root cause
		 * is still lurking and can cause instability (read: "random crashes").
		 * 		--RAM, 2020-03-22
		 */

		if (bc->handle != NULL) {
#ifdef MINGW32
			bfd_close_all_done(bc->handle);
#else
			bfd_close(bc->handle);
#endif
		}

		symbols_free_null(&bc->text_symbols);

		bc->magic = 0;
		mutex_destroy(&bc->lock);
		xfree(bc);
		*bc_ptr = NULL;
	}
}

/**
 * Get a binary file context for the given program / library path.
 */
static bfd_ctx_t *
bfd_util_get_bc(struct bfd_list **list, const char *path)
{
	struct bfd_list *item = *list;
	bfd_ctx_t bc, *bp;

	/*
	 * We're probably crashing, use simple data structures, and not a
	 * hash table / hash list here.  We're going to handle only a handful
	 * of modules, so linear lookups are perfectly OK.
	 */

	while (item != NULL) {
		if (0 == strcmp(path, item->path))
			return item->bc;
		item = item->next;
	}

	ZERO(&bc);

	if (!bfd_util_open(&bc, path))
		return NULL;

	bp = XCOPY(&bc);
	XMALLOC(item);
	item->bc = bp;
	item->path = xstrdup(path);

	/* Insert at head of list */

	item->next = *list;
	*list = item;

	return bp;
}

/**
 * Compute the mapping offset for the program / library.
 *
 * The .text section could say 0x500000 but the actual virtual memory
 * address where the library was mapped could be 0x600000.  Hence looking
 * for addresses at 0x6xxxxx would not create any match with the symbol
 * addresses held in the file.
 *
 * The base given here should be the actual VM address where the kernel
 * loaded the first section.
 *
 * The computed offset will then be automatically used to adjust the given
 * addresses being looked at, remapping them to the proper range for lookup
 * purposes.
 *
 * @param bc		the BFD context (NULL allowed for convenience)
 * @param base		the VM mapping address of the text segment
 */
void
bfd_util_compute_offset(bfd_ctx_t *bc, ulong base)
{
	asection *sec;
	bfd *b;

	if (NULL == bc)
		return;			/* Convenience */

	bfd_ctx_check(bc);

	if (bc->offseted || NULL == bc->handle)
		return;

	mutex_lock_fast(&bc->lock);

	if (bc->offseted) {
		mutex_unlock_fast(&bc->lock);
		return;
	}

	b = bc->handle;
	if (NULL == b) {
		mutex_unlock_fast(&bc->lock);
		return;
	}

	/*
	 * Take the first section of the file and look where its page would start.
	 * Then compare that to the advertised mapping base for the object to
	 * know the offset we have to apply for proper symbol resolution.
	 */

	sec = b->sections;

	/*
	 * Notes for later: sections are linked through sec->next.
	 *
	 * It is possible to gather the section name via:
	 *		const char *name = bfd_section_name(b, sec);
	 */

	if (sec != NULL) {
		bfd_vma addr = BFD_UTIL_SECTION_VMA(b, sec);

		bc->offset = ptr_diff(vmm_page_start(ulong_to_pointer(addr)),
			vmm_page_start(ulong_to_pointer(base)));
	}

	bc->offseted = TRUE;
	mutex_unlock_fast(&bc->lock);
}

/**
 * Free the whole list of binary contexts.
 */
static void
bfd_util_free_list(struct bfd_list *list)
{
	struct bfd_list *item = list;

	while (item != NULL) {
		struct bfd_list *next = item->next;
		xfree(item->path);
		bfd_util_close_context_null(&item->bc);
		item->next = NULL;
		xfree(item);
		item = next;
	}
}

/**
 * Initialze a BFD symbol lookup environment context.
 *
 * @return new context that will need to be closed with bfd_util_close_null().
 */
bfd_env_t *
bfd_util_init(void)
{
	static once_flag_t done;
	bfd_env_t *be;

	XMALLOC0(be);
	be->magic = BFD_ENV_MAGIC;
	mutex_init(&be->lock);

	ONCE_FLAG_RUN(done, bfd_init);

	return be;
}

/**
 * Get a binary file context for the given program / library path.
 *
 * @param be		the BFD environment created by bfd_util_init()
 * @param path		pathname of the program / library
 *
 * @return BFD context that can be queried for symbol resolution, NULL if
 * it is not possible to gather any information from the specified path.
 */
bfd_ctx_t *
bfd_util_get_context(bfd_env_t *be, const char *path)
{
	bfd_ctx_t *bc;

	bfd_env_check(be);
	g_assert(path != NULL);

	mutex_lock_fast(&be->lock);
	bc = bfd_util_get_bc(&be->head, path);
	mutex_unlock_fast(&be->lock);

	return bc;
}

/**
 * Are symbols available for this BFD context?
 */
bool
bfd_util_has_symbols(const bfd_ctx_t *bc)
{
	bfd_ctx_check(bc);

	return bc->symbols != NULL;
}

/**
 * Release the environment and its associated BFD contexts.
 */
static void
bfd_util_close(bfd_env_t *be)
{
	bfd_env_check(be);

	mutex_lock(&be->lock);		/* Not a fast mutex since we'll destroy it */
  	bfd_util_free_list(be->head);
	be->magic = 0;
	mutex_destroy(&be->lock);
	xfree(be);
}

/**
 * Close environment, freeing up all the associated resources, then nullifying
 * the referenced pointer.
 */
void
bfd_util_close_null(bfd_env_t **be_ptr)
{
	bfd_env_t *be = *be_ptr;

	if (be != NULL) {
		bfd_util_close(be);
		*be_ptr = NULL;
	}
}

/**
 * Load text symbols into the supplied symbol table from the specified file.
 *
 * This is equivalent to running "nm -p file" and parsing back the results
 * although we do not have to actually launch a new process and parse the
 * command output: the symbol extraction is handled by the BFD library.
 *
 * Symbols are merely appended to the symbol table, which will need to be
 * sorted before being
 *
 * @param st		the symbol table into which loaded symbols are added
 * @param file		the object file where symbols should be extracted from
 *
 * @return whether we could attempt loading from the file (regardless of the
 * presence of symbol information).
 */
bool
bfd_util_load_text_symbols(symbols_t *st, const char *file)
{
	bfd_env_t *be;
	bfd_ctx_t *bc;

	g_assert(st != NULL);
	g_assert(file != NULL);

	be = bfd_util_init();
	bc = bfd_util_get_context(be, file);
	if (bc != NULL)
		bfd_util_load_text(bc, st);

	bfd_util_close(be);
	return TRUE;
}

#else	/* !HAS_BFD_LIBRARY */

bfd_env_t *
bfd_util_init(void)
{
	return NULL;
}

bfd_ctx_t *
bfd_util_get_context(bfd_env_t *env, const char *path)
{
	g_assert(NULL == env);
	g_assert(path != NULL);

	return NULL;
}

bool
bfd_util_locate(bfd_ctx_t *bc, const void *addr, struct symbol_loc *loc)
{
	g_assert(loc != NULL);
	g_assert(NULL == bc);

	(void) addr;

	return FALSE;
}

bool
bfd_util_has_symbols(const bfd_ctx_t *bc)
{
	g_assert(NULL == bc);

	return FALSE;
}

void
bfd_util_compute_offset(bfd_ctx_t *bc, ulong base)
{
	g_assert(NULL == bc);
	(void) base;
}

bool
bfd_util_load_text_symbols(symbols_t *st, const char *filepath)
{
	g_assert(st != NULL);
	g_assert(filepath != NULL);

	return FALSE;
}

void
bfd_util_close_null(bfd_env_t **be_ptr)
{
	g_assert(NULL == *be_ptr);

	/* Nothing to do */
}

#endif	/* HAS_BFD_LIBRARY */

/* vi: set ts=4 sw=4 cindent: */
