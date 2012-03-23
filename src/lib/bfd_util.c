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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * BFD library wrapper functions.
 *
 * This interface is a wrapping API on top of the BFD library which allows
 * to conveniently perform operations on a set of files withing one execution
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
 * closed.  The environment of execution is typically symbol extraction
 * from an executable to format a nice stack trace, for instance.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#ifdef HAS_BFD_LIBRARY
#include <bfd.h>
#endif

#include "bfd_util.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

#ifdef HAS_BFD_LIBRARY

enum bfd_ctx_magic { BFD_CTX_MAGIC = 0x3bb7920e };

struct bfd_ctx {
	enum bfd_ctx_magic magic;	/* Magic number */
	bfd *handle;				/* Opened handle on binary file */
	asymbol **symbols;			/* Symbol table */
	long count;					/* Amount of symbols */
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
 * Lookup callback.
 */
static void
bfd_util_lookup_section(bfd *b, asection *sec, void *data)
{
	struct symbol_ctx *sc = data;
	bfd_vma vma;

	if (sc->location.function != NULL)
		return;		/* Already found */

	if (0 == (bfd_get_section_flags(b, sec) & SEC_ALLOC))
		return;

	vma = bfd_get_section_vma(b, sec);
	if (sc->addr < vma || sc->addr >= bfd_get_section_size(sec) + vma)
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

	g_assert(loc != NULL);

	if G_UNLIKELY(NULL == bc)
		return FALSE;

	bfd_ctx_check(bc);

	ZERO(&sc);
	sc.addr = pointer_to_ulong(addr);
	sc.symbols = bc->symbols;

	bfd_map_over_sections(bc->handle, bfd_util_lookup_section, &sc);

	if (sc.location.function != NULL) {
		*loc = sc.location;		/* Struct copy */
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
	bfd *b;
	void *symbols = NULL;
	unsigned x = 0;
	long count;
	int fd;

	fd = open(path, O_RDONLY);
	if (-1 == fd) {
		s_miniwarn("%s: can't open %s: %m", G_STRFUNC, path);
		return FALSE;
	}

	b = bfd_fdopenr(path, NULL, fd);
	if (NULL == b) {
		close(fd);
		return FALSE;
	}

	if (!bfd_util_check_format(b, bfd_object, path)) {
		s_miniwarn("%s: %s is not an object", G_STRFUNC, path);
		goto failed;
	}

	if (0 == (bfd_get_file_flags(b) & HAS_SYMS)) {
		s_miniwarn("%s: %s has no symbols", G_STRFUNC, path);
		goto failed;
	}

	count = bfd_read_minisymbols(b, FALSE, &symbols, &x);
	if (count <= 0)
		count = bfd_read_minisymbols(b, TRUE, &symbols, &x);

	if (count < 0) {
		s_miniwarn("%s: unable to load symbols from %s ", G_STRFUNC, path);
		symbols = NULL;
		count = 0;
	}

	bc->magic = BFD_CTX_MAGIC;
	bc->handle = b;
	bc->symbols = symbols;		/* Allocated by the bfd library */
	bc->count = count;

	return TRUE;

failed:
	bfd_close(b);
	return FALSE;
}

/**
 * Close BFD context, releasing its resources and nullifying its pointer.
 */
static void
bfd_util_close_context_null(bfd_ctx_t **bc_ptr)
{
	bfd_ctx_t *bc = *bc_ptr;

	if (bc != NULL) {
		if (bc->symbols != NULL)
			free(bc->symbols);	/* Not xfree(): created by the bfd library */

		/*
		 * We use bfd_close_all_done() and not bfd_close() because the latter
		 * causes a SIGSEGV now that we are using bfd_fdopenr(). The fault
		 * occurs in some part trying to write changes to the file...
		 *
		 * Since the file is opened as read-only and we don't expect any
		 * write operation, using bfd_close_all_done() is a viable workaround
		 * for this BFD library bug.
		 */

		bfd_close_all_done(bc->handle);		/* Workaround for BFD bug */
		bc->magic = 0;
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

	if (!bfd_util_open(&bc, path))
		return NULL;

	bp = xcopy(&bc, sizeof bc);
	item = xmalloc(sizeof *item);
	item->bc = bp;
	item->path = xstrdup(path);

	/* Insert at head of list */

	item->next = *list;
	*list = item;

	return bp;
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
	static bool done;
	bfd_env_t *be;

	XMALLOC0(be);
	be->magic = BFD_ENV_MAGIC;

	if (!done) {
		bfd_init();
		done = TRUE;
	}

	return be;
}

/**
 * Get a binary file context for the  given program / library path.
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
	bfd_env_check(be);
	g_assert(path != NULL);

	return bfd_util_get_bc(&be->head, path);
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

  	bfd_util_free_list(be->head);
	be->magic = 0;
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
bfd_util_close_null(bfd_env_t **be_ptr)
{
	g_assert(NULL == *be_ptr);

	/* Nothing to do */
}

#endif	/* HAS_BFD_LIBRARY */

/* vi: set ts=4 sw=4 cindent: */
