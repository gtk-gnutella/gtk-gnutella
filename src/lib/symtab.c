/*
 * Copyright (c) 2010, Raphael Manfredi
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
 * Symbol table.
 *
 * A symbol table is conceptually a name/value table, but with an additional
 * feature: each name (symbol) is associated with a depth level and an entry
 * at level n+1 will shadow an entry at level n, until the level n+1 is
 * left, at which time all symbols defined at that level are freed up.
 *
 * The depth level corresponds to the "lexical scope" of the symbol.
 *
 * A symbol defined at an outer lexcical scope is visible at an inner one
 * until it is superseded by a shadowing entry, at which time that new value
 * is the one seen.
 *
 * The table forbids redefinition of a symbol at the same lexical scope.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"

#include "symtab.h"

#include "nv.h"
#include "pslist.h"
#include "unsigned.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

enum symtab_magic { SYMTAB_MAGIC = 0x3e264d27U };

/**
 * A symbol table.
 *
 * Entries at new lexical depths are prepended to the list and are therefore
 * visible before those made at outer levels.
 */
struct symtab {
	enum symtab_magic magic;
	nv_table_t *table;			/**< Maps "name" -> symtab_value */
};

static inline void
symtab_check(const struct symtab * const syt)
{
	g_assert(syt != NULL);
	g_assert(SYMTAB_MAGIC == syt->magic);
}

enum symtab_value_magic { SYMTAB_VALUE_MAGIC = 0x46864892U };

/**
 * Values in the symbol table.
 */
struct symtab_value {
	enum symtab_value_magic magic;
	pslist_t *symbols;				/**< List of symbol_entry */
};

static inline void
symtab_value_check(const struct symtab_value * const sv)
{
	g_assert(sv != NULL);
	g_assert(SYMTAB_VALUE_MAGIC == sv->magic);
}

enum symbol_entry_magic { SYMBOL_ENTRY_MAGIC = 0x0733a191U };

/**
 * A symbol entry.
 *
 * The value of the symbol is application-specific.
 */
struct symbol_entry {
	enum symbol_entry_magic magic;
	nv_pair_t *symbol;			/**< name / opaque value */
	unsigned depth;				/**< Lexical scope depth */
};

static inline void
symbol_entry_check(const struct symbol_entry * const se)
{
	g_assert(se != NULL);
	g_assert(se->magic == SYMBOL_ENTRY_MAGIC);
}

/**
 * Allocate a new symbol entry.
 */
static struct symbol_entry *
symbol_entry_alloc(nv_pair_t *symbol, unsigned depth)
{
	struct symbol_entry *se;

	WALLOC0(se);
	se->magic = SYMBOL_ENTRY_MAGIC;
	se->symbol = symbol;
	se->depth = depth;

	return se;
}

/**
 * Free a symbol entry.
 */
static void
symbol_entry_free(struct symbol_entry *se)
{
	symbol_entry_check(se);
	if (se->symbol != NULL)
		nv_pair_free(se->symbol);
	se->magic = 0;
	WFREE(se);
}

/**
 * Allocate a new symtab_value.
 */
static struct symtab_value *
symtab_value_alloc(void)
{
	struct symtab_value *sv;

	WALLOC0(sv);
	sv->magic = SYMTAB_VALUE_MAGIC;

	return sv;
}

/**
 * Free a symtab_value.
 */
static void
symtab_value_free(struct symtab_value *sv)
{
	pslist_t *sl;

	symtab_value_check(sv);

	PSLIST_FOREACH(sv->symbols, sl) {
		symbol_entry_free(sl->data);
	}
	pslist_free_null(&sv->symbols);
	sv->magic = 0;
	WFREE(sv);
}

/**
 * Create new symbol table.
 */
symtab_t *
symtab_make(void)
{
	symtab_t *syt;

	WALLOC(syt);
	syt->magic = SYMTAB_MAGIC;
	syt->table = nv_table_make(FALSE);

	return syt;
}

/**
 * nv_table_t iterator to free values from the symbol table.
 */
static bool
symtab_free_nv(nv_pair_t *nv, void *data)
{
	struct symtab_value *sv;

	(void) data;

	sv = nv_pair_value(nv);
	symtab_value_free(sv);
	nv_pair_free(nv);

	return TRUE;
}

/**
 * Destroy symbol table.
 */
void
symtab_free(symtab_t *syt)
{
	symtab_check(syt);

	nv_table_foreach_remove(syt->table, symtab_free_nv, NULL);
	nv_table_free_null(&syt->table);
	syt->magic = 0;
	WFREE(syt);
}

/**
 * Destroy symbol table and nullify its pointer.
 */
void
symtab_free_null(symtab_t **syt_ptr)
{
	symtab_t *syt = *syt_ptr;

	if (syt != NULL) {
		symtab_free(syt);
		*syt_ptr = NULL;
	}
}

/**
 * Lookup symbol in table.
 *
 * @param syt		the symbol table
 * @param name		the symbol name
 *
 * @return the (opaque) symbol value, or NULL if not found.
 */
void *
symtab_lookup(const symtab_t *syt, const char *name)
{
	nv_pair_t *nv;

	symtab_check(syt);
	g_assert(name != NULL);

	nv = nv_table_lookup(syt->table, name);
	if (nv != NULL) {
		struct symtab_value *sv = nv_pair_value(nv);
		struct symbol_entry *se;

		symtab_value_check(sv);
		g_assert(sv->symbols != NULL);	/* Or entry would have been removed */

		se = sv->symbols->data;
		symbol_entry_check(se);

		return nv_pair_value(se->symbol);
	}

	return NULL;
}

struct symtab_leave_ctx {
	unsigned depth;
};

/**
 * nv_table_t iterator to remove out-of-scope symbols from the symbol table.
 */
static bool
symtab_leave_nv(nv_pair_t *nv, void *data)
{
	struct symtab_value *sv;
	struct symtab_leave_ctx *ctx = data;

	sv = nv_pair_value(nv);
	symtab_value_check(sv);

	while (sv->symbols != NULL) {
		struct symbol_entry *se = sv->symbols->data;

		symbol_entry_check(se);

		/*
		 * List is ordered, inner levels come first.
		 */

		if (se->depth < ctx->depth)
			break;

		sv->symbols = pslist_remove(sv->symbols, se);
		symbol_entry_free(se);
	}

	if (NULL == sv->symbols) {
		symtab_value_free(sv);
		nv_pair_free(nv);
		return TRUE;
	}

	return FALSE;	/* Symbols remain defined at an outer depth, keep name */
}

/**
 * Leave lexical scope, freeing all symbols whose depth is greater than or equal
 * to the one specified (a depth of 0 freeing all symbols).
 */
void
symtab_leave(symtab_t *syt, unsigned depth)
{
	struct symtab_leave_ctx ctx;

	symtab_check(syt);

	ctx.depth = depth;
	nv_table_foreach_remove(syt->table, symtab_leave_nv, &ctx);
}

/**
 * Insert symbol in table, at specified depth.
 *
 * A shallow copy of the symbol's value is made.
 * If an identical symbol exists at the same depth, the operation fails.
 *
 * @param syt		the symbol table
 * @param symbol	the symbol name/value to insert
 * @param depth		symbol's lexical depth
 *
 * @return whether symbol was inserted (FALSE indicating a duplicate).
 */
bool
symtab_insert_pair(symtab_t *syt, nv_pair_t *symbol, unsigned depth)
{
	nv_pair_t *nv;
	struct symbol_entry *se;
	struct symtab_value *sv;
	bool existed = FALSE;
	const char *name;

	symtab_check(syt);
	g_assert(symbol != NULL);

	/*
	 * Create all the objects, assuming insertion will be successful.
	 */

	se = symbol_entry_alloc(symbol, depth);
	name = nv_pair_name(symbol);

	nv = nv_table_lookup(syt->table, name);
	if (nv != NULL) {
		sv = nv_pair_value(nv);
		existed = TRUE;
	} else {
		/* Insertion will not fail since symbol does not exist yet */
		sv = symtab_value_alloc();
		nv = nv_pair_make_nocopy(name, sv, sizeof *sv);
	}

	if (sv->symbols != NULL) {
		struct symbol_entry *pse = sv->symbols->data;

		symbol_entry_check(pse);

		/*
		 * List is ordered, inner levels come first.
		 */

		if (pse->depth >= depth) {
			/*
			 * Insertion cannot happen: we have a symbol already present in
			 * the table at a depth greater than or equal to the specified one.
			 *
			 * Free the already created objects and signal insertion failure.
			 */

			se->symbol = NULL;		/* We did not allocate it! */
			symbol_entry_free(se);
			return FALSE;
		}
	}

	/*
	 * Inner-depth symbol inserted at the head of the list.
	 */

	sv->symbols = pslist_prepend(sv->symbols, se);

	if (!existed)
		nv_table_insert_pair(syt->table, nv);

	return TRUE;
}

/**
 * Insert symbol in table, at specified depth.
 *
 * A shallow copy of the symbol's value is made.
 * If an identical symbol exists at the same depth, the operation fails.
 *
 * @param syt		the symbol table
 * @param name		the symbol name (string, copied)
 * @param value		the symbol's value (opaque structure)
 * @param len		size of the value
 * @param depth		symbol's lexical depth
 *
 * @return whether symbol was inserted (FALSE indicating a duplicate).
 */
bool
symtab_insert(symtab_t *syt,
	const char *name, void *value, size_t len, unsigned depth)
{
	nv_pair_t *symbol;

	symtab_check(syt);
	g_assert(name != NULL);
	g_assert(value != NULL);
	g_assert(size_is_positive(len));

	symbol = nv_pair_make(name, value, len);

	if (symtab_insert_pair(syt, symbol, depth))
		return TRUE;

	nv_pair_free(symbol);
	return FALSE;
}

/* vi: set ts=4 sw=4 cindent: */
