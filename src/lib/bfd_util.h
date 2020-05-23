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
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _bfd_util_h_
#define _bfd_util_h_

struct bfd_ctx;
typedef struct bfd_ctx bfd_ctx_t;

struct bfd_env;
typedef struct bfd_env bfd_env_t;

/**
 * A symbol location, as filled by bfd_util_locate().
 */
struct symbol_loc {
	const char *function;
	const char *file;
	unsigned line;
};

/*
 * Public interface.
 */

bfd_env_t *bfd_util_init(void);
bfd_ctx_t *bfd_util_get_context(bfd_env_t *be, const char *path);
bool bfd_util_locate(bfd_ctx_t *bc, const void *pc, struct symbol_loc *loc);
bool bfd_util_has_symbols(const bfd_ctx_t *bc);
void bfd_util_close_null(bfd_env_t **be_ptr);
void bfd_util_compute_offset(bfd_ctx_t *bc, ulong base);

struct symbols;

bool bfd_util_load_text_symbols(struct symbols *st, const char *file);

#endif	/* _bfd_util_h_ */

/* vi: set ts=4 sw=4 cindent: */

