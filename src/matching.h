/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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

#ifndef _matching_h_
#define _matching_h_

#include "ui_core_interface_matching_defs.h"
#include "ui_core_interface_share_defs.h"

struct query_hashvec;

void matching_init(void);
void matching_close(void);


guint query_make_word_vec(const gchar *query, word_vec_t **wovec);
void query_word_vec_free(word_vec_t *wovec, guint n);

guint match_map_string(char_map_t map, gchar *string);


cpattern_t *pattern_compile(gchar *pattern);
void pattern_free(cpattern_t *cpat);
gchar *pattern_qsearch(cpattern_t *cpat,
	gchar *text, guint32 tlen, guint32 toffset, qsearch_mode_t word);


void st_initialize(search_table_t *, char_map_t);
void st_create(search_table_t *table);
void st_destroy(search_table_t *);
void st_insert_item(search_table_t *, const gchar *, void *);
void st_compact(search_table_t *);

/* FIXME: The type of this callback is too specific. */
typedef gboolean (*st_search_callback)(shared_file_t *);

gint st_search(
	search_table_t *table,
	gchar *search,
	st_search_callback callback,
	gint max_res,
	struct query_hashvec *qhv);

#endif	/* _matching_h_ */

/* vi: set ts=4: */
