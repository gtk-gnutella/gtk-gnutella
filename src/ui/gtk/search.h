/*
 * Copyright (c) 2001-2003, Richard Eckart
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

#ifndef _gtk_search_h_
#define _gtk_search_h_

#include "gui.h"
#include "if/ui/gtk/search.h"

struct bitzi_data;
struct filter;
struct gnet_host_vec;
struct host_addr;
struct record;
struct search;

/*
 * Global Functions
 */

void search_gui_init(void);
void search_gui_shutdown(void);

const GList *search_gui_get_searches(void);

gboolean search_gui_new_search_full(const char *query, unsigned mtype,
	time_t create_time, guint lifetime, guint32 reissue_timeout,
	int sort_col, int sort_order, guint32 flags, struct search **);

gboolean search_gui_new_browse_host(
	const char *hostname, struct host_addr addr, guint16 port,
	const struct guid *guid, const struct gnet_host_vec *proxies,
	guint32 flags);

struct search *search_gui_get_current_search(void);
void search_gui_store_searches(void);

void search_gui_start_search(struct search *);
gboolean search_gui_has_pending_downloads(const struct search *);

void search_gui_set_filter(struct search *, struct filter *);
struct filter *search_gui_get_filter(const struct search *);
int search_gui_get_sort_column(const struct search *);
int search_gui_get_sort_order(const struct search *);
const char *search_gui_query(const struct search *);
unsigned search_gui_media_type(const struct search *);

void search_gui_record_check(const struct record *);

/**
 * Metadata Update.
 */

void search_gui_metadata_update(const struct bitzi_data *);

#endif /* _gtk_search_h_ */

/* -*- mode: cc-mode; tab-width:4; -*- */
/* vi: set ts=4 sw=4 cindent: */
