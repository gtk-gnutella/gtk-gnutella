/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

#ifndef _gtk_search_h_
#define _gtk_search_h_

#include "gui.h"
#include "filter_core.h"

#include "if/core/search.h"
#include "if/core/bitzi.h"
#include "lib/hashlist.h"
#include "lib/slist.h"
#include "lib/prop.h"

/**
 * Structure for search results.
 */
struct search {
    gnet_search_t search_handle;	/**< Search handle */

#ifdef USE_GTK2
	GtkTreeView  *tree;				/**< GtkTreeView for this search */
#else
	GtkCTree   *tree;			   	/**< GtkCTree for this search */
#endif /* USE_GTK2 */

	GHashTable *parents;			/**< table of mount iterators for
										 any seen SHA1 */
	GtkWidget  *scrolled_window;	/**< GtkScrolledWindow, contains
										 the GtkCList */
    GtkWidget  *arrow;				/**< The arrow displaying sort order */

    gint        sort_col;
    gint        sort_order;
    gboolean    sort;

	time_t      last_update_time;	/**< last time notebook tab was updated */
	guint32     last_update_items;	/**< # of items included in last update */
	gint        tab_updating;		/**< ID for timeout func. to be cancelled */
	guint32     unseen_items;		/**< How many items haven't been seen yet */

	GHashTable *dups;				/**< keep a record of dups. */

    filter_t   *filter;				/**< filter ruleset bound to this search */

	slist_t	*queue;					/**< records to be inserted */

	/*
	 * Search stats.
	 */

	guint32     items;				/**< Total number of items for the search */
	guint32		tcp_qhits;			/**< Query hits received from TCP */
	guint32		udp_qhits;			/**< Query hits received from UDP */
	guint32		skipped;			/**< Ignored hits (skipped over) */
	guint32		ignored;			/**< Filtered out hits */
	guint32		hidden;				/**< Hidden hits, never shown */
	guint32		auto_downloaded;	/**< Auto-downloaded hits */
	guint32		duplicates;			/**< Duplicate hits ignored */
};

#include "search_common.h"

#ifdef USE_GTK1

/**
 *	Record associated with each gui node in the search results ctree.
 */
typedef struct gui_record {
	record_t *shared_record;		/**< Common record data, shared between
										 searches */

	gint num_children;				/**< Number of children under this node */
} gui_record_t;

#endif /* USE_GTK1 */


/*
 * Global Functions
 */

void search_gui_init(void);
void search_gui_shutdown(void);

gboolean search_gui_new_search_full(const gchar *query,
	time_t create_time, guint lifetime, guint32 reissue_timeout,
	gint sort_col, gint sort_order, flag_t flags, struct search **);
struct search *search_new_full(const gchar *, guint32, flag_t flags);
void search_gui_close_search(struct search *);

void search_gui_clear_search(struct search *);
void search_gui_remove_search(struct search *);
void search_gui_reset_search(struct search *);
void search_gui_download_files(void);
void search_gui_discard_files(void);

void search_gui_sort_column(struct search *, gint column);

void search_gui_add_record(struct search *, record_t *, enum gui_color);

gboolean gui_search_update_tab_label(struct search *);
void gui_search_clear_results(void);

#ifdef USE_GTK2
void gui_search_force_update_tab_label(struct search *, time_t now);
void search_gui_request_bitzi_data(void);
const record_t *search_gui_get_record_at_path(GtkTreeView *, GtkTreePath *);
#else
void gui_search_force_update_tab_label(struct search *);
#endif /* USE_GTK2 */

void search_gui_expand_all(void);
void search_gui_collapse_all(void);

void gui_search_set_enabled(struct search *, gboolean enabled);
const GList *search_gui_get_searches(void);

void search_gui_set_clear_button_sensitive(gboolean flag);

void search_gui_start_massive_update(struct search *);
void search_gui_end_massive_update(struct search *);

/**
 * Metadata Update.
 */

void search_gui_metadata_update(const bitzi_data_t *);
void search_gui_queue_bitzi_by_sha1(const record_t *);

#endif /* _gtk_search_h_ */

/* -*- mode: cc-mode; tab-width:4; -*- */
/* vi: set ts=4 sw=4 cindent: */
