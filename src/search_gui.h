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

#ifndef _search_gui_h_
#define _search_gui_h_

#include "gui.h"

#include <time.h>
#include "filter.h"

#include "search_gui_common.h"

/* 
 * Structure for search results 
 */
typedef struct search {
    gnet_search_t search_handle; /* Search handle */

	gchar      *query;			   /* The search query */
	gboolean    enabled;

#ifdef USE_GTK2
	GtkWidget  *tree_view;			   /* GtkCList for this search */
	GHashTable *parents;	/* table of mount iterators for any seen SHA1 */
#else
	GtkWidget  *clist;			   /* GtkCList for this search */
#endif
	GtkWidget  *scrolled_window;   /* GtkScrolledWindow, contains the GtkCList */
	GtkWidget  *list_item;		   /* The GtkListItem in combo for this search */
    GtkWidget  *arrow;             /* The arrow displaying sort order  */

    gint        sort_col;
    gint        sort_order;
    gboolean    sort;

	time_t      last_update_time;  /* last time the notebook tab was updated */
	guint32     last_update_items; /* Number of items included in last update */
	gint        tab_updating;	   /* token for timeout func. to be cancelled */
	guint32     unseen_items;	   /* How many items haven't been seen yet. */

	gboolean    passive;		   /* Is this a passive search? */

	GSList     *r_sets;			   /* The results sets of this search */
	GHashTable *dups;			   /* keep a record of dups. */
	guint32     items;			   /* Total number of items for this search */

    filter_t   *filter;				/* filter ruleset bound to this search */
} search_t;



/*
 * Global Data
 */
extern GtkWidget *dialog_filters;
extern guint32 search_passive;
extern GList *searches;			/* List of search structs */
#ifdef USE_GTK2
extern GtkWidget *default_search_tree_view;
#else
extern GtkWidget *default_search_clist;
#endif
extern time_t tab_update_time;
extern search_t *search_selected;




/*
 * Global Functions
 */

void search_gui_init(void);
void search_gui_shutdown(void);

gboolean search_gui_new_search(
	const gchar *, flag_t flags, search_t **search);
gboolean search_gui_new_search_full(
	const gchar *query, guint16 speed,
	guint32 reissue_timeout, gint sort_col, 
	gint sort_order, flag_t flags, search_t **search);
struct search *search_new_full(const gchar *, guint16, guint32, flag_t flags);
void search_gui_close_search(search_t *sch);

void search_gui_clear_search(search_t *sch);
void search_gui_remove_search(search_t * sch);
void search_gui_restart_search(search_t *sch);
void search_gui_download_files(void);

void search_gui_set_current_search(search_t *sch);
search_t *search_gui_get_current_search(void);

void search_gui_sort_column(search_t *search, gint column);

gint search_gui_compare_records(
	gint sort_col, const record_t *r1, const record_t *r2);

gboolean gui_search_update_tab_label(struct search *);
void gui_search_clear_results(void);
void gui_search_history_add(gchar *s);
#ifdef USE_GTK2
void gui_search_create_tree_view(GtkWidget ** sw, GtkWidget ** tree_view);
void gui_search_force_update_tab_label(struct search *, time_t now);
#else
void gui_search_create_clist(GtkWidget ** sw, GtkWidget ** clist);
void gui_search_force_update_tab_label(struct search *);
#endif
void gui_search_update_items(struct search *);


/*
 * Callbacks
 */
gboolean search_gui_search_results_col_widths_changed(property_t prop);
gboolean search_gui_search_results_col_visible_changed(property_t prop);

void search_matched(search_t *sch, results_set_t *rs);

#endif /* _search_gui_h_ */
