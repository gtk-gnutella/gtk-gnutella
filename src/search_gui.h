/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Richard Eckart
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

#ifndef __search_gui_h__
#define __search_gui_h__

#include <gtk/gtk.h>

#include "gui.h"
#include "gnet.h"
#include "gnutella.h"
#include "gnet.h"

#include <time.h>
#include "filter.h"

#include <gtk/gtk.h> // FIXME: remove this dependency

/*
 * A results_set structure factorizes the common information from a Query Hit
 * packet, and then has a list of individual records, one for each hit.
 *
 * A single structure is created for each Query Hit packet we receive, but
 * then it can be dispatched for displaying some of its records to the
 * various searches in presence.  Each time the structure is dispatched,
 * the `refcount' is incremented, so that we don't free it and its content
 * until it has been "forgotten" that many times.
 */
typedef struct results_set {
	gint refcount;				/* Numner of "struct search" this belongs to */

	guchar *guid;				/* Servent's GUID (atom) */
	guint32 ip;
	guint16 port;
	guint16 status;				/* Parsed status bits from trailer */
	guint16 speed;
	time_t  stamp;				/* Reception time of the hit */
	guchar  vendor[4];			/* Vendor code */

	guint32 num_recs;
	GSList *records;
} results_set_t;

/*
 * An individual hit.  It referes to a file entry on the remote servent,
 * as identified by the parent results_set structure that contains this hit.
 *
 * When a record is kept in a search window for display, it is put into
 * a hash table and its `refcount' is incremented: since the parent structure
 * can be dispatched to various searches, each record can be inserted in so
 * many different hash tables (one per search).
 */
typedef struct record {
	struct results_set *results_set;	/* Parent, containing record */
	gint refcount;				/* Number of hash tables it has been put to */

	gchar *name;				/* File name */
	guint32 size;				/* Size of file, in bytes */
	guint32 index;				/* Index for GET command */
	gchar *sha1;				/* SHA1 URN (binary form, atom) */
	gchar *tag;					/* Optional tag data string (atom) */
} record_t;

/* 
 * Structure for search results 
 */
typedef struct search {
    gnet_search_t search_handle; /* Search handle */

	gchar      *query;			   /* The search query */

	GtkWidget  *clist;			   /* GtkCList for this search */
	GtkWidget  *scrolled_window;   /* GtkScrolledWindow containing the GtkCList */
	GtkWidget  *list_item;		   /* The GtkListItem in combo for this search */
    GtkWidget  *arrow;             /* The arrow displaying sort order  */

    gint        sort_col;
    gint        sort_order;
    gboolean    sort;

	time_t      last_update_time;  /* the last time the notebook tab was updated */
	guint32     last_update_items; /* Number of items included in last update */
	gint        tab_updating;	   /* token for timeout function to be canceled. */
	guint32     unseen_items;	   /* How many items haven't been seen yet. */

	gboolean    passive;		   /* Is this a passive search? */

	GSList     *r_sets;			   /* The results sets of this search */
	GHashTable *dups;			   /* keep a record of dups. */
	guint32     items;			   /* Total number of items for this search */

    filter_t   *filter;            /* the filter ruleset bound to this search */
} search_t;



/*
 * Global Data
 */
extern GtkWidget *dialog_filters;
extern guint32 search_passive;
extern guint32 search_reissue_timeout;
extern GList *searches;			/* List of search structs */
extern GtkWidget *default_search_clist;
extern time_t tab_update_time;
extern search_t *search_selected;




/*
 * Global Functions
 */

void search_gui_init(void);
void search_gui_shutdown(void);

search_t *search_gui_new_search(const gchar *, guint16, flag_t flags);
search_t *search_gui_new_search_full
    (const gchar *query, guint16 speed, guint32 reissue_timeout, flag_t flags);
struct search *search_new_full(const gchar *, guint16, guint32, flag_t flags);
void search_gui_close_search(search_t *sch);

void search_gui_clear_search(search_t *sch);
void search_gui_remove_search(search_t * sch);
void search_gui_restart_search(search_t *sch);
void search_gui_clear_search(search_t *sch);
void search_gui_download_files(void);

void search_gui_set_current_search(search_t *sch);
search_t *search_gui_get_current_search(void);

void search_gui_store_searches(void);

gint search_gui_compare_records(gint sort_col, record_t *r1, record_t *r2);

/*
 * Callbacks
 */
gboolean search_gui_search_results_col_widths_changed(property_t prop);
gboolean search_gui_search_results_col_visible_changed(property_t prop);

#endif /* __search_gui_h__ */
