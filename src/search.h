/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#ifndef __search_h__
#define __search_h__

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
struct results_set {
	gint refcount;				/* Numner of "struct search" this belongs to */

	guchar *guid;				/* Servent's GUID (atom) */
	guint32 num_recs;
	guint32 ip;
	guint16 port;
	guint16 status;				/* Parsed status bits from trailer */
	guint32 speed;
	time_t stamp;				/* Reception time of the hit */
	guchar vendor[4];			/* Vendor code */

	GSList *records;
};

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
 * Result sets `status' flags.
 */
#define ST_KNOWN_VENDOR			0x8000		/* Found known vendor code */
#define ST_PARSED_TRAILER		0x4000		/* Was able to parse trailer */
#define ST_UPLOADED				0x0004		/* Is "stable", people downloaded */
#define ST_BUSY					0x0002		/* Has currently no slots */
#define ST_FIREWALL				0x0001		/* Is behind a firewall */

/* 
 * Structure for search results 
 */
typedef struct search {
    gnet_search_t search_handle; /* Search handle */

	GtkWidget *clist;			/* GtkCList for this search */
	GtkWidget *scrolled_window; /* GtkScrolledWindow containing the GtkCList */
	GtkWidget *list_item;		/* The GtkListItem in combo for this search */
    GtkWidget *arrow;           /* The arrow displaying sort order  */
	gchar *query;				/* The search query */
	guint16 speed;				/* Minimum speed for the results of query */
	time_t time;				/* Time when this search was started */
	GSList *muids;				/* Message UID's of this search */
	GSList *r_sets;				/* The results sets of this search */
	guint32 items;				/* Total number of items for this search */

    gint sort_col;
    gint sort_order;
    gboolean sort;

	time_t last_update_time;	/* the last time the notebook tab was updated */
	guint32 last_update_items;	/* Number of items included in last update */
	gint tab_updating;			/* token for timeout function to be canceled. */
	guint32 unseen_items;		/* How many items haven't been seen yet. */

	gboolean passive;			/* Is this a passive search? */
	gboolean frozen;			/* True => don't update window */
	GHashTable *dups;			/* keep a record of dups. */
	/* keep a record of nodes we've sent this search w/ this muid to. */
	GHashTable *sent_nodes;

	GHook *new_node_hook;
	guint reissue_timeout_id;
	guint reissue_timeout;		/* timeout per search, 0 = search stopped */
    struct filter *filter;      /* the filter ruleset bound to this search */
} search_t;



/*
 * Global Data
 */
extern GtkWidget *dialog_filters;
extern guint32 search_passive;
extern guint32 search_reissue_timeout;
extern GList *searches;			/* List of search structs */
extern struct search *search_selected;
extern struct search *current_search;	/*	The search currently displayed */

/* flags for _new_search() */
#define SEARCH_PASSIVE	 0x01 /* start a passive search */



/*
 * Global Functions
 */
void search_init(void);
struct search *search_new(gchar *, guint16);
struct search *search_new_passive(gchar *, guint16);
struct search *search_new_full(gchar *, guint16, guint32, guint flags);
void search_stop(struct search *sch);
void search_restart(struct search *sch);
void search_reissue(struct search *sch);
void search_resume(struct search *sch);
gboolean search_results(struct gnutella_node *n);
void search_extract_host(struct gnutella_node *n, guint32 *ip, guint16 *port);
void search_download_files(void);
void search_clear_clicked(void);
void search_update_reissue_timeout(search_t *, guint32);
void search_shutdown(void);
void search_clear(search_t *sch);
void search_store(void);
void search_close(search_t *sch);
gint search_compare(gint sort_col, record_t *r1, record_t *r2);

#endif							/* __search_h__ */

/* vi: set ts=4: */
