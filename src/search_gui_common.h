/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
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

#ifndef _search_gui_common_h_
#define _search_gui_common_h_

#include <time.h>
#include <glib.h>

#include "gnet.h"

#define TAB_UPDATE_TIME	5		/* Update search tabs after 5 seconds */

/*
 * A results_set structure factorizes the common information from a Query Hit
 * packet, and then has a list of individual records, one for each hit.
 *
 * A single structure is created for each Query Hit packet we receive, but
 * then it can be dispatched for displaying some of its records to the
 * various searches in presence.  Each time the structure is dispatched,
 * the `refcount' is incremented, so that we don't free it and its content
 * until it has been "forgotten" that many times.
 *
 * NB: we reuse the pure data structure gnet_host_vec_t from the core.  It
 *     is purely descriptive anyway.
 */
typedef struct results_set {
	gint refcount;				/* Number of "struct search" this belongs to */

	gchar *guid;				/* Servent's GUID (atom) */
	guint32 ip;
	guint16 port;
	guint16 status;				/* Parsed status bits from trailer */
	guint16 speed;
	time_t  stamp;				/* Reception time of the hit */
	guchar  vendor[4];			/* Vendor code */
	gchar *version;				/* Version information (atom) */
	gnet_host_vec_t *proxies;	/* Optional: known push proxies */
	gchar *hostname;			/* Optional: server's hostname */

	guint32 num_recs;
	GSList *records;
    GSList *schl;
} results_set_t;

/*
 * A host.
 */
typedef struct host {
	guint32 ip;
	guint16 port;
} host_t;

/*
 * Host vector held in query hits.
 */
typedef struct host_vec {
	host_t *hvec;				/* Vector of alternate locations */
	gint hvcnt;					/* Amount of hosts in vector */
} host_vec_t;

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
	results_set_t *results_set;	/* Parent, containing record */
	gint refcount;				/* Number of hash tables it has been put to */

	gchar  *name;				/* File name */
	guint32 size;				/* Size of file, in bytes */
	guint32 index;				/* Index for GET command */
	gchar  *sha1;				/* SHA1 URN (binary form, atom) */
	gchar  *tag;				/* Optional tag data string (atom) */
	gchar  *info;				/* Short version of tag (atom) */
	gnet_host_vec_t *alt_locs;	/* Optional alternate locations for record */
    flag_t  flags;              /* same flags as in gnet_record_t */
} record_t;

/*
 * Global Functions
 */

typedef struct search search_t;

void search_matched(search_t *sch, results_set_t *rs);

void search_gui_common_init(void);
void search_gui_common_shutdown(void);

search_t *search_gui_get_current_search(void);
void search_gui_set_current_search(search_t *sch);
void search_gui_forget_current_search();
void search_gui_current_search(search_t *sch);

void search_gui_free_alt_locs(record_t *rc);
void search_gui_free_proxies(results_set_t *rs);
void search_gui_free_record(record_t *rc);
void search_gui_clean_r_set(results_set_t *rs);
void search_gui_free_r_set(results_set_t *rs);
void search_gui_dispose_results(results_set_t *rs);
void search_gui_ref_record(record_t *rc);
void search_gui_unref_record(record_t *rc);
void search_gui_free_r_sets(search_t *sch);
guint search_gui_hash_func(const record_t *key);
gint search_gui_hash_key_compare(const record_t *a, const record_t *b);
void search_gui_remove_r_set(search_t *sch, results_set_t *rs);
gboolean search_gui_result_is_dup(search_t *sch, record_t *rc);
search_t *search_gui_find(gnet_search_t sh);
record_t *search_gui_create_record(results_set_t *rs, gnet_record_t *r) ;
void search_gui_check_alt_locs(results_set_t *rs, record_t *rc);
void search_gui_store_searches(void);
void search_gui_retrieve_searches(void);
void search_gui_got_results(GSList *schl, const gnet_results_set_t *r_set);
void search_gui_flush(time_t);
gboolean search_gui_autoselect_cmp(record_t *rc, record_t *rc2,
    gboolean search_autoselect, gboolean search_autoselect_ident,
    gboolean search_autoselect_fuzzy, guint32 fuzzy_threshold);

#endif /* _search_gui_common_h_ */
