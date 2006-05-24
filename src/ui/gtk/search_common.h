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

#ifndef _gtk_search_common_h_
#define _gtk_search_common_h_

#include "if/core/search.h"
#include "if/ui/gtk/search.h"

void search_add_got_results_listener(search_got_results_listener_t l);
void search_remove_got_results_listener(search_got_results_listener_t l);

#define TAB_UPDATE_TIME	5		/**< Update search tabs after 5 seconds */

/**
 * A results_set structure factorizes the common information from a Query Hit
 * packet, and then has a list of individual records, one for each hit.
 *
 * A single structure is created for each Query Hit packet we receive, but
 * then it can be dispatched for displaying some of its records to the
 * various searches in presence.  Each time the structure is dispatched,
 * the `refcount' is incremented, so that we don't free it and its content
 * until it has been "forgotten" that many times.
 *
 * @attention
 * NB: we reuse the pure data structure gnet_host_vec_t from the core.  It
 *     is purely descriptive anyway.
 */
typedef struct results_set {
	gint refcount;			/**< Number of "struct search" this belongs to */

	gchar *guid;			/**< Servent's GUID (atom) */
	host_addr_t addr;
	guint8 hops;
	guint8 ttl;
	guint16 port;
	guint16 status;				/**< Parsed status bits from trailer */
	guint16 speed;
	time_t  stamp;				/**< Reception time of the hit */
	union vendor_code vcode;	/**< Vendor code */
	gchar *version;				/**< Version information (atom) */
	gint country;				/**< Country code -- encoded ISO3166 */
	gnet_host_vec_t *proxies;	/**< Optional: known push proxies */
	gchar *hostname;			/**< Optional: server's hostname (atom) */
	host_addr_t last_hop;		/**< IP of delivering node */

	guint32 num_recs;
	GSList *records;
    GSList *schl;
} results_set_t;

/**
 * Host vector held in query hits.
 */
typedef struct host_vec {
	gnet_host_t *hvec;			/**< Vector of alternate locations */
	gint hvcnt;					/**< Amount of hosts in vector */
} host_vec_t;

typedef enum {
	RECORD_MAGIC = 0x3fb9c04e
} record_magic_t;

/**
 * An individual hit.  It referes to a file entry on the remote servent,
 * as identified by the parent results_set structure that contains this hit.
 *
 * When a record is kept in a search window for display, it is put into
 * a hash table and its `refcount' is incremented: since the parent structure
 * can be dispatched to various searches, each record can be inserted in so
 * many different hash tables (one per search).
 */
typedef struct record {
	results_set_t *results_set;	/**< Parent, containing record */
	gint refcount;				/**< Number of hash tables it has been put to */
	record_magic_t magic;		/**< Magic ID */

	gchar  *name;				/**< Filename (atom) */
	gchar  *ext;				/**< File extension (atom) */
	gchar  *utf8_name;			/**< Filename converted to UTF-8 (atom) */
	const gchar *charset;		/**< Detected charset of name (static const) */
	filesize_t size;			/**< Size of file, in bytes */
	guint32 index;				/**< Index for GET command */
	gchar  *sha1;				/**< SHA1 URN (binary form, atom) */
	gchar  *xml;				/**< Optional XML data string (atom) */
	gchar  *tag;				/**< Optional tag data string (atom) */
	gchar  *info;				/**< Short version of tag (atom) */
	gnet_host_vec_t *alt_locs;	/**< Optional alternate locations for record */
    flag_t  flags;              /**< same flags as in gnet_record_t */
} record_t;

struct query {
	gchar *text;
	GList *rules;
	guint flags;
};


#include "search.h"

/*
 * Global Functions
 */

void search_matched(search_t *sch, results_set_t *rs);

void search_gui_common_init(void);
void search_gui_common_shutdown(void);

search_t *search_gui_get_current_search(void);
void search_gui_set_current_search(search_t *sch);
void search_gui_forget_current_search(void);
void search_gui_current_search(search_t *sch);

void search_gui_free_alt_locs(record_t *rc);
void search_gui_host_vec_free(gnet_host_vec_t *v);
gnet_host_vec_t *search_gui_proxies_clone(gnet_host_vec_t *v);
void search_gui_free_proxies(results_set_t *rs);
void search_gui_clean_r_set(results_set_t *rs);
void search_gui_free_r_set(results_set_t *rs);
void search_gui_dispose_results(results_set_t *rs);
void search_gui_ref_record(record_t *rc);
void search_gui_unref_record(record_t *rc);
void search_gui_free_r_sets(search_t *sch);
guint search_gui_hash_func(gconstpointer key);
gint search_gui_hash_key_compare(gconstpointer a, gconstpointer b);
void search_gui_remove_r_set(search_t *sch, results_set_t *rs);
gboolean search_gui_result_is_dup(search_t *sch, record_t *rc);
const gchar * search_gui_get_route(const record_t *rc);
search_t *search_gui_find(gnet_search_t sh);
gchar *search_gui_get_filename_extension(const gchar *filename_utf8);
record_t *search_gui_create_record(results_set_t *rs, gnet_record_t *r) ;
void search_gui_check_alt_locs(results_set_t *rs, record_t *rc);
void search_gui_set_sort_defaults(void);
void search_gui_store_searches(void);
void search_gui_retrieve_searches(void);
void search_gui_restart_search(search_t *sch);
void search_gui_got_results(GSList *schl, const gnet_results_set_t *r_set);
void search_gui_flush(time_t);
struct query *search_gui_handle_query(const gchar *query_str, flag_t flags,
						const gchar **error_str);
void search_gui_query_free(struct query **query_ptr);
void search_gui_filter_new(search_t *sch, GList *rules);

gboolean search_gui_new_browse_host(
	const gchar *hostname, host_addr_t addr, guint16 port,
	const gchar *guid, gboolean push, const gnet_host_vec_t *proxies);

struct filter;
void search_gui_add_targetted_search(gpointer data, gpointer unused_udata);
void search_gui_update_items(const struct search *);
gboolean search_gui_update_expiry(const struct search *sch);
gboolean search_gui_is_expired(const struct search *sch);
void search_gui_new_search_entered(void);
void search_gui_option_menu_searches_update(void);
void search_gui_option_menu_searches_select(const search_t *sch);

void search_gui_browse_selected(void);
gboolean search_gui_handle_magnet(const gchar *url, const gchar **error_str);
gboolean search_gui_handle_http(const gchar *url, const gchar **error_str);
gboolean search_gui_handle_urn(const gchar *url, const gchar **error_str);

gchar *search_xml_indent(const gchar *s);

void on_option_menu_search_changed(GtkOptionMenu *option_menu, gpointer unused_udata);

#endif /* _gtk_search_common_h_ */

/* vi: set ts=4 sw=4 cindent: */
