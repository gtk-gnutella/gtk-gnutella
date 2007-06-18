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

typedef enum {
	RESULTS_SET_MAGIC = 0xa44eb853U
} results_set_magic_t;

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
	results_set_magic_t magic;
	gint num_recs;

	const gchar *guid;			/**< Servent's GUID (atom) */
	const gchar *version;		/**< Version information (atom) */
	const gchar *hostname;		/**< Optional: server's hostname (atom) */
	const gchar *query;			/**< Optional: original query (atom) */

	GSList *records;
    GSList *schl;
	gnet_host_vec_t *proxies;	/**< Optional: known push proxies */

	host_addr_t addr;
	host_addr_t last_hop;		/**< IP of delivering node */
	time_t  stamp;				/**< Reception time of the hit */

	vendor_code_t vcode;		/**< Vendor code */
	guint32 status;				/**< Parsed status bits from trailer */
	guint16 country;			/**< Country code -- encoded ISO3166 */
	guint16 port;
	guint16 speed;
	guint8 hops;
	guint8 ttl;
} results_set_t;

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
	record_magic_t magic;		/**< Magic ID */
	gint refcount;				/**< Number of hash tables it has been put to */

	results_set_t *results_set;	/**< Parent, containing record */
	const gchar *name;			/**< Filename (atom) */
	const gchar *ext;			/**< File extension (atom) */
	const gchar *utf8_name;		/**< Path/Filename converted to UTF-8 (atom) */
	const gchar *charset;		/**< Detected charset of name (static const) */
	const struct sha1 *sha1;	/**< SHA1 URN (binary form, atom) */
	const gchar *xml;			/**< Optional XML data string (atom) */
	const gchar *tag;			/**< Optional tag data string (atom) */
	const gchar *info;			/**< Short version of tag (atom) */
	const gchar *path;			/**< Optional path (atom) */
	gnet_host_vec_t *alt_locs;	/**< Optional alternate locations for record */
	filesize_t size;			/**< Size of file, in bytes */
	time_t  create_time;		/**< Create Time of file; zero if unknown */
	guint32 file_index;			/**< Index for GET command */
    flag_t  flags;              /**< same flags as in gnet_record_t */
} record_t;

static inline void
record_check(const record_t * const rc)
{
	g_assert(rc);
	g_assert(rc->magic == RECORD_MAGIC);
	g_assert(rc->refcount >= 0);
	g_assert(rc->refcount < INT_MAX);
}

static inline void
results_set_check(const results_set_t * const rs)
{
	g_assert(rs);
	g_assert(rs->magic == RESULTS_SET_MAGIC);
	g_assert(rs->num_recs >= 0);
	g_assert(rs->num_recs < INT_MAX);
}

struct query {
	gchar *text;
	GList *rules;
	guint flags;
};

enum gui_color {
	GUI_COLOR_DEFAULT,
	GUI_COLOR_DOWNLOADING,
	GUI_COLOR_HOSTILE,
	GUI_COLOR_IGNORED,
	GUI_COLOR_MARKED,
	GUI_COLOR_MAYBE_SPAM,
	GUI_COLOR_SPAM,
	GUI_COLOR_UNREQUESTED,

	NUM_GUI_COLORS
};


void gui_color_init(GtkWidget *widget);
GdkColor *gui_color_get(enum gui_color id);
void gui_color_set(const enum gui_color id, GdkColor *color);
void gui_search_get_colors(search_t *sch,
		GdkColor **mark_color, GdkColor **ignore_color);

#include "search.h"

/*
 * Global Functions
 */

void search_gui_common_init(void);
void search_gui_common_shutdown(void);

search_t *search_gui_get_current_search(void);
void search_gui_set_current_search(search_t *sch);
void search_gui_forget_current_search(void);
void search_gui_current_search(search_t *sch);

void search_gui_ref_record(record_t *rc);
void search_gui_unref_record(record_t *rc);
guint search_gui_hash_func(gconstpointer key);
gint search_gui_hash_key_compare(gconstpointer a, gconstpointer b);
const gchar *search_gui_get_route(const struct results_set *rs);
search_t *search_gui_find(gnet_search_t sh);
const gchar *search_gui_get_filename_extension(const gchar *filename_utf8);
void search_gui_set_sort_defaults(void);
void search_gui_store_searches(void);
void search_gui_retrieve_searches(void);

void search_gui_got_results(GSList *schl, const gnet_results_set_t *r_set);
void search_gui_flush(time_t now, gboolean force);
struct query *search_gui_handle_query(const gchar *query_str, flag_t flags,
						const gchar **error_str);
void search_gui_query_free(struct query **query_ptr);
void search_gui_filter_new(search_t *sch, GList *rules);

gboolean search_gui_new_browse_host(
	const gchar *hostname, host_addr_t addr, guint16 port,
	const gchar *guid, const gnet_host_vec_t *proxies, guint32 flags);

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

gint search_gui_cmp_sha1s(const struct sha1 *a, const struct sha1 *b);

void search_gui_duplicate_search(search_t *search);
void search_gui_restart_search(search_t *search);
void search_gui_resume_search(search_t *search);
void search_gui_stop_search(search_t *search);

/***
 *** Search results popup
 ***/

void on_popup_search_download_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_drop_name_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_drop_sha1_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_drop_host_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_drop_name_global_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_drop_sha1_global_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_drop_host_global_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_edit_filter_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_clear_results_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_close_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_duplicate_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_restart_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_resume_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_stop_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_config_cols_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_expand_all_activate (GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_collapse_all_activate (GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_metadata_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_copy_magnet_activate(GtkMenuItem *menuitem,
		gpointer user_data);

/***
 *** Search list popup
 ***/

void on_popup_search_list_clear_results_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_list_close_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_list_duplicate_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_list_restart_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_list_resume_activate(GtkMenuItem *menuitem,
		gpointer user_data);
void on_popup_search_list_stop_activate(GtkMenuItem *menuitem,
		gpointer user_data);

gboolean on_search_list_button_press_event(GtkWidget *unused_widget,
	GdkEventButton *event, gpointer unused_udata);

GSList *search_gui_get_selected_searches(void);
gboolean search_gui_has_selected_item(search_t *search);
void search_gui_refresh_popup(void);
void search_gui_search_list_clicked(GtkWidget *widget, GdkEventButton *event);
void search_gui_flush_queues(void);

const gchar *search_gui_query(const search_t *search);
gboolean search_gui_is_browse(const search_t *search);
gboolean search_gui_is_enabled(const search_t *search);
gboolean search_gui_is_local(const search_t *search);
gboolean search_gui_is_passive(const search_t *search);

void search_gui_download(record_t *rc);
const gchar *search_gui_nice_size(const record_t *rc);
const gchar *search_gui_get_vendor(const struct results_set *rs);
void search_gui_set_details(const record_t *rc);

/* FIXME: This does not belong here. */
gchar *gnet_host_vec_to_string(const gnet_host_vec_t *hvec);

void search_gui_clear_details(void);
void search_gui_append_detail(const gchar *title, const gchar *value);

#endif /* _gtk_search_common_h_ */

/* vi: set ts=4 sw=4 cindent: */
