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

#include "gtk/search.h"
#include "gtk/search_result.h"

#include "if/core/search.h"
#include "if/ui/gtk/search.h"

struct filter;
struct slist;

/**
 * Structure for search results.
 */
typedef struct search {
    gnet_search_t search_handle;	/**< Search handle */

	GtkWidget  *tree;				/**< GtkTreeView or GtkCTree */
	GtkWidget  *scrolled_window;	/**< GtkScrolledWindow, contains tree */
    GtkWidget  *arrow;				/**< The arrow displaying sort order */

	GHashTable *dups;				/**< keep a record of dups. */
	GHashTable *parents;			/**< table of mount iterators for
										 any seen SHA1 */

    struct filter *filter;		/**< filter ruleset bound to this search */
	struct slist *queue;		/**< records to be inserted */

	gboolean	list_refreshed;
	gboolean	sort;

    int        sort_col;
    int        sort_order;

	/*
	 * Search stats.
	 */

	guint32     items;			/**< Total number of items for the search */
	guint32     unseen_items;	/**< How many items haven't been seen yet */
	guint32		tcp_qhits;			/**< Query hits received from TCP */
	guint32		udp_qhits;			/**< Query hits received from UDP */
	guint32		skipped;			/**< Ignored hits (skipped over) */
	guint32		ignored;			/**< Filtered out hits */
	guint32		hidden;				/**< Hidden hits, never shown */
	guint32		auto_downloaded;	/**< Auto-downloaded hits */
	guint32		duplicates;			/**< Duplicate hits ignored */
} search_t;

#ifdef USE_GTK1

/**
 *	Record associated with each gui node in the search results ctree.
 */
typedef struct gui_record {
	struct record *shared_record;		/**< Common record data, shared between
										 searches */

	int num_children;				/**< Number of children under this node */
} gui_record_t;

#endif /* USE_GTK1 */

struct query {
	char *text;
	GList *rules;
	unsigned flags;
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
	GUI_COLOR_BACKGROUND,

	NUM_GUI_COLORS
};


GdkColor *gui_color_get(enum gui_color);

/*
 * Global Functions
 */

void search_gui_common_init(void);

void search_gui_init_tree(struct search *);
void search_gui_set_current_search(struct search *);

void search_gui_ref_record(record_t *);
void search_gui_unref_record(record_t *);
unsigned search_gui_hash_func(gconstpointer);
int search_gui_hash_key_compare(gconstpointer, gconstpointer);
const char *search_gui_get_route(const struct results_set *);
const char *search_gui_get_filename_extension(const char *filename_utf8);
void search_gui_set_sort_defaults(void);

struct query *search_gui_handle_query(const char *, flag_t flags,
						const char **error_str);
void search_gui_query_free(struct query **query_ptr);
void search_gui_filter_new(search_t *, GList *rules);

void search_gui_add_targetted_search(void *data, void *user_data);
gboolean search_gui_is_expired(const struct search *);
void search_gui_new_search_entered(void);

void search_gui_browse_selected(void);
gboolean search_gui_insert_query(const char *);

char *search_xml_indent(const char *);

const char *search_gui_column_title(int column);
gboolean search_gui_column_justify_right(int column);

void on_spinbutton_search_reissue_timeout_changed(GtkEditable *,
			void *user_udata);
gboolean on_search_details_key_press_event(GtkWidget *, GdkEventKey *,
			void *user_data);

void on_popup_search_metadata_activate(GtkMenuItem *, void *user_data);
void on_popup_search_copy_magnet_activate(GtkMenuItem *, void *user_data);

int search_gui_cmp_sha1s(const struct sha1 *, const struct sha1 *);

void search_gui_refresh_popup(void);
GtkMenu *search_gui_get_search_list_popup_menu(void);

void search_gui_callbacks_shutdown(void);

gboolean on_search_list_button_release_event(GtkWidget *, GdkEventButton *,
			void *user_data);
gboolean on_search_list_key_release_event(GtkWidget *, GdkEventKey *,
			void *user_data);

GSList *search_gui_get_selected_searches(void);
gboolean search_gui_has_selected_item(struct search *);
void search_gui_search_list_clicked(void);
void search_gui_download_files(struct search *);
void search_gui_discard_files(struct search *);
void search_gui_sort_column(struct search *, int column);
void search_gui_expand_all(struct search *);
void search_gui_collapse_all(struct search *);
void search_gui_flush_queues(void);
void search_gui_remove_search(search_t *);
void search_gui_update_list_label(const struct search *);
void search_gui_clear_search(struct search *);
char *search_gui_get_local_file_url(GtkWidget *);
char *search_gui_details_get_text(GtkWidget *);
GtkWidget *search_gui_create_tree(void);

void search_gui_option_menu_searches_thaw(void);
void search_gui_option_menu_searches_freeze(void);

gboolean search_gui_is_enabled(const struct search *);

void search_gui_download(record_t *);
const char *search_gui_nice_size(const record_t *);
const char *search_gui_get_vendor(const struct results_set *);

gboolean search_gui_item_is_inspected(const record_t *);
void search_gui_set_details(const record_t *);
void search_gui_set_bitzi_metadata(const record_t *);
void search_gui_clear_details(void);
void search_gui_append_detail(const char *title, const char *value);
const char *search_new_error_to_string(enum search_new_result);

record_t *search_gui_record_get_parent(search_t *, record_t *);
GSList *search_gui_record_get_children(search_t *, record_t *);

char *search_gui_get_magnet(search_t *, record_t *);

typedef search_t *(*search_gui_synchronize_list_cb)(void *user_data);

void search_gui_synchronize_search_list(search_gui_synchronize_list_cb,
			void *user_data);

void search_gui_start_massive_update(struct search *);
void search_gui_end_massive_update(struct search *);
void search_gui_queue_bitzi_by_sha1(const record_t *);
void search_gui_add_record(struct search *, record_t *, enum gui_color);
void search_gui_hide_search(struct search *);
void search_gui_show_search(struct search *);

/*
 * Search result record comparison functions.
 */

int gui_record_name_eq(const void *, const void *);
int gui_record_sha1_eq(const void *, const void *);
int gui_record_host_eq(const void *, const void *);
int gui_record_sha1_or_name_eq(const void *, const void *);

/* FIXME: This does not belong here. */
char *gnet_host_vec_to_string(const gnet_host_vec_t *);

#endif /* _gtk_search_common_h_ */

/* vi: set ts=4 sw=4 cindent: */
