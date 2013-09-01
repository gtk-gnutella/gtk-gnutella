/*
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

#include "if/core/guess.h"
#include "if/core/search.h"
#include "if/ui/gtk/search.h"

struct filter;
struct slist;
struct htable;
struct hset;

/**
 * Structure for search results.
 */
typedef struct search {
    gnet_search_t search_handle;	/**< Search handle */

	GtkWidget  *tree;				/**< GtkTreeView or GtkCTree */
	GtkWidget  *scrolled_window;	/**< GtkScrolledWindow, contains tree */
    GtkWidget  *arrow;				/**< The arrow displaying sort order */

	struct hset *dups;				/**< keep a record of dups. */
	struct htable *parents;			/**< table of mount iterators for
										 any seen SHA1 */

    struct filter *filter;		/**< filter ruleset bound to this search */
	struct slist *queue;		/**< records to be inserted */

	bool	list_refreshed;
	bool	clicked;
	bool	sort;
	bool	frozen;

    int     sort_col;
    int     sort_order;

	/*
	 * Cached attributes.
	 */

	unsigned	cached_attributes;	/**< Mask for things we cached */
	unsigned	attributes;			/**< Actual attributes we know */

	/*
	 * Search stats.
	 */

	uint32 items;				/**< Total number of items for the search */
	uint32 unseen_items;		/**< How many items haven't been seen yet */
	uint32 tcp_qhits;			/**< Query hits received from TCP */
	uint32 udp_qhits;			/**< Query hits received from UDP */
	uint32 skipped;				/**< Ignored hits (skipped over) */
	uint32 ignored;				/**< Filtered out hits */
	uint32 hidden;				/**< Hidden hits, never shown */
	uint32 auto_downloaded;		/**< Auto-downloaded hits */
	uint32 duplicates;			/**< Duplicate hits ignored */

	/*
	 * GUESS stats and attributes.
	 */

	size_t guess_queries;		/**< Total amount of queries run */
	size_t guess_hosts;			/**< Hosts queried by last completed query */
	size_t guess_last_kept;		/**< Kept results at last query */
	uint64 guess_bw_query;		/**< Total bandwidth used by queries */
	uint64 guess_bw_qk;			/**< Total bandwidth used by query keys */
	uint64 guess_results;		/**< Total results received */
	uint64 guess_kept;			/**< Total results kept */
	time_delta_t guess_elapsed;	/**< Elapsed time for last completed query */
	time_t guess_cur_start;		/**< Start time of current query (0 if none) */
	size_t guess_cur_max_ultra;	/**< Max amount of ultra nodes to query */
	size_t guess_cur_pool;		/**< Current pool of unqueried nodes */
	size_t guess_cur_queried;	/**< Current amount of queried nodes */
	size_t guess_cur_acks;		/**< Current amount of acks received */
	size_t guess_cur_results;	/**< Current amount of results received */
	size_t guess_cur_kept;		/**< Current amount of results kept */
	size_t guess_cur_hops;		/**< Current query iteration count */
	size_t guess_cur_rpc_pending;	/**< Current RPCs pending */
	size_t guess_cur_bw_query;		/**< Current b/w used for queries */
	size_t guess_cur_bw_qk;			/**< Current b/w used for query keys */
	enum guess_mode guess_cur_mode;	/**< Current query mode */
	uint guess_cur_pool_load:1;		/**< Whether pool loading is pending */
	uint guess_cur_end_starving:1;	/**< Whether query will end on starving */
} search_t;

enum {
	SEARCH_GUI_F_WHATS_NEW	= 1 << 3,
	SEARCH_GUI_F_BROWSE		= 1 << 2,
	SEARCH_GUI_F_LOCAL		= 1 << 1,
	SEARCH_GUI_F_PASSIVE	= 1 << 0
};

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
	GUI_COLOR_ALIEN,
	GUI_COLOR_BANNED_GUID,
	GUI_COLOR_UNREQUESTED,
	GUI_COLOR_PUSH,
	GUI_COLOR_PUSH_PROXY,
	GUI_COLOR_PARTIAL_PUSH,
	GUI_COLOR_PARTIAL,
	GUI_COLOR_MEDIA,
	GUI_COLOR_BACKGROUND,

	NUM_GUI_COLORS
};


GdkColor *gui_color_get(enum gui_color);

/*
 * Global Functions
 */

void search_gui_common_init(void);
void search_gui_common_shutdown(void);

void search_gui_init_tree(struct search *);
void search_gui_set_current_search(struct search *);
void search_gui_current_search_refresh(void);

void search_gui_ref_record(record_t *);
void search_gui_unref_record(record_t *);
const char *search_gui_get_route(const struct results_set *);
const char *search_gui_get_filename_extension(const char *filename_utf8);
void search_gui_set_sort_defaults(void);

struct query *search_gui_handle_query(const char *, guint32 flags,
						const char **error_str);
void search_gui_query_free(struct query **query_ptr);
void search_gui_filter_new(search_t *, GList *rules);

void search_gui_add_targetted_search(void *data, void *user_data);
bool search_gui_is_expired(const struct search *);
void search_gui_new_search_entered(void);

void search_gui_browse_selected(void);
bool search_gui_insert_query(const char *);

const char *search_gui_column_title(int column);
bool search_gui_column_justify_right(int column);

void on_spinbutton_search_reissue_timeout_changed(GtkEditable *,
			void *user_udata);
bool on_search_details_key_press_event(GtkWidget *, GdkEventKey *,
			void *user_data);

void on_popup_search_metadata_activate(GtkMenuItem *, void *user_data);
void on_popup_search_copy_magnet_activate(GtkMenuItem *, void *user_data);

int search_gui_cmp_sha1s(const struct sha1 *, const struct sha1 *);

void search_gui_refresh_popup(void);
GtkMenu *search_gui_get_search_list_popup_menu(void);

void search_gui_callbacks_shutdown(void);

bool on_search_list_button_release_event(GtkWidget *, GdkEventButton *,
			void *user_data);
bool on_search_list_key_release_event(GtkWidget *, GdkEventKey *,
			void *user_data);

GSList *search_gui_get_selected_searches(void);
bool search_gui_has_selected_item(struct search *);
void search_gui_search_list_clicked(void);
void search_gui_download_files(struct search *);
void search_gui_discard_files(struct search *);
void search_gui_sort_column(struct search *, int column);
void search_gui_expand_all(struct search *);
void search_gui_collapse_all(struct search *);
void search_gui_flush_queues(void);
unsigned search_gui_queue_length(const struct search *);
void search_gui_remove_search(search_t *);
void search_gui_update_list_label(const struct search *);
void search_gui_clear_search(struct search *);
char *search_gui_get_local_file_url(GtkWidget *);
char *search_gui_details_get_text(GtkWidget *);
GtkWidget *search_gui_create_tree(void);

void search_gui_option_menu_searches_thaw(void);
void search_gui_option_menu_searches_freeze(void);

bool search_gui_is_enabled(const struct search *);

void search_gui_download(record_t *, gnet_search_t sh);
const char *search_gui_nice_size(const record_t *);
const char *search_gui_get_vendor(const struct results_set *);

bool search_gui_item_is_inspected(const record_t *);
void search_gui_set_details(const record_t *);
void search_gui_set_bitzi_metadata(const record_t *);
void search_gui_set_bitzi_metadata_text(const char *);
void search_gui_clear_details(void);
void search_gui_append_detail(const char *title, const char *value);
const char *search_new_error_to_string(enum search_new_result);

record_t *search_gui_record_get_parent(search_t *, record_t *);
GSList *search_gui_record_get_children(search_t *, record_t *);

char *search_gui_get_magnet(search_t *, record_t *);

typedef search_t *(*search_gui_synchronize_list_cb)(void *user_data);

void search_gui_synchronize_search_list(search_gui_synchronize_list_cb,
			void *user_data);

bool search_gui_start_massive_update(struct search *);
void search_gui_end_massive_update(struct search *);
void search_gui_queue_bitzi_by_sha1(const record_t *);
void search_gui_add_record(struct search *, record_t *, enum gui_color);
void search_gui_hide_search(struct search *);
void search_gui_show_search(struct search *);

void search_gui_media_type_clear(void);

/*
 * Search result record comparison functions.
 */

int gui_record_name_eq(const void *, const void *);
int gui_record_sha1_eq(const void *, const void *);
int gui_record_host_eq(const void *, const void *);
int gui_record_sha1_or_name_eq(const void *, const void *);

#endif /* _gtk_search_common_h_ */

/* vi: set ts=4 sw=4 cindent: */
