/*
 * Copyright (c) 2001-2003, Raphael Manfredi
 * Copyright (c) 2002, Michael Tesch
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

/**
 * @ingroup gtk
 * @file
 *
 * Needs short description here.
 *
 * Keep track of what search terms we have seen, and how frequently
 * each has been seen.
 *
 * @note
 * This uses the glib hash tables and lists, but a much more efficient
 * implementation could be done with a specialized hash table /
 * re-keyable binary tree.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 * @author Michael Tesch
 * @date 2002
 */

#include "gtk/gui.h"

#include "gtk/search_stats.h"
#include "gtk/misc.h"

#include "if/gui_property.h"
#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"

#include "lib/concat.h"
#include "lib/htable.h"
#include "lib/utf8.h"
#include "lib/walloc.h"
#include "lib/wordvec.h"
#include "lib/override.h"		/* Must be the last header included */

/* This is what the stat_hash's 'val' points to */
struct term_counts {
	guint32 period_cnt;
	guint32 total_cnt;
	guint32 periods;
};

static unsigned stat_count;

static htable_t *stat_hash;
static GtkListStore *store_search_stats;
static GtkTreeView *treeview_search_stats;
static GtkLabel *label_search_stats_count;
static gboolean search_stats_gui_overload;

#if GTK_CHECK_VERSION(2,6,0)
static GtkSortType search_stats_sort_order;
static int search_stats_sort_column;
#endif	/* Gtk+ >= 2.6.0 */

static bool
free_hash_entry(const void *key, void *value, void *unused_data)
{
	struct term_counts *val = value;
	char *s = deconstify_pointer(key);

	(void) unused_data;

	wfree(s, 1 + strlen(s));
	WFREE(val);
	return TRUE;
}

/**
 * Save Search Stats sort order.
 */
static void
search_stats_gui_sort_save(void)
{
#if GTK_CHECK_VERSION(2,6,0)
	GtkTreeSortable *sortable;
	GtkSortType order;
	int column;

	sortable = GTK_TREE_SORTABLE(store_search_stats);
	if (gtk_tree_sortable_get_sort_column_id(sortable, &column, &order)) {
		search_stats_sort_column = column;
		search_stats_sort_order = order;
		gtk_tree_sortable_set_sort_column_id(sortable,
			GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID, order);
	}
#endif /* Gtk+ >= 2.6.0 */
}

/**
 * Re-enable Search Stats sorting and restore sort order.
 */
static void
search_stats_gui_sort_restore(void)
{
#if GTK_CHECK_VERSION(2,6,0)
	if (GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID != search_stats_sort_column) {
		gtk_tree_sortable_set_sort_column_id(
			GTK_TREE_SORTABLE(store_search_stats),
			search_stats_sort_column, search_stats_sort_order);
	}
#endif /* Gtk+ >= 2.6.0 */
}

/*
 * Disable Search Stats sorting.
 */
static void
search_stats_gui_disable_sort(void)
{
#if GTK_CHECK_VERSION(2,6,0)
	GtkTreeSortable *sortable;
	GtkSortType order;
	int column;

	sortable = GTK_TREE_SORTABLE(store_search_stats);
	if (gtk_tree_sortable_get_sort_column_id(sortable, &column, &order)) {
		gtk_tree_sortable_set_sort_column_id(sortable,
			GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID,
			GTK_SORT_DESCENDING);
	}
#endif /* Gtk+ >= 2.6.0 */
}

static gboolean callback_registered;
static int selected_type = NO_SEARCH_STATS;

/***
 *** Private function prototypes
 ***/
static void search_stats_tally(const word_vec_t * vec);


/***
 *** Callbacks
 ***/

static void
search_stats_notify_word(query_type_t type, const char *search,
	 const host_addr_t unused_addr, guint16 unused_port)
{
	word_vec_t *wovec;
	unsigned wocnt;

	(void) unused_addr;
	(void) unused_port;

	if (type == QUERY_SHA1)
		return;

	wocnt = word_vec_make(search, &wovec);
	if (wocnt != 0) {
		unsigned i;

		for (i = 0; i < wocnt; i++) {
			search_stats_tally(&wovec[i]);
		}
		word_vec_free(wovec, wocnt);
	}
}

static void
search_stats_notify_whole(query_type_t type, const char *search,
	const host_addr_t unused_addr, guint16 unused_port)
{
    word_vec_t wovec;
	char buf[1024];

	(void) unused_addr;
	(void) unused_port;

	concat_strings(ARYLEN(buf),
		type == QUERY_SHA1 ? "urn:sha1:" : "[",
		search,
		type == QUERY_SHA1 ? "" : "]",
        NULL_PTR);

	wovec.word = buf;
    wovec.len = strlen(wovec.word);
    wovec.amount = 1;

    search_stats_tally(&wovec);
}

static void
search_stats_notify_routed(query_type_t unused_type, const char *unused_search,
	const host_addr_t addr, guint16 port)
{
    word_vec_t wovec;

	(void) unused_type;
	(void) unused_search;

    wovec.word = deconstify_char(host_addr_port_to_string(addr, port));
    wovec.len = strlen(wovec.word);
    wovec.amount = 1;

    search_stats_tally(&wovec);
}

/***
 *** Private functions
 ***/

/* this sucks -- too slow */
static void
empty_hash_table(void)
{
	if (!stat_hash)
		return;

	htable_foreach_remove(stat_hash, free_hash_entry, NULL);
}

/**
 * Helper func for stats_display -
 *  does two things:
 *
 *  - clears out aged / infrequent search terms
 *  - sticks the rest of the search terms in treeview_search_stats
 */
static bool
stats_hash_to_treeview(const void *key, void *value, void *unused_udata)
{
	struct term_counts *val = value;
	GtkTreeIter iter;
	char *s;

	(void) unused_udata;

	/* update counts */
	val->periods = val->period_cnt ? 0 : (val->periods + 1);
	val->total_cnt += val->period_cnt;

	/* try to keep the number of infrequent terms down */
	if (
		(1.0 * val->total_cnt / (val->periods + 2.0)) * 100 <
			GUI_PROPERTY(search_stats_delcoef)
	) {
		free_hash_entry(key, value, NULL);
		return TRUE;
	}

	stat_count++;

	/* update the display */

	s = key ? unknown_to_utf8_normalized(key, UNI_NORM_GUI, NULL) : NULL;

	gtk_list_store_append(store_search_stats, &iter);
	gtk_list_store_set(store_search_stats, &iter,
		0, s,
		1, (gulong) val->period_cnt,
		2, (gulong) val->total_cnt,
		(-1));

	if (key != s) {
		G_FREE_NULL(s);
	}

	/* new period begins */
	val->period_cnt = 0;

	return FALSE;
}

/**
 * Enable search stats.
 */
static void
search_stats_gui_enable(search_request_listener_t lst)
{
	(void) lst;
#if GTK_CHECK_VERSION(2,6,0)
    if (!callback_registered) {
        guc_search_request_listener_add(lst);
        callback_registered = TRUE;
    }
#endif /* Gtk+ >= 2.6.0 */
}

static void
search_stats_gui_disable(void)
{
    if (callback_registered) {
        guc_search_request_listener_remove(search_stats_notify_word);
        guc_search_request_listener_remove(search_stats_notify_whole);
        guc_search_request_listener_remove(search_stats_notify_routed);
        callback_registered = FALSE;
    }

    empty_hash_table();
	search_stats_gui_disable_sort();
}

/**
 * Count a word that has been seen.
 */
static void
search_stats_tally(const word_vec_t *vec)
{
	struct term_counts *val;

	if (vec->word[1] == '\0' || vec->word[2] == '\0')
		return;

	val = htable_lookup(stat_hash, vec->word);

	if (val) {
		val->period_cnt++;
	} else {
		const char *key;

		WALLOC0(val);
		val->period_cnt = vec->amount;
		key = wcopy(vec->word, 1 + strlen(vec->word));
		htable_insert(stat_hash, key, val);
	}
}



/***
 *** Public functions
 ***/

/**
 * Clear the list, empty the hash table.
 */
void
search_stats_gui_reset(void)
{
	empty_hash_table();
	gtk_list_store_clear(store_search_stats);
	search_stats_gui_disable_sort();
	search_stats_gui_overload = FALSE;
}

void
search_stats_gui_set_type(int type)
{
	if (type == selected_type)
		return;

	search_stats_gui_reset();
	search_stats_gui_disable();
	selected_type = type;

	switch (type) {
	case NO_SEARCH_STATS:
		/* already disabled */
		break;
	case WORD_SEARCH_STATS:
		search_stats_gui_enable(search_stats_notify_word);
		break;
	case WHOLE_SEARCH_STATS:
		search_stats_gui_enable(search_stats_notify_whole);
		break;
	case ROUTED_SEARCH_STATS:
		search_stats_gui_enable(search_stats_notify_routed);
		break;
	default:
		g_assert_not_reached();
	}
}

/* FIXME: merge all `add_column' functions into one */
static void
add_column(GtkTreeView *treeview, int id, float xalign,
	const char *label)
{
    GtkTreeViewColumn *column;
    GtkCellRenderer *renderer;

    renderer = gtk_cell_renderer_text_new();
    gtk_cell_renderer_text_set_fixed_height_from_font(
        GTK_CELL_RENDERER_TEXT(renderer), 1);
    g_object_set(renderer,
        "xalign", xalign,
        "ypad", GUI_CELL_RENDERER_YPAD,
        NULL_PTR);

    column = gtk_tree_view_column_new_with_attributes(
                label, renderer, "text", id, NULL_PTR);

	g_object_set(G_OBJECT(column),
		"fixed-width", 1,
		"min-width", 1,
		"reorderable", TRUE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		"visible", TRUE,
		NULL_PTR);

    gtk_tree_view_append_column(treeview, column);
	gtk_tree_view_column_set_sort_column_id(column, id);

	gui_column_map(column, treeview);	/* Capture resize events */
}

/**
 * Display the data gathered during the last time period.
 * Perhaps it would be better to have this done on a button click(?)
 */
static void
search_stats_gui_update_display(void)
{
	gboolean sorting_disabled;
	tm_t start_time, end_time;
	time_delta_t elapsed;

	stat_count = 0;
	g_object_freeze_notify(G_OBJECT(treeview_search_stats));
	gtk_list_store_clear(store_search_stats);

	/*
	 * Temporarily disable sorting while inserting the updated table.
	 * Otherwise, CPU is overloaded with sorting every addition
	 *  to the hash table.
	 */
	sorting_disabled = FALSE;
	tm_now_exact(&start_time);
	if (store_search_stats->sort_column_id >= 0) {
		sorting_disabled = TRUE;
		search_stats_gui_sort_save();
	}
	/* insert the hash table contents into the sorted treeview */
	htable_foreach_remove(stat_hash, stats_hash_to_treeview, NULL);

	tm_now_exact(&end_time);
	elapsed = tm_elapsed_ms(&end_time, &start_time);

	/*
	 * Re-enable sorting if previously disabled.
	 * If too much time has elapsed, leave sorting disabled.
	 */
	if (sorting_disabled && elapsed < 100) {
		search_stats_gui_sort_restore();
	} else if (!sorting_disabled && elapsed > 200) {
		/*
		 * If sorting is disabled, and too much time is still elapsing,
		 * then the search stats collection will need to be
		 * discontinued
		 */
    	search_stats_gui_reset();
	    search_stats_gui_disable();
	    search_stats_gui_overload = TRUE;
	}

	if (search_stats_gui_overload) {
		/* update status bar message */
		gtk_label_set_text(GTK_LABEL(label_search_stats_count),
			"Disabling Search Stats due to system load" );
	} else {
		/* update the status bar counter */
		gtk_label_printf(GTK_LABEL(label_search_stats_count),
			NG_("%u term counted", "%u terms counted", stat_count),
			stat_count);
	}
	g_object_thaw_notify(G_OBJECT(treeview_search_stats));
}

static void
search_stats_gui_timer(time_t now)
{
	static time_t last_update;
	time_delta_t interval = GUI_PROPERTY(search_stats_update_interval);

    if (!last_update || delta_time(now, last_update) > interval) {
    	last_update = now;
		search_stats_gui_update_display();
	}
}

void
search_stats_gui_init(void)
{
	static GType types[] = {
		G_TYPE_STRING,
		G_TYPE_ULONG,
		G_TYPE_ULONG
	};
	static const struct {
		const int id;
		const float align;
		const char *title;
	} cols[] = {
		{ 0, 0.0, N_("Search Term") },
		{ 1, 1.0, N_("This Interval") },
		{ 2, 1.0, N_("Total") },
	};
	size_t i;
	GtkTreeModel *model;
    GtkTreeView *treeview;

	STATIC_ASSERT(N_ITEMS(cols) == N_ITEMS(types));

	treeview_search_stats =
        GTK_TREE_VIEW(gui_main_window_lookup("treeview_search_stats"));
	label_search_stats_count =
		GTK_LABEL(gui_main_window_lookup("label_search_stats_count"));

	treeview = treeview_search_stats;

    /* set up the treeview to be sorted properly */
	model = GTK_TREE_MODEL(gtk_list_store_newv(N_ITEMS(types), types));
	gtk_tree_view_set_model(treeview, model);
    store_search_stats = GTK_LIST_STORE(model);
	g_object_unref(model);

	gui_parent_widths_saveto(treeview, PROP_SEARCH_STATS_COL_WIDTHS);

	for (i = 0; i < N_ITEMS(cols); i++) {
		add_column(treeview, cols[i].id, cols[i].align, _(cols[i].title));
	}
	tree_view_restore_widths(treeview, PROP_SEARCH_STATS_COL_WIDTHS);
	tree_view_set_fixed_height_mode(treeview, TRUE);

	stat_hash = htable_create(HASH_KEY_STRING, 0);
	main_gui_add_timer(search_stats_gui_timer);
}

void
search_stats_gui_shutdown(void)
{
    search_stats_gui_set_type(NO_SEARCH_STATS);
	empty_hash_table();
    htable_free_null(&stat_hash);
}

/* vi: set ts=4 sw=4 cindent: */
