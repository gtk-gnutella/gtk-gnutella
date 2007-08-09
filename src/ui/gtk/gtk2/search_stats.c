/*
 * $Id$
 *
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

RCSID("$Id$")

#include "gtk/search_stats.h"
#include "gtk/misc.h"

#include "if/gui_property.h"
#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"

#include "lib/atoms.h"
#include "lib/glib-missing.h"
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

static guint stat_count = 0;

static GHashTable *stat_hash = NULL;
static GtkListStore *store_search_stats = NULL;
static GtkTreeView *treeview_search_stats = NULL;
static GtkLabel *label_search_stats_count = NULL;

static gboolean delete_hash_entry(gpointer key, gpointer val, gpointer data);
static void empty_hash_table(void);
static gboolean stats_hash_to_treeview(
	gpointer key, gpointer value, gpointer userdata);

static gboolean
delete_hash_entry(gpointer key, gpointer value, gpointer unused_data)
{
	struct term_counts *val = (struct term_counts *) value;

	(void) unused_data;

	/* free the key str (was atomized below) */
	atom_str_free(key);
	wfree(val, sizeof *val);
	return TRUE;
}

static gboolean callback_registered = FALSE;
static gint selected_type = NO_SEARCH_STATS;

/***
 *** Private function prototypes
 ***/
static void search_stats_tally(const word_vec_t * vec);


/***
 *** Callbacks
 ***/

static void
search_stats_notify_word(query_type_t type, const gchar *search,
	 const host_addr_t unused_addr, guint16 unused_port)
{
    word_vec_t *wovec;
    guint wocnt;
    guint i;

	(void) unused_addr;
	(void) unused_port;

    if (type == QUERY_SHA1)
        return;

   	wocnt = word_vec_make(search, &wovec);
	if (wocnt != 0) {
		for (i = 0; i < wocnt; i++)
			search_stats_tally(&wovec[i]);

		word_vec_free(wovec, wocnt);
	}
}

static void
search_stats_notify_whole(query_type_t type, const gchar *search,
	const host_addr_t unused_addr, guint16 unused_port)
{
    word_vec_t wovec;
	gchar buf[1024];

	(void) unused_addr;
	(void) unused_port;

	gm_snprintf(buf, sizeof buf, type == QUERY_SHA1 ? "urn:sha1:%s" : "[%s]",
        search);

	wovec.word = buf;
    wovec.len = strlen(wovec.word);
    wovec.amount = 1;

    search_stats_tally(&wovec);
}

static void
search_stats_notify_routed(query_type_t unused_type, const gchar *unused_search,
	const host_addr_t addr, guint16 port)
{
    word_vec_t wovec;

	(void) unused_type;
	(void) unused_search;

    wovec.word = deconstify_gchar(host_addr_port_to_string(addr, port));
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

	g_hash_table_foreach_remove(stat_hash, delete_hash_entry, NULL);
}

/**
 * Helper func for stats_display -
 *  does two things:
 *
 *  - clears out aged / infrequent search terms
 *  - sticks the rest of the search terms in treeview_search_stats
 */
static gboolean
stats_hash_to_treeview(gpointer key, gpointer value, gpointer unused_udata)
{
	struct term_counts *val = value;
	GtkTreeIter iter;
	gchar *s;

	(void) unused_udata;

	/* update counts */
	val->periods = val->period_cnt ? 0 : (val->periods + 1);
	val->total_cnt += val->period_cnt;

	/* try to keep the number of infrequent terms down */
	if (
		(1.0 * val->total_cnt / (val->periods + 2.0)) * 100 <
			GUI_PROPERTY(search_stats_delcoef)
	) {
		atom_str_free(key);
		wfree(val, sizeof *val);
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
/*
 * FIXME: The search stats take too much CPU so that it causes the GUI to
 *        lock up.
 */

	(void) lst;

#if 0
    if (!callback_registered) {
        guc_share_add_search_request_listener(lst);
        callback_registered = TRUE;
    }
#endif
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
}

/**
 * Count a word that has been seen.
 */
static void
search_stats_tally(const word_vec_t *vec)
{
	struct term_counts *val;
	gconstpointer key;

	if (vec->word[1] == '\0' || vec->word[2] == '\0')
		return;

	val = g_hash_table_lookup(stat_hash, vec->word);
	if (val) {
		val->period_cnt++;
	} else {
		key = atom_str_get(vec->word);
		val = walloc0(sizeof *val);
		val->period_cnt = vec->amount;
		gm_hash_table_insert_const(stat_hash, key, val);
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
}

void
search_stats_gui_set_type(gint type)
{
    if (type == selected_type)
        return;

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
add_column(GtkTreeView *treeview, gint id, gfloat xalign,
	const gchar *label)
{
    GtkTreeViewColumn *column;
    GtkCellRenderer *renderer;

    renderer = gtk_cell_renderer_text_new();
    gtk_cell_renderer_text_set_fixed_height_from_font(
        GTK_CELL_RENDERER_TEXT(renderer), 1);
    g_object_set(renderer,
        "xalign", xalign,
        "ypad", GUI_CELL_RENDERER_YPAD,
        (void *) 0);

    column = gtk_tree_view_column_new_with_attributes(
                label, renderer, "text", id, (void *) 0);

	g_object_set(G_OBJECT(column),
		"fixed-width", 1,
		"min-width", 1,
		"reorderable", TRUE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		"visible", TRUE,
		(void *) 0);

    gtk_tree_view_append_column(treeview, column);
	gtk_tree_view_column_set_sort_column_id(column, id);
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
		const gint id;
		const gfloat align;
		const gchar *title;
	} cols[] = {
		{ 0, 0.0, N_("Search Term") },
		{ 1, 1.0, N_("This Interval") },
		{ 2, 1.0, N_("Total") },
	};
	size_t i;
	GtkTreeModel *model;
    GtkTreeView *treeview;

	STATIC_ASSERT(G_N_ELEMENTS(cols) == G_N_ELEMENTS(types));

	treeview_search_stats =
        GTK_TREE_VIEW(gui_main_window_lookup("treeview_search_stats"));
	label_search_stats_count =
		GTK_LABEL(gui_main_window_lookup("label_search_stats_count"));

	treeview = treeview_search_stats;

    /* set up the treeview to be sorted properly */
	model = GTK_TREE_MODEL(gtk_list_store_newv(G_N_ELEMENTS(types), types));
	gtk_tree_view_set_model(treeview, model);
    store_search_stats = GTK_LIST_STORE(model);
	g_object_unref(model);

	for (i = 0; i < G_N_ELEMENTS(cols); i++) {
		add_column(treeview, cols[i].id, cols[i].align, _(cols[i].title));
	}
	tree_view_restore_widths(treeview, PROP_SEARCH_STATS_COL_WIDTHS);
	tree_view_set_fixed_height_mode(treeview, TRUE);

	stat_hash = g_hash_table_new(NULL, NULL);
}

void
search_stats_gui_shutdown(void)
{
	tree_view_save_widths(treeview_search_stats, PROP_SEARCH_STATS_COL_WIDTHS);
    search_stats_gui_set_type(NO_SEARCH_STATS);
    g_hash_table_destroy(stat_hash);
	stat_hash = NULL;
}

/**
 * Display the data gathered during the last time period.
 * Perhaps it would be better to have this done on a button click(?)
 */
void
search_stats_gui_update(time_t now)
{
	static time_t last_update = 0;
	const time_delta_t interval = GUI_PROPERTY(search_stats_update_interval);

    if (delta_time(now, last_update) < interval)
        return;

    last_update = now;

	stat_count = 0;
	gtk_list_store_clear(store_search_stats);
	g_object_freeze_notify(G_OBJECT(treeview_search_stats));
	/* insert the hash table contents into the sorted treeview */
	g_hash_table_foreach_remove(stat_hash, stats_hash_to_treeview, NULL);
	g_object_thaw_notify(G_OBJECT(treeview_search_stats));

	/* update the counter */
	gtk_label_printf(GTK_LABEL(label_search_stats_count),
		NG_("%u term counted", "%u terms counted", stat_count),
		stat_count);
}

/* vi: set ts=4 sw=4 cindent: */
