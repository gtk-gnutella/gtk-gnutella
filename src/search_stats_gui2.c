/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 *
 * search_stats.c - keep track of what search terms we have seen, and 
 *					how frequently each has been seen.
 *
 *		this uses the glib hash tables and lists, but a much more efficient
 *		implementation could be done with a specialized hash table /
 *		re-keyable binary tree. (TODO?)	would be easy in c++.
 *
 *		(C) 2002 Michael Tesch, released with gtk-gnutella & its license
 */

#include "config.h"

#ifdef USE_GTK2

#include "search_stats_gui.h"

#include <stdio.h>
#include <stdlib.h>

RCSID("$Id$");

/* this is what the stat_hash's 'val' points to */
struct term_counts {
	guint32 period_cnt;
	guint32 total_cnt;
	guint32 periods;
};

static gulong stat_count = 0;

static GHashTable *stat_hash = NULL;
static GtkListStore *store_search_stats = NULL;
static GtkTreeView *treeview_search_stats = NULL;
static GtkLabel *label_search_stats_count = NULL;

static gboolean delete_hash_entry(gpointer key, gpointer val, gpointer data);
static void empty_hash_table(void);
static gboolean stats_hash_to_treeview(
	gpointer key, gpointer value, gpointer userdata);

static gboolean delete_hash_entry(gpointer key, gpointer val, gpointer data)
{
	/* free the key str (was strdup'd below) */
	g_free(key);
	g_free(val);
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

static void search_stats_notify_word(
    query_type_t type, const gchar *search, guint32 ip, guint16 port)
{
    word_vec_t *wovec;
    guint wocnt;
    guint i;

    if (type == QUERY_SHA1)
        return;

   	wocnt = query_make_word_vec(search, &wovec);

	if (wocnt != 0) {
		for (i = 0; i < wocnt; i++)
			search_stats_tally(&wovec[i]);

		query_word_vec_free(wovec, wocnt);
	}
}

static void search_stats_notify_whole(
    query_type_t type, const gchar *search, guint32 ip, guint16 port)
{
    word_vec_t wovec;

    if (type == QUERY_SHA1)
        wovec.word = g_strconcat("urn:sha1:", search);
    else
        wovec.word = g_strconcat("[", search, "]");

    wovec.len = strlen(wovec.word);
    wovec.amount = 1;

    search_stats_tally(&wovec);

    g_free(wovec.word);
}

static void search_stats_notify_routed(
    query_type_t type, const gchar *search, guint32 ip, guint16 port)
{
    word_vec_t wovec;

/*    if (type == QUERY_SHA1)
        return;*/

    wovec.word = ip_port_to_gchar(ip, port);
    wovec.len = strlen(wovec.word);
    wovec.amount = 1;

    search_stats_tally(&wovec);
}

/***
 *** Private functions
 ***/

/* this sucks -- too slow */
static void empty_hash_table(void)
{
	if (!stat_hash)
		return;

	g_hash_table_foreach_remove(stat_hash, delete_hash_entry, NULL);
}

/*
 * helper func for stats_display -
 *  does two things:
 *  1. clears out aged / infrequent search terms
 *  2. sticks the rest of the search terms in treeview_search_stats
 *
 */
static gboolean stats_hash_to_treeview(
    gpointer key, gpointer value, gpointer userdata)
{
	GtkTreeIter iter;
	struct term_counts *val = (struct term_counts *) value;

	/* update counts */
	if (!val->period_cnt)
		val->periods++;
	else
		val->periods = 0;
	val->total_cnt += val->period_cnt;

	/* try to keep the number of infrequent terms down */
	if (
		((gfloat) val->total_cnt / (val->periods + 2.0)) * 100 <
			search_stats_delcoef
	) {
		G_FREE_NULL(key);
		G_FREE_NULL(val);
		return TRUE;
	}

	stat_count++;

	/* update the display */

	gtk_list_store_append(store_search_stats, &iter);
	gtk_list_store_set(store_search_stats, &iter,
		0, locale_to_utf8(key, 0),
		1, (gulong) val->period_cnt,
		2, (gulong) val->total_cnt,
		(-1));

	/* new period begins */
	val->period_cnt = 0;

	return FALSE;
}

/*
 * search_stats_enable
 *
 * Enable search stats.
 */
static void search_stats_gui_enable(search_request_listener_t lst)
{
    if (!callback_registered) {
        share_add_search_request_listener(lst);
        callback_registered = TRUE;
    }
}

static void search_stats_gui_disable(void)
{
    if (callback_registered) {
        share_remove_search_request_listener
            (search_stats_notify_word);
        share_remove_search_request_listener
            (search_stats_notify_whole);
        share_remove_search_request_listener
            (search_stats_notify_routed);
        callback_registered = FALSE;
    }

    empty_hash_table();
}

/*
 * search_stats_tally:
 *
 * Count a word that has been seen.
 */
static void search_stats_tally(const word_vec_t * vec)
{
	struct term_counts *val;
	gpointer key;

	if (vec->word[1] == '\0' || vec->word[2] == '\0')
		return;

	val = g_hash_table_lookup(stat_hash, vec->word);
	if (val) {
		val->period_cnt++;
	} else {
		key = g_strdup(vec->word);
		val = (struct term_counts *) g_malloc0(sizeof(struct term_counts));
		val->period_cnt = vec->amount;
		g_hash_table_insert(stat_hash, key, (gpointer) val);
	}
}



/***
 *** Public functions 
 ***/

/*
 * search_stats_reset:
 *
 * Clear the list, empty the hash table.
 */
void search_stats_gui_reset(void)
{
	empty_hash_table();
	gtk_list_store_clear(store_search_stats);
}

void search_stats_gui_set_type(gint type)
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
    };
}

/* FIXME: merge all `add_column' functions into one */
static void add_column(
    GtkTreeView *treeview,
    gint column_id,
    gint width,
    gfloat xalign,
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
        NULL);

    column = gtk_tree_view_column_new_with_attributes(
                label, renderer, "text", column_id, NULL);
    gtk_tree_view_column_set_min_width(column, 1);
    gtk_tree_view_column_set_fixed_width(column, MAX(1, width));
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_reorderable(column, TRUE);
    gtk_tree_view_append_column(treeview, column);
}

void search_stats_gui_init(void)
{
    GtkCombo *combo_types;
	GtkTreeModel *model;
    GtkTreeView *treeview;

	treeview_search_stats = 
        GTK_TREE_VIEW(lookup_widget(main_window, "treeview_search_stats"));
	label_search_stats_count =
		GTK_LABEL(lookup_widget(main_window, "label_search_stats_count"));
    combo_types =
		GTK_COMBO(lookup_widget(main_window, "combo_search_stats_type"));

	treeview = treeview_search_stats;
#if 0
    search_stats_mode_def = gui_prop_get_def(PROP_SEARCH_STATS_MODE);

    gtk_combo_init_choices(
        combo_types, 
        GTK_SIGNAL_FUNC(on_search_stats_type_selected),
        search_stats_mode_def);

    prop_free_def(search_stats_mode_def);

    /*
     * Save search_stats_mode because it will be overridden
     * when we create the menu.
     */
    original_mode = search_stats_mode;

    n = 0;
    while (search_stats_mode->data.guint32.choices[n].title != NULL) {
        GtkWidget *list_item;
        GList *l;

        list_item = gtk_list_item_new_with_label(type_str[n]);
        gtk_widget_show(list_item);
        
        gtk_signal_connect(
            GTK_OBJECT(list_item), "select",
            GTK_SIGNAL_FUNC(on_search_stats_type_selected),
            GINT_TO_POINTER(search_stats_mode->data.guint32.choices[n].value));

        l = g_list_prepend(NULL, (gpointer) list_item);
        gtk_list_append_items(GTK_LIST(GTK_COMBO(combo_types)->list), l);

        if (search_stats_mode->data.guint32.choices[n].value == original_mode)
            gtk_list_select_child(
                GTK_LIST(GTK_COMBO(combo_types)->list), list_item);
    }
#endif

    /* set up the treeview to be sorted properly */
	model = GTK_TREE_MODEL(gtk_list_store_new(3,
		G_TYPE_STRING, G_TYPE_ULONG, G_TYPE_ULONG));
	gtk_tree_view_set_model(treeview, model);
    store_search_stats = GTK_LIST_STORE(model);
	g_object_unref(model);
	add_column(treeview, 0, 200, 0.0, "Search Term");
	add_column(treeview, 1, 60, 1.0, "This Interval");
	add_column(treeview, 2, 60, 1.0, "Total");
	stat_hash = g_hash_table_new(g_str_hash, g_str_equal);
}

void search_stats_gui_shutdown(void)
{
	tree_view_save_widths(treeview_search_stats, PROP_SEARCH_STATS_COL_WIDTHS);
    search_stats_gui_set_type(NO_SEARCH_STATS);
    g_hash_table_destroy(stat_hash);
	stat_hash = NULL;
}

/*
 * Display the data gathered during the last time period.
 * Perhaps it would be better to have this done on a button click(?)
 */
void search_stats_gui_update(time_t now)
{
	static guint32 last_update = 0;
	char tmpstr[32];

    if (last_update + search_stats_update_interval > now)
        return;

    last_update = now;

	stat_count = 0;
	g_object_freeze_notify(G_OBJECT(treeview_search_stats));
	gtk_list_store_clear(store_search_stats);
	/* insert the hash table contents into the sorted treeview */
	g_hash_table_foreach_remove(stat_hash, stats_hash_to_treeview, NULL);
	g_object_thaw_notify(G_OBJECT(treeview_search_stats));

	/* update the counter */
	gm_snprintf(tmpstr, sizeof(tmpstr), "%lu terms counted", stat_count);
	gtk_label_set_text(label_search_stats_count, tmpstr);
}

#endif	/* USE_GTK2 */
