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

#include "search_stats_gui.h"

#include <stdio.h>
#include <stdlib.h>

/* this is what the stat_hash's 'val' points to */
struct term_counts {
	guint32 period_cnt;
	guint32 total_cnt;
	guint32 periods;
};

static guint32 stat_count;

static GHashTable *stat_hash = NULL;

static gboolean delete_hash_entry(gpointer key, gpointer val, gpointer data);
static void empty_hash_table();
static gboolean stats_hash_to_clist(
	gpointer key, gpointer value, gpointer userdata);

static gboolean
delete_hash_entry(gpointer key, gpointer val, gpointer data)
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
    gchar *buf;

    if (type == QUERY_SHA1)
        return;

	buf = g_strdup(search);
   	wocnt = query_make_word_vec(buf, &wovec);

	if (wocnt != 0) {
		for (i = 0; i < wocnt; i++)
			search_stats_tally(&wovec[i]);

		query_word_vec_free(wovec, wocnt);
	}

    g_free(buf);
}

static void search_stats_notify_whole(
    query_type_t type, const gchar *search, guint32 ip, guint16 port)
{
    word_vec_t wovec;

    if (type == QUERY_SHA1)
        wovec.word = g_strdup_printf("urn:sha1:%s", search);
    else
        wovec.word = g_strdup_printf("[%s]", search);

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
static void empty_hash_table()
{
	if (!stat_hash)
		return;

	g_hash_table_foreach_remove(stat_hash, delete_hash_entry, NULL);
}

/*
 * helper func for stats_display -
 *  does two things:
 *  1. clears out aged / infrequent search terms
 *  2. sticks the rest of the search terms in clist_search_stats
 *
 */
static gboolean stats_hash_to_clist(
    gpointer key, gpointer value, gpointer userdata)
{
	gchar *text[3];
	gchar period_tmp[32];
	gchar total_tmp[32];
	struct term_counts *val = (struct term_counts *) value;

	/* update counts */
	if (!val->period_cnt)
		val->periods++;
	else
		val->periods = 0;
	val->total_cnt += val->period_cnt;

	/* try to keep the number of infrequent terms down */
	if (
		((float) val->total_cnt / (val->periods + 2.0)) * 100 <
			search_stats_delcoef
	) {
		g_free(key);
		g_free(val);
		return TRUE;
	}

	stat_count++;

	/* update the display */

    // FIXME: make %8.8d %d and set up custom sort function
	g_snprintf(period_tmp, sizeof(period_tmp), "%8.8d", (int) val->period_cnt);
	g_snprintf(total_tmp, sizeof(total_tmp), "%8.8d", (int) val->total_cnt);

	text[0] = (gchar *) key;
	text[1] = period_tmp;
	text[2] = total_tmp;

    {
        GtkWidget *clist_search_stats = 
            lookup_widget(main_window, "clist_search_stats");
        
        gtk_clist_insert(GTK_CLIST(clist_search_stats), 0, text);
    }

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
	gtk_clist_clear(GTK_CLIST(
        lookup_widget(main_window, "clist_search_stats")));
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

void search_stats_gui_init(void)
{
    GtkCombo *combo_types;
    GtkWidget *clist_search_stats = 
        lookup_widget(main_window, "clist_search_stats");

    combo_types = GTK_COMBO(
        lookup_widget(main_window, "combo_search_stats_type"));

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

    /* set up the clist to be sorted properly */
	gtk_clist_set_sort_column(GTK_CLIST(clist_search_stats), c_st_total);
	gtk_clist_set_sort_type(GTK_CLIST(clist_search_stats),
		GTK_SORT_DESCENDING);

	stat_hash = g_hash_table_new(g_str_hash, g_str_equal);

}

void search_stats_gui_shutdown(void)
{
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
    GtkWidget *clist_search_stats;
    GtkWidget *label_search_stats_count;

    if (last_update + search_stats_update_interval > now)
        return;

    last_update = now;

    clist_search_stats = lookup_widget(main_window, "clist_search_stats");
    label_search_stats_count = 
        lookup_widget(main_window, "label_search_stats_count");

	stat_count = 0;
	gtk_clist_freeze(GTK_CLIST(clist_search_stats));

	gtk_clist_clear(GTK_CLIST(clist_search_stats));
	/* insert the hash table contents into the sorted clist */
	g_hash_table_foreach_remove(stat_hash, stats_hash_to_clist, NULL);
	gtk_clist_sort(GTK_CLIST(clist_search_stats));

	gtk_clist_thaw(GTK_CLIST(clist_search_stats));

	/* update the counter */
	g_snprintf(tmpstr, sizeof(tmpstr), "%u terms counted", stat_count);
	gtk_label_set_text(GTK_LABEL(label_search_stats_count), tmpstr);
}
