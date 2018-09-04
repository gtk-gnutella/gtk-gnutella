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
 *
 * Released with gtk-gnutella & its license.
 */

#include "common.h"

#include "gtk/gui.h"

#include "gtk/columns.h"
#include "gtk/misc.h"
#include "gtk/search_stats.h"

#include "if/core/share.h"
#include "if/gui_property.h"
#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"

#include "lib/htable.h"
#include "lib/misc.h"
#include "lib/str.h"
#include "lib/wordvec.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * This is what the stat_hash's 'val' points to.
 */
struct term_counts {
	guint32 period_cnt;
	guint32 total_cnt;
	guint32 periods;
};

static guint stat_count;

static htable_t *stat_hash = NULL;

static bool
delete_hash_entry(const void *key, void *val, void *unused_data)
{
	void *p = deconstify_pointer(key);

	(void) unused_data;
	/* free the key str (was strdup'd below) */
	G_FREE_NULL(p);
	G_FREE_NULL(val);
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
    gchar *buf;

	(void) unused_addr;
	(void) unused_port;

    if (QUERY_SHA1 == type)
        return;

	buf = g_strdup(search);
   	wocnt = word_vec_make(buf, &wovec);

	if (wocnt != 0) {
		for (i = 0; i < wocnt; i++)
			search_stats_tally(&wovec[i]);

		word_vec_free(wovec, wocnt);
	}

    G_FREE_NULL(buf);
}

static void
search_stats_notify_whole(query_type_t type, const gchar *search,
	const host_addr_t unused_addr, guint16 unused_port)
{
    word_vec_t wovec;
	gchar buf[1024];

	(void) unused_addr;
	(void) unused_port;

    str_bprintf(buf, sizeof buf, QUERY_SHA1 == type ? "urn:sha1:%s" : "[%s]",
		search);

	wovec.word = buf;
    wovec.len = vstrlen(wovec.word);
    wovec.amount = 1;

    search_stats_tally(&wovec);
}

static void
search_stats_notify_routed(query_type_t unused_type,
	const gchar *unused_search, const host_addr_t addr, guint16 port)
{
    const word_vec_t *p_wovec;
    word_vec_t wovec;

	(void) unused_type;
	(void) unused_search;

    wovec.word = deconstify_gchar(host_addr_port_to_string(addr, port));
    wovec.len = vstrlen(wovec.word);
    wovec.amount = 1;
	p_wovec = &wovec;

    search_stats_tally(p_wovec);
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

	htable_foreach_remove(stat_hash, delete_hash_entry, NULL);
}

/**
 * helper func for stats_display -
 *  does two things:
 *
 *  - clears out aged / infrequent search terms
 *  - sticks the rest of the search terms in clist_search_stats
 *
 */
static gboolean
stats_hash_to_clist(const void *key, void *value, void *unused_udata)
{
	gchar *text[3];
	gchar period_tmp[32];
	gchar total_tmp[32];
	struct term_counts *val = value;

	(void) unused_udata;

	/* update counts */
	if (!val->period_cnt)
		val->periods++;
	else
		val->periods = 0;
	val->total_cnt += val->period_cnt;

	/* try to keep the number of infrequent terms down */
	if (
		(1.0 * val->total_cnt / (val->periods + 2.0)) * 100 <
			GUI_PROPERTY(search_stats_delcoef)
	) {
		void *p = deconstify_pointer(key);
		G_FREE_NULL(p);
		G_FREE_NULL(val);
		return TRUE;
	}

	stat_count++;

	/* update the display */

    /* FIXME: make %8.8d %d and set up custom sort function */
	str_bprintf(period_tmp, sizeof period_tmp, "%8.8d", (int) val->period_cnt);
	str_bprintf(total_tmp, sizeof total_tmp, "%8.8d", (int) val->total_cnt);

	text[0] = deconstify_pointer(key);
	text[1] = period_tmp;
	text[2] = total_tmp;

    {
        GtkWidget *clist_search_stats =
            gui_main_window_lookup("clist_search_stats");

        gtk_clist_insert(GTK_CLIST(clist_search_stats), 0, text);
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
    if (!callback_registered) {
        guc_search_request_listener_add(lst);
        callback_registered = TRUE;
    }
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
search_stats_tally(const word_vec_t * vec)
{
	struct term_counts *val;
	gpointer key;
	guint i;

	for (i = 0; i < 3; i++) {
		if ('\0' == vec->word[i])
			return;
	}

	val = htable_lookup(stat_hash, vec->word);
	if (val) {
		val->period_cnt++;
	} else {
		key = g_strdup(vec->word);
		val = g_malloc0(sizeof *val);
		val->period_cnt = vec->amount;
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
	gtk_clist_clear(GTK_CLIST(
        gui_main_window_lookup("clist_search_stats")));
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

/**
 * Display the data gathered during the last time period.
 * Perhaps it would be better to have this done on a button click(?)
 */
static void
search_stats_gui_update_display(void)
{
    GtkWidget *clist_search_stats;
    GtkWidget *label_search_stats_count;

    clist_search_stats = gui_main_window_lookup("clist_search_stats");
    label_search_stats_count =
        gui_main_window_lookup("label_search_stats_count");

	stat_count = 0;
	gtk_clist_freeze(GTK_CLIST(clist_search_stats));

	gtk_clist_clear(GTK_CLIST(clist_search_stats));
	/* insert the hash table contents into the sorted clist */
	htable_foreach_remove(stat_hash, stats_hash_to_clist, NULL);
	gtk_clist_sort(GTK_CLIST(clist_search_stats));

	gtk_clist_thaw(GTK_CLIST(clist_search_stats));

	/* update the counter */
	gtk_label_printf(GTK_LABEL(label_search_stats_count),
		NG_("%u term counted", "%u terms counted", stat_count),
		stat_count);
}

static gboolean
search_stats_gui_is_visible(void)
{
	return main_gui_window_visible() &&
		nb_main_page_search_stats == main_gui_notebook_get_page();
}

static void
search_stats_gui_timer(time_t now)
{
	static time_t last_update;
	time_delta_t interval = GUI_PROPERTY(search_stats_update_interval);

    if (
		search_stats_gui_is_visible() &&
		delta_time(now, last_update) > interval
	) {
    	last_update = now;
		search_stats_gui_update_display();
	}
}

void
search_stats_gui_init(void)
{
    GtkCList *clist = GTK_CLIST(gui_main_window_lookup("clist_search_stats"));

    /* set up the clist to be sorted properly */
	gtk_clist_set_sort_column(clist, c_st_total);
	gtk_clist_set_sort_type(clist, GTK_SORT_DESCENDING);
	clist_restore_widths(clist, PROP_SEARCH_STATS_COL_WIDTHS);

	stat_hash = htable_create(HASH_KEY_STRING, 0);
	main_gui_add_timer(search_stats_gui_timer);
}

void
search_stats_gui_shutdown(void)
{
	clist_save_widths(
		GTK_CLIST(gui_main_window_lookup("clist_search_stats")),
		PROP_SEARCH_STATS_COL_WIDTHS);
    search_stats_gui_set_type(NO_SEARCH_STATS);
    empty_hash_table();
    htable_free_null(&stat_hash);
}

/* vi: set ts=4 sw=4 cindent: */
