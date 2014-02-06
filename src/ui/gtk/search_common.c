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

/**
 * @ingroup gtk
 * @file
 *
 * Common GUI search routines.
 *
 * @author Raphael Manfredi
 * @date 2003
 */

#include "gui.h"

#include "gtk/search_common.h"
#include "gtk/search_xml.h"

#include "gtk/bitzi.h"
#include "gtk/clipboard.h"
#include "gtk/drag.h"
#include "gtk/drop.h"
#include "gtk/filter_core.h"
#include "gtk/gtkcolumnchooser.h"
#include "gtk/misc.h"
#include "gtk/search.h"
#include "gtk/settings.h"
#include "gtk/statusbar.h"

#include "if/gui_property_priv.h"
#include "if/gnet_property.h"
#include "if/core/downloads.h"
#include "if/core/guess.h"
#include "if/core/guid.h"
#include "if/core/search.h"
#include "if/core/sockets.h"
#include "if/bridge/ui2c.h"

#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/base16.h"
#include "lib/base32.h"
#include "lib/concat.h"
#include "lib/file.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/hashing.h"
#include "lib/hset.h"
#include "lib/htable.h"
#include "lib/iso3166.h"
#include "lib/magnet.h"
#include "lib/mime_type.h"
#include "lib/misc.h"			/* For xml_indent() */
#include "lib/parse.h"
#include "lib/pslist.h"
#include "lib/random.h"
#include "lib/slist.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/timestamp.h"
#include "lib/tm.h"
#include "lib/url.h"
#include "lib/url_factory.h"
#include "lib/urn.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

/**
 * Accumulated results (coming from the core) are kept around and flushed
 * on a regular basis.
 *
 * Because filtering of records happens in the GUI but we need to inform
 * the core about the amount of "kept" results, we tie each result to the MUID
 * of the query that generated it.
 *
 * This allows us to give accurate feedback to the number of results "kept" for
 * a GUESS query.
 */
struct accum_rs {
	const struct guid *muid;		/**< The query MUID (atom) */
	results_set_t *rs;				/**< The GUI result set */
};

static GList *list_searches;	/**< List of search structs */
static htable_t *ht_searches;	/**< Maps a gnet_search_t to a search_t */

static search_t *current_search; /**< The search currently displayed */

static const gchar search_file[] = "searches"; /**< "old" file to searches */

static slist_t *accumulated_rs;		/**< List of accum_rs structs */
static GList *list_search_history;

static GtkNotebook *notebook_search_results;
static GtkLabel *label_items_found;
static GtkLabel *label_search_expiry;
static GtkLabel *label_guess_stats;
static GtkWidget *guess_stats_line;

static gboolean store_searches_requested;
static gboolean store_searches_disabled;

static record_t *search_details_record;

/**
 * Human readable translation of servent trailer open flags.
 * Decompiled flags are listed in the order of the table.
 */
static struct {
	guint32 flag;
	const gchar *status;
} open_flags[] = {
	{ ST_G2,			N_("g2") },			/* Make sure this is shown first */
	{ ST_BUSY,			N_("busy") },
	{ ST_UPLOADED,		N_("stable") },		/**< Allows uploads -> stable */
	{ ST_FIREWALL,		N_("push") },
	{ ST_PUSH_PROXY,	N_("proxy") },
	{ ST_BOGUS,			N_("bogus") },		/**< Bogus IP address */
	{ ST_ALIEN,			N_("alien") },		/**< Alien IP address */
	{ ST_MEDIA,			N_("media") },		/**< Media-type mismatch */
};

static struct {
	const gchar * const spec;
	const enum gui_color id;
	GdkColor color;
} colors[] = {
	{ "#000000", GUI_COLOR_DEFAULT,		{ 0, 0, 0, 0 } }, /* black */
	{ "#326732", GUI_COLOR_DOWNLOADING,	{ 0, 0, 0, 0 } }, /* dark green */
	{ "#5F007F", GUI_COLOR_HOSTILE,		{ 0, 0, 0, 0 } }, /* indigo */
	{ "#7F7F7F", GUI_COLOR_IGNORED,		{ 0, 0, 0, 0 } }, /* gray */
	{ "#001F7F", GUI_COLOR_MARKED, 		{ 0, 0, 0, 0 } }, /* blue */
	{ "#FC000D", GUI_COLOR_MAYBE_SPAM, 	{ 0, 0, 0, 0 } }, /* flashy red */
	{ "#7f0000", GUI_COLOR_SPAM, 		{ 0, 0, 0, 0 } }, /* dark red */
	{ "#CD1076", GUI_COLOR_ALIEN, 		{ 0, 0, 0, 0 } }, /* deep pink */
	{ "#FF69B4", GUI_COLOR_BANNED_GUID,	{ 0, 0, 0, 0 } }, /* hot pink */
	{ "#7E5029", GUI_COLOR_UNREQUESTED,	{ 0, 0, 0, 0 } }, /* marroon */
	{ "#708090", GUI_COLOR_PUSH,		{ 0, 0, 0, 0 } }, /* slate gray */
	{ "#2F4F4F", GUI_COLOR_PUSH_PROXY,	{ 0, 0, 0, 0 } }, /* dark slate gray */
	{ "#7B68EE", GUI_COLOR_PARTIAL_PUSH,{ 0, 0, 0, 0 } }, /* med. slate blue */
	{ "#D7B700", GUI_COLOR_PARTIAL,		{ 0, 0, 0, 0 } }, /* gold (darker) */
	{ "#8B4513", GUI_COLOR_MEDIA,		{ 0, 0, 0, 0 } }, /* chocolate4 */
	{ "#FFFFFF", GUI_COLOR_BACKGROUND,	{ 0, 0, 0, 0 } }, /* white */
};

GdkColor *
gui_color_get(const enum gui_color id)
{
	g_assert((guint) id <= NUM_GUI_COLORS);
	return &colors[(guint) id].color;
}

static void
gui_color_set(const enum gui_color id, GdkColor *color)
{
	g_assert((guint) id <= NUM_GUI_COLORS);
	g_return_if_fail(color);
	colors[(guint) id].color = *color;
}

static void
gui_color_init(GtkWidget *widget)
{
	static gboolean initialized;
    GdkColormap *cmap;
	guint i;

	if (initialized)
		return;

	initialized = TRUE;
	STATIC_ASSERT(NUM_GUI_COLORS == G_N_ELEMENTS(colors));
	cmap = gdk_colormap_get_system();
    g_assert(cmap);

	for (i = 0; i < NUM_GUI_COLORS; i++) {
		GdkColor color;

		g_assert(colors[i].id == i);
		gdk_color_parse(colors[i].spec, &color);
		gdk_colormap_alloc_color(cmap, &color, FALSE, TRUE);
		gui_color_set(colors[i].id, &color);
	}
	if (widget) {
		gui_color_set(GUI_COLOR_DEFAULT,
			&gtk_widget_get_style(GTK_WIDGET(widget))->fg[GTK_STATE_NORMAL]);
	}
}

const GList *
search_gui_get_searches(void)
{
	return (const GList *) list_searches;
}

search_t *
search_gui_get_current_search(void)
{
	return current_search;
}

gboolean
search_gui_is_enabled(const search_t *search)
{
	g_assert(search);
	return !guc_search_is_frozen(search->search_handle);
}

static gboolean
search_gui_is_of_type(const search_t *search, unsigned flag,
	gboolean (*is_of_type)(gnet_search_t))
{
	g_assert(search != NULL);
	g_assert(flag != 0);
	g_assert(is_of_type != NULL);

	if (0 == (search->cached_attributes & flag)) {
		gboolean value = (*is_of_type)(search->search_handle);
		search_t *ws = deconstify_gpointer(search);

		ws->cached_attributes |= flag;
		if (value)
			ws->attributes |= flag;
	}

	return booleanize(search->attributes & flag);
}

static gboolean
search_gui_is_browse(const search_t *search)
{
	return search_gui_is_of_type(search,
		SEARCH_GUI_F_BROWSE, guc_search_is_browse);
}

static gboolean
search_gui_is_local(const search_t *search)
{
	return search_gui_is_of_type(search,
		SEARCH_GUI_F_LOCAL, guc_search_is_local);
}

static gboolean
search_gui_is_passive(const search_t *search)
{
	return search_gui_is_of_type(search,
		SEARCH_GUI_F_PASSIVE, guc_search_is_passive);
}

static gboolean
search_gui_is_whats_new(const search_t *search)
{
	return search_gui_is_of_type(search,
		SEARCH_GUI_F_WHATS_NEW, guc_search_is_whats_new);
}

static void
on_option_menu_menu_item_activate(GtkMenuItem *unused_item, gpointer udata)
{
	GtkOptionMenu *option_menu;

	(void) unused_item;

	option_menu = GTK_OPTION_MENU(udata);
	search_gui_set_current_search(option_menu_get_selected_data(option_menu));
}

static GtkOptionMenu *
option_menu_searches(void)
{
	static GtkWidget *widget;

	if (NULL == widget) {
		widget = gui_main_window_lookup("option_menu_searches");
	}
	return GTK_OPTION_MENU(widget);
}

static unsigned option_menu_searches_frozen;

static void
search_gui_option_menu_searches_update(void)
{
	GtkMenu *menu;
	const GList *iter;
	guint idx = 0, n = 0;

	if (option_menu_searches_frozen)
		return;

	menu = GTK_MENU(gtk_menu_new());

	iter = g_list_last(deconstify_gpointer(search_gui_get_searches()));
	for (/* NOTHING */; iter != NULL; n++, iter = g_list_previous(iter)) {
		search_t *search = iter->data;
		const gchar *query;
		GtkWidget *item;
		gchar *name;

		if (search_gui_get_current_search() == search) {
			idx = n;
		}
		query = search_gui_query(search);
		if (search_gui_is_browse(search)) {
			name = g_strconcat("browse:", query, (void *) 0);
		} else if (search_gui_is_passive(search)) {
			name = g_strconcat("passive:", query, (void *) 0);
		} else if (search_gui_is_local(search)) {
			name = g_strconcat("local:", query, (void *) 0);
		} else {
			name = g_strdup(query);
		}

		/*
		 * Limit the title length of the menu item to a certain amount
		 * of characters (not bytes) because overlong query strings
		 * would cause a very wide menu.
		 */
		{
			const gchar ellipse[] = "[...]";
			gchar title[BITPRINT_BASE32_SIZE * 4 + sizeof ellipse];
			const gchar *ui_query;
			size_t title_size;

			ui_query = lazy_utf8_to_ui_string(name);
			title_size = sizeof title - sizeof ellipse;
			utf8_strcpy_max(title, title_size, ui_query, BITPRINT_BASE32_SIZE);
			if (strlen(title) < strlen(ui_query)) {
				strncat(title, ellipse, CONST_STRLEN(ellipse));
			}

			item = gtk_menu_item_new_with_label(title);
		}
		G_FREE_NULL(name);
	
		gtk_widget_show(item);
		gtk_object_set_user_data(GTK_OBJECT(item), search);
		gtk_menu_shell_prepend(GTK_MENU_SHELL(menu), item);
		gui_signal_connect(item, "activate",
			on_option_menu_menu_item_activate, option_menu_searches());
	}

	gtk_option_menu_set_menu(option_menu_searches(), GTK_WIDGET(menu));

	if (n > 0) {
		idx = n - idx - 1;
		gtk_option_menu_set_history(option_menu_searches(), idx);
	}
}

static void
search_gui_option_menu_searches_select(const search_t *search)
{
	if (search && !option_menu_searches_frozen) {
		option_menu_select_item_by_data(option_menu_searches(), search);
	}
}

void
search_gui_option_menu_searches_freeze(void)
{
	option_menu_searches_frozen++;
}

void
search_gui_option_menu_searches_thaw(void)
{
	g_return_if_fail(option_menu_searches_frozen > 0);
	if (--option_menu_searches_frozen > 0)
		return;
	
	search_gui_option_menu_searches_update();
	search_gui_option_menu_searches_select(current_search);
}

static void
search_gui_update_tab_label(const struct search *search)
{
	char label[4096];
	char items[32];

	if (NULL == search)
		return;

    uint32_to_string_buf(search->items, items, sizeof items);
	concat_strings(label, sizeof label,
		lazy_utf8_to_ui_string(search_gui_query(search)),
		"\n(", items,
		search->unseen_items > 0 ? ", " : "",
		search->unseen_items > 0 ? uint32_to_string(search->unseen_items) : "",
		")",
		(void *) 0);

	gtk_notebook_set_tab_label_text(notebook_search_results,
		search->scrolled_window, label);
}

void 
search_gui_update_status_label(const struct search *search)
{
	char expire[128];
	char downloads[48];
	unsigned dlcount;

	if (search != current_search)
		return;

	if G_UNLIKELY(NULL == search) {
        gtk_label_printf(label_search_expiry, "%s", _("No search"));
		return;
	}

	dlcount = guc_search_associated_sha1_count(search->search_handle);
	expire[0] = downloads[0] = '\0';

	if (!search_gui_is_enabled(search)) {
		unsigned queued = search_gui_queue_length(search);

		if (queued > 0) {
       		str_bprintf(expire, sizeof expire,
				_("Flushing queue (%u results pending)"), queued);
		} else {
			str_bprintf(expire, sizeof expire, "%s",
				_("The search has been stopped"));
		}
	} else if (search_gui_is_passive(search)) {
		str_bprintf(expire, sizeof expire, "%s", _("Passive search"));
	} else if (search_gui_is_expired(search)) {
		str_bprintf(expire, sizeof expire, "%s", _("Expired"));
	} else {
		unsigned time_left;

		time_left = 3600 * guc_search_get_lifetime(search->search_handle);
		if (time_left) {
			time_t created;
			time_delta_t d;
					
			created = guc_search_get_create_time(search->search_handle);
					
			d = delta_time(tm_time(), created);
			d = MAX(0, d);
			d = UNSIGNED(d) < time_left ? time_left - UNSIGNED(d) : 0;
			str_bprintf(expire, sizeof expire,
				_("Expires in %s"), short_time(d));
		} else {
   			str_bprintf(expire, sizeof expire, "%s",
				_("Expires with this session"));
		}
	}

	if (dlcount != 0) {
		str_bprintf(downloads, sizeof downloads,
			NG_(" [%u download]", " [%u downloads]", dlcount), dlcount);
	}

  	gtk_label_printf(label_search_expiry, "%s%s", expire, downloads);
}

/**
 * Update the label string showing search stats.
 */
static void
search_gui_update_items_label(const struct search *search)
{
	if (search != current_search)
		return;

    if (search) {
		gtk_label_printf(label_items_found, _("%u %s "
			"(%u skipped, %u ignored, %u hidden, %u auto-d/l, %u %s)"
			" Hits: %u (%u TCP, %u UDP)"),
			search->items, NG_("item", "items", search->items),
			search->skipped,
			search->ignored,
			search->hidden,
			search->auto_downloaded,
			search->duplicates, NG_("dupe", "dupes", search->duplicates),
			search->tcp_qhits + search->udp_qhits,
			search->tcp_qhits,
			search->udp_qhits);
    } else {
       gtk_label_printf(label_items_found, "%s", _("No search"));
	}
}

/**
 * Can search be the target of a GUESS query?
 */
static bool
search_gui_can_use_guess(const struct search *search)
{
	g_return_val_if_fail(search != NULL, FALSE);

	return !search_gui_is_passive(search) &&
		!search_gui_is_whats_new(search) &&
		!search_gui_is_browse(search) &&
		!search_gui_is_local(search);
}

/**
 * Update the label string showing GUESS stats, if displayed.
 */
static void
search_gui_update_guess_stats(const struct search *search)
{
	char buf[256];

	if (
		NULL == search ||
		search != current_search ||
		!search_gui_can_use_guess(search) ||
		!GUI_PROPERTY(search_display_guess_stats)
	)
		return;

	if (0 == search->guess_queries) {
		g_strlcpy(buf, _("No GUESS queries run yet"), sizeof buf);
	} else if (
		GUI_PROPERTY(guess_stats_show_total) ||
		0 == search->guess_cur_start
	) {
		/*
		 * Either they want summary stats or there are no currently running
		 * GUESS search: display summary only.
		 */
		char prev[128];
		uint64 hits = search->guess_results + search->guess_cur_results;
		if (search->guess_elapsed != 0) {
			str_bprintf(prev, sizeof prev,
				_(" previous took %s querying %zu %s with %zu %s kept"),
				compact_time(search->guess_elapsed),
				search->guess_hosts,
				NG_("host", "hosts", search->guess_hosts),
				search->guess_last_kept,
				NG_("hit", "hits", search->guess_last_kept));
		} else {
			prev[0] = '\0';
		}
		str_bprintf(buf, sizeof buf, _("GUESS %s [Total: %zu %s "
			"(%s %s, %s kept, %s queries, %s keys)%s]"),
			0 == search->guess_cur_start ? _("idle") :
				compact_time(delta_time(tm_time(), search->guess_cur_start)),
			search->guess_queries,
			NG_("query", "queries", search->guess_queries),
			uint64_to_string(hits), NG_("hit", "hits", hits),
			uint64_to_string2(search->guess_kept + search->guess_cur_kept),
			short_size(
				search->guess_bw_query + search->guess_cur_bw_query, FALSE),
			short_size2(
				search->guess_bw_qk + search->guess_cur_bw_qk, FALSE),
			prev);
	} else {
		size_t queried = search->guess_cur_ultra + search->guess_cur_g2;
		/*
		 * A GUESS search is active AND they don't want only summary stats.
		 */
		str_bprintf(buf, sizeof buf, _("GUESS %s [%s "
			"(%zu %s, %zu kept, %s queries, %s keys)] "
			"[Pool: %zu %s, (%zu+%zu)/%zu queried, %zu %s (%.2f%%), "
			"%zu pending, %zu %s%s%s]"),
			compact_time(delta_time(tm_time(), search->guess_cur_start)),
			GUESS_QUERY_LOOSE == search->guess_cur_mode ?
				_("loose") : _("bounded"),
			search->guess_cur_results,
			NG_("hit", "hits", search->guess_cur_results),
			search->guess_cur_kept,
			short_size(search->guess_cur_bw_query, FALSE),
			short_size2(search->guess_cur_bw_qk, FALSE),
			search->guess_cur_pool,
			NG_("host", "hosts", search->guess_cur_pool),
			search->guess_cur_ultra, search->guess_cur_g2,
			search->guess_cur_max_ultra,
			search->guess_cur_acks,
			NG_("ack", "acks", search->guess_cur_acks),
			100.0 * search->guess_cur_acks / (0 == queried ?  1 : queried),
			search->guess_cur_rpc_pending,
			search->guess_cur_hops,
			NG_("hop", "hops", search->guess_cur_hops),
			search->guess_cur_pool_load ? _(" (load pending)") : "",
			search->guess_cur_end_starving ? _(" (end if starving)") : "");
	}

	gtk_label_printf(label_guess_stats, "%s", buf);
}

static gboolean
search_gui_is_visible(void)
{
	return main_gui_window_visible() &&
		nb_main_page_search == main_gui_notebook_get_page();
}

static void
search_gui_update_counters(struct search *search)
{
	if (search && !search->list_refreshed) {
		if (search == current_search) {
			search->unseen_items = 0;
		}
		search->list_refreshed = TRUE;
		search_gui_update_list_label(search);
		search_gui_update_tab_label(search);
	}
}

static void 
search_gui_update_status(struct search *search)
{
	if (search_gui_is_visible()) {
		search_gui_update_counters(search);
		search_gui_update_status_label(search);
		search_gui_update_items_label(search);
		search_gui_update_guess_stats(search);
	}
}


/**
 * Tell the core to start or stop the search.
 */
static void
search_gui_set_enabled(struct search *search, gboolean enable)
{
	if (search_gui_is_enabled(search) != enable) {
		if (enable) {
			guc_search_start(search->search_handle);
		} else {
			guc_search_stop(search->search_handle);
		}
		/* Refresh is caused by status change event */
	} else {
		/* Refresh the status anyway, required initially */
		search_gui_update_status(search);
	}
}

void
search_gui_start_search(search_t *search)
{
	g_return_if_fail(search);

	search_gui_set_enabled(search, TRUE);
}

static void
search_gui_stop_search(search_t *search)
{
	g_return_if_fail(search);

	search_gui_set_enabled(search, FALSE);
}

/**
 * Reset the internal model of the search.
 * Called when a search is restarted, for example.
 */
static void
search_gui_reset_search(search_t *search)
{
	search->items = 0;
	search->unseen_items = 0;
	search->list_refreshed = FALSE;
	guc_search_update_items(search->search_handle, search->items);

	search_gui_clear_search(search);
	search_gui_update_status(search);
}

/**
 * Removes all search results from the current search.
 */
static void
search_gui_clear_results(void)
{
	search_t *search;

	search = search_gui_get_current_search();
	g_return_if_fail(search);

	search_gui_reset_search(search);
	search_gui_update_status(search);
}

/**
 * Remove the search from the list of searches and free all
 * associated resources (including filter and gui stuff).
 */
static void
search_gui_close_search(search_t *search)
{
	GList *next;

	g_return_if_fail(search);

	next = g_list_find(list_searches, search);
	next = g_list_next(next) ? g_list_next(next) : g_list_previous(next);
 	list_searches = g_list_remove(list_searches, search);

	search_gui_set_current_search(next ? next->data : NULL);
	filter_close_search(search);

	/*
	 * The association between the core search_handle and the GUI search,
	 * which is recorded in `ht_searches' needs to be removed only after
	 * the core side has finished its cleanup to allow GUI callback events
	 * to proceed (e.g. GUESS cancellation events).
	 */

    guc_search_close(search->search_handle);
	htable_remove(ht_searches, uint_to_pointer(search->search_handle));

	/*
	 * Now that the core is done cleaning up, we can free up the GUI data
	 * structures attached with the search.
	 */

	search_gui_clear_search(search);
    search_gui_remove_search(search);

	gtk_notebook_remove_page(notebook_search_results,
		gtk_notebook_page_num(notebook_search_results,
			search->scrolled_window));

	hset_free_null(&search->dups);
	htable_free_null(&search->parents);

	WFREE(search);

	/*
	 * One less search, update list of searches in memory and on disk.
	 */

	search_gui_store_searches();
	search_gui_option_menu_searches_update();

}

/**
 * Reset all media type flags, so that the next search bear no specific
 * media type flag.
 */
void
search_gui_media_type_clear(void)
{
	gui_prop_set_boolean_val(PROP_SEARCH_MEDIA_TYPE_AUDIO, FALSE);
	gui_prop_set_boolean_val(PROP_SEARCH_MEDIA_TYPE_VIDEO, FALSE);
	gui_prop_set_boolean_val(PROP_SEARCH_MEDIA_TYPE_DOCUMENT, FALSE);
	gui_prop_set_boolean_val(PROP_SEARCH_MEDIA_TYPE_IMAGE, FALSE);
	gui_prop_set_boolean_val(PROP_SEARCH_MEDIA_TYPE_ARCHIVE, FALSE);
}

/**
 * Compute media type flag to use for next search based on current media
 * type configuration.
 */
static unsigned
search_gui_configured_media_type(void)
{
	unsigned mask = 0;

	if (GUI_PROPERTY(search_media_type_audio))
		mask |= SEARCH_AUDIO_TYPE;
	if (GUI_PROPERTY(search_media_type_video))
		mask |= SEARCH_VIDEO_TYPE;
	if (GUI_PROPERTY(search_media_type_document))
		mask |= SEARCH_DOC_TYPE;
	if (GUI_PROPERTY(search_media_type_image))
		mask |= SEARCH_IMG_TYPE;
	if (GUI_PROPERTY(search_media_type_archive))
		mask |= SEARCH_WIN_TYPE | SEARCH_UNIX_TYPE;

	return mask;
}

/**
 * Create a new search and start it. Use default reissue timeout and the
 * current media type filtering.
 *
 * @note `*search' may be set to NULL even on success. You have to check this
 *		 explicitely.
 */
gboolean
search_gui_new_search(const gchar *query, guint32 flags, search_t **search)
{
    guint32 timeout;
	gboolean ret;

    gnet_prop_get_guint32_val(PROP_SEARCH_REISSUE_TIMEOUT, &timeout);

	if (!((SEARCH_F_PASSIVE | SEARCH_F_WHATS_NEW) & flags))
		query = lazy_ui_string_to_utf8(query);

    ret = search_gui_new_search_full(query,
			search_gui_configured_media_type(),
			tm_time(),
			GUI_PROPERTY(search_lifetime), timeout,
			GUI_PROPERTY(search_sort_default_column),
			GUI_PROPERTY(search_sort_default_order),
			flags | SEARCH_F_ENABLED, search);

	return ret;
}

/**
 * Free the alternate locations held within a file record.
 */
static void
search_gui_free_alt_locs(record_t *rc)
{
	gnet_host_vec_free(&rc->alt_locs);
}

/**
 * Compares search result records by filename.
 */
int
gui_record_name_eq(const void *p1, const void *p2)
{
	const struct record *a = p1, *b = p2;
    return 0 == strcmp(a->name, b->name);
}

/**
 * Compares search result records by SHA-1.
 */
int
gui_record_sha1_eq(const void *p1, const void *p2)
{
	const struct record *a = p1, *b = p2;

    if (a->sha1 == b->sha1)
        return 0;

    if (a->sha1 == NULL || b->sha1 == NULL)
		return 1;

    return memcmp(a->sha1, b->sha1, SHA1_RAW_SIZE);
}

/**
 * Compares search result records by host address.
 */
int
gui_record_host_eq(const void *p1, const void *p2)
{
	const struct record *a = p1, *b = p2;
    return !host_addr_equal(a->results_set->addr, b->results_set->addr);
}

/**
 * Tells if two hit records have the same SHA1 or the same name.
 *
 * The targetted search feature by Andrew Meredith (andrew@anvil.org)
 * now uses this function to filter input and avoid duplicates.
 * Andrew, if this somehow breaks the intent, let me know at
 * junkpile@free.fr.
 *
 * This provides the following behavior :
 *
 * - If several hits with the same SHA1 are selected, only one SHA1 rule
 *   will be added even if the filenames differ (same as before).
 *
 * - If several hits with the same filename and no SHA1 are selected,
 *   only one filename rule will be added.
 *
 * - If two selected hits have the same filename, but one has an SHA1
 *   and the other doesn't, both rules (filename and SHA1) will be added.
 *
 */
int
gui_record_sha1_or_name_eq(const void *p1, const void *p2)
{
	const struct record *a = p1, *b = p2;
	
    if (a->sha1 || b->sha1)
        return gui_record_sha1_eq(a, b);
    else
        return gui_record_name_eq(a, b);
}

/**
 * Clone the proxies list given by the core.
 */
gnet_host_vec_t *
search_gui_proxies_clone(gnet_host_vec_t *v)
{
	return v ? gnet_host_vec_copy(v) : NULL;
}

/**
 * Free the cloned vector of host.
 */
static void
search_gui_host_vec_free(gnet_host_vec_t *v)
{
	g_assert(v != NULL);
	gnet_host_vec_free(&v);
}

/**
 * Free the push proxies held within a result set.
 */
static void
search_gui_free_proxies(results_set_t *rs)
{
	g_assert(rs);

	if (rs->proxies) {
		search_gui_host_vec_free(rs->proxies);
		rs->proxies = NULL;
	}
}

/**
 * Free one file record.
 *
 * Those records may be inserted into some `dups' tables, at which time they
 * have their refcount increased.  They may later be removed from those tables
 * and they will have their refcount decreased.
 *
 * To ensure some level of sanity, we ask our callers to explicitely check
 * for a refcount to be zero before calling us.
 */
static void
search_gui_free_record(record_t *rc)
{
	record_check(rc);

	g_assert(NULL == rc->results_set);

	WFREE_TYPE_NULL(rc->partial);
	atom_str_free_null(&rc->name);
	atom_str_free_null(&rc->utf8_name);
    atom_str_free_null(&rc->ext);
	atom_str_free_null(&rc->tag);
	atom_str_free_null(&rc->xml);
	atom_str_free_null(&rc->info);
	atom_sha1_free_null(&rc->sha1);
	atom_tth_free_null(&rc->tth);
	search_gui_free_alt_locs(rc);
	rc->refcount = -1;
	rc->magic = 0;
	WFREE(rc);
}

/**
 * Tries to extract the extenstion of a file from the filename.
 * The return value is only valid until the function is called again.
 */
const gchar *
search_gui_extract_ext(const gchar *filename)
{
    static gchar ext[32];
	const gchar *p;
	size_t rw = 0;

    g_assert(NULL != filename);

    ext[0] = '\0';
    p = strrchr(filename, '.');
	if (p) {
		p++;
	}

	rw = g_strlcpy(ext, p ? p : "", sizeof ext);
	if (rw >= sizeof ext) {
		/* If the guessed extension is really this long, assume the
		 * part after the dot isn't an extension at all. */
		ext[0] = '\0';
	} else {
		/* Using g_utf8_strdown() (for GTK2) would be cleaner but it
         * allocates a new string which is ugly. Nobody uses such file
         * extensions anyway. */
		ascii_strlower(ext, ext);
	}

    return ext;
}

static void
search_gui_results_set_free(results_set_t *rs)
{
	results_set_check(rs);

	g_assert(0 == rs->num_recs);
	g_assert(NULL == rs->records);

    /*
     * Free list of searches set was intended for.
     */

	gm_slist_free_null(&rs->schl);
	atom_guid_free_null(&rs->guid);
	atom_str_free_null(&rs->version);
	atom_str_free_null(&rs->hostname);
	atom_str_free_null(&rs->query);
	search_gui_free_proxies(rs);
	rs->magic = 0;
	WFREE(rs);
}

static void
search_gui_remove_record(record_t *rc)
{
	results_set_t *rs;
	
	record_check(rc);
    g_assert(0 == rc->refcount);
	
	rs = rc->results_set;
	results_set_check(rs);
	rc->results_set = NULL;

    g_assert(rs->num_recs > 0);
    g_assert(rs->records);
	rs->records = g_slist_remove(rs->records, rc);
	rs->num_recs--;

	if (rs->num_recs == 0) {
		search_gui_results_set_free(rs);
	}
}

/**
 * Add a reference to the record but don't dare to redeem it!
 */
void
search_gui_ref_record(record_t *rc)
{
	record_check(rc);
	rc->refcount++;
}

/**
 * Remove one reference to a file record.
 *
 * If the record has no more references, remove it from its parent result
 * set and free the record physically.
 */
void
search_gui_unref_record(record_t *rc)
{
	record_check(rc);
	results_set_check(rc->results_set);

	g_assert(rc->refcount > 0);
	rc->refcount--;
	if (rc->refcount == 0) {
		search_gui_remove_record(rc);
		search_gui_free_record(rc);
	}
}

static guint
search_gui_hash_func(gconstpointer p)
{
	const record_t *rc = p;

	record_check(rc);

	/* Must use same fields as search_hash_key_compare() --RAM */
	return
		pointer_hash(rc->sha1) ^	/* atom! (may be NULL) */
		pointer_hash(rc->results_set->guid) ^	/* atom! */
		(NULL != rc->sha1 ? 0 : string_mix_hash(rc->name)) ^
		integer_hash(rc->size) ^
		host_addr_hash(rc->results_set->addr) ^
		port_hash(rc->results_set->port);
}

static guint
search_gui_hash_func2(gconstpointer p)
{
	const record_t *rc = p;

	record_check(rc);

	/* Must use same fields as search_gui_hash_key_compare() --RAM */
	return
		pointer_hash2(rc->sha1) ^	/* atom! (may be NULL) */
		pointer_hash2(rc->results_set->guid) ^	/* atom! */
		(NULL != rc->sha1 ? 0 : string_hash(rc->name)) ^
		integer_hash2(rc->size) ^
		host_addr_hash2(rc->results_set->addr) ^
		port_hash2(rc->results_set->port);
}

static gint
search_gui_hash_key_compare(gconstpointer a, gconstpointer b)
{
	const record_t *rc1 = a, *rc2 = b;

	/* Must compare same fields as search_gui_hash_func() --RAM */
	return rc1->size == rc2->size
		&& host_addr_equal(rc1->results_set->addr, rc2->results_set->addr)
		&& rc1->results_set->port == rc2->results_set->port
		&& rc1->results_set->guid == rc2->results_set->guid	/* atom! */
		&& (rc1->sha1 != NULL /* atom! */
				? rc1->sha1 == rc2->sha1 : (0 == strcmp(rc1->name, rc2->name)));
}

/**
 * Check to see whether we already have a record for this file.
 * If we do, make sure that the index is still accurate,
 * otherwise inform the interested parties about the change.
 *
 * @returns true if the record is a duplicate.
 */
static gboolean
search_gui_result_is_dup(search_t *sch, record_t *rc)
{
	const void *orig_key;

	record_check(rc);

	if (hset_contains_extended(sch->dups, rc, &orig_key)) {
		record_t *old_rc = deconstify_pointer(orig_key);

		/*
		 * Actually, if the index is the only thing that changed,
		 * we want to overwrite the old one (and if we've
		 * got the download queue'd, replace it there too.
		 *		--RAM, 17/12/2001 from a patch by Vladimir Klebanov
		 *
		 * FIXME needs more care: handle is_old, and use GUID for patching.
		 * FIXME the client may change its GUID as well, and this must only
		 * FIXME be used in the hash table where we record which downloads are
		 * FIXME queued from whom.
		 * FIXME when the GUID changes for a download in push mode, we have to
		 * FIXME change it.  We have a new route anyway, since we just got a
		 * FIXME match!
		 */

		if (rc->file_index != old_rc->file_index) {
			if (GUI_PROPERTY(gui_debug)) {
				g_warning("%s(): index changed from %u to %u at #%s for %s",
					G_STRFUNC, old_rc->file_index, rc->file_index,
					guid_hex_str(rc->results_set->guid), rc->name);
			}

			guc_download_index_changed(
				rc->results_set->addr,	/* This is for optimizing lookups */
				rc->results_set->port,
				rc->results_set->guid,	/* This is for formal identification */
				old_rc->file_index,
				rc->file_index);
			old_rc->file_index = rc->file_index;
		}

		return TRUE;		/* yes, it's a duplicate */
	} else {
		return FALSE;
	}
}

/**
 * @returns a pointer to gui_search_t from gui_searches which has
 * sh as search_handle. If none is found, return NULL.
 */
static search_t *
search_gui_find(gnet_search_t sh)
{
	return htable_lookup(ht_searches, uint_to_pointer(sh));
}

/**
 * Extract the filename extensions - if any - from the given UTF-8
 * encoded filename and convert it to lowercase. If the extension
 * exceeds a certain length, it is assumed that it's no extension
 * but just a non-specific dot inside a filename.
 *
 * @return NULL if there's no filename extension, otherwise a pointer
 *         to a static string holding the lowercased extension.
 */
const gchar *
search_gui_get_filename_extension(const gchar *filename_utf8)
{
	const gchar *p = strrchr(filename_utf8, '.');
	static gchar ext[32];

	if (!p || utf8_strlower(ext, &p[1], sizeof ext) >= sizeof ext) {
		/* If the guessed extension is really this long, assume the
		 * part after the dot isn't an extension at all. */
		return NULL;
	}
	return ext;
}

static const gchar *
search_gui_get_info(const record_t *rc, const gchar *vinfo)
{
	const results_set_t *rs = rc->results_set;
  	gchar info[1024];
	size_t rw = 0;

	info[0] = '\0';

	/*
	 * The tag is usually shown in the "Info" column, but for local searches
	 * it contains the complete file path, and this should only be shown in
	 * the information summary, not in the Info column.
	 */

	if (rc->tag && 0 == (ST_LOCAL & rs->status)) {
		const size_t MAX_TAG_SHOWN = 60; /**< Show only first chars of tag */
		size_t size;

		/*
		 * We want to limit the length of the tag shown, but we don't
		 * want to loose that information.	I imagine to have a popup
		 * "show file info" one day that will give out all the
		 * information.
		 *				--RAM, 09/09/2001
		 */

		size = 1 + strlen(rc->tag);
		size = MIN(size, MAX_TAG_SHOWN + 1);
		size = MIN(size, sizeof info);
		rw = utf8_strlcpy(info, lazy_unknown_to_ui_string(rc->tag), size);
	}
	if (vinfo) {
		g_assert(rw < sizeof info);
		rw += str_bprintf(&info[rw], sizeof info - rw, "%s%s",
				info[0] != '\0' ? "; " : "", vinfo);
	}

	if (rc->flags & SR_PARTIAL_HIT) {
		g_assert(rw < sizeof info);
		rw += str_bprintf(&info[rw], sizeof info - rw, "%s%s",
			info[0] != '\0' ? ", " : "", _("partial"));
	}

	if (rc->alt_locs != NULL) {
		guint count = gnet_host_vec_count(rc->alt_locs);
		g_assert(rw < sizeof info);
		rw += str_bprintf(&info[rw], sizeof info - rw, "%salt",
			info[0] != '\0' ? ", " : "");
		if (count > 1)
			rw += str_bprintf(&info[rw], sizeof info - rw, "(%u)", count);
	}

	return info[0] != '\0' ? atom_str_get(info) : NULL;
}

/**
 * Create a new GUI record within `rs' from a Gnutella record.
 */
static record_t *
search_gui_create_record(const gnet_results_set_t *rs, gnet_record_t *r)
{
    static const record_t zero_record;
    record_t *rc;

    g_assert(r != NULL);
    g_assert(rs != NULL);

    WALLOC(rc);
	*rc = zero_record;
	rc->magic = RECORD_MAGIC;
	rc->refcount = 1;

    rc->size = r->size;
    rc->file_index = r->file_index;
	if (r->sha1) {
    	rc->sha1 = atom_sha1_get(r->sha1);
	}
	if (r->tth) {
    	rc->tth = atom_tth_get(r->tth);
	}
	if (r->xml) {
    	rc->xml = atom_str_get(r->xml);
	}
	if (r->tag) {
    	rc->tag = atom_str_get(r->tag);
	}
   	rc->flags = r->flags;
   	rc->create_time = r->create_time;
	rc->name = atom_str_get(r->filename);

	if (r->available != 0 || r->mod_time != 0) {
		struct precord *prc;

		WALLOC0(prc);
		prc->available = r->available;
		prc->mod_time = r->mod_time;
		rc->partial = prc;
	}
	
	{
		const gchar *utf8_name, *name;
		gchar *to_free;

		if (r->path) {
			to_free = make_pathname(r->path, r->filename);
			name = to_free;
		} else {
			to_free = NULL;
			name = r->filename;
		}
		if (ST_LOCAL & rs->status) {
			utf8_name = name;
		} else {
			utf8_name = lazy_unknown_to_utf8_normalized(name,
							UNI_NORM_GUI, &rc->charset);
			if (utf8_name == name || 0 == strcmp("UTF-8", rc->charset)) {
				rc->charset = NULL;
			}
		}
		rc->utf8_name = atom_str_get(utf8_name);
		HFREE_NULL(to_free);
	}

	{
		const gchar *ext = search_gui_get_filename_extension(rc->utf8_name);
		rc->ext = ext ? atom_str_get(ext) : NULL;
	}

	if (NULL != r->alt_locs) {
		rc->alt_locs = gnet_host_vec_copy(r->alt_locs);
	}

	return rc;
}

/**
 * Create a new GUI result set from a Gnutella one.
 */
static results_set_t *
search_gui_create_results_set(pslist_t *schl, const gnet_results_set_t *r_set)
{
    results_set_t *rs;
	guint ignored;
    pslist_t *sl;

    WALLOC(rs);
	rs->magic = RESULTS_SET_MAGIC;
    rs->schl = gm_pslist_to_slist(schl);

    rs->guid = atom_guid_get(r_set->guid);
    rs->addr = r_set->addr;
    rs->port = r_set->port;
    rs->status = r_set->status;
    rs->speed = r_set->speed;
	rs->stamp = r_set->stamp;
    rs->vendor = r_set->vcode.u32;
	rs->version = r_set->version ? atom_str_get(r_set->version) : NULL;
	rs->hostname = r_set->hostname ? atom_str_get(r_set->hostname) : NULL;
	rs->query = r_set->query ? atom_str_get(r_set->query) : NULL;
	rs->country = r_set->country;
	rs->last_hop = r_set->last_hop;
	rs->hops = r_set->hops;
	rs->ttl = r_set->ttl;
	rs->media = r_set->media;

    rs->num_recs = 0;
    rs->records = NULL;
	rs->proxies = search_gui_proxies_clone(r_set->proxies);

	ignored = 0;
	PSLIST_FOREACH(r_set->records, sl) {
		gnet_record_t *grc = sl->data;

		if (grc->flags & SR_DONT_SHOW) {
			ignored++;
		} else {
			record_t *rc;
			
			rc = search_gui_create_record(r_set, grc);
    		rc->results_set = rs;
			rs->records = g_slist_prepend(rs->records, rc);
			rs->num_recs++;
		}
    }

    g_assert(rs->num_recs + ignored == r_set->num_recs);

	if (rs->records) {
    	return rs;
	} else {
		search_gui_results_set_free(rs);
		return NULL;
	}
}

/**
 * Free item from the accumulated_rs list, but not the result set.
 */
static void
accum_rs_free(struct accum_rs *ars)
{
	atom_guid_free_null(&ars->muid);
	WFREE(ars);
}

/**
 * Free item from the accumulated_rs list, including the result set.
 */
static void
accum_rs_free_full(void *data)
{
	struct accum_rs *ars = data;

	search_gui_results_set_free(ars->rs);
	accum_rs_free(ars);
}

static void
search_gui_download_selected_files(void)
{
	struct search *search;
	bool stopped;

    search = search_gui_get_current_search();
	g_return_if_fail(search);

	stopped = search_gui_start_massive_update(search);
   	search_gui_download_files(search);
	if (stopped)
		search_gui_end_massive_update(search);

   	guc_search_update_items(search->search_handle, search->items);

	search->list_refreshed = FALSE;
   	search_gui_update_status(search);
}

static void
search_gui_discard_selected_files(void)
{
	struct search *search;
	bool stopped;

    search = search_gui_get_current_search();
	g_return_if_fail(search);

	stopped = search_gui_start_massive_update(search);
   	search_gui_discard_files(search);
	if (stopped)
		search_gui_end_massive_update(search);

   	guc_search_update_items(search->search_handle, search->items);

	search->list_refreshed = FALSE;
   	search_gui_update_status(search);
}

/**
 *	Create a search based on query entered
 */
static void
on_button_search_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;
	search_gui_new_search_entered();
}

/**
 *	Create a search based on query entered
 */
static void
on_entry_search_activate(GtkEditable *unused_editable, gpointer unused_udata)
{
	(void) unused_editable;
	(void) unused_udata;
	search_gui_new_search_entered();
}

/**
 *	When a search string is entered, activate the search button
 */
static void
on_entry_search_changed(GtkEditable *editable, void *unused_udata)
{
	char *s = STRTRACK(gtk_editable_get_chars(editable, 0, -1));
	gboolean changed;

	(void) unused_udata;

	if (GTK_CHECK_VERSION(2,0,0)) {
		char *normalized;

		/* Gimmick: Normalize the input on the fly because Gtk+ currently
		 * renders them differently (for example decomposed) if they're are
		 * not in Normalization Form Canonic (NFC)
		 */
		normalized = utf8_normalize(s, UNI_NORM_GUI);
		changed = normalized != s && 0 != strcmp(s, normalized);
		if (changed) {
			gtk_entry_set_text(GTK_ENTRY(editable), normalized);
		}
		if (normalized != s) {
			G_FREE_NULL(normalized);
		}
	} else {
		changed = FALSE;
	}

	if (!changed) {
		g_strstrip(s);
		gtk_widget_set_sensitive(gui_main_window_lookup("button_search"),
			s[0] != '\0');
	}
	G_FREE_NULL(s);

    gui_prop_set_boolean_val(PROP_SEARCHBAR_VISIBLE, TRUE);
}

/**
 *	When the user switches notebook tabs, update the rest of GUI
 *
 *	This may be obsolete as we removed the tabbed interface --Emile 27/12/03
 */
static void
on_notebook_search_results_switch_page(GtkNotebook *notebook,
	GtkNotebookPage *unused_page, int page_num, void *unused_udata)
{
	GtkWidget *widget;
	search_t *search;

	(void) unused_page;
	(void) unused_udata;

	widget = gtk_notebook_get_nth_page(notebook, page_num);
	search = gtk_object_get_user_data(GTK_OBJECT(widget));
	if (search) {
    	search_gui_set_current_search(search);
	}
}

static void
search_gui_set_clear_button_sensitive(gboolean sensitive)
{
	gtk_widget_set_sensitive(
		GTK_WIDGET(GTK_BUTTON(gui_main_window_lookup("button_search_clear"))),
		sensitive);
}

/**
 *	Clear search results, de-activate clear search button
 */
static void
on_button_search_clear_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	search_gui_clear_results();
	search_gui_set_clear_button_sensitive(FALSE);
}

static void
on_button_search_close_clicked(GtkButton *unused_button, gpointer unused_udata)
{
    struct search *search;

	(void) unused_button;
	(void) unused_udata;

    search = search_gui_get_current_search();
	g_return_if_fail(search);

	search_gui_close_search(search);
}

static void
on_button_search_download_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;
	search_gui_download_selected_files();
}

static void
on_button_search_filter_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	filter_open_dialog();
}

static void
on_spinbutton_adjustment_value_changed(GtkAdjustment *unused_adj, gpointer data)
{
	GtkWidget *widget;
    search_t *search;

	(void) unused_adj;
	widget = GTK_WIDGET(data);
    search = search_gui_get_current_search();
    if (search && guc_search_is_active(search->search_handle)) {
    	guint32 timeout;
		
		timeout = gtk_spin_button_get_value(GTK_SPIN_BUTTON(widget));
		guc_search_set_reissue_timeout(search->search_handle, timeout);
		timeout = guc_search_get_reissue_timeout(search->search_handle);
		gtk_spin_button_set_value(GTK_SPIN_BUTTON(widget), timeout);
	}
}

/**
 * Create a new search with currenly selected filter.
 */
static void
search_gui_create_search_with_filter(const char *name, guint32 flags)
{
    filter_t *default_filter;
	search_t *search;

    /*
     * We have to capture the selection here already, because
     * new_search will trigger a rebuild of the menu as a
     * side effect.
     */
    default_filter = option_menu_get_selected_data(GTK_OPTION_MENU(
					gui_main_window_lookup("optionmenu_search_filter")));

	if (SEARCH_NEW_SUCCESS != search_gui_new_search(name, flags, &search)) {
		gdk_beep();
		return;
	}

    /*
     * If we should set a default filter, we do that.
     */
    if (default_filter != NULL) {
        rule_t *rule = filter_new_jump_rule(default_filter, RULE_FLAG_ACTIVE);

        /*
         * Since we don't want to distrub the shadows and
         * do a "force commit" without the user having pressed
         * the "ok" button in the dialog, we add the rule
         * manually.
         */
        search->filter->ruleset = g_list_append(search->filter->ruleset, rule);
        rule->target->refcount++;
    }
}

static void
on_button_search_passive_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	search_gui_create_search_with_filter(_("Passive"), SEARCH_F_PASSIVE);
}

static void
on_button_search_whats_new_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	search_gui_create_search_with_filter(_("What's New?"), SEARCH_F_WHATS_NEW);
}

static void
on_button_search_media_type_any_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	search_gui_media_type_clear();
}

static gboolean
on_search_results_key_press_event(GtkWidget *unused_widget,
	GdkEventKey *event, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;

	if (0 == (gtk_accelerator_get_default_mod_mask() & event->state)) {
		switch (event->keyval) {
		case GDK_Return:
			search_gui_download_selected_files();
			return TRUE;
		case GDK_Delete:
			search_gui_discard_selected_files();
			return TRUE;
		default:
			break;
		}
	}
	return FALSE;
}

static gboolean
on_search_results_button_press_event(GtkWidget *widget,
	GdkEventButton *event, gpointer unused_udata)
{
	(void) unused_udata;

	if (
		GDK_2BUTTON_PRESS == event->type &&
		1 == event->button &&
		0 == (gtk_accelerator_get_default_mod_mask() & event->state)
	) {
		gui_signal_stop_emit_by_name(widget, "button_press_event");
		search_gui_download_selected_files();
		return TRUE;
	}
	return FALSE;
}

gboolean
on_search_details_key_press_event(GtkWidget *widget,
	GdkEventKey *event, gpointer unused_udata)
{
	(void) unused_udata;

	switch (event->keyval) {
	guint modifier;
	case GDK_c:
		modifier = gtk_accelerator_get_default_mod_mask() & event->state;
		if (GDK_CONTROL_MASK == modifier) {
			char *text = search_gui_details_get_text(widget);
			clipboard_set_text(widget, text);
			G_FREE_NULL(text);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

/**
 * Check for alternate locations in the result set, and enqueue the downloads
 * if there are any.  Then free the alternate location from the record.
 */
static void
search_gui_check_alt_locs(record_t *rc)
{
	const results_set_t *rs;

	record_check(rc);

	rs = rc->results_set;
	results_set_check(rs);

	if (rc->alt_locs) {
		gint i, n;

		n = gnet_host_vec_count(rc->alt_locs);
		for (i = 0; i < n; i++) {
			gnet_host_t host;
			host_addr_t addr;
			guint16 port;

			host = gnet_host_vec_get(rc->alt_locs, i);
			addr = gnet_host_get_addr(&host);
			port = gnet_host_get_port(&host);
			if (port > 0 && host_addr_is_routable(addr)) {
				uint32 flags = 0;

				/*
				 * Even if "G2" results came back from GTKG (which is possible
				 * since GTKG nodes are connected on G2 and respond to queries)
				 * we know that GTKG is not going to discriminate between G2
				 * and Gnutella and that both networks can happily download
				 * from it, regardless of how they managed to get a hold on the
				 * resource.
				 */

				if ((rs->status & ST_G2) && rs->vendor != T_GTKG)
					flags = SOCK_F_G2;

				guc_download_auto_new(rc->name,
					rc->size,
					addr,
					port,
					&blank_guid,
					NULL,	/* hostname */
					rc->sha1,
					rc->tth,
					rc->results_set->stamp,
					NULL,	/* fileinfo */
					NULL,	/* proxies */
					flags);	/* flags */
			}
		}
	}
}

void
search_gui_download(record_t *rc, gnet_search_t sh)
{
	const results_set_t *rs;
	guint32 flags = 0;
	gchar *uri;

	g_return_if_fail(rc);
	record_check(rc);

	rs = rc->results_set;
	flags |= (rs->status & ST_FIREWALL) ? SOCK_F_PUSH : 0;
	flags |= (rs->status & ST_TLS) ? SOCK_F_TLS : 0;
	flags |= ((rs->status & ST_G2) && rs->vendor != T_GTKG) ? SOCK_F_G2 : 0;

	if (rc->sha1) {
		uri = NULL;
		guc_search_associate_sha1(sh, rc->sha1);
	} else {
		uri = str_cmsg("/get/%lu/%s", (gulong) rc->file_index, rc->name);
	}

	guc_download_new(rc->name,
		uri,
		rc->size,
		rs->addr,
		rs->port,
		rs->guid,
		rs->hostname,
		rc->sha1,
		rc->tth,
		rs->stamp,
		NULL,	/* fileinfo */
		rs->proxies,
		flags,
		NULL);	/* PARQ ID */

	rc->flags |= SR_DOWNLOADED;
	search_gui_check_alt_locs(rc);
	HFREE_NULL(uri);
}

/**
 * Makes the sort column and order of the current search the default settings.
 */
void
search_gui_set_sort_defaults(void)
{
	const search_t *sch;
	
	sch = current_search;
	if (sch) {
		gui_prop_set_guint32_val(PROP_SEARCH_SORT_DEFAULT_COLUMN,
			sch->sort_col);
		gui_prop_set_guint32_val(PROP_SEARCH_SORT_DEFAULT_ORDER,
			sch->sort_order);
	}
}

/**
 * Persist searches to disk.
 */
static void
search_gui_real_store_searches(void)
{
	char *path;

	search_store_xml();

	path = make_pathname(settings_gui_config_dir(), search_file);
    if (file_exists(path)) {
		char *path_old;

      	path_old = h_strdup_printf("%s.old", path);
		if (NULL != path_old) {
        	g_warning(
            	_("Found old searches file. The search information has been\n"
            	"stored in the new XML format and the old file is renamed to\n"
            	"%s"), path_old);
        	if (-1 == rename(path, path_old))
          		g_warning(_("could not rename %s as %s: %m\n"
                	"The XML file will not be used "
					"unless this problem is resolved."), path, path_old);
			HFREE_NULL(path_old);
		}
    }
	HFREE_NULL(path);
}

/**
 * Retrieve searches from disk.
 */
static void
search_gui_retrieve_searches(void)
{
    search_retrieve_xml();
}

/**
 * @return a string showing the route information for the given
 *         result record. The return string uses a static buffer.
 * @note   If the result is from a local search or browse host, NULL
 *		   is returned.
 */
const gchar *
search_gui_get_route(const struct results_set *rs)
{
	static gchar addr_buf[128];
	size_t n;
		
	results_set_check(rs);
	
	if (ST_LOCAL & rs->status)
		return NULL;

	n = host_addr_to_string_buf(rs->last_hop, addr_buf, sizeof addr_buf);

	/*
	 * For successful OOBv3 results, append a "+" to the route address.
	 * For GUESS query results, append a "~" to the route address.
	 */

	if ((ST_GOOD_TOKEN & rs->status) && n < sizeof addr_buf) {
		g_strlcpy(&addr_buf[n], "+", sizeof addr_buf - n);
		n++;
	}
	if ((ST_GUESS & rs->status) && n < sizeof addr_buf) {
		g_strlcpy(&addr_buf[n], "~", sizeof addr_buf - n);
	}
	return addr_buf;
}

static enum gui_color
search_gui_color_for_record(const record_t * const rc)
{
	const results_set_t *rs = rc->results_set;
	
	if (SR_SPAM & rc->flags) {
		return GUI_COLOR_SPAM;
	} else if (ST_HOSTILE & rs->status) {
		return GUI_COLOR_HOSTILE;
	} else if ((ST_SPAM & rs->status) && !(ST_BROWSE & rs->status)) {
		return GUI_COLOR_MAYBE_SPAM;
	} else if (rs->status & ST_UNREQUESTED) {
		return GUI_COLOR_UNREQUESTED;
	} else if (rs->status & ST_BANNED_GUID) {
		return GUI_COLOR_BANNED_GUID;
	} else if (rc->flags & SR_MEDIA) {
		return GUI_COLOR_MEDIA;
	} else if (rc->flags & (SR_IGNORED | SR_OWNED | SR_SHARED)) {
		return GUI_COLOR_IGNORED;
	} else if (rc->flags & (SR_DOWNLOADED | SR_PARTIAL)) {
		return GUI_COLOR_DOWNLOADING;
	} else if (ST_ALIEN & rs->status) {
		return GUI_COLOR_ALIEN;
	} else if (rc->flags & SR_PARTIAL_HIT) {
		return rc->flags & SR_PUSH ?
			GUI_COLOR_PARTIAL_PUSH : GUI_COLOR_PARTIAL;
	} else if (rc->flags & SR_PUSH) {
		return ST_PUSH_PROXY & rs->status ?
			GUI_COLOR_PUSH_PROXY : GUI_COLOR_PUSH;
	} else {
		return GUI_COLOR_DEFAULT;
	}
}

static void
search_gui_set_record_info(results_set_t *rs)
{
	str_t *vinfo = str_new(40);
	GSList *iter;
	guint i;

	results_set_check(rs);

	/* If banned GUID, make it prominent: at the start of the information! */
	if (rs->status & ST_BANNED_GUID) {
		STR_CAT(vinfo, "GUID");
	}

	for (i = 0; i < G_N_ELEMENTS(open_flags); i++) {
		if (rs->status & open_flags[i].flag) {
			if (str_len(vinfo) > 0)
				STR_CAT(vinfo, ", ");
			str_cat(vinfo, _(open_flags[i].status));
		}
	}

	if (!(rs->status & ST_PARSED_TRAILER)) {
		if (str_len(vinfo) > 0)
			STR_CAT(vinfo, ", ");
		str_cat(vinfo, _("<unparsed>"));
	}

	if (rs->status & ST_TLS) {
		if (str_len(vinfo) > 0)
			STR_CAT(vinfo, ", TLS");
		else
			STR_CAT(vinfo, "TLS");
	}
	if (rs->status & ST_BH) {
		if (str_len(vinfo) > 0) {
			STR_CAT(vinfo, ", ");
		}
		str_cat(vinfo, _("browsable"));
	}

	for (iter = rs->records; iter != NULL; iter = g_slist_next(iter)) {
		record_t *rc = iter->data;

		record_check(rc);
		g_assert(rs == rc->results_set);
		g_assert(NULL == rc->info);
		rc->info = search_gui_get_info(rc,
			str_len(vinfo) > 0 ? str_2c(vinfo) : NULL);
	}
  	str_destroy(vinfo);
}

/**
 * Called to dispatch results to the search window.
 */
static void
search_matched(search_t *sch, const guid_t *muid, results_set_t *rs)
{
	guint32 old_items = sch->items;
	gboolean skip_records;		/* Shall we skip those records? */
    GSList *sl;
    gboolean send_pushes;
    gboolean is_firewalled;
	guint32 flags = 0, results_kept = 0;
	guint32 max_results;

    g_assert(sch != NULL);
	results_set_check(rs);

	if (search_gui_is_browse(sch)) {
		gnet_prop_get_guint32_val(PROP_BROWSE_HOST_MAX_RESULTS, &max_results);
	} else if (search_gui_is_whats_new(sch)) {
		gnet_prop_get_guint32_val(PROP_WHATS_NEW_SEARCH_MAX_RESULTS,
			&max_results);
	} else if (search_gui_is_passive(sch) || search_gui_is_local(sch)) {
		gnet_prop_get_guint32_val(PROP_PASSIVE_SEARCH_MAX_RESULTS,
			&max_results);
	} else {
		gnet_prop_get_guint32_val(PROP_SEARCH_MAX_RESULTS, &max_results);
	}

	if (rs->status & ST_UDP) {
		sch->udp_qhits++;
	} else {
		sch->tcp_qhits++;
	}

	flags |= (rs->status & ST_TLS) ? SOCK_F_TLS : 0;

	/*
	 * If we're firewalled, or they don't want to send pushes, then don't
	 * bother displaying results if they need a push request to succeed.
	 *		--RAM, 10/03/2002
	 */
    gnet_prop_get_boolean_val(PROP_SEND_PUSHES, &send_pushes);
    gnet_prop_get_boolean_val(PROP_IS_FIREWALLED, &is_firewalled);

	flags |= (rs->status & ST_FIREWALL) ? SOCK_F_PUSH : 0;
	if ((ST_LOCAL | ST_BROWSE) & rs->status) {
		skip_records = FALSE;
	} else {
		skip_records = (!send_pushes || is_firewalled) && (flags & SOCK_F_PUSH);
	}

	if (GUI_PROPERTY(gui_debug) > 6) {
		g_debug("%s(): [%s] got hit with %d record%s (from %s via %s%s%s%s) "
			"need_push=%d, skipping=%d", G_STRFUNC,
			search_gui_query(sch), rs->num_recs, plural(rs->num_recs),
			host_addr_port_to_string(rs->addr, rs->port),
			(rs->status & ST_UDP) ? "UDP" : "TCP",
			(rs->status & ST_GUESS) ? " + GUESS" : "",
			(NULL == muid) ? "" : " ",
			(NULL == muid) ? "" : guid_to_string(muid),
			booleanize(flags & SOCK_F_PUSH), skip_records);
	}

  	for (sl = rs->records; sl && !skip_records; sl = g_slist_next(sl)) {
		record_t *rc = sl->data;
		enum gui_color color;

		record_check(rc);

        if (GUI_PROPERTY(gui_debug) > 7)
            g_debug("%s(): [%s] considering %s",
				G_STRFUNC, search_gui_query(sch), rc->name);

        if (rc->flags & SR_DOWNLOADED)
			sch->auto_downloaded++;

        /*
		 * Note that we pass ALL records through search_gui_result_is_dup(),
		 * to be able to update the index/GUID of our records correctly, when
		 * we detect a change.
		 */


		if (search_gui_result_is_dup(sch, rc)) {
			/*
			 * We already have that result displayed.
			 *
			 * We don't want to count as "kept" something that is (likely) spam.
			 * It can be shown in the results if they don't want to
			 * discard the spam, but it's certainly not a valuable entry!
			 */

			if (
				0 == ((ST_HOSTILE | ST_SPAM | ST_ALIEN |
					ST_BANNED_GUID) & rs->status) &&
				0 == (SR_SPAM & rc->flags)
			) {
				results_kept++;		/* Counts for measuring popularity */
			}
			sch->duplicates++;
			continue;
		}

		color = GUI_COLOR_DEFAULT;
		if (0 == (ST_LOCAL & rs->status)) {
			enum filter_prop_state filter_state, filter_download;
			gpointer filter_udata;
			gboolean is_hostile;
			gint spam_score;

			if (skip_records) {
				sch->skipped++;
				continue;
			}

			is_hostile = ST_HOSTILE & rs->status;
			spam_score = ST_SPAM & rs->status ? 1 : 0;
			spam_score |= SR_SPAM & rc->flags ? 2 : 0;

			if (
				rc->size == 0 ||
				(!rc->sha1 && GUI_PROPERTY(search_discard_hashless)) ||
				(
					GUI_PROPERTY(search_discard_spam) &&
				 	(spam_score > 1 || is_hostile)
				) ||
				(
					GUI_PROPERTY(search_discard_alien_ip) &&
					(ST_ALIEN & rs->status)
				) ||
				(
					GUI_PROPERTY(search_discard_banned_guid) &&
					(ST_BANNED_GUID & rs->status)
				)
			) {
				sch->ignored++;
				continue;
			}

			g_assert(rc->refcount >= 0);
			{
        		filter_result_t *flt_result;
				
				flt_result = filter_record(sch, rc);
				filter_state = flt_result->props[FILTER_PROP_DISPLAY].state;
				filter_udata = flt_result->props[FILTER_PROP_DISPLAY].user_data;
				filter_download = flt_result->props[FILTER_PROP_DOWNLOAD].state;
				filter_free_result(flt_result);
			}
			g_assert(rc->refcount >= 0);

			/*
			 * Check for FILTER_PROP_DOWNLOAD:
			 */
			if (
				!(SR_DOWNLOADED & rc->flags) && 
				!is_hostile &&
				0 == spam_score &&
				FILTER_PROP_STATE_DO == filter_download
		   ) {
				search_gui_download(rc, sch->search_handle);
				if (SR_DOWNLOADED & rc->flags) {
					sch->auto_downloaded++;
				}
			}

			/*
			 * Don't show something we downloaded if they don't want it.
			 */

			if (
				(SR_DOWNLOADED & rc->flags) &&
				GUI_PROPERTY(search_hide_downloaded)
			) {
				results_kept++;
				sch->hidden++;
				continue;
			}

			/*
			 * We start with FILTER_PROP_DISPLAY:
			 */
			if (FILTER_PROP_STATE_DONT == filter_state && !filter_udata) {
				sch->ignored++;
				continue;
			}

			/* Count as kept even if max results but not spam */
			if (0 == spam_score && !is_hostile) {
				results_kept++;
			}

			if (sch->items >= max_results) {
				sch->ignored++;
				continue;
			}
			
			if (
				FILTER_PROP_STATE_DONT == filter_state &&
				int_to_pointer(1) == filter_udata
			) {
				color = GUI_COLOR_MARKED;
			}
		}
		sch->items++;

		hset_insert(sch->dups, rc);
		search_gui_ref_record(rc);

		if (GUI_COLOR_MARKED != color)
			color = search_gui_color_for_record(rc);
		search_gui_add_record(sch, rc, color);
	}

	if (old_items == 0 && sch == current_search && sch->items > 0) {
		search_gui_set_clear_button_sensitive(TRUE);
	}
	sch->unseen_items += sch->items - old_items;

	/*
	 * Update counters in the core-side of the search.
	 *
	 * NB: we need to call guc_search_add_kept() even if we kept nothing,
	 * that is required for proper dynamic querying support by leaf nodes.
	 */

	guc_search_update_items(sch->search_handle, sch->items);
	guc_search_add_kept(sch->search_handle, muid, results_kept);

	/*
	 * Disable search when the maximum amount of items is shown: they need
	 * to make some room to allow the search to continue.
	 */

	if (sch->items >= max_results && !search_gui_is_passive(sch)) {
		search_gui_stop_search(sch);
	}

	/*
	 * Update the GUI periodically but not immediately due to the overhead
	 * when we're receiving lots of results quickly.
	 */
	sch->list_refreshed = FALSE;
}

gboolean
search_gui_is_expired(const struct search *search)
{
	if (search && !search_gui_is_passive(search)) {
		return guc_search_is_expired(search->search_handle);
	} else {
		return FALSE;
	}
}

static GtkMenu *
search_gui_get_popup_menu(void)
{
	if (search_gui_get_current_search()) {
		search_gui_refresh_popup();
		return GTK_MENU(gui_popup_search());
	} else {
		return NULL;
	}
}

static GtkWidget *
search_gui_create_scrolled_window(void)
{
	GtkScrolledWindow *sw;

	sw = GTK_SCROLLED_WINDOW(gtk_scrolled_window_new(NULL, NULL));
	gtk_scrolled_window_set_shadow_type(sw, GTK_SHADOW_IN);
	gtk_scrolled_window_set_policy(sw, GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
	return GTK_WIDGET(sw);
}

static void
search_gui_switch_search(struct search *search)
{
	search_gui_option_menu_searches_select(search);

	/*
	 * This prevents side-effects otherwise caused by  changing the value of
	 * spinbutton_reissue_timeout.
	 */
   	current_search = NULL;

	if (search) {
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(
				gui_main_window_lookup("spinbutton_search_reissue_timeout")),
			guc_search_get_reissue_timeout(search->search_handle));
	}
	gtk_widget_set_sensitive(
		gui_main_window_lookup("spinbutton_search_reissue_timeout"),
		NULL != search && guc_search_is_active(search->search_handle));
	gtk_widget_set_sensitive(gui_main_window_lookup("button_search_close"),
		NULL != search);
	gtk_widget_set_sensitive(gui_main_window_lookup("button_search_clear"),
		NULL != search && search->items > 0);
    gtk_widget_set_sensitive(gui_main_window_lookup("button_search_download"),
		NULL != search && !search_gui_is_local(search));

	if (search) {
		current_search = search;

		search->unseen_items = 0;
		search->list_refreshed = FALSE;
		gtk_notebook_set_current_page(notebook_search_results,
			gtk_notebook_page_num(notebook_search_results,
				search->scrolled_window));
	} else {
		GtkWidget *sw, *tree;
		char text[256];

		sw = search_gui_create_scrolled_window();
		tree = search_gui_create_tree();
		gtk_widget_set_sensitive(tree, FALSE);
		gtk_container_add(GTK_CONTAINER(sw), tree);
		gtk_notebook_append_page(notebook_search_results, sw, NULL);
		str_bprintf(text, sizeof text, "(%s)", _("No search"));
		gtk_notebook_set_tab_label_text(notebook_search_results, sw, text);
		gtk_widget_show_all(sw);
	}
	search_gui_update_status(search);
}

static void
search_gui_guess_stats_display(const search_t *search)
{
	bool guess_stats;

	guess_stats = search_gui_can_use_guess(search) &&
		GUI_PROPERTY(search_display_guess_stats);

	if (guess_stats)
		gtk_widget_show(guess_stats_line);
	else
		gtk_widget_hide(guess_stats_line);
}

void
search_gui_set_current_search(search_t *search)
{
	if (search != current_search) {
		struct search *previous = current_search;

		search_gui_switch_search(search);
		if (previous) {
			gtk_widget_hide(previous->tree);
			if (!previous->frozen)
				search_gui_start_massive_update(previous);
			search_gui_hide_search(previous);
			previous->list_refreshed = FALSE;
			search_gui_update_counters(previous);
		}
		if (search) {	
			search_gui_guess_stats_display(search);
			search_gui_show_search(search);
			if (search->frozen)
				search_gui_end_massive_update(search);
			gtk_widget_show(search->tree);
			search->list_refreshed = FALSE;
			search_gui_update_counters(search);
		}
	}
}

void
search_gui_current_search_refresh(void)
{
	if (current_search != NULL) {
		search_gui_guess_stats_display(current_search);
	}
}

/***
 *** Callbacks
 ***/

/**
 * Called when the core has finished parsing the result set, and the results
 * need to be dispatched to the searches listed in `schl'.
 *
 * @param schl		list of gnet_search_t handles
 * @param muid		the MUID of the query hit (NULL if non-GUESS)
 * @param r_set		the core's result set, which will be duplicated
 */
static void
search_gui_got_results(pslist_t *schl, const struct guid *muid,
	const gnet_results_set_t *r_set)
{
    results_set_t *rs;

    /*
     * Copy the data we got from the backend.
     */
    rs = search_gui_create_results_set(schl, r_set);
	if (rs) {
		struct accum_rs *ars;

		if (GUI_PROPERTY(gui_debug) >= 12) {
			g_debug("%s(): got incoming results...", G_STRFUNC);
		}

		WALLOC(ars);
		ars->muid = muid != NULL ? atom_guid_get(muid) : NULL;
		ars->rs = rs;
		slist_append(accumulated_rs, ars);
	} else {
		if (GUI_PROPERTY(gui_debug) >= 6) {
			g_debug("%s(): ignoring %u result%s%s%s",
				G_STRFUNC, r_set->num_recs, plural(r_set->num_recs),
				NULL == muid ? "" : " for GUESS ",
				NULL == muid ? "" : guid_to_string(muid));
		}
	}
}

static void
search_gui_status_change(gnet_search_t search_handle)
{
	search_t *search;

	search = search_gui_find(search_handle);
	g_return_if_fail(search);
	search->list_refreshed = FALSE;
	search_gui_update_status(search);
}

static void
search_gui_flush_info(void)
{
    guint rs_count = slist_length(accumulated_rs);

    if (GUI_PROPERTY(gui_debug) >= 6 && rs_count > 0) {
		const struct accum_rs *ars;
		slist_iter_t *iter;
        guint recs = 0;

		iter = slist_iter_before_head(accumulated_rs);
		while (NULL != (ars = slist_iter_next(iter))) {
            recs += ars->rs->num_recs;
        }
		slist_iter_free(&iter);

        g_debug("flushing %u rsets (%u recs, %u recs avg)...",
            rs_count, recs, recs / rs_count);
    }
}

/**
 * Periodic timer to flush the accumulated hits during the period and
 * dispatch them to the GUI.
 */
void
search_gui_flush(time_t now, gboolean force)
{
    static time_t last;
    GSList *frozen = NULL, *sl;
	struct accum_rs *ars;
	tm_t t0, t1;

	if (!force) {
		guint32 period = GUI_PROPERTY(search_accumulation_period);

		if (last && delta_time(now, last) < (time_delta_t) period)
			return;
	}
    last = now;
	
	search_gui_flush_info();
	tm_now_exact(&t0);

	while (NULL != (ars = slist_shift(accumulated_rs))) {
		results_set_t *rs;
        GSList *schl;
		const guid_t *muid;

		muid = ars->muid != NULL ? atom_guid_get(ars->muid) : NULL;
		rs = ars->rs;

		g_assert(rs != NULL);

		accum_rs_free(ars);
        schl = rs->schl;
        rs->schl = NULL;

		if (GUI_PROPERTY(gui_debug) > 6 && muid != NULL) {
			g_debug("%s(): processing accumulated %u record%s for %s",
				G_STRFUNC, rs->num_recs, plural(rs->num_recs),
				guid_to_string(muid));
		}

		search_gui_set_record_info(rs);

        /*
         * Dispatch to all searches and freeze display where necessary
         * remembering what was frozen.
         */
        for (sl = schl; sl != NULL; sl = g_slist_next(sl)) {
			gnet_search_t handle;
            search_t *sch;

			handle = pointer_to_uint(sl->data);
            sch = search_gui_find(handle);

            /*
             * Since we keep results around for a while, the search may have
             * been closed until they get dispatched... so we need to check
             * that.
             *     --BLUE, 4/1/2004
             */

            if (sch != NULL) {
				if (!sch->frozen) {
                	search_gui_start_massive_update(sch);
                	frozen = g_slist_prepend(frozen, sch);
				}
                search_matched(sch, muid, rs);
            } else if (GUI_PROPERTY(gui_debug) >= 6) {
				g_debug("%s(): no search for cached search result (handle #%u)",
					G_STRFUNC, handle);
			}
        }
		gm_slist_free_null(&schl);
		atom_guid_free_null(&muid);

        /*
         * Some of the records might have not been used by searches, and need
         * to be freed.  If no more records remain, we request that the
         * result set be removed from all the dispatched searches, the last one
         * removing it will cause its destruction.
         */

        if (GUI_PROPERTY(gui_debug) >= 15)
            g_debug("%s(): cleaning phase", G_STRFUNC);

		for (sl = rs->records; sl != NULL; /* NOTHING */) {
			record_t *rc = sl->data;

			record_check(rc);
			g_assert(rc->results_set == rs);

			/* Must prefetch next due to search_gui_clean_r_set() */
			sl = g_slist_next(sl);

			/* Remove our initial reference */
			search_gui_unref_record(rc);
		}
    }

    /*
     * Unfreeze all we have frozen before.
     */
    for (sl = frozen; sl != NULL; sl = g_slist_next(sl)) {
		search_gui_end_massive_update(sl->data);
    }
    gm_slist_free_null(&frozen);

	if (GUI_PROPERTY(gui_debug)) {
		tm_now_exact(&t1);
		g_debug("%s(): dispatching results took %lu ms",
			G_STRFUNC, (ulong) tm_elapsed_ms(&t1, &t0));
	}

	search_gui_flush_queues();
}

/**
 * Parse the given query text and looks for negative patterns. That means
 * "blah -zadda" will be converted to "blah" and a sub-string filter is added
 * to discard results matching "zadda". A minus followed by a space or
 * another minus is always used literally. A plus character has the
 * opposite effect. In either case, the pattern will not be part of the
 * emitted search term. Single-quotes and double-quotes can be used to
 * use a whole string as pattern instead of a single word
 * (e.g., blah -'but not this') or to enforce handling of '+' and '-'
 * as literals (e.g., 'this contains -no filter pattern'). Single-quotes
 * and double-quotes are handled equally; either can be used to embed
 * the other.
 */
static void
search_gui_parse_text_query(const gchar *text, struct query *query)
{
	const gchar *p, *start, *next;
	gchar *dst;

	g_assert(text);
	g_assert(query);
	g_assert(NULL == query->text);

	query->text = g_strdup(text);
	dst = query->text;

	start = text;
	for (p = text; *p != '\0'; p = next) {
		const gchar *endptr;
		gint filter;

		/* Treat word after '-' (if preceded by a space) as negative pattern */
		/* Treat word after '+' (if preceded by a space) as positive pattern */
		if (
			('-' == *p || '+' == *p) &&
			(p == text || is_ascii_space(p[-1])) &&
			p[1] != *p && p[1] != '\0' && !is_ascii_space(p[1])
		) {
			filter = '-' == *p ? -1 : +1;
			p++;
		} else {
			filter = 0;
		}

		switch (*p) {
		case '\'':
		case '"':
			start = &p[1];
			endptr = strchr(start, *p);
			if (endptr) {
				next = &endptr[1];
			} else {
				endptr = strchr(start, '\0');
				next = endptr;
			}
			break;
		default:
			start = p;
			endptr = skip_ascii_non_spaces(start);
			next = endptr;
			break;
		}
		next = skip_ascii_spaces(next);

		if (filter) {
			if (endptr != start) {
				filter_t *target;
				rule_t *rule;
				gchar *substr;
				gint flags;

				substr = h_strndup(start, endptr - start);
				if (GUI_PROPERTY(gui_debug)) {
					g_debug("%s: \"%s\"",
							filter < 0 ? "negative" : "positive", substr);
				}

				target = filter_get_drop_target();
				g_assert(target != NULL);

				flags = RULE_FLAG_ACTIVE;
				flags |= filter > 0 ? RULE_FLAG_NEGATE : 0;
				rule = filter_new_text_rule(substr, RULE_TEXT_SUBSTR, FALSE,
							target, flags);
				query->rules = g_list_prepend(query->rules, rule);
				HFREE_NULL(substr);
			}
		} else {
			p = start;
			if (GUI_PROPERTY(gui_debug)) {
				g_debug("literal: \"%.*s\"", (int)(guint)(endptr - p), p);
			}
			if (dst != query->text && !is_ascii_space(dst[-1])) {
				*dst++ = ' ';
			}
			while (p != endptr) {
				*dst++ = *p++;
			}
			*dst = '\0';
		}
	}
	query->rules = g_list_reverse(query->rules);
}

static void
clear_error_str(const gchar ***error_str)
{
	if (NULL == *error_str) {
		static const gchar *error_dummy;
		*error_str = &error_dummy;
	}
	**error_str = NULL;
}

static gboolean
search_gui_handle_magnet(const gchar *url, const gchar **error_str)
{
	struct magnet_resource *res;

	clear_error_str(&error_str);
	res = magnet_parse(url, error_str);
	if (res) {
		unsigned n_downloads, n_searches;

		n_downloads = res->display_name ? guc_download_handle_magnet(url) : 0;
		n_searches = guc_search_handle_magnet(url);

		if (n_downloads > 0 || n_searches > 0) {
			gchar msg_search[128], msg_download[128];

			str_bprintf(msg_download, sizeof msg_download,
				NG_("%u download", "%u downloads", n_downloads), n_downloads);
			str_bprintf(msg_search, sizeof msg_search,
				NG_("%u search", "%u searches", n_searches), n_searches);
			statusbar_gui_message(15, _("Handled magnet link (%s, %s)."),
				msg_download, msg_search);
		} else {
			statusbar_gui_message(15, _("Ignored unusable magnet link."));
		}

		magnet_resource_free(&res);
		return TRUE;
	} else {
		if (error_str && *error_str) {
			statusbar_gui_warning(10, "%s", *error_str);
		}
		return FALSE;
	}
}

static gboolean
search_gui_handle_url(const gchar *url, const gchar **error_str)
{
	gchar *magnet_url;
	gboolean success;

	clear_error_str(&error_str);
	g_return_val_if_fail(url, FALSE);
	g_return_val_if_fail(
		is_strcaseprefix(url, "http://") || is_strcaseprefix(url, "push://"),
		FALSE);

	{
		struct magnet_resource *magnet;
		gchar *escaped_url;

		/* Assume the URL was entered by a human; humans don't escape
		 * URLs except on accident and probably incorrectly. Try to
		 * correct the escaping but don't touch '?', '&', '=', ':',
		 * '[', ']'.
		 */
		escaped_url = url_fix_escape(url);

		/* Magnet values are ALWAYS escaped. */
		magnet = magnet_resource_new();
		magnet_add_source_by_url(magnet, escaped_url);
		if (escaped_url != url) {
			HFREE_NULL(escaped_url);
		}
		magnet_url = magnet_to_string(magnet);
		magnet_resource_free(&magnet);
	}
	
	success = guc_download_handle_magnet(magnet_url) > 0;
	if (success) {
		statusbar_gui_message(15, _("Created download from URL."));
	} else {
		statusbar_gui_message(15, _("Ignored unusable URL."));
	}
	HFREE_NULL(magnet_url);

	return success;
}

static gboolean
search_gui_handle_urn(const gchar *urn, const gchar **error_str)
{
	gchar *magnet_url;
	gboolean success;

	clear_error_str(&error_str);
	g_return_val_if_fail(urn, FALSE);
	g_return_val_if_fail(is_strcaseprefix(urn, "urn:"), FALSE);

	{
		struct magnet_resource *magnet;
		gchar *escaped_urn;

		/* Assume the URL was entered by a human; humans don't escape
		 * URLs except on accident and probably incorrectly. Try to
		 * correct the escaping but don't touch '?', '&', '=', ':'.
		 */

		escaped_urn = url_fix_escape(urn);

		/* Magnet values are ALWAYS escaped. */
		magnet = magnet_resource_new();
		success = magnet_set_exact_topic(magnet, escaped_urn);
		if (escaped_urn != urn) {
			HFREE_NULL(escaped_urn);
		}
		if (!success) {
			*error_str = _("The given urn type is not supported.");
			magnet_resource_free(&magnet);
			return FALSE;
		}
		magnet_url = magnet_to_string(magnet);
		magnet_resource_free(&magnet);
	}
	
	success = search_gui_handle_magnet(magnet_url, error_str);
	HFREE_NULL(magnet_url);

	return success;
}

static gboolean
search_gui_handle_sha1(const gchar *text, const gchar **error_str)
{
	struct sha1 sha1;
	size_t ret;

	clear_error_str(&error_str);
	g_return_val_if_fail(text, FALSE);

	text = is_strcaseprefix(text, "sha1:");
	g_return_val_if_fail(text, FALSE);

	if (
		strlen(text) >= SHA1_BASE16_SIZE &&
		!is_ascii_alnum(text[SHA1_BASE16_SIZE])
	) {
		ret = base16_decode(sha1.data, sizeof sha1.data,
				text, SHA1_BASE16_SIZE);
	} else {
		ret = (size_t) -1;
	}

	if (sizeof sha1.data != ret) {
		*error_str = _("The given SHA-1 is not correctly encoded.");
		return FALSE;
	} else {
		static const gchar prefix[] = "urn:sha1:";
		gchar urn[SHA1_BASE32_SIZE + sizeof prefix];

		concat_strings(urn, sizeof urn, prefix, sha1_base32(&sha1), (void *) 0);
		return search_gui_handle_urn(urn, error_str);
	}
}

static gboolean
search_gui_handle_local(const gchar *query, const gchar **error_str)
{
	gboolean success, rebuilding;
	search_t *search;
	const gchar *text;

	clear_error_str(&error_str);
	g_return_val_if_fail(query, FALSE);

	text = is_strcaseprefix(query, "local:");
	g_return_val_if_fail(text, FALSE);

	gnet_prop_get_boolean_val(PROP_LIBRARY_REBUILDING, &rebuilding);
	if (rebuilding) {
		statusbar_gui_message(5,
			_("Still scanning for shared file, results may be inconclusive."));
	}

	success = search_gui_new_search_full(text,
			search_gui_configured_media_type(), tm_time(), 0, 0,
			GUI_PROPERTY(search_sort_default_column),
			GUI_PROPERTY(search_sort_default_order),
			SEARCH_F_LOCAL | SEARCH_F_LITERAL | SEARCH_F_ENABLED,
			&search);
	if (success && search) {
		bool stopped;
		
		stopped = search_gui_start_massive_update(search);
		success = guc_search_locally(search->search_handle, text);
		if (stopped)
			search_gui_end_massive_update(search);
	}
	*error_str = NULL;

	return success;
}

struct browse_request {
	const gchar *host;	/**< atom */
	guint32 flags;		/**< socket flags */
	guint16 port;		/**< port to connect to */
};

static void
browse_request_free(struct browse_request **req_ptr)
{
	struct browse_request *req;
	
	g_assert(req_ptr);

	req = *req_ptr;
	if (req) {
		g_assert(req);

		atom_str_free_null(&req->host);
		WFREE(req);
		*req_ptr = NULL;
	}
}


/**
 * Called when we got a reply from the ADNS process.
 */
static void
search_gui_browse_helper(const host_addr_t *addrs, size_t n, gpointer user_data)
{
	struct browse_request *req = user_data;

	g_assert(addrs);
	g_assert(req);

	if (n > 0) {
		size_t i = random_value(n - 1);

		search_gui_new_browse_host(req->host, addrs[i], req->port,
			NULL, NULL, req->flags);
	}
	browse_request_free(&req);
}

static void
search_gui_browse(const gchar *host, guint16 port, guint32 flags)
{
	struct browse_request *req;

	WALLOC(req);
	req->host = atom_str_get(host);
	req->port = port;
	req->flags = flags;
	guc_adns_resolve(req->host, search_gui_browse_helper, req);
}

gboolean
search_gui_handle_browse(const gchar *s, const gchar **error_str)
{
	gboolean success = FALSE;
	host_addr_t addr;
	const char *endptr;
	guint32 flags = SOCK_F_FORCE;
	guint16 port;

	clear_error_str(&error_str);
	g_return_val_if_fail(s, FALSE);

	s = is_strcaseprefix(s, "browse:");
	g_return_val_if_fail(s, FALSE);
	
	endptr = is_strprefix(s, "tls:");
	if (endptr) {
		s = endptr;
		flags |= SOCK_F_TLS;
	}

	if (string_to_host_or_addr(s, &endptr, &addr)) {
		char hostname[MAX_HOSTLEN + 1];

		if (!is_host_addr(addr)) {
			size_t size;

			size = (endptr - s) + 1;
			size = MIN(size, sizeof hostname);
			g_strlcpy(hostname, s, size);
		}
		if (':' == endptr[0]) {
			int error;
			port = parse_uint16(&endptr[1], NULL, 10, &error);
		} else {
			port = 0;
		}
		if (port > 0) {
			if (is_host_addr(addr)) {
				search_gui_new_browse_host(NULL, addr, port,
					NULL, NULL, flags);
			} else {
				search_gui_browse(hostname, port, flags);
			}
			success = TRUE;
		} else {
			*error_str = _("Missing port number");
		}
	} else {
		*error_str = _("Could not parse host address");
	}

	return success;
}


/**
 * Frees a "struct query" and nullifies the given pointer.
 */
void
search_gui_query_free(struct query **query_ptr)
{
	g_assert(query_ptr);
	if (*query_ptr) {
		struct query *query = *query_ptr;

		G_FREE_NULL(query->text);	
		gm_list_free_null(&query->rules);
		WFREE(query);
		*query_ptr = NULL;
	}
}

/**
 * Handles a query string as entered by the user. This does also handle
 * magnets and special search strings. These will be handled immediately
 * which means that multiple searches and downloads might have been
 * initiated when the functions returns.
 *
 * @param	query_str must point to the query string.
 * @param	flags Diverse SEARCH_F_* flags.
 * @param	error_str Will be set to NULL on success or point to an
 *          error message for the user on failure.
 * @return	NULL if no search should be created. This is not necessarily
 *			a failure condition, check error_str instead. If a search
 *			should be created, an initialized "struct query" is returned.
 */
struct query *
search_gui_handle_query(const gchar *query_str, guint32 flags,
	const gchar **error_str)
{
	gboolean parse;

	clear_error_str(&error_str);
	g_return_val_if_fail(query_str, NULL);

	if (!utf8_is_valid_string(query_str)) {
		*error_str = _("The query string is not UTF-8 encoded");
		return NULL;
	}

	/*
	 * Prevent recursively parsing special search strings i.e., magnet links.
	 */
	parse = !((SEARCH_F_PASSIVE | SEARCH_F_BROWSE | SEARCH_F_LITERAL) & flags);
	if (parse && ':' == *skip_ascii_alnum(query_str)) {
		static const struct {
			const gchar *prefix;
			gboolean (*handler)(const gchar *, const gchar **);
		} tab[] = {
			{ "browse:",	search_gui_handle_browse },
			{ "http:",		search_gui_handle_url },
			{ "local:",		search_gui_handle_local },
			{ "magnet:",	search_gui_handle_magnet },
			{ "push:",		search_gui_handle_url },
			{ "sha1:",		search_gui_handle_sha1 },
			{ "urn:",		search_gui_handle_urn },
		};
		guint i;

		for (i = 0; i < G_N_ELEMENTS(tab); i++) {
			if (is_strcaseprefix(query_str, tab[i].prefix)) {
				tab[i].handler(query_str, error_str);
				return NULL;
			}
		}
		/*
		 * It is better to reject "blah:", so that the behaviour does not
		 * change for some strings in the future.
		 */
		*error_str = _("Unhandled search prefix.");
		return NULL;
	}

	{	
		static const struct query zero_query;
		struct query *query;

		WALLOC(query);
		*query = zero_query;

		if (parse) {
			search_gui_parse_text_query(query_str, query);
		} else {
			query->text = g_strdup(query_str);
		}
		return query;
	}
}

/**
 * Initializes a new filter for the search ``sch'' and adds the rules
 * from the rule list ``rules'' (if any).
 *
 * @param sch a new search
 * @param rules a GList with items of type (rule_t *). ``rules'' may be NULL.
 */
void
search_gui_filter_new(search_t *sch, GList *rules)
{
	GList *l;

	g_assert(sch != NULL);

  	filter_new_for_search(sch);
	g_assert(sch->filter != NULL);

	for (l = rules; l != NULL; l = g_list_next(l)) {
		rule_t *r;

		r = l->data;
		g_assert(r != NULL);
		filter_append_rule(sch->filter, r);
	}
}

gboolean
search_gui_new_search_full(const gchar *query_str, unsigned mtype,
	time_t create_time, guint lifetime, guint32 reissue_timeout,
	gint sort_col, gint sort_order, guint32 flags, search_t **search_ptr)
{
	static const search_t zero_search;
	gboolean is_only_search;
	enum search_new_result result;
    const gchar *error_str;
	gnet_search_t sch_id;
	struct query *query;
	search_t *search;

	if (search_ptr) {
		*search_ptr = NULL;
	}

	query = search_gui_handle_query(query_str, flags, &error_str);
	if (!query) {
		if (error_str) {
			statusbar_gui_warning(5, "%s", error_str);
			return FALSE;
		} else {
			return TRUE;
		}
	}
	g_assert(query);
	g_assert(query->text);
	
	result = guc_search_new(&sch_id, query->text, mtype, create_time, lifetime,
				reissue_timeout, flags);
	if (SEARCH_NEW_SUCCESS != result) {
		statusbar_gui_warning(5, "%s", search_new_error_to_string(result));
		search_gui_query_free(&query);
		return FALSE;
	}

	WALLOC(search);
	*search = zero_search;

	if (search_ptr) {
		*search_ptr = search;
	}

	if (sort_col >= 0 && (guint) sort_col < SEARCH_RESULTS_VISIBLE_COLUMNS) {
		search->sort_col = sort_col;
	} else {
		search->sort_col = -1;
	}
	switch (sort_order) {
	case SORT_ASC:
	case SORT_DESC:
		search->sort_order = sort_order;
		break;
	default:
		search->sort_order = SORT_NONE;
	}
 
	search->search_handle = sch_id;
	search->dups = hset_create_any(search_gui_hash_func,
		search_gui_hash_func2, search_gui_hash_key_compare);

	search_gui_filter_new(search, query->rules);
	search_gui_query_free(&query);

	search->scrolled_window = search_gui_create_scrolled_window();
	search->tree = search_gui_create_tree();

	search_gui_init_tree(search);
	search_gui_start_massive_update(search);
	gtk_widget_hide(search->tree);
	gui_color_init(GTK_WIDGET(search->tree));
	widget_add_popup_menu(search->tree, search_gui_get_popup_menu);	
	if (search_gui_is_local(search)) {
		drag_attach_uri(search->tree, search_gui_get_local_file_url);
	}

	gtk_container_add(GTK_CONTAINER(search->scrolled_window), search->tree);
	gtk_widget_show_all(search->scrolled_window);
	gtk_object_set_user_data(GTK_OBJECT(search->scrolled_window), search);
	gtk_notebook_append_page(notebook_search_results,
		search->scrolled_window, NULL);

	is_only_search = NULL == list_searches;
	list_searches = g_list_append(list_searches, search);
	htable_insert(ht_searches, uint_to_pointer(search->search_handle), search);
	search_gui_option_menu_searches_update();

	if (is_only_search) {
    	gtk_notebook_remove_page(notebook_search_results, 0);
		search_gui_set_current_search(search);
	}

	if (search_gui_is_expired(search) || !(SEARCH_F_ENABLED & flags)) {
		search_gui_stop_search(search);
	} else {
		search_gui_start_search(search);
	}

	gui_signal_connect(search->tree,
		"button_press_event", on_search_results_button_press_event, NULL);
    gui_signal_connect(search->tree,
		"key_press_event", on_search_results_key_press_event, NULL);

	search_gui_update_status(search);
	search_gui_store_searches();

	return TRUE;
}

void
search_gui_synchronize_search_list(search_gui_synchronize_list_cb func,
	void *user_data)
{
	GList *iter;

	g_assert(func);

	for (iter = list_searches; NULL != iter; iter = g_list_next(iter)) {
		iter->data = (*func)(user_data);
		g_assert(iter->data);
	}
	search_gui_option_menu_searches_update();
}

/**
 * Adds a search string to the search history combo. Makes
 * sure we do not get more than 50 entries in the history.
 * Also makes sure we don't get duplicate history entries.
 * If a string is already in history and it's added again,
 * it's moved to the beginning of the history list.
 */
static void
search_gui_history_add(const gchar *text)
{
	GList *iter;

    g_return_if_fail(text);

	/* Remove the text from the history because duplicate strings break
	 * keyboard navigation.
	 */
	for (iter = list_search_history; NULL != iter; iter = g_list_next(iter)) {
		if (0 == strcmp(text, iter->data)) {
			G_FREE_NULL(iter->data);
			list_search_history = g_list_delete_link(list_search_history, iter);
			break;
		}
	}

	/* Remove the oldest item if the list length has reached the limit. */
	if (g_list_length(list_search_history) >= 50) {
		G_FREE_NULL(list_search_history->data);
		list_search_history = g_list_delete_link(list_search_history,
								list_search_history);
	}

	list_search_history = g_list_append(list_search_history, g_strdup(text));
	gtk_combo_set_popdown_strings(
		GTK_COMBO(gui_main_window_lookup("combo_search")),
		list_search_history);
}

gboolean
search_gui_insert_query(const gchar *text)
{
	GtkEntry *entry;

	g_return_val_if_fail(text, FALSE);

#if GTK_CHECK_VERSION(2,0,0)
	g_return_val_if_fail(utf8_is_valid_string(text), FALSE);
#endif	/* Gtk+ >= 2.0 */
	
    entry = GTK_ENTRY(gui_main_window_lookup("entry_search"));
	gtk_entry_set_text(entry, text);
	return TRUE;
}

/**
 * Create a new search from a query entered by the user.
 */
void
search_gui_new_search_entered(void)
{
	GtkWidget *entry;
	gchar *text;
	
    entry = gui_main_window_lookup("entry_search");
   	text = STRTRACK(gtk_editable_get_chars(GTK_EDITABLE(entry), 0, -1));
    g_strstrip(text);
	
	if ('\0' != text[0]) {
        filter_t *default_filter;
        search_t *search;
        gboolean res;

        /*
         * We have to capture the selection here already, because
         * new_search will trigger a rebuild of the menu as a
         * side effect.
         */
        default_filter = option_menu_get_selected_data(GTK_OPTION_MENU(
					gui_main_window_lookup("optionmenu_search_filter")));

		res = search_gui_new_search(text, 0, &search);
        if (res) {
			if (search && default_filter) {
				rule_t *rule;

				rule = filter_new_jump_rule(default_filter, RULE_FLAG_ACTIVE);

				/*
				 * Since we don't want to distrub the shadows and
				 * do a "force commit" without the user having pressed
				 * the "ok" button in the dialog, we add the rule
				 * manually.
				 */

				g_assert(search->filter);
				search->filter->ruleset =
					g_list_append(search->filter->ruleset, rule);

				g_assert(rule);
				g_assert(rule->target);
				g_assert(rule->target->refcount >= 0);
				rule->target->refcount++;
			}

        	search_gui_history_add(text);
			gtk_entry_set_text(GTK_ENTRY(entry), "");

			if (search && GUI_PROPERTY(search_jump_to_created)) {
				search_gui_set_current_search(search);
				main_gui_notebook_set_page(nb_main_page_search);
			}
		} else {
        	gdk_beep();
		}
    }

	gtk_widget_grab_focus(entry);
	G_FREE_NULL(text);
}

/**
 * Create a new "browse host" type search.
 *
 * @param hostname	the DNS name of the host, or NULL if none known
 * @param addr		the IP address of the host to browse
 * @param port		the port to contact
 * @param guid		the GUID of the remote host
 * @param proxies	vector holding known push-proxies
 * @param flags		connection flags like SOCK_F_PUSH, SOCK_F_TLS etc.
 *
 * @return whether the browse host request could be launched.
 */
gboolean
search_gui_new_browse_host(
	const gchar *hostname, host_addr_t addr, guint16 port,
	const struct guid *guid, const gnet_host_vec_t *proxies, guint32 flags)
{
	gchar *host_and_port;
	search_t *search;

	/*
	 * Browse Host (client-side) works thusly:
	 *
	 * We are going to issue a download to request "/" on the remote host.
	 * Once the HTTP connection is established, the remote servent will
	 * send back possibly compressed query hits listing all the shared files.
	 * Those hits will be displayed in the search results.
	 *
	 * The core side is responsible for managing the relationship between
	 * the HTTP packets and the search.  From a GUI standpoint, all we
	 * want to do is display the results.
	 *
	 * However, the "browse host" search is NOT persisted among the searches,
	 * so its lifetime is implicitely this session only.
	 */

	if (guid && (!is_host_addr(addr) || 0 == port)) {
		host_and_port = g_strdup(guid_to_string(guid));
		addr = ipv4_unspecified;
		port = 0;
	} else {
		host_and_port = g_strdup(host_port_to_string(hostname, addr, port));
	}

	(void) search_gui_new_search_full(host_and_port, 0, tm_time(), 0, 0,
			 	GUI_PROPERTY(search_sort_default_column),
				GUI_PROPERTY(search_sort_default_order),
			 	SEARCH_F_BROWSE | SEARCH_F_ENABLED, &search);

	if (search) {
		if (
			guc_search_browse(search->search_handle, hostname, addr, port,
				guid, proxies, flags)
		) {
			statusbar_gui_message(15,
				_("Added search showing browsing results for %s"),
				host_and_port);
		} else {
			search_gui_close_search(search);
			search = NULL;
		}
	}
	if (!search) {
		statusbar_gui_message(10,
			_("Could not launch browse host for %s"), host_and_port);
	}
	G_FREE_NULL(host_and_port);
	return NULL != search;
}

gint
search_gui_cmp_sha1s(const struct sha1 *a, const struct sha1 *b)
{
	if (a && b) {
		return a == b ? 0 : memcmp(a, b, SHA1_RAW_SIZE);
	} else {
		return a ? 1 : (b ? -1 : 0);
	}
}

static void
search_gui_duplicate_search(search_t *search)
{
    guint32 timeout;

	g_return_if_fail(search);
	g_return_if_fail(!search_gui_is_browse(search));
	g_return_if_fail(!search_gui_is_local(search));

	timeout = guc_search_get_reissue_timeout(search->search_handle);

    /* FIXME: should also duplicate filters! */
    /* FIXME: should call search_duplicate which has to be written. */
    /* FIXME: should properly duplicate passive searches. */

	search_gui_new_search_full(search_gui_query(search),
		search_gui_media_type(search),
		tm_time(),
		GUI_PROPERTY(search_lifetime),
		timeout, search->sort_col, search->sort_order,
		search_gui_is_enabled(search) ? SEARCH_F_ENABLED : 0, NULL);
}

/**
 * Restart a search from scratch, clearing all existing content.
 */
static void
search_gui_restart_search(search_t *search)
{
	search_gui_reset_search(search);
	search->items = 0;
	search->unseen_items = 0;
	search->list_refreshed = FALSE;
	search->hidden = 0;
	search->tcp_qhits = 0;
	search->udp_qhits = 0;
	search->skipped = 0;
	search->ignored = 0;
	search->auto_downloaded = 0;
	search->duplicates = 0;

	guc_search_set_create_time(search->search_handle, tm_time());
	search_gui_start_search(search);
}

static void
search_gui_resume_search(search_t *search)
{
	g_return_if_fail(search);

	if (!search_gui_is_expired(search)) {
		search_gui_start_search(search);
	}
}

gboolean
search_gui_has_pending_downloads(const search_t *search)
{
	g_return_val_if_fail(search, FALSE);

	return 0 != guc_search_associated_sha1_count(search->search_handle);
}

static void
on_popup_search_list_close_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *searches, *sl;

	(void) unused_menuitem;
	(void) unused_udata;

	searches = search_gui_get_selected_searches();
	search_gui_option_menu_searches_freeze();
	for (sl = searches; sl; sl = g_slist_next(sl)) {
		search_gui_close_search(sl->data);
	}
	search_gui_option_menu_searches_thaw();
	g_slist_free(searches);
}

static void
on_popup_search_list_restart_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *searches, *sl;

	(void) unused_menuitem;
	(void) unused_udata;

	searches = search_gui_get_selected_searches();
	for (sl = searches; sl; sl = g_slist_next(sl)) {
		search_gui_restart_search(sl->data);
	}
	g_slist_free(searches);
}

static void
on_popup_search_list_resume_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *searches, *sl;

	(void) unused_menuitem;
	(void) unused_udata;

	searches = search_gui_get_selected_searches();
	for (sl = searches; sl; sl = g_slist_next(sl)) {
		search_gui_resume_search(sl->data);
	}
	g_slist_free(searches);
}

static void
on_popup_search_list_stop_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *searches, *sl;

	(void) unused_menuitem;
	(void) unused_udata;

	searches = search_gui_get_selected_searches();
	for (sl = searches; sl; sl = g_slist_next(sl)) {
		search_gui_stop_search(sl->data);
	}
	g_slist_free(searches);
}

static void
on_popup_search_list_duplicate_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *searches, *sl;

	(void) unused_menuitem;
	(void) unused_udata;

	searches = search_gui_get_selected_searches();
	for (sl = searches; sl; sl = g_slist_next(sl)) {
		search_gui_duplicate_search(sl->data);
	}
	g_slist_free(searches);
}

static void
on_popup_search_list_edit_filters_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

    filter_open_dialog();
}

GtkMenu *
search_gui_get_search_list_popup_menu(void)
{
	return GTK_MENU(gui_popup_search_list());
}

gboolean
on_search_list_key_release_event(GtkWidget *unused_widget,
	GdkEventKey *event, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;

	if (
		GDK_Return == event->keyval &&
		0 == (gtk_accelerator_get_default_mod_mask() & event->state)
	) {
		main_gui_notebook_set_page(nb_main_page_search);
		search_gui_search_list_clicked();
	}
	return FALSE;
}

gboolean
on_search_list_button_release_event(GtkWidget *unused_widget,
	GdkEventButton *event, gpointer unused_udata)
{
	(void) unused_udata;
	(void) unused_widget;

	if (
		GDK_BUTTON_RELEASE == event->type &&
		1 == event->button &&
		0 == (gtk_accelerator_get_default_mod_mask() & event->state)
	) {
		main_gui_notebook_set_page(nb_main_page_search);
		search_gui_search_list_clicked();
	}
	return FALSE;
}

void
search_gui_refresh_popup(void)
{
	/*
	 * The following popup items are set insensitive if nothing is currently
	 * selected (actually if the cursor is unset).
	 */
	static const struct {
		const gchar *name;
		gboolean local;
	} menu[] = {
		{	"popup_search_metadata",	TRUE },
		{	"popup_search_browse_host",	FALSE },
		{	"popup_search_download",	FALSE },
		{	"popup_search_copy_magnet", TRUE },
	};
	search_t *search = search_gui_get_current_search();
	gboolean has_selected, is_local;
	guint i;

	is_local = search && search_gui_is_local(search);
	has_selected = search && search_gui_has_selected_item(search);
	gtk_widget_set_sensitive(gui_main_window_lookup("button_search_download"),
		has_selected && !is_local);

	for (i = 0; i < G_N_ELEMENTS(menu); i++) {
		GtkWidget *w = gui_popup_search_lookup(menu[i].name);
		if (w) {
			gtk_widget_set_sensitive(w,
				has_selected && (menu[i].local || !is_local));
		}
	}

    if (search) {
        gtk_widget_set_sensitive(
            gui_popup_search_lookup("popup_search_stop"),
			!guc_search_is_frozen(search->search_handle));
		gtk_widget_set_sensitive(
			gui_popup_search_lookup("popup_search_resume"),
			guc_search_is_frozen(search->search_handle)
				&& !search_gui_is_expired(search));
		gtk_widget_set_sensitive(
			gui_popup_search_lookup("popup_search_restart"),
			is_local || !search_gui_is_passive(search));
    } else {
		gtk_widget_set_sensitive(
			gui_popup_search_lookup("popup_search_stop"), FALSE);
		gtk_widget_set_sensitive(
			gui_popup_search_lookup("popup_search_resume"), FALSE);
    }

	{
		GtkWidget *item;

		item = gui_popup_search_lookup("popup_search_toggle_tabs");
		gtk_label_set(GTK_LABEL(GTK_MENU_ITEM(item)->item.bin.child),
				GUI_PROPERTY(search_results_show_tabs)
				? _("Show search list")
				: _("Show tabs"));
	}
}

static gboolean
search_results_show_tabs_changed(property_t prop)
{
	gboolean enabled;
	
    gui_prop_get_boolean_val(prop, &enabled);
	gtk_notebook_set_show_tabs(notebook_search_results, enabled);
	widget_set_visible(gui_main_window_lookup("sw_searches"), !enabled);
	return FALSE;
}

static void
on_popup_search_toggle_tabs_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
    gboolean value;

	(void) unused_menuitem;
	(void) unused_udata;

    gui_prop_get_boolean_val(PROP_SEARCH_RESULTS_SHOW_TABS, &value);
    value = !value;
    gui_prop_set_boolean_val(PROP_SEARCH_RESULTS_SHOW_TABS, value);
}

static void
on_popup_search_config_cols_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
    struct search *search;
	GtkWidget *cc;

	(void) unused_menuitem;
	(void) unused_udata;

    search = search_gui_get_current_search();
	g_return_if_fail(search);

	cc = gtk_column_chooser_new(GTK_WIDGET(search->tree));
   	gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1,
		gtk_get_current_event_time());
}

static void
on_popup_search_download_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;
	search_gui_download_selected_files();
}

static void
on_popup_search_restart_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	search_gui_restart_search(search_gui_get_current_search());
}

static void
on_popup_search_resume_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

    search_gui_resume_search(search_gui_get_current_search());
}

static void
on_popup_search_stop_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

    search_gui_stop_search(search_gui_get_current_search());
}

static void
on_popup_search_expand_all_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	search_gui_expand_all(current_search);
}

static void
on_popup_search_collapse_all_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	search_gui_collapse_all(current_search);
}

static void
on_popup_search_browse_host_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	search_gui_browse_selected();
}

static void
on_popup_search_sort_defaults_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;
	
	search_gui_set_sort_defaults();
}

const gchar *
search_gui_query(const search_t *search)
{
	g_assert(search);
	return guc_search_query(search->search_handle);
}

unsigned
search_gui_media_type(const search_t *search)
{
	g_assert(search);
	return guc_search_get_media_type(search->search_handle);
}


const gchar *
search_gui_nice_size(const record_t *rc)
{
	return nice_size(rc->size, show_metric_units());
}

const gchar *
search_gui_get_vendor(const struct results_set *rs)
{
	const gchar *vendor;

	g_assert(rs);

	vendor = vendor_code_get_name(rs->vendor);
	if (vendor) {
		if (rs->version) {
			static gchar buf[128];

			concat_strings(buf, sizeof buf, vendor, "/", rs->version,
				(void *) 0);
			vendor = buf;
		}
	} else {
		vendor = _("Unknown");
	}
	return vendor;
}

void
search_gui_set_filter(struct search *search, struct filter *filter)
{
	g_return_if_fail(search);
	search->filter = filter;
}

struct filter *
search_gui_get_filter(const struct search *search)
{
	g_return_val_if_fail(search, NULL);
	return search->filter;
}

int
search_gui_get_sort_column(const struct search *search)
{
	g_return_val_if_fail(search, -1);
	return search->sort_col;
}

int
search_gui_get_sort_order(const struct search *search)
{
	g_return_val_if_fail(search, 0);
	return search->sort_order;
}

gnet_search_t
search_gui_get_handle(const struct search *search)
{
	g_return_val_if_fail(search, 0);
	return search->search_handle;
}

gboolean
search_gui_item_is_inspected(const record_t *rc)
{
	record_check(rc);

	if (NULL == search_details_record || NULL == rc)
		return FALSE;

	record_check(search_details_record);

	return rc == search_details_record ||
		(
		 	NULL != rc->sha1 &&
			rc->sha1 == search_details_record->sha1 &&
			rc->size == search_details_record->size
		);
}

void
search_gui_set_details(const record_t *rc)
{
	const struct results_set *rs;

	search_gui_clear_details();

	if (search_details_record) {
		search_gui_unref_record(search_details_record);
		search_details_record = NULL;
	}

	if (NULL == rc)
		return;

	record_check(rc);
	rs = rc->results_set;

	search_details_record = deconstify_gpointer(rc);
	search_gui_ref_record(search_details_record);

	search_gui_append_detail(_("Filename"),
		lazy_utf8_to_ui_string(rc->utf8_name));
	search_gui_append_detail(_("Extension"), rc->ext);
	search_gui_append_detail(_("Size"), search_gui_nice_size(rc));
	search_gui_append_detail(_("MIME type"),
		mime_type_to_string(mime_type_from_extension(rc->ext)));
	search_gui_append_detail(_("SHA-1"),
		rc->sha1 ? sha1_to_urn_string(rc->sha1) : NULL);
	search_gui_append_detail(_("TTH"),
		rc->tth ? tth_to_urn_string(rc->tth) : NULL);
	search_gui_append_detail(_("Owned"),
		(SR_OWNED   & rc->flags) ? _("owned") :
		(SR_PARTIAL & rc->flags) ? _("partial") :
		(SR_SHARED  & rc->flags) ? _("shared") :
		_("No"));

	if (!(ST_LOCAL & rs->status)) {
		if (rc->tag != NULL) {
			search_gui_append_detail(_("Tag"),
				lazy_unknown_to_ui_string(rc->tag));
		}
		search_gui_append_detail(_("Spam"),
			(SR_SPAM & rc->flags) ? _("Yes") :
			(ST_SPAM & rs->status) ? _("Maybe") :
			_("No"));
		search_gui_append_detail(_("Source"),
			host_addr_port_to_string(rs->addr, rs->port));
		if (ST_ALIEN & rs->status) {
			search_gui_append_detail(_("Alien IP"), _("Yes"));
		}
	}

	search_gui_append_detail(_("Created"),
		(time_t) -1 != rc->create_time
		? timestamp_to_string(rc->create_time)
		: _("Unknown"));

	if (rc->alt_locs) {
		gchar *hosts = gnet_host_vec_to_string(rc->alt_locs);
		search_gui_append_detail(_("Alt-Locs"), hosts);
		HFREE_NULL(hosts);
	}

	search_gui_append_detail(_("Partial"),
		SR_PARTIAL_HIT & rc->flags ? _("Yes") : _("No"));

	if (rc->partial != NULL) {
		struct precord *prc = rc->partial;

		if (rc->size != 0) {
			char buf[80];
			double pct = 100.0 * prc->available / (double) rc->size;
			str_bprintf(buf, sizeof buf, _("%s [%.2f%%]"),
				nice_size(prc->available, show_metric_units()), pct);
			search_gui_append_detail(_("Available"), buf);
		}
		search_gui_append_detail(_("Last modification"),
			0 != prc->mod_time
			? timestamp_to_string(prc->mod_time)
			: _("Unknown"));
	}

	if (utf8_can_latinize(rc->utf8_name)) {
		size_t size;
		gchar *buf;
		
		size = 1 + utf8_latinize(NULL, 0, rc->utf8_name);
		buf = walloc(size);
		utf8_latinize(buf, size, rc->utf8_name);
		search_gui_append_detail(_("Latinized"), lazy_utf8_to_ui_string(buf));
		WFREE_NULL(buf, size);
	}

	/*
	 * The index is already shown in the classic URL in expert mode,
	 * so don't show it explicitely as it's just visual noise.
	 */

	if (rc->sha1) {
		bitzi_data_t data;

		search_gui_append_detail(_("External metadata"), NULL);	/* Separator */
		search_gui_append_detail(_("Bitzi URL"),
			url_for_bitzi_lookup(rc->sha1));

		if (guc_bitzi_data_by_sha1(&data, rc->sha1, rc->size)) {
			char *meta = bitzi_gui_get_metadata(&data);
			search_gui_append_detail(_("Bitzi metadata"),
				meta != NULL ? meta : _("Not in database"));
			HFREE_NULL(meta);
		}
	}

	if (ST_LOCAL & rs->status) {
		const gchar *display_path;
		gchar *url;

		display_path = lazy_filename_to_ui_string(rc->tag);
		if (0 == strcmp(display_path, rc->tag)) {
			/* Only show the pathname if its encoding matches the
			 * the UI encoding. Otherwise, drag & drop would result
			 * in different string than the actual pathname.
			 */
			search_gui_append_detail(_("Pathname"), display_path);
		}

		url = url_from_absolute_path(rc->tag);
		search_gui_append_detail(_("File URL"), url);
		G_FREE_NULL(url);
	} else {
		search_gui_append_detail(_("Host information"), NULL);

		search_gui_append_detail(_("Hostname"), rs->hostname);
		if (rs->status & ST_BANNED_GUID) {
			char buf[80];

			str_bprintf(buf, sizeof buf, "%s [%s]",
				guid_to_string(rs->guid), _("banned"));

			search_gui_append_detail(_("Servent ID"), buf);
		} else {
			search_gui_append_detail(_("Servent ID"), guid_to_string(rs->guid));
		}
		search_gui_append_detail(_("Vendor"), search_gui_get_vendor(rs));
		search_gui_append_detail(_("Browsable"),
				ST_BH & rs->status ? _("Yes") : _("No"));
		search_gui_append_detail(_("Hostile"),
				ST_HOSTILE & rs->status ? _("Yes") : _("No"));

		if (ISO3166_INVALID != rs->country) {
			search_gui_append_detail(_("Country"),
				iso3166_country_name(rs->country));
		}

		if (rs->proxies) {
			gchar *hosts = gnet_host_vec_to_string(rs->proxies);
			search_gui_append_detail(_("Push-proxies"), hosts);
			HFREE_NULL(hosts);
		}

		search_gui_append_detail(_("Packet information"), NULL);

		search_gui_append_detail(_("Route"), search_gui_get_route(rs));
		if (!(ST_BROWSE & rs->status)) {
			search_gui_append_detail(_("Protocol"),
				ST_UDP & rs->status ? "UDP" : "TCP");

			search_gui_append_detail(_("Hops"), uint32_to_string(rs->hops));
			search_gui_append_detail(_("TTL"), uint32_to_string(rs->ttl));

			if (0 == rs->media) {
				search_gui_append_detail(_("Query"),
					lazy_unknown_to_utf8_normalized(EMPTY_STRING(rs->query),
						UNI_NORM_GUI, NULL));
			} else {
				const char *media = guc_search_media_mask_to_string(rs->media);
				const char *query = str_smsg("%s (%s)",
					lazy_unknown_to_utf8_normalized(EMPTY_STRING(rs->query),
						UNI_NORM_GUI, NULL), media);
				search_gui_append_detail(_("Query"), query);
			}
		}
		search_gui_append_detail(_("Received"), timestamp_to_string(rs->stamp));
	}

	if (GUI_PROPERTY(expert_mode)) {
		search_gui_append_detail(_("URLs"), NULL);

		if (rc->sha1) {
			gchar *url;

			url = g_strconcat("http://",
					host_addr_port_to_string(rs->addr, rs->port),
					"/uri-res/N2R?", bitprint_to_urn_string(rc->sha1, rc->tth),
					(void *)0);
			search_gui_append_detail(_("N2R URI"), url);
			G_FREE_NULL(url);
		}

		if (rc->sha1) {
			gchar *url;
			host_addr_t addr;
			guint16 port;

			if (rs->proxies) {
				gnet_host_t host;

				host = gnet_host_vec_get(rs->proxies, 0);
				addr = gnet_host_get_addr(&host);
				port = gnet_host_get_port(&host);
			} else {
				addr = rs->addr;
				port = rs->port;
			}

			url = g_strconcat("push://",
					guid_to_string(rs->guid), ":",
					host_addr_port_to_string(addr, port),
					"/uri-res/N2R?", bitprint_to_urn_string(rc->sha1, rc->tth),
					(void *)0);
			search_gui_append_detail(_("Push URL"), url);
			G_FREE_NULL(url);
		}

		{
			const gchar *filename;
			gchar *url, *escaped;

			filename = filepath_basename(rc->utf8_name);
			escaped = url_escape(filename);
			url = h_strconcat("http://",
					host_addr_port_to_string(rs->addr, rs->port),
					"/get/", uint32_to_string(rc->file_index), "/", escaped,
					(void *)0);
			search_gui_append_detail(_("Classic URL"), url);
			if (filename != escaped) {
				HFREE_NULL(escaped);
			}
			HFREE_NULL(url);
		}
	}
}

static gboolean
handle_not_implemented(const gchar *url)
{
	g_return_val_if_fail(url, FALSE);
	statusbar_gui_warning(10,
			_("Support for this protocol is not yet implemented"));
	return FALSE;
}

static gboolean
handle_magnet(const gchar *url)
{
	const gchar *error_str;
	gboolean success;

	g_return_val_if_fail(url, FALSE);

	success = search_gui_handle_magnet(url, &error_str);
	if (!success) {
		statusbar_gui_warning(10, "%s", error_str);
	}
	return success;
}

static gboolean
handle_url(const gchar *url)
{
	const gchar *error_str;
	gboolean success;

	g_return_val_if_fail(url, FALSE);

	success = search_gui_handle_url(url, &error_str);
	if (!success) {
		statusbar_gui_warning(10, "%s", error_str);
	}
	return success;
}

static gboolean
handle_urn(const gchar *url)
{
	const gchar *error_str;
	gboolean success;

	g_return_val_if_fail(url, FALSE);

	success = search_gui_handle_urn(url, &error_str);
	if (!success) {
		statusbar_gui_warning(10, "%s", error_str);
	}
	return success;
}

/* FIXME: We shouldn't try to handle from ourselves without a confirmation
 *        because an URL might have been accidently while dragging it
 *		  around.
 */
static void
drag_data_received(GtkWidget *widget, GdkDragContext *dc,
	gint unused_x, gint unused_y, GtkSelectionData *data,
	guint unused_info, guint stamp, gpointer unused_udata)
{
	static const struct {
		const char * const proto;
		gboolean (* handler)(const gchar *url);
	} proto_handlers[] = {
		{ "ftp",	handle_not_implemented },
		{ "http",	handle_url },
		{ "push",	handle_url },
		{ "magnet",	handle_magnet },
		{ "urn",	handle_urn },
	};
	gboolean success = FALSE;

	(void) unused_x;
	(void) unused_y;
	(void) unused_info;
	(void) unused_udata;

	if (data->length > 0 && data->format == 8) {
		const gchar *text = cast_to_gchar_ptr(data->data);
		guint i;

		if (GUI_PROPERTY(gui_debug) > 0) {
			g_debug("drag_data_received: text=\"%s\"", text);
		}
		
		if (gui_main_window_lookup("entry_search") != widget) {
			for (i = 0; i < G_N_ELEMENTS(proto_handlers); i++) {
				const char *endptr;

				endptr = is_strcaseprefix(text, proto_handlers[i].proto);
				if (endptr && ':' == endptr[0]) {
					success = proto_handlers[i].handler(text);
					goto cleanup;
				}
			}
		}
		success = search_gui_insert_query(text);
	}

cleanup:
	if (!success && data->length > 0) {
		statusbar_gui_warning(10, _("Cannot handle the dropped data"));
	}
	gtk_drag_finish(dc, success, FALSE, stamp);
}

const gchar *
search_new_error_to_string(enum search_new_result result)
{
	const gchar *msg = "";

	switch (result) {
	case SEARCH_NEW_TOO_LONG:
		msg = _("The normalized search text is too long.");
		break;
	case SEARCH_NEW_TOO_SHORT:
		msg = _("The normalized search text is too short.");
		break;
	case SEARCH_NEW_TOO_EARLY:
		msg = _("One cannot send \"What's New?\" queries too often.");
		break;
	case SEARCH_NEW_INVALID_URN:
		msg = _("The URN in the search text is invalid.");
		break;
	case SEARCH_NEW_SUCCESS:
		break;
	}
	return msg;
}

static void
search_gui_magnet_add_source(struct magnet_resource *magnet, record_t *record)
{
	struct results_set *rs;

	g_return_if_fail(magnet);
	g_return_if_fail(record);
	record_check(record);
	
	rs = record->results_set;

	if (!(ST_FIREWALL & rs->status)) {
		magnet_add_sha1_source(magnet, record->sha1, rs->addr, rs->port,
			NULL, NULL);
	} else {
		magnet_add_sha1_source(magnet, record->sha1,
			ipv4_unspecified, 0, rs->guid, rs->proxies);
	}
	if (record->alt_locs) {
		gint i, n;

		n = gnet_host_vec_count(record->alt_locs);
		n = MIN(10, n);

		for (i = 0; i < n; i++) {
			gnet_host_t host;

			host = gnet_host_vec_get(record->alt_locs, i);
			magnet_add_sha1_source(magnet, record->sha1,
				gnet_host_get_addr(&host), gnet_host_get_port(&host),
				NULL, NULL);
		}
	}
}

char *
search_gui_get_magnet(search_t *search, record_t *record)
{
	struct magnet_resource *magnet;
	char *url;

	g_return_val_if_fail(search, NULL);
	g_return_val_if_fail(record, NULL);
	record_check(record);

	magnet = magnet_resource_new();
	magnet_set_display_name(magnet, record->utf8_name);
	magnet_set_filesize(magnet, record->size);

	if (record->sha1) {
		record_t *parent;

		magnet_set_sha1(magnet, record->sha1);
		search_gui_magnet_add_source(magnet, record);

		parent = search_gui_record_get_parent(search, record);
		if (parent) {
			GSList *children, *iter;

			children = search_gui_record_get_children(search, parent);
			for (iter = children; NULL != iter; iter = g_slist_next(iter)) {
				record_t *child = iter->data;
				record_check(child);
				search_gui_magnet_add_source(magnet, child);
			}
			g_slist_free(children);
		}
	}

	url = magnet_to_string(magnet);
	magnet_resource_free(&magnet);
	return url;
}

/* Display Bitzi data for the result if any */
void
search_gui_set_bitzi_metadata(const record_t *rc)
{
	const char *ticket;
	char *tmp, *text;

	if (NULL == rc) {
		search_gui_set_bitzi_metadata_text("");
		return;
	}

	record_check(rc);

	if (NULL == rc->sha1) {
		search_gui_set_bitzi_metadata_text(_("SHA-1 is unknown."));
		return;
	}

	if (!guc_bitzi_has_cached_ticket(rc->sha1)) {
		search_gui_set_bitzi_metadata_text(_("No Bitzi ticket requested yet."));
		return;
	}

	ticket = guc_bitzi_ticket_by_sha1(rc->sha1, rc->size);
	if (NULL == ticket) {
		search_gui_set_bitzi_metadata_text(_("Not in Bitzi database."));
		return;
	}

	/* This also decodes 8-bit entities */
	tmp = xml_indent(ticket);

	/*
	 * Bitzi converts all ticket data from ISO-8859-1 to UTF-8, therefore this
	 * conversion must be reversed to get the original encoding back.
	 */
	text = utf8_to_iso8859_1(tmp);
	HFREE_NULL(tmp);

	search_gui_set_bitzi_metadata_text(
		lazy_unknown_to_utf8_normalized(text, UNI_NORM_GUI, NULL));
	G_FREE_NULL(text);
}

void
search_gui_store_searches(void)
{
	store_searches_requested = TRUE;
}

static void
search_gui_timer(time_t now)
{
    static time_t last_update;

    search_gui_flush(now, FALSE);

	if (delta_time(last_update, now)) {
		GList *iter;

		last_update = now;
		for (iter = list_searches; NULL != iter; iter = g_list_next(iter)) {
			struct search *search = iter->data;
			search_gui_update_counters(search);
		}
		search_gui_update_status(current_search);
		search_gui_refresh_popup();
	}
	if (store_searches_requested && !store_searches_disabled) {
		store_searches_requested = FALSE;
		search_gui_real_store_searches();
	}
}

static void
search_gui_guess_event(gnet_search_t sh, const struct guess_query *query)
{
	search_t *search;

	search = search_gui_find(sh);
	g_return_if_fail(search != NULL);

	if (NULL == query) {
		/* Current query terminated, consolidate results */
		search->guess_bw_query += search->guess_cur_bw_query;
		search->guess_bw_qk += search->guess_cur_bw_qk;
		search->guess_results += search->guess_cur_results;
		search->guess_kept += search->guess_cur_kept;
		search->guess_elapsed = delta_time(tm_time(), search->guess_cur_start);
		search->guess_hosts = search->guess_cur_acks;	/* Really queried */
		search->guess_last_kept = search->guess_cur_kept;
		/* Reset stats for new query */
		search->guess_cur_start = 0;
		search->guess_cur_pool = 0;
		search->guess_cur_ultra = 0;
		search->guess_cur_g2 = 0;
		search->guess_cur_acks = 0;
		search->guess_cur_results = 0;
		search->guess_cur_kept = 0;
		search->guess_cur_hops = 0;
		search->guess_cur_rpc_pending = 0;
		search->guess_cur_bw_query = 0;
		search->guess_cur_bw_qk = 0;
	} else {
		/* New query starting */
		search->guess_queries++;
		search->guess_cur_start = tm_time();
		search->guess_cur_mode = query->mode;
		search->guess_cur_max_ultra = query->max_ultra;
	}
}

static void
search_gui_guess_stats(gnet_search_t sh, const struct guess_stats *stats)
{
	search_t *search;

	search = search_gui_find(sh);
	g_return_if_fail(search != NULL);

	search->guess_cur_pool			= stats->pool;
	search->guess_cur_ultra			= stats->queried_ultra;
	search->guess_cur_g2			= stats->queried_g2;
	search->guess_cur_acks			= stats->acks;
	search->guess_cur_results		= stats->results;
	search->guess_cur_kept			= stats->kept;
	search->guess_cur_hops			= stats->hops;
	search->guess_cur_rpc_pending	= stats->rpc_pending;
	search->guess_cur_bw_query		= stats->bw_out_query;
	search->guess_cur_bw_qk			= stats->bw_out_qk;
	search->guess_cur_mode			= stats->mode;
	search->guess_cur_pool_load		= stats->pool_load;
	search->guess_cur_end_starving	= stats->end_starving;
}


static void
search_gui_signals_init(void)
{
#define WIDGET_SIGNAL_CONNECT(widget, event) \
		gui_signal_connect(gui_main_window_lookup(#widget), #event, \
			on_ ## widget ## _ ## event, NULL)
	
	WIDGET_SIGNAL_CONNECT(button_search, clicked);
	WIDGET_SIGNAL_CONNECT(button_search_clear, clicked);
	WIDGET_SIGNAL_CONNECT(button_search_close, clicked);
	WIDGET_SIGNAL_CONNECT(button_search_download, clicked);
	WIDGET_SIGNAL_CONNECT(button_search_filter, clicked);
	WIDGET_SIGNAL_CONNECT(button_search_passive, clicked);
	WIDGET_SIGNAL_CONNECT(button_search_whats_new, clicked);
	WIDGET_SIGNAL_CONNECT(button_search_media_type_any, clicked);
	WIDGET_SIGNAL_CONNECT(entry_search, activate);
	WIDGET_SIGNAL_CONNECT(entry_search, changed);
	WIDGET_SIGNAL_CONNECT(notebook_search_results, switch_page);

#undef WIDGET_SIGNAL_CONNECT

#define ON_ACTIVATE(item) \
		gui_signal_connect( \
			gui_popup_search_list_lookup("popup_search_list_" #item), \
			"activate", on_popup_search_list_ ## item ## _activate, NULL)

/* sed -n 's,^on_popup_search_list_\(.*\)_activate[(].*$,ON_ACTIVATE(\1),p' */

	ON_ACTIVATE(close);
	ON_ACTIVATE(duplicate);
	ON_ACTIVATE(edit_filters);
	ON_ACTIVATE(restart);
	ON_ACTIVATE(resume);
	ON_ACTIVATE(stop);

#undef ON_ACTIVATE

#define ON_ACTIVATE(item) \
		gui_signal_connect(gui_popup_search_lookup("popup_search_" #item), \
			"activate", on_popup_search_ ## item ## _activate, NULL)

/* sed -n 's,^on_popup_search_\([^l].*\)_activate[(].*$,ON_ACTIVATE(\1);,p' */

	ON_ACTIVATE(browse_host);
	ON_ACTIVATE(collapse_all);
	ON_ACTIVATE(config_cols);
	ON_ACTIVATE(download);
	ON_ACTIVATE(expand_all);
	ON_ACTIVATE(restart);
	ON_ACTIVATE(resume);
	ON_ACTIVATE(sort_defaults);
	ON_ACTIVATE(stop);
	ON_ACTIVATE(toggle_tabs);

	/* TODO: Code not merged yet */
	ON_ACTIVATE(metadata);
	ON_ACTIVATE(copy_magnet);

#undef ON_ACTIVATE
}

const char *
search_gui_column_title(int column)
{
	g_return_val_if_fail(column >= 0, NULL);
	g_return_val_if_fail(column < c_sr_num, NULL);

	switch ((enum c_sr_columns) column) {
	case c_sr_filename:	return _("Filename");
	case c_sr_ext:		return _("Extension");
	case c_sr_charset:	return _("Encoding");
	case c_sr_size:		return _("Size");
	case c_sr_mime:		return _("MIME type");
	case c_sr_count:	return _("#");
	case c_sr_loc:		return _("Country");
	case c_sr_meta:		return _("Metadata");
	case c_sr_vendor:	return _("Vendor");
	case c_sr_info:		return _("Info");
	case c_sr_route:	return _("Route");
	case c_sr_protocol:	return _("Protocol");
	case c_sr_hops:		return _("Hops");
	case c_sr_ttl:		return _("TTL");
	case c_sr_owned:	return _("Owned");
	case c_sr_spam:		return _("Spam");
	case c_sr_hostile:	return _("Hostile");
	case c_sr_sha1:		return _("SHA-1");
	case c_sr_ctime:	return _("Created");
	case c_sr_num:		break;
	}
	g_assert_not_reached();
	return NULL;
}

gboolean
search_gui_column_justify_right(int column)
{
	g_return_val_if_fail(column >= 0, FALSE);
	g_return_val_if_fail(column < c_sr_num, FALSE);

	switch ((enum c_sr_columns) column) {
	case c_sr_filename:	return FALSE;
	case c_sr_ext:		return FALSE;
	case c_sr_charset:	return FALSE;
	case c_sr_size:		return TRUE;
	case c_sr_mime:		return FALSE;
	case c_sr_count:	return TRUE;
	case c_sr_loc:		return FALSE;
	case c_sr_meta:		return FALSE;
	case c_sr_vendor:	return FALSE;
	case c_sr_info:		return FALSE;
	case c_sr_route:	return FALSE;
	case c_sr_protocol:	return FALSE;
	case c_sr_hops:		return TRUE;
	case c_sr_ttl:		return TRUE;
	case c_sr_owned:	return FALSE;
	case c_sr_spam:		return FALSE;
	case c_sr_hostile:	return FALSE;
	case c_sr_sha1:		return FALSE;
	case c_sr_ctime:	return FALSE;
	case c_sr_num:		break;
	}
	g_assert_not_reached();
	return FALSE;
}


/**
 * Initialize common structures.
 */
void
search_gui_common_init(void)
{
	accumulated_rs = slist_new();
	ht_searches = htable_create(HASH_KEY_SELF, 0);

	label_items_found = GTK_LABEL(
		gui_main_window_lookup("label_items_found"));
	label_search_expiry = GTK_LABEL(
		gui_main_window_lookup("label_search_expiry"));
	label_guess_stats = GTK_LABEL(
		gui_main_window_lookup("label_guess_stats"));
	guess_stats_line = gui_main_window_lookup("guess_stats_line");

	{
		GtkNotebook *nb;
		
		nb = GTK_NOTEBOOK(gui_main_window_lookup("notebook_search_results"));
		notebook_search_results = nb;

		gtk_notebook_set_scrollable(nb, TRUE);
		gui_prop_add_prop_changed_listener(PROP_SEARCH_RESULTS_SHOW_TABS,
			search_results_show_tabs_changed, TRUE);
	}

    gtk_combo_set_case_sensitive(
        GTK_COMBO(gui_main_window_lookup("combo_search")), TRUE);

	{
		GtkWidget *widget;
	    GtkAdjustment *adj;
		
		widget = gui_main_window_lookup("spinbutton_search_reissue_timeout");
 		adj = gtk_spin_button_get_adjustment(GTK_SPIN_BUTTON(widget));
		gui_signal_connect_after(adj, "value-changed",
			on_spinbutton_adjustment_value_changed, widget);
	}

	drop_widget_init(gui_main_window(), drag_data_received, NULL);
	
#if !GTK_CHECK_VERSION(2,0,0)
	drop_widget_init(gui_main_window_lookup("entry_search"),
		drag_data_received, NULL);
#endif	/* Gtk+ < 2.0 */

   	gtk_notebook_remove_page(notebook_search_results, 0);
	search_gui_switch_search(NULL);
	search_gui_signals_init();

	search_gui_option_menu_searches_update();
	search_gui_option_menu_searches_freeze();
	search_gui_retrieve_searches();
	search_gui_option_menu_searches_thaw();

    guc_search_got_results_listener_add(search_gui_got_results);
    guc_search_status_change_listener_add(search_gui_status_change);

    guc_guess_event_listener_add(search_gui_guess_event);
    guc_guess_stats_listener_add(search_gui_guess_stats);

	main_gui_add_timer(search_gui_timer);
}

/**
 * Destroy common structures.
 */
void
search_gui_common_shutdown(void)
{
	search_gui_callbacks_shutdown();

 	guc_search_got_results_listener_remove(search_gui_got_results);
 	guc_search_status_change_listener_remove(search_gui_status_change);

    guc_guess_event_listener_remove(search_gui_guess_event);
    guc_guess_stats_listener_remove(search_gui_guess_stats);

	gui_prop_remove_prop_changed_listener(PROP_SEARCH_RESULTS_SHOW_TABS,
		search_results_show_tabs_changed);

	search_gui_real_store_searches();
	store_searches_disabled = TRUE;

	search_gui_option_menu_searches_freeze();
    while (search_gui_get_searches()) {
        search_gui_close_search(search_gui_get_searches()->data);
	}
	search_gui_option_menu_searches_thaw();

	/* Discard pending accumulated search results */
    search_gui_flush(tm_time(), TRUE);
	slist_free_all(&accumulated_rs, accum_rs_free_full);

	search_gui_set_details(NULL);

    gm_list_free_null(&list_search_history);
	htable_free_null(&ht_searches);
}

/* vi: set ts=4 sw=4 cindent: */
