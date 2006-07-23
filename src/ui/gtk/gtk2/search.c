/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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
 * GUI filtering functions.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "gtk/gui.h"

#include "search_cb.h"

#include "gtk/bitzi.h"
#include "gtk/search.h"
#include "gtk/gtk-missing.h"
#include "gtk/settings.h"
#include "gtk/columns.h"
#include "gtk/misc.h"
#include "gtk/notebooks.h"
#include "gtk/statusbar.h"

#include "if/gui_property.h"
#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"
#include "if/core/bitzi.h"
#include "if/core/sockets.h"

#include "lib/atoms.h"
#include "lib/magnet.h"
#include "lib/misc.h"
#include "lib/glib-missing.h"
#include "lib/iso3166.h"
#include "lib/tm.h"
#include "lib/url.h"
#include "lib/utf8.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

RCSID("$Id$");

#define MAX_TAG_SHOWN	60		/**< Show only first chars of tag */

static GList *searches = NULL;	/**< List of search structs */

static GtkTreeView *tree_view_search = NULL;
static GtkNotebook *notebook_search_results = NULL;
static GtkButton *button_search_clear = NULL;

static gboolean search_gui_shutting_down = FALSE;

/*
 * Private function prototypes.
 */
static void gui_search_create_tree_view(GtkWidget ** sw,
				GtkWidget ** tv, gpointer udata);
static void search_gui_init_dnd(GtkTreeView *tv);

/*
 * If no search are currently allocated
 */
static GtkWidget *default_search_tree_view = NULL;
GtkWidget *default_scrolled_window = NULL;


/** For cyclic updates of the tooltip. */
static tree_view_motion_t *tvm_search;

/* ----------------------------------------- */

struct result_data {
	GtkTreeIter iter;
	const GdkColor *fg;
	const GdkColor *bg;

	record_t *record;
	gchar *ext;			/**< Atom */
	gchar *meta;		/**< Atom */
	gchar *info;		/**< g_malloc()ed */
	guint count;		/**< count of children */
	guint32 rank;		/**< for stable sorting */
};

static inline struct result_data *
get_result_data(GtkTreeModel *model, GtkTreeIter *iter)
{
	static const GValue zero_value;
	GValue value = zero_value;

	gtk_tree_model_get_value(model, iter, 0, &value);
	return g_value_get_pointer(&value);
}

gpointer
search_gui_get_record(GtkTreeModel *model, GtkTreeIter *iter)
{
	return get_result_data(model, iter)->record;
}

void
search_gui_set_data(GtkTreeModel *model, struct result_data *rd)
{
	static const GValue zero_value;
	GValue value = zero_value;

	g_value_init(&value, G_TYPE_POINTER);
	g_value_set_pointer(&value, rd);
	gtk_tree_store_set_value(GTK_TREE_STORE(model), &rd->iter, 0, &value);
}

/**
 * Callback handler used with gtk_tree_model_foreach() to record the current
 * rank/position in tree enabling stable sorting. 
 */
gboolean
search_gui_update_rank(
	GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer udata)
{
	guint32 *rank_ptr = udata;
	struct result_data *data;

	(void) path;
	
	data = get_result_data(model, iter);
	data->rank = *rank_ptr;
	(*rank_ptr)++;
	return FALSE;
}

static void
cell_renderer(GtkTreeViewColumn *unused_column, GtkCellRenderer *cell, 
	GtkTreeModel *model, GtkTreeIter *iter, gpointer udata)
{
	const struct result_data *data;
	const gchar *text;
	guint id;

	(void) unused_column;
	
	id = GPOINTER_TO_UINT(udata);
	data = get_result_data(model, iter);
	switch (id) {
	case c_sr_filename:
		text = data->record->utf8_name;
		break;
	case c_sr_ext:
		text = data->ext;
		break;
	case c_sr_meta:
		text = data->meta;
		break;
	case c_sr_info:
		text = data->info ? data->info : data->record->info;
		break;
	case c_sr_size:
		text = compact_size(data->record->size, show_metric_units());
		break;
	case c_sr_count:
		text = data->count ? uint32_to_string(1 + data->count) : NULL;
		break;
	case c_sr_loc:
		text = iso3166_country_cc(data->record->results_set->country);
		break;
	case c_sr_charset:
		text = data->record->charset;
		break;
	case c_sr_route:
		text = search_gui_get_route(data->record);
		break;
	default:
		text = NULL;
	}
	g_object_set(cell,
		"text", text,
		"foreground-gdk", data->fg,
		"background-gdk", data->bg,
		(void *) 0);
}

static GtkCellRenderer *
create_cell_renderer(gfloat xalign)
{
	GtkCellRenderer *renderer;
	
	renderer = gtk_cell_renderer_text_new();
	gtk_cell_renderer_text_set_fixed_height_from_font(
		GTK_CELL_RENDERER_TEXT(renderer), 1);
	g_object_set(G_OBJECT(renderer),
		"mode",		GTK_CELL_RENDERER_MODE_INERT,
		"xalign",	xalign,
		"ypad",		(guint) GUI_CELL_RENDERER_YPAD,
		"foreground-set", TRUE,
		"background-set", TRUE,
		(void *) 0);

	return renderer;
}

static GtkTreeViewColumn *
add_column(
	GtkTreeView *tv,
	const gchar *name,
	gint id,
	gint width,
	gfloat xalign,
	GtkTreeCellDataFunc cell_data_func,
	gint fg_col,
	gint bg_col)
{
    GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;

	renderer = create_cell_renderer(xalign);
	if (cell_data_func) {
		column = gtk_tree_view_column_new_with_attributes(name, renderer,
					(void *) 0);
		gtk_tree_view_column_set_cell_data_func(column, renderer,
			cell_data_func, GUINT_TO_POINTER(id), NULL);
	} else {
		column = gtk_tree_view_column_new_with_attributes(name, renderer,
					"text", id, (void *) 0);
	}

	if (fg_col > 0)
		gtk_tree_view_column_add_attribute(column, renderer,
			"foreground-gdk", fg_col);
	if (bg_col > 0)
		gtk_tree_view_column_add_attribute(column, renderer,
			"background-gdk", bg_col);
			
	g_object_set(G_OBJECT(column),
		"fixed-width", MAX(1, width),
		"min-width", 1,
		"reorderable", FALSE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		(void *) 0);
	
    gtk_tree_view_append_column(tv, column);

	return column;
}

/**
 * Decrement refcount of hash table key entry.
 */
void
ht_unref_record(gpointer p)
{
	record_t *rc = p;

	g_assert(rc->refcount > 0);
	search_gui_unref_record(rc);
}


static inline void
add_parent_with_sha1(GHashTable *ht, gpointer key, struct result_data *data)
{
	g_hash_table_insert(ht, key, data);
}

static inline void
remove_parent_with_sha1(GHashTable *ht, const gchar *sha1)
{
	g_hash_table_remove(ht, sha1);
}

struct result_data *
find_parent_with_sha1(GHashTable *ht, gpointer key)
{
	return g_hash_table_lookup(ht, key);
}

static gboolean
unref_record(GtkTreeModel *model, GtkTreePath *unused_path, GtkTreeIter *iter,
	gpointer ht_ptr)
{
	GHashTable *dups = ht_ptr;
	struct result_data *rd;

	(void) unused_path;

	rd = get_result_data(model, iter);
	g_assert(rd->record->magic == RECORD_MAGIC);
	g_assert(rd->record->refcount > 0);
	g_assert(g_hash_table_lookup(dups, rd->record) != NULL);
	search_gui_unref_record(rd->record);

	g_assert(rd->record->refcount > 0);
	g_hash_table_remove(dups, rd->record);
	/*
	 * rd->record may point to freed memory now if this was the last reference
	 */

	atom_str_free_null(&rd->ext);
	atom_str_free_null(&rd->meta);
	G_FREE_NULL(rd->info);
	WFREE_NULL(rd, sizeof *rd);

	return FALSE;
}

static void
search_gui_clear_store(search_t *sch)
{
	GtkTreeModel *model;

	model = GTK_TREE_MODEL(sch->model);
	gtk_tree_model_foreach(model, unref_record, sch->dups);
	gtk_tree_store_clear(GTK_TREE_STORE(model));
	g_assert(0 == g_hash_table_size(sch->dups));
}

/**
 * Reset internal search model.
 * Called when a search is restarted, for example.
 */
void
search_gui_reset_search(search_t *sch)
{
	search_gui_clear_store(sch);
	search_gui_clear_search(sch);
	sch->dups = g_hash_table_new_full(search_gui_hash_func,
					search_gui_hash_key_compare, ht_unref_record, NULL);
	sch->parents = g_hash_table_new(sha1_hash, sha1_eq);
}

static gboolean
on_leave_notify(GtkWidget *widget, GdkEventCrossing *unused_event,
		gpointer unused_udata)
{
	(void) unused_event;
	(void) unused_udata;

	search_update_tooltip(GTK_TREE_VIEW(widget), NULL);
	return FALSE;
}

static gboolean
gui_search_update_tab_label_cb(gpointer p)
{
	struct search *sch = p;
	
	return gui_search_update_tab_label(sch);
}

/**
 * Clear all results from search.
 */
void
search_gui_clear_search(search_t *sch)
{
	g_assert(sch);
	g_assert(sch->dups);

	/*
	 * Before invoking search_free_r_sets(), we must iterate on the
	 * hash table where we store records and decrement the refcount of
	 * each record, and remove them from the hash table.
	 *
	 * Otherwise, we will violate the pre-condition of search_free_record(),
	 * which is there precisely for that reason!
	 */
/* XXX */
#if 0
	g_hash_table_foreach_remove(sch->dups, dec_records_refcount, NULL);
#endif /* 0 */
	search_gui_free_r_sets(sch);

	g_hash_table_destroy(sch->dups);
	sch->dups = NULL;
	g_hash_table_destroy(sch->parents);
	sch->parents = NULL;

	sch->items = sch->unseen_items = 0;
	guc_search_update_items(sch->search_handle, sch->items);
}

/**
 * Remove the search from the list of searches and free all
 * associated ressources (including filter and gui stuff).
 */
void
search_gui_close_search(search_t *sch)
{
    g_assert(sch != NULL);

    /*
     * We remove the search immeditaly from the list of searches,
     * because some of the following calls (may) depend on
     * "searches" holding only the remaining searches.
     * We may not free any ressources of "sch" yet, because
     * the same calls may still need them!.
     *      --BLUE 26/05/2002
     */

	if (tvm_search && sch == search_gui_get_current_search()) {
		tree_view_motion_clear_callback(GTK_TREE_VIEW(sch->tree_view),
			tvm_search);
		tvm_search = NULL;
	}
	search_gui_clear_store(sch);
 	searches = g_list_remove(searches, sch);
	search_gui_option_menu_searches_update();

    search_gui_remove_search(sch);
	filter_close_search(sch);
	search_gui_clear_search(sch);

    guc_search_close(sch->search_handle);
	atom_str_free(sch->query);

	G_FREE_NULL(sch);
}

/**
 * @returns TRUE if search was sucessfully created and FALSE if an error
 * happened. If the "search" argument is not NULL a pointer to the new
 * search is stored there.
 */
gboolean
search_gui_new_search_full(const gchar *query_str,
	time_t create_time, guint lifetime, guint32 reissue_timeout,
	gint sort_col, gint sort_order, flag_t flags, search_t **search)
{
	static const search_t zero_sch;
	const gchar *error_str;
	struct query *query;
	search_t *sch;
	gnet_search_t sch_id;
	GtkListStore *model;
	GtkTreeIter iter;
	gboolean is_only_search;
	
	query = search_gui_handle_query(query_str, flags, &error_str);
	if (query || !error_str) {
		gtk_entry_set_text(
			GTK_ENTRY(lookup_widget(main_window, "entry_search")), "");
	}
	if (!query) {
		if (error_str) {
			statusbar_gui_warning(5, "%s", error_str);
		}
		return FALSE;
	}
	g_assert(query);
	g_assert(query->text);
	
	sch_id = guc_search_new(query->text, create_time, lifetime,
				reissue_timeout, flags);
	if ((gnet_search_t) -1 == sch_id) {
		/*
		 * An invalidly encoded SHA1 is already detected by
		 * search_gui_query_parse(), so a too short query is the only reason
		 * this may fail at the moment.
		 */
		statusbar_gui_warning(5, "%s",
			_("The normalized search text is too short."));
		return FALSE;
	}

	sch = g_malloc(sizeof *sch);
	*sch = zero_sch;

	if (sort_col >= 0 && (guint) sort_col < SEARCH_RESULTS_VISIBLE_COLUMNS)
		sch->sort_col = sort_col;
	else
		sch->sort_col = -1;

	switch (sort_order) {
	case SORT_ASC:
	case SORT_DESC:
		sch->sort_order = sort_order;
		break;
	default:
		sch->sort_order = SORT_NONE;
	}
 
	sch->query = atom_str_get(query->text);
	sch->enabled = (flags & SEARCH_F_ENABLED) ? TRUE : FALSE;
	sch->browse = (flags & SEARCH_F_BROWSE) ? TRUE : FALSE;
	sch->local = (flags & SEARCH_F_LOCAL) ? TRUE : FALSE;
	sch->search_handle = sch_id;
	sch->passive = (flags & SEARCH_F_PASSIVE) ? TRUE : FALSE;
	sch->dups = g_hash_table_new_full(search_gui_hash_func,
					search_gui_hash_key_compare, ht_unref_record, NULL);

	sch->parents = g_hash_table_new(sha1_hash, sha1_eq);

	search_gui_filter_new(sch, query->rules);

	/* Create a new TreeView if needed, or use the default TreeView */

	if (searches) {
		/* We have to create a new TreeView for this search */
		gui_search_create_tree_view(&sch->scrolled_window,
			&sch->tree_view, sch);
		gtk_object_set_user_data(GTK_OBJECT(sch->scrolled_window), sch);
		gtk_notebook_append_page(GTK_NOTEBOOK(notebook_search_results),
			 sch->scrolled_window, NULL);
	} else {
		/* There are no searches currently, we can use the default TreeView */

		if (default_scrolled_window && default_search_tree_view) {
			sch->scrolled_window = default_scrolled_window;
			sch->tree_view = default_search_tree_view;

			default_search_tree_view = default_scrolled_window = NULL;
		} else
			g_warning("new_search():"
				" No current search but no default tree_view !?");

		gtk_object_set_user_data(GTK_OBJECT(sch->scrolled_window), sch);
	}
	sch->model = gtk_tree_view_get_model(GTK_TREE_VIEW(sch->tree_view));

	if (
		SORT_NONE != sch->sort_order &&
		sch->sort_col >= 0 &&
		(guint) sch->sort_col < SEARCH_RESULTS_VISIBLE_COLUMNS
	) {
		gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(sch->model),
			sch->sort_col, SORT_ASC == sch->sort_order
							? GTK_SORT_ASCENDING : GTK_SORT_DESCENDING);
	} else {
		gint id;
		
#if GTK_CHECK_VERSION(2,6,0)
		id = GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID;
#else
		id = c_sr_count;
#endif /* Gtk+ >= 2.6.0 */
		gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(sch->model),
			id, GTK_SORT_ASCENDING);
	}


	/* Add the search to the TreeView in pane on the left */
	model = GTK_LIST_STORE(gtk_tree_view_get_model(tree_view_search));
	gtk_list_store_append(model, &iter);
	gtk_list_store_set(model, &iter,
		c_sl_name, sch->query,
		c_sl_hit, 0,
		c_sl_new, 0,
		c_sl_sch, sch,
		c_sl_fg, NULL,
		c_sl_bg, NULL,
		(-1));

	gui_search_update_tab_label(sch);
	sch->tab_updating = gtk_timeout_add(TAB_UPDATE_TIME * 1000,
							gui_search_update_tab_label_cb, sch);

    if (!searches) {
		gtk_notebook_set_tab_label_text(
            GTK_NOTEBOOK(notebook_search_results),
            gtk_notebook_get_nth_page(
				GTK_NOTEBOOK(notebook_search_results), 0), _("(no search)"));
    }
	
	gtk_widget_set_sensitive(lookup_widget(main_window, "button_search_close"),
		TRUE);
	
	is_only_search = NULL == searches;
	searches = g_list_append(searches, sch);
	search_gui_option_menu_searches_update();

	if (search_gui_update_expiry(sch))
		sch->enabled = FALSE;

	if (sch->enabled)
		guc_search_start(sch->search_handle);

	/*
	 * Make new search the current search, unless it's a browse-host search:
	 * we need to initiate the download and only if everything is OK will
	 * we be able to move to the newly created search.
	 *
	 * If the browse host is the only search in the list, it must be made
	 * the current search though, since the code relies on one always being
	 * set when the list of searches is not empty.
	 */
	
	if (sch->browse && !is_only_search)
		gui_search_force_update_tab_label(sch, tm_time());
	else
		search_gui_set_current_search(sch);

	if (NULL != search)
		*search = sch;

	search_gui_query_free(&query);

	if (sch->local) {
		search_gui_init_dnd(GTK_TREE_VIEW(sch->tree_view));
	}
	return TRUE;
}

/**
 * Search results.
 */
static gint
search_gui_cmp_size(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer unused_udata)
{
	const struct result_data *d1, *d2;
	gint ret;
	
	(void) unused_udata;
	
	d1 = get_result_data(model, a);
	d2 = get_result_data(model, b);
	ret = CMP(d1->record->size, d2->record->size);
	return 0 != ret ? ret : CMP(d1->rank, d2->rank);
}

static gint
search_gui_cmp_count(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer unused_udata)
{
	const struct result_data *d1, *d2;
	gint ret;

	(void) unused_udata;

	d1 = get_result_data(model, a);
	d2 = get_result_data(model, b);
	ret = CMP(d1->count, d2->count);
	return 0 != ret ? ret : CMP(d1->rank, d2->rank);
}

static inline gint
search_gui_cmp_strings(const gchar *a, const gchar *b)
{
	if (a && b)
		return a == b ? 0 : strcmp(a, b);
	
	return a ? 1 : (b ? -1 : 0);
}

static gint
search_gui_cmp_filename(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer unused_udata)
{
	const struct result_data *d1, *d2;
	gint ret;

	(void) unused_udata;

	d1 = get_result_data(model, a);
	d2 = get_result_data(model, b);
	ret = search_gui_cmp_strings(d1->record->utf8_name, d2->record->utf8_name);
	return 0 != ret ? ret : CMP(d1->rank, d2->rank);
}

static gint
search_gui_cmp_charset(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer unused_udata)
{
	const struct result_data *d1, *d2;
	gint ret;

	(void) unused_udata;

	d1 = get_result_data(model, a);
	d2 = get_result_data(model, b);
	ret = search_gui_cmp_strings(d1->record->charset, d2->record->charset);
	return 0 != ret ? ret : CMP(d1->rank, d2->rank);
}


static gint
search_gui_cmp_ext(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer unused_udata)
{
	const struct result_data *d1, *d2;
	gint ret;

	(void) unused_udata;

	d1 = get_result_data(model, a);
	d2 = get_result_data(model, b);
	ret = search_gui_cmp_strings(d1->ext, d2->ext);
	return 0 != ret ? ret : CMP(d1->rank, d2->rank);
}

static gint
search_gui_cmp_meta(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer unused_udata)
{
	const struct result_data *d1, *d2;
	gint ret;

	(void) unused_udata;

	d1 = get_result_data(model, a);
	d2 = get_result_data(model, b);
	ret = search_gui_cmp_strings(d1->meta, d2->meta);
	return 0 != ret ? ret : CMP(d1->rank, d2->rank);
}


static gint
search_gui_cmp_country(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer unused_udata)
{
	const struct result_data *d1, *d2;
	gint ret;

	(void) unused_udata;

	d1 = get_result_data(model, a);
	d2 = get_result_data(model, b);

	ret = CMP(d1->record->results_set->country,
					d2->record->results_set->country);
	return 0 != ret ? ret : CMP(d1->rank, d2->rank);
}

static gint
search_gui_cmp_info(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer unused_udata)
{
	const struct result_data *d1, *d2;
	const gchar *s1, *s2;
	gint ret;

	(void) unused_udata;

	d1 = get_result_data(model, a);
	d2 = get_result_data(model, b);
	s1 = d1->info ? d1->info : d1->record->info;
	s2 = d2->info ? d2->info : d2->record->info;
	ret = search_gui_cmp_strings(s1, s2);
	return 0 != ret ? ret : CMP(d1->rank, d2->rank);
}

static gint
search_gui_cmp_route(
    GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer unused_udata)
{
	const struct result_data *d1, *d2;
	const struct results_set *rs1, *rs2;
	gint ret;

	(void) unused_udata;

	d1 = get_result_data(model, a);
	d2 = get_result_data(model, b);
	rs1 = d1->record->results_set;
	rs2 = d2->record->results_set;
	ret = host_addr_cmp(rs1->last_hop, rs2->last_hop);
	if (0 == ret) {
		ret = CMP((ST_UDP & rs1->status) , (ST_UDP & rs2->status));
		if (0 == ret) {
			ret = CMP(rs1->hops, rs2->hops);
			if (0 == ret)
				ret = CMP(rs1->ttl, rs2->ttl);
		}
	}

	return 0 != ret ? ret : CMP(d1->rank, d2->rank);
}

static gchar *
search_gui_get_info(const record_t *rc, const gchar *vinfo)
{
	size_t rw = 0;
  	gchar info[1024];

	info[0] = '\0';

	if (rc->tag) {
		size_t len = strlen(rc->tag);

		/*
		 * We want to limit the length of the tag shown, but we don't
		 * want to loose that information.	I imagine to have a popup
		 * "show file info" one day that will give out all the
		 * information.
		 *				--RAM, 09/09/2001
		 */

		len = MIN(len, MAX_TAG_SHOWN);
		len = MIN(len, sizeof info);
		rw = utf8_strlcpy(info,
				lazy_unknown_to_utf8_normalized(rc->tag, UNI_NORM_GUI, NULL),
				len);
	}
	if (vinfo) {
		g_assert(rw < sizeof info);
		rw += gm_snprintf(&info[rw], sizeof info - rw, "%s%s",
			info[0] != '\0' ? "; " : "", vinfo);
	}

	if (rc->alt_locs != NULL) {
		gint count = rc->alt_locs->hvcnt;
		g_assert(rw < sizeof info);
		rw += gm_snprintf(&info[rw], sizeof info - rw, "%salt",
			info[0] != '\0' ? ", " : "");
		if (count > 1)
			rw += gm_snprintf(&info[rw], sizeof info - rw, "(%d)", count);
	}

	return info[0] != '\0' ? g_strdup(info) : NULL;
}

void
search_gui_add_record(
	search_t *sch,
	record_t *rc,
	GString *vinfo,
	GdkColor *fg,
	GdkColor *bg)
{
	GtkTreeIter *parent_iter;
	static const struct result_data zero_data;
	struct result_data *data;

	data = walloc(sizeof *data);
	*data = zero_data;

	/*
	 * When the search is displayed in multiple search results, the refcount
	 * can also be larger than 1.
	 * FIXME: Check that the refcount is less then the number of search that we
	 * have open
	 *		-- JA, 6/11/2003
	 */

	g_assert(rc->magic == RECORD_MAGIC);
	g_assert(rc->refcount >= 1);

	data->record = rc;

	data->ext = search_gui_get_filename_extension(rc->utf8_name);
	if (data->ext)
		data->ext = atom_str_get(data->ext);

	if (rc->info) {
		data->info = NULL;
	} else {
		data->info = search_gui_get_info(rc, vinfo->len ? vinfo->str : NULL);
	}
	data->fg = fg;
	data->bg = bg;

	if (rc->sha1) {
		struct result_data *parent;

		parent = find_parent_with_sha1(sch->parents, rc->sha1);
		g_assert(data->record->refcount > 0);
		parent_iter = parent ? &parent->iter : NULL;
		if (parent) {
			parent->count++;
			/* Re-store the parent to refresh the display/sorting */
			search_gui_set_data(sch->model, parent);
		} else {
			add_parent_with_sha1(sch->parents, rc->sha1, data);
		}
	} else {
		parent_iter = NULL;
	}

	g_assert(rc->refcount >= 1);
	search_gui_ref_record(rc);
	g_assert(rc->refcount >= 2);

	gtk_tree_store_append(GTK_TREE_STORE(sch->model), &data->iter, parent_iter);
	search_gui_set_data(sch->model, data);

	/*
	 * There might be some metadata about this record already in the
	 * cache. If so lets update the GUI to reflect this.
	 */
	if (NULL != rc->sha1) {
		bitzi_data_t *bd = guc_query_cache_bitzi_by_sha1(rc->sha1);

		if (bd)
			search_gui_metadata_update(bd);
	}
}

const record_t *
search_gui_get_record_at_path(GtkTreeView *tv, GtkTreePath *path)
{
	const GList *l = search_gui_get_searches();
	const struct result_data *data;
	GtkTreeModel *model;
	GtkTreeIter iter;
	search_t *sch = NULL;

	for (/* NOTHING */; NULL != l; l = g_list_next(l)) {
		if (tv == GTK_TREE_VIEW(((search_t *) l->data)->tree_view)) {
			sch = l->data;
			break;
		}
	}
	g_return_val_if_fail(NULL != sch, NULL);

	model = GTK_TREE_MODEL(sch->model);
	if (!gtk_tree_model_get_iter(model, &iter, path))
		return NULL;
	data = get_result_data(model, &iter);

	return data->record;
}

void
search_gui_set_clear_button_sensitive(gboolean flag)
{
	gtk_widget_set_sensitive(GTK_WIDGET(button_search_clear), flag);
}

/* ----------------------------------------- */


gchar *
search_gui_get_magnet(GtkTreeModel *model, GtkTreeIter *iter)
{
	GtkTreeIter parent_iter;
	struct result_data *parent;
	struct magnet_resource *magnet;
	gchar *url;

	magnet = magnet_resource_new();

	if (gtk_tree_model_iter_parent(model, &parent_iter, iter)) {
		iter = &parent_iter;
	}
	parent = get_result_data(model, iter);

	magnet_set_display_name(magnet, parent->record->utf8_name);

	if (parent->record->sha1) {
		GtkTreeIter child;

		magnet_set_sha1(magnet, parent->record->sha1);
		magnet_set_filesize(magnet, parent->record->size);
		
		if (0 == (ST_FIREWALL & parent->record->results_set->status)) {
			magnet_add_sha1_source(magnet, parent->record->sha1,
				parent->record->results_set->addr,
				parent->record->results_set->port);
		}

		if (gtk_tree_model_iter_children(model, &child, &parent->iter)) {
			do {	
				struct result_data *data;

				data = get_result_data(model, &child);
				g_assert(data);

				if (0 != (ST_FIREWALL & data->record->results_set->status))
					continue;

				magnet_add_sha1_source(magnet, data->record->sha1,
					data->record->results_set->addr,
					data->record->results_set->port);
			} while (gtk_tree_model_iter_next(model, &child));
		}
	}

	url = magnet_to_string(magnet);
	magnet_resource_free(magnet);	
	return url;
}

static void
download_selected_file(GtkTreeModel *model, GtkTreeIter *iter, GSList **sl)
{
	struct result_data *rd;
	struct results_set *rs;
	struct record *rc;
	guint32 flags = 0;

	g_assert(model != NULL);
	g_assert(iter != NULL);

	if (sl) {
		*sl = g_slist_prepend(*sl, w_tree_iter_copy(iter));
	}

	rd = get_result_data(model, iter);
	rc = rd->record;
	g_assert(rc->refcount > 0);

	rs = rc->results_set;
	flags |= (rs->status & ST_FIREWALL) ? CONNECT_F_PUSH : 0;
	flags |= (rs->status & ST_TLS) ? CONNECT_F_TLS : 0;

	guc_download_new(rc->name, rc->size, rc->index, rs->addr,
		rs->port, rs->guid, rs->hostname, rc->sha1, rs->stamp,
		NULL, rs->proxies, flags);

	if (rs->proxies != NULL)
		search_gui_free_proxies(rs);

	if (rc->alt_locs != NULL)
		search_gui_check_alt_locs(rs, rc);

	g_assert(rc->refcount > 0);
}

static void
remove_selected_file(gpointer iter_ptr, gpointer model_ptr)
{
	GtkTreeModel *model = model_ptr;
	GtkTreeIter *iter = iter_ptr;
	GtkTreeIter child;
	struct result_data *rd;
	record_t *rc;
	search_t *search = search_gui_get_current_search();

	g_assert(search->items > 0);
	search->items--;

	rd = get_result_data(model, iter);
	rc = rd->record;

	/* First get the record, it must be unreferenced at the end */
	g_assert(rc->refcount > 1);

	if (gtk_tree_model_iter_nth_child(model, &child, iter, 0)) {
		struct result_data *child_data;

		/*
		 * Copy the contents of the first child's row into the parent's row
		 */

		child_data = get_result_data(model, &child);
		g_assert(child_data->record->refcount > 0);

		atom_str_free_null(&rd->ext);
		atom_str_free_null(&rd->meta);
		G_FREE_NULL(rd->info);
		
		rd->record = child_data->record;
		rd->ext = atom_str_get(child_data->ext);
		rd->meta = child_data->meta;
		rd->info = child_data->info;
		
		WFREE_NULL(child_data, sizeof *child_data);

		/* And remove the child's row */
		gtk_tree_store_remove(GTK_TREE_STORE(model), &child);
		
		rd->count--;
		/* Re-store the parent to refresh the display/sorting */
		search_gui_set_data(model, rd);

		g_assert(rd->record->refcount > 0);
	} else {
		
		g_assert(rc->refcount > 0);
		
		/*
		 * The row has no children, it's either a child or a top-level node
		 * without children.
		 */

		if (rc->sha1) {
			struct result_data *parent;
			
			parent = find_parent_with_sha1(search->parents, rc->sha1);
			if (rd == parent) {
				remove_parent_with_sha1(search->parents, rc->sha1);
			} else {
				/* Re-store the parent to refresh the display/sorting */
				parent->count--;
				search_gui_set_data(model, parent);
			}
		}
		gtk_tree_store_remove(GTK_TREE_STORE(model), iter);
	}

	search_gui_unref_record(rc);
	g_assert(rc->refcount > 0);
	g_hash_table_remove(search->dups, rc);
	/* hash table with dups unrefs the record itself */

	w_tree_iter_free(iter);
}

struct selection_ctx {
	GtkTreeView *tv;
	GSList **iters;
};

static void
download_selected_all_files(GtkTreeModel *model, GtkTreePath *path,
		GtkTreeIter *iter, gpointer data)
{
	struct selection_ctx *ctx = data;

	g_assert(ctx);
	g_assert(iter);

	download_selected_file(model, iter, ctx->iters);
    if (!gtk_tree_view_row_expanded(ctx->tv, path)) {
        GtkTreeIter child;
        gint i = 0;

        while (gtk_tree_model_iter_nth_child(model, &child, iter, i)) {
			download_selected_file(model, &child, ctx->iters);
            i++;
        }
	}
}

static void
collect_all_iters(GtkTreeModel *model, GtkTreePath *path,
		GtkTreeIter *iter, gpointer data)
{
	struct selection_ctx *ctx = data;

	g_assert(ctx != NULL);
	g_assert(ctx->iters != NULL);

	*ctx->iters = g_slist_prepend(*ctx->iters, w_tree_iter_copy(iter));
    if (
            gtk_tree_model_iter_has_child(model, iter) &&
            !gtk_tree_view_row_expanded(ctx->tv, path)
    ) {
        GtkTreeIter child;
        gint i = 0;

        while (gtk_tree_model_iter_nth_child(model, &child, iter, i)) {
			*ctx->iters = g_slist_prepend(*ctx->iters,
								w_tree_iter_copy(&child));
            i++;
        }
	}
}

struct menu_helper {
	gint page;
	GtkTreeIter iter;
};

static gboolean
search_gui_menu_select_helper(
	GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer data)
{
	struct menu_helper *mh = data;
	gpointer value;
	gint page;

	(void) path;
	gtk_tree_model_get(model, iter, 1, &value, (-1));
	page = GPOINTER_TO_INT(value);
	if (page == mh->page) {
		mh->iter = *iter;
		return TRUE;
	}
	return FALSE;
}

static void
search_gui_menu_select(gint page)
{
	GtkTreeView *treeview;
	GtkTreeModel *model;
	GtkTreeSelection *selection;
	struct menu_helper mh;

	mh.page = page;

	treeview = GTK_TREE_VIEW(
		lookup_widget(main_window, "treeview_menu"));
	model = GTK_TREE_MODEL(gtk_tree_view_get_model(treeview));
	gtk_tree_model_foreach(model, search_gui_menu_select_helper, &mh);
	selection = gtk_tree_view_get_selection(treeview);
	gtk_tree_selection_select_iter(selection, &mh.iter);
}

void
search_gui_download_files(void)
{
	search_t *search = search_gui_get_current_search();
	GSList *sl = NULL;
	struct selection_ctx ctx;
    gboolean clear;

	if (!search) {
		g_warning("search_download_files(): no possible search!");
		return;
	}

	/* XXX: This has to be GUI (not a core) property! */
    gnet_prop_get_boolean_val(PROP_SEARCH_REMOVE_DOWNLOADED, &clear);

	ctx.tv = GTK_TREE_VIEW(search->tree_view);
	ctx.iters = clear ? &sl : NULL;
	gtk_tree_selection_selected_foreach(gtk_tree_view_get_selection(ctx.tv),
		download_selected_all_files, &ctx);

	if (sl) {
		GtkTreeModel *model;

		model = gtk_tree_view_get_model(ctx.tv);
		g_slist_foreach(sl, remove_selected_file, model);
    	g_slist_free(sl);
	}

    gui_search_force_update_tab_label(search, tm_time());
    search_gui_update_items(search);
    guc_search_update_items(search->search_handle, search->items);
}


void
search_gui_discard_files(void)
{
	search_t *search = search_gui_get_current_search();
	GSList *sl = NULL;
	struct selection_ctx ctx;

	if (!search) {
		g_warning("search_download_files(): no possible search!");
		return;
	}

	ctx.tv = GTK_TREE_VIEW(search->tree_view);
	ctx.iters = &sl;
	gtk_tree_selection_selected_foreach(gtk_tree_view_get_selection(ctx.tv),
		collect_all_iters, &ctx);

	if (sl) {
		GtkTreeModel *model;

		model = gtk_tree_view_get_model(ctx.tv);
		g_slist_foreach(sl, remove_selected_file, model);
    	g_slist_free(sl);
	}

    gui_search_force_update_tab_label(search, tm_time());
    search_gui_update_items(search);
    guc_search_update_items(search->search_handle, search->items);
}

/***
 *** Private functions
 ***/

static void
add_list_columns(GtkTreeView *tv)
{
	static const struct {
		const gchar * const title;
		const gint id;
		const gfloat align;
	} columns[] = {
		{ N_("Search"), c_sl_name, 0.0 },
		{ N_("Hits"),	c_sl_hit,  1.0 },
		{ N_("New"),	c_sl_new,  1.0 }
	};
	guint32 width[G_N_ELEMENTS(columns)];
	guint i;

	STATIC_ASSERT(SEARCH_LIST_VISIBLE_COLUMNS == G_N_ELEMENTS(columns));

    gui_prop_get_guint32(PROP_SEARCH_LIST_COL_WIDTHS, width, 0,
		G_N_ELEMENTS(width));

	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		GtkTreeViewColumn *col;
		
		col = add_column(tv, _(columns[i].title), columns[i].id,
				width[i], columns[i].align, NULL, c_sl_fg, c_sl_bg);
		gtk_tree_view_column_set_sort_column_id(col, columns[i].id);
	}

	
}

static void
add_results_column(
	GtkTreeView *tv,
	const gchar *name,
	gint id,
	gint width,
	gfloat xalign,
	GtkTreeIterCompareFunc sortfunc,
	gpointer udata)
{
    GtkTreeViewColumn *column;
	GtkTreeModel *model;

	model = gtk_tree_view_get_model(tv);
	column = add_column(tv, name, id, width, xalign, cell_renderer, -1, -1);
   	gtk_tree_view_column_set_sort_column_id(column, id);
	gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(model), id,
		sortfunc, NULL, NULL);
	g_signal_connect(G_OBJECT(column), "clicked",
		G_CALLBACK(on_tree_view_search_results_click_column),
		udata);
}

static GtkTreeModel *
create_searches_model(void)
{
	static GType columns[c_sl_num];
	GtkListStore *store;
	guint i;

	STATIC_ASSERT(c_sl_num == G_N_ELEMENTS(columns));
#define SET(c, x) case (c): columns[i] = (x); break
	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		switch (i) {
		SET(c_sl_name, G_TYPE_STRING);
		SET(c_sl_hit, G_TYPE_INT);
		SET(c_sl_new, G_TYPE_INT);
		SET(c_sl_fg, GDK_TYPE_COLOR);
		SET(c_sl_bg, GDK_TYPE_COLOR);
		SET(c_sl_sch, G_TYPE_POINTER);
		default:
			g_assert_not_reached();
		}
	}
#undef SET

	store = gtk_list_store_newv(G_N_ELEMENTS(columns), columns);
	return GTK_TREE_MODEL(store);
}

static void
drag_begin(GtkWidget *widget, GdkDragContext *unused_drag_ctx, gpointer udata)
{
	GtkTreeView *tv;
	GtkTreePath *path;
	GtkTreeIter iter;
	GtkTreeModel *model;
	gchar **url_ptr = udata;

	(void) unused_drag_ctx;

	g_signal_stop_emission_by_name(G_OBJECT(widget), "drag-begin");

	g_assert(url_ptr != NULL);
	G_FREE_NULL(*url_ptr);

	tv = GTK_TREE_VIEW(widget);
	gtk_tree_view_get_cursor(tv, &path, NULL);
	if (!path)
		return;

	model = gtk_tree_view_get_model(tv);
	if (gtk_tree_model_get_iter(model, &iter, path)) {
		const struct result_data *data;
		const gchar *pathname;
		gchar *escaped;
		
		data = get_result_data(model, &iter);
		pathname = data->record->path;
		if (!pathname) {
			pathname = "(null)";
		}
		escaped = url_escape(pathname);
		*url_ptr = g_strconcat("file://", escaped, (void *) 0);
		if (escaped != pathname) {
			G_FREE_NULL(escaped);
		}
	}

	gtk_tree_path_free(path);
}

static void
drag_data_get(GtkWidget *widget, GdkDragContext *unused_drag_ctx,
	GtkSelectionData *data, guint unused_info, guint unused_stamp,
	gpointer udata)
{
	gchar **url_ptr = udata;

	(void) unused_drag_ctx;
	(void) unused_info;
	(void) unused_stamp;

	g_signal_stop_emission_by_name(G_OBJECT(widget), "drag-data-get");

	g_assert(url_ptr != NULL);
	if (NULL == *url_ptr)
		return;

	gtk_selection_data_set_text(data, *url_ptr, -1);
	G_FREE_NULL(*url_ptr);
}

static void
drag_end(GtkWidget *widget, GdkDragContext *unused_drag_ctx, gpointer udata)
{
	gchar **url_ptr = udata;

	(void) unused_drag_ctx;

	g_signal_stop_emission_by_name(G_OBJECT(widget), "drag-end");

	g_assert(url_ptr != NULL);
	G_FREE_NULL(*url_ptr);
}

static void
search_gui_init_dnd(GtkTreeView *tv)
{
    static const GtkTargetEntry targets[] = {
        { "STRING", 0, 23 },
        { "text/plain", 0, 23 },
    };
	static gchar *dnd_url; /* Holds the URL to set the drag data */

	g_return_if_fail(tv);

	/* Initialize drag support */
	gtk_drag_source_set(GTK_WIDGET(tv),
		GDK_BUTTON1_MASK | GDK_BUTTON2_MASK, targets, G_N_ELEMENTS(targets),
		GDK_ACTION_DEFAULT | GDK_ACTION_COPY | GDK_ACTION_ASK);

    g_signal_connect(G_OBJECT(tv), "drag-data-get",
        G_CALLBACK(drag_data_get), &dnd_url);
    g_signal_connect(G_OBJECT(tv), "drag-begin",
        G_CALLBACK(drag_begin), &dnd_url);
    g_signal_connect(G_OBJECT(tv), "drag-end",
        G_CALLBACK(drag_end), &dnd_url);
}

/***
 *** Public functions
 ***/

void
search_gui_init(void)
{
    GtkTreeView *tv;
	search_t *current_search;

    tree_view_search = GTK_TREE_VIEW(lookup_widget(main_window,
							"tree_view_search"));
    button_search_clear = GTK_BUTTON(lookup_widget(main_window,
							"button_search_clear"));
    notebook_search_results = GTK_NOTEBOOK(lookup_widget(main_window,
								"notebook_search_results"));
	gtk_notebook_popup_enable(notebook_search_results);

	search_gui_common_init();
	
	g_signal_connect(GTK_OBJECT(tree_view_search), "button_press_event",
		G_CALLBACK(on_tree_view_search_button_press_event), NULL);

	gtk_tree_view_set_model(tree_view_search, create_searches_model());
	add_list_columns(tree_view_search);
	g_signal_connect(G_OBJECT(tree_view_search), "cursor-changed",
		G_CALLBACK(on_tree_view_search_select_row), NULL);

	gui_search_create_tree_view(&default_scrolled_window,
		&default_search_tree_view, NULL);
    gtk_notebook_remove_page(notebook_search_results, 0);
	gtk_notebook_set_scrollable(notebook_search_results, TRUE);
	gtk_notebook_append_page(notebook_search_results,
		default_scrolled_window, NULL);
  	gtk_notebook_set_tab_label_text(notebook_search_results,
		default_scrolled_window, _("(no search)"));

	g_signal_connect(GTK_OBJECT(notebook_search_results), "switch_page",
		G_CALLBACK(on_search_notebook_switch), NULL);
	g_signal_connect(GTK_OBJECT(notebook_search_results), "focus_tab",
		G_CALLBACK(on_search_notebook_focus_tab), NULL);

   	current_search = search_gui_get_current_search();
    tv = current_search != NULL ?
			GTK_TREE_VIEW(current_search->tree_view) :
			GTK_TREE_VIEW(default_search_tree_view);
	tree_view_restore_visibility(tv, PROP_SEARCH_RESULTS_COL_VISIBLE);
	search_gui_retrieve_searches();
    search_add_got_results_listener(search_gui_got_results);
}

void
search_gui_shutdown(void)
{
	GtkTreeView *tv;
	search_t *current_search = search_gui_get_current_search();
	guint32 pos;

	search_gui_shutting_down = TRUE;
	search_callbacks_shutdown();
 	search_remove_got_results_listener(search_gui_got_results);
	search_gui_store_searches();

	pos = gtk_paned_get_position(
			GTK_PANED(lookup_widget(main_window, "vpaned_results")));

	gui_prop_set_guint32(PROP_RESULTS_DIVIDER_POS, &pos, 0, 1);

	tv = current_search != NULL
		? GTK_TREE_VIEW(current_search->tree_view)
		: GTK_TREE_VIEW(default_search_tree_view);

	tree_view_save_widths(tv, PROP_SEARCH_RESULTS_COL_WIDTHS);
	tree_view_save_visibility(tv, PROP_SEARCH_RESULTS_COL_VISIBLE);

    while (searches != NULL)
        search_gui_close_search(searches->data);

	tree_view_save_widths(tree_view_search, PROP_SEARCH_LIST_COL_WIDTHS);
	search_gui_common_shutdown();
}

const GList *
search_gui_get_searches(void)
{
	return (const GList *) searches;
}

static void
selection_counter_helper(
	GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer data)
{
	gint *counter = data;

	(void) model;
	(void) path;
	(void) iter;
	*counter += 1;
}

static gint
selection_counter(GtkTreeView *tv)
{
	gint rows = 0;

	if (tv) {
		gtk_tree_selection_selected_foreach(gtk_tree_view_get_selection(tv),
			selection_counter_helper, &rows);
	}

	return rows;
}

/**
 * Remove the search from the gui and update all widget accordingly.
 */
void
search_gui_remove_search(search_t *sch)
{
	GtkTreeModel *model;
    gboolean sensitive;

    g_assert(sch != NULL);

	model = gtk_tree_view_get_model(tree_view_search);

	{
		GtkTreeIter iter;

		if (tree_find_iter_by_data(model, c_sl_sch, sch, &iter))
    		gtk_list_store_remove(GTK_LIST_STORE(model), &iter);
	}

    gtk_timeout_remove(sch->tab_updating);

    if (searches) {				/* Some other searches remain. */
		gtk_notebook_remove_page(notebook_search_results,
			gtk_notebook_page_num(notebook_search_results,
				sch->scrolled_window));
	} else {
		/*
		 * Keep the GtkTreeView of this search, clear it and make it the
		 * default GtkTreeView
		 */

		default_search_tree_view = sch->tree_view;
		default_scrolled_window = sch->scrolled_window;

		search_gui_forget_current_search();
		search_gui_update_items(NULL);
		search_gui_update_expiry(NULL);

        gtk_notebook_set_tab_label_text(notebook_search_results,
			default_scrolled_window, _("(no search)"));

		gtk_widget_set_sensitive(GTK_WIDGET(button_search_clear), FALSE);
	}

    sensitive = searches != NULL;
	gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_search_close"), sensitive);

	{
		search_t *current_search;
		current_search = search_gui_get_current_search();

		if (current_search != NULL)
			sensitive = sensitive &&
				selection_counter(GTK_TREE_VIEW(current_search->tree_view)) > 0;
	}

    gtk_widget_set_sensitive(
		lookup_widget(popup_search, "popup_search_download"), sensitive);
}

void
search_gui_set_current_search(search_t *sch)
{
	search_t *old_sch = search_gui_get_current_search();
    GtkWidget *spinbutton_reissue_timeout;
    static gboolean locked = FALSE;
    gboolean active;
    gboolean frozen;
    guint32 reissue_timeout;
	search_t *current_search = old_sch;

	g_assert(sch != NULL);

    if (locked)
		return;
    locked = TRUE;

	if (old_sch)
		gui_search_force_update_tab_label(old_sch, tm_time());

    active = guc_search_is_active(sch->search_handle);
    frozen = guc_search_is_frozen(sch->search_handle);
    reissue_timeout = guc_search_get_reissue_timeout(sch->search_handle);

    /*
     * We now propagate the column visibility from the current_search
     * to the new current_search.
     */

    if (current_search != NULL) {
        GtkTreeView *tv_new = GTK_TREE_VIEW(sch->tree_view);
        GtkTreeView *tv_old = GTK_TREE_VIEW(current_search->tree_view);

		gtk_widget_hide(GTK_WIDGET(tv_old));
		g_object_freeze_notify(G_OBJECT(tv_old));
		gtk_widget_show(GTK_WIDGET(tv_new));
		g_object_thaw_notify(G_OBJECT(tv_new));
		if (tvm_search) {
			tree_view_motion_clear_callback(tv_old, tvm_search);
			tvm_search = NULL;
		}
		tree_view_save_widths(tv_old, PROP_SEARCH_RESULTS_COL_WIDTHS);
		tree_view_save_visibility(tv_old, PROP_SEARCH_RESULTS_COL_VISIBLE);
		tree_view_restore_visibility(tv_new, PROP_SEARCH_RESULTS_COL_VISIBLE);
    } else if (default_search_tree_view) {
		tree_view_save_widths(GTK_TREE_VIEW(default_search_tree_view),
			PROP_SEARCH_RESULTS_COL_WIDTHS);
	}


	search_gui_current_search(sch);
	sch->unseen_items = 0;

    spinbutton_reissue_timeout = lookup_widget(main_window,
									"spinbutton_search_reissue_timeout");

    if (sch != NULL) {
		GtkTreeModel *model;
		GtkTreeIter iter;
		
        gui_search_force_update_tab_label(sch, tm_time());
        search_gui_update_items(sch);

        gtk_spin_button_set_value
            (GTK_SPIN_BUTTON(spinbutton_reissue_timeout), reissue_timeout);
        gtk_widget_set_sensitive(spinbutton_reissue_timeout, active);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_download"),
			selection_counter(GTK_TREE_VIEW(sch->tree_view)) > 0);
        gtk_widget_set_sensitive(GTK_WIDGET(button_search_clear),
            sch->items != 0);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search_list, "popup_search_restart"),
		   	active);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search_list, "popup_search_duplicate"),
			active);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search_list, "popup_search_stop"), !frozen);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search_list, "popup_search_resume"), frozen);

		model = gtk_tree_view_get_model(tree_view_search);
		if (tree_find_iter_by_data(model, c_sl_sch, sch, &iter)) {
			GtkTreePath *path;
	
			path = gtk_tree_model_get_path(model, &iter);
			gtk_tree_view_set_cursor(tree_view_search, path, NULL, FALSE);
			gtk_tree_path_free(path);
		}
    } else {
		static const gchar * const popup_items[] = {
			"popup_search_restart",
			"popup_search_duplicate",
			"popup_search_stop",
			"popup_search_resume",
		};
		guint i;

        gtk_tree_selection_unselect_all(
			gtk_tree_view_get_selection(tree_view_search));
        gtk_widget_set_sensitive(spinbutton_reissue_timeout, FALSE);
       	gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_download"), FALSE);

		for (i = 0; i < G_N_ELEMENTS(popup_items); i++) {
       		gtk_widget_set_sensitive(
            	lookup_widget(popup_search_list, popup_items[i]), FALSE);
		}
    }

	tree_view_restore_widths(GTK_TREE_VIEW(sch->tree_view),
		PROP_SEARCH_RESULTS_COL_WIDTHS);

	tvm_search = tree_view_motion_set_callback(GTK_TREE_VIEW(sch->tree_view),
					search_update_tooltip, 400);

    /*
     * Search results notebook
     */
	gtk_notebook_set_current_page(notebook_search_results,
		gtk_notebook_page_num(notebook_search_results, sch->scrolled_window));

	search_gui_menu_select(nb_main_page_search);
	
	if (search_gui_update_expiry(sch))
		gui_search_set_enabled(sch, FALSE);

    locked = FALSE;
}

static GtkTreeModel *
create_results_model(void)
{
	GtkTreeStore *store;

	store = gtk_tree_store_new(1, G_TYPE_POINTER);
	return GTK_TREE_MODEL(store);
}

static void
add_results_columns(GtkTreeView *treeview, gpointer udata)
{
	static const struct {
		const gchar * const title;
		const gint id;
		const gfloat align;
		const GtkTreeIterCompareFunc func;
	} columns[] = {
		{ N_("File"),	   c_sr_filename, 0.0, search_gui_cmp_filename },
		{ N_("Extension"), c_sr_ext,	  0.0, search_gui_cmp_ext },
		{ N_("Encoding"),  c_sr_charset,  0.0, search_gui_cmp_charset },
		{ N_("Size"),	   c_sr_size,	  1.0, search_gui_cmp_size },
		{ N_("#"),		   c_sr_count,	  1.0, search_gui_cmp_count },
		{ N_("Loc"),	   c_sr_loc,	  0.0, search_gui_cmp_country },
		{ N_("Metadata"),  c_sr_meta,	  0.0, search_gui_cmp_meta },
		{ N_("Info"),	   c_sr_info,	  0.0, search_gui_cmp_info },
		{ N_("Route"),	   c_sr_route,	  0.0, search_gui_cmp_route }
	};
	guint32 width[G_N_ELEMENTS(columns)];
	guint i;

	STATIC_ASSERT(SEARCH_RESULTS_VISIBLE_COLUMNS == G_N_ELEMENTS(columns));

    gui_prop_get_guint32(PROP_SEARCH_RESULTS_COL_WIDTHS, width, 0,
		G_N_ELEMENTS(width));
	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		add_results_column(treeview, _(columns[i].title), columns[i].id,
			width[columns[i].id], columns[i].align, columns[i].func, udata);
	}
}

static gboolean
search_by_regex(GtkTreeModel *model, gint column, const gchar *key,
	GtkTreeIter *iter, gpointer unused_data)
{
	static const gboolean found = FALSE;
	static gchar *last_key;	/* This will be "leaked" on exit */
	static regex_t re;		/* The last regex will be "leaked" on exit */
	gint ret;

	g_return_val_if_fail(model, !found);
	g_return_val_if_fail(column >= 0, !found);
	g_return_val_if_fail((guint) column < SEARCH_RESULTS_VISIBLE_COLUMNS,
		!found);
	g_return_val_if_fail(key, !found);
	g_return_val_if_fail(iter, !found);
	(void) unused_data;

	if (!last_key || 0 != strcmp(last_key, key)) {
		if (last_key) {
			regfree(&re);
			G_FREE_NULL(last_key);
		}

		ret = regcomp(&re, key, REG_EXTENDED | REG_NOSUB | REG_ICASE);
		g_return_val_if_fail(0 == ret, !found);

		last_key = g_strdup(key);
	}

	{
		const struct result_data *rd;
		
		rd = get_result_data(model, iter);
		g_return_val_if_fail(NULL != rd, !found);
		g_return_val_if_fail(NULL != rd->record->utf8_name, !found);

		ret = regexec(&re, rd->record->utf8_name, 0, NULL, 0);
	}

	return 0 == ret ? found : !found;
}

static gboolean
tree_view_search_update(
	GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer data)
{
	search_t *sch;

	(void) path;
    gtk_tree_model_get(model, iter, c_sl_sch, &sch, (-1));
 	if (sch == data) {
   		GtkWidget *widget;
		GdkColor *fg;
		GdkColor *bg;

		widget = GTK_WIDGET(tree_view_search);
		if (sch->unseen_items > 0) {
#if 0
    		fg = &(gtk_widget_get_style(widget)->fg[GTK_STATE_PRELIGHT]);
    		bg = &(gtk_widget_get_style(widget)->bg[GTK_STATE_PRELIGHT]);
#endif
			fg = NULL;
			bg = NULL;
		} else if (!sch->enabled) {
    		fg = &(gtk_widget_get_style(widget)->fg[GTK_STATE_INSENSITIVE]);
    		bg = &(gtk_widget_get_style(widget)->bg[GTK_STATE_INSENSITIVE]);
		} else {
			fg = NULL;
			bg = NULL;
		}

		gtk_list_store_set(GTK_LIST_STORE(model), iter,
			c_sl_hit, sch->items,
			c_sl_new, sch->unseen_items,
			c_sl_fg, fg,
			c_sl_bg, bg,
			(-1));
		return TRUE;
	}

	return FALSE;
}

/**
 * Like search_update_tab_label but always update the label.
 */
void
gui_search_force_update_tab_label(search_t *sch, time_t now)
{
    search_t *search;
	GtkTreeModel *model;
	gchar buf[4096];

    search = search_gui_get_current_search();

	if (sch == search || sch->unseen_items == 0) {
		gm_snprintf(buf, sizeof buf, "%s\n(%d)", sch->query, sch->items);
	} else {
		gm_snprintf(buf, sizeof buf, "%s\n(%d, %d)", sch->query,
		   sch->items, sch->unseen_items);
	}
	sch->last_update_items = sch->items;
	gtk_notebook_set_tab_label_text(notebook_search_results,
		sch->scrolled_window, buf);
	model = gtk_tree_view_get_model(tree_view_search);
	gtk_tree_model_foreach(model, tree_view_search_update, sch);
	sch->last_update_time = now;

}

/**
 * Doesn't update the label if nothing's changed or if the last update was
 * recent.
 */
gboolean
gui_search_update_tab_label(struct search *sch)
{
	static time_t now;

	if (sch->items != sch->last_update_items) {
		now = tm_time();

		if (delta_time(now, sch->last_update_time) >= TAB_UPDATE_TIME)
			gui_search_force_update_tab_label(sch, now);
	}

	return TRUE;
}

void
gui_search_clear_results(void)
{
	search_t *search;

	search = search_gui_get_current_search();
	search_gui_reset_search(search);
	gui_search_force_update_tab_label(search, tm_time());
	search_gui_update_items(search);
}

/**
 * Extract the mark/ignore/download color.
 */
void
gui_search_get_colors(
	search_t *sch,
	GdkColor **mark_color, GdkColor **ignore_color, GdkColor **download_color)
{
    *mark_color = &(gtk_widget_get_style(GTK_WIDGET(sch->tree_view))
        ->bg[GTK_STATE_INSENSITIVE]);

    *ignore_color = &(gtk_widget_get_style(GTK_WIDGET(sch->tree_view))
        ->fg[GTK_STATE_INSENSITIVE]);

    *download_color =  &(gtk_widget_get_style(GTK_WIDGET(sch->tree_view))
        ->fg[GTK_STATE_ACTIVE]);
}

/**
 * Flag whether search is enabled.
 */
void
gui_search_set_enabled(struct search *sch, gboolean enabled)
{
	gboolean was_enabled = sch->enabled;

	if (was_enabled == enabled)
		return;

	sch->enabled = enabled;

	if (enabled)
		guc_search_start(sch->search_handle);
	else
		guc_search_stop(sch->search_handle);

	/* Marks this entry as active/inactive in the searches list. */
	gui_search_force_update_tab_label(sch, tm_time());
}


/**
 * Expand all nodes in tree for current search.
 */
void
search_gui_expand_all(void)
{
	search_t *current_search = search_gui_get_current_search();
	gtk_tree_view_expand_all(GTK_TREE_VIEW(current_search->tree_view));
}


/**
 * Collapse all nodes in tree for current search.
 */
void
search_gui_collapse_all(void)
{
	search_t *current_search = search_gui_get_current_search();
	gtk_tree_view_collapse_all(GTK_TREE_VIEW(current_search->tree_view));
}

void
search_gui_start_massive_update(search_t *sch)
{
	g_assert(sch);

	g_object_freeze_notify(G_OBJECT(sch->tree_view));
}

void
search_gui_end_massive_update(search_t *sch)
{
	g_assert(sch);

    gui_search_force_update_tab_label(sch, tm_time());
	g_object_thaw_notify(G_OBJECT(sch->tree_view));
}


void
search_gui_request_bitzi_data(void)
{
	guint32 bitzi_debug;
	search_t *search;
	GtkTreeSelection *selection;
	GSList *sl, *sl_records;

	/* collect the list of files selected */

	search = search_gui_get_current_search();
	g_assert(search != NULL);

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(search->tree_view));
	sl_records = tree_selection_collect_data(selection, search_gui_get_record,
					gui_record_sha1_eq);

    gnet_prop_get_guint32_val(PROP_BITZI_DEBUG, &bitzi_debug);
	if (bitzi_debug)
		g_message("on_search_meta_data: %d items", g_slist_length(sl_records));

	/* Make sure the column is actually visible. */
	{
		static const int min_width = 80;
		GtkTreeViewColumn *col;
		gint w;
		
		col = gtk_tree_view_get_column(GTK_TREE_VIEW(search->tree_view),
				c_sr_meta);
		g_assert(NULL != col);
		gtk_tree_view_column_set_visible(col, TRUE);
		w = gtk_tree_view_column_get_width(col);
		if (w < min_width)
			gtk_tree_view_column_set_fixed_width(col, min_width);
	}

	/* Queue up our requests */
	for (sl = sl_records; sl; sl = g_slist_next(sl)) {
		record_t *rec;

		rec = sl->data;
		if (rec->sha1) {
			struct result_data *rd;

			rd = find_parent_with_sha1(search->parents, rec->sha1);
			g_assert(rd);
			
			/* set the feedback */
			rd->meta = atom_str_get(_("Query queued..."));

			/* then send the query... */
	    	guc_query_bitzi_by_sha1(rec->sha1);
		}
    }

	g_slist_free(sl_records);
}

/**
 * Update the search displays with the correct meta-data.
 */
void
search_gui_metadata_update(const bitzi_data_t *data)
{
	GList *iter;
	gchar *text;

	text = bitzi_gui_get_metadata(data);

	/*
	 * Fill in the columns in each search that contains a reference
	 */

	for (iter = searches; iter != NULL; iter = g_list_next(iter)) {
		struct result_data *rd;
		search_t *search = iter->data;

	   	rd = find_parent_with_sha1(search->parents, data->sha1);
		if (rd) {
			rd->meta = atom_str_get(text ? text : _("Not in database"));
			text = NULL;
			
			/* Re-store the parent to refresh the display/sorting */
			search_gui_set_data(search->model, rd);
		}
	}

	G_FREE_NULL(text);
}

/**
 * Create a new GtkTreeView for search results.
 */
static void
gui_search_create_tree_view(GtkWidget ** sw, GtkWidget ** tv, gpointer udata)
{
	GtkTreeModel *model = create_results_model();
	GtkTreeSelection *selection;
	GtkTreeView	*treeview;

	*sw = gtk_scrolled_window_new(NULL, NULL);

	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(*sw),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);

	treeview = GTK_TREE_VIEW(gtk_tree_view_new_with_model(model));
	*tv = GTK_WIDGET(treeview);
	g_object_unref(model);

	selection = gtk_tree_view_get_selection(treeview);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_MULTIPLE);
	gtk_tree_view_set_headers_visible(treeview, TRUE);
	gtk_tree_view_set_headers_clickable(treeview, TRUE);
	gtk_tree_view_set_enable_search(treeview, TRUE);
	gtk_tree_view_set_search_column(treeview, 0);
	gtk_tree_view_set_rules_hint(treeview, TRUE);
	gtk_tree_view_set_search_equal_func(treeview, search_by_regex, NULL, NULL);

      /* add columns to the tree view */
	add_results_columns(treeview, udata);

	gtk_container_add(GTK_CONTAINER(*sw), *tv);

	if (!GTK_WIDGET_VISIBLE (*sw))
		gtk_widget_show_all(*sw);

	g_signal_connect(GTK_OBJECT(treeview), "cursor-changed",
		G_CALLBACK(on_tree_view_search_results_select_row), treeview);
	g_signal_connect(GTK_OBJECT(treeview), "button_press_event",
		G_CALLBACK(on_tree_view_search_results_button_press_event), NULL);
    g_signal_connect(GTK_OBJECT(treeview), "key_press_event",
		G_CALLBACK(on_tree_view_search_results_key_press_event), NULL);
    g_signal_connect(GTK_OBJECT(treeview), "leave-notify-event",
		G_CALLBACK(on_leave_notify), NULL);
	g_object_freeze_notify(G_OBJECT(treeview));
}
/* -*- mode: cc-mode; tab-width:4; -*- */
/* vi: set ts=4 sw=4 cindent: */
