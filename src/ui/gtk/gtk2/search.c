/*
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

#include "gtk/columns.h"
#include "gtk/drag.h"
#include "gtk/misc.h"
#include "gtk/search_common.h"
#include "gtk/settings.h"
#include "gtk/statusbar.h"

#include "column_sort.h"

#include "if/gui_property.h"
#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"
#include "if/core/sockets.h"

#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/halloc.h"
#include "lib/hset.h"
#include "lib/hstrfn.h"
#include "lib/htable.h"
#include "lib/iso3166.h"
#include "lib/mime_type.h"
#include "lib/misc.h"
#include "lib/stringify.h"
#include "lib/timestamp.h"
#include "lib/tm.h"
#include "lib/url.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

static GtkTreeView *tree_view_search;
static struct sorting_context search_list_sort;

/** For cyclic updates of the tooltip. */
static tree_view_motion_t *tvm_search;

struct result_data {
	GtkTreeIter iter;

	record_t *record;
	guint children;		/**< count of children */
	gnet_search_t sh;	/**< Search handle */
	enum gui_color color;
};

static inline struct result_data *
get_result_data(GtkTreeModel *model, GtkTreeIter *iter)
{
	static const GValue zero_value;
	GValue value = zero_value;
	struct result_data *rd;

	gtk_tree_model_get_value(model, iter, 0, &value);
	rd = g_value_get_pointer(&value);
	record_check(rd->record);
	g_assert(rd->record->refcount > 0);
	return rd;
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

/* Refresh the display/sorting */
static inline void
search_gui_data_changed(GtkTreeModel *model, struct result_data *rd)
{
#if 0
	/* THIS DOES NOT KEEP THE ROWS IN ORDER */
	tree_model_iter_changed(model, &rd->iter);
#else
	search_gui_set_data(model, rd);
#endif
}

struct synchronize_search_list {
	GtkTreeModel *model;
	GtkTreeIter iter;
};

static search_t *
synchronize_search_list_callback(void *user_data)
{
	struct synchronize_search_list *ctx = user_data;
	void *data;

	data = NULL;
   	gtk_tree_model_get(ctx->model, &ctx->iter, c_sl_sch, &data, (-1));
	g_assert(data);
	gtk_tree_model_iter_next(ctx->model, &ctx->iter);
	return data;
}

static void
search_gui_synchronize_list(GtkTreeModel *model)
{
	struct synchronize_search_list ctx;

	ctx.model = model;
	if (!gtk_tree_model_get_iter_first(model, &ctx.iter))
		return;
	search_gui_synchronize_search_list(synchronize_search_list_callback, &ctx);
}

static void
on_search_list_row_deleted(GtkTreeModel *model, GtkTreePath *unused_path,
	gpointer unused_udata)
{
	(void) unused_path;
	(void) unused_udata;

	search_gui_synchronize_list(model);
}

static void
on_search_list_column_clicked(GtkTreeViewColumn *column, gpointer unused_udata)
{
	(void) unused_udata;

	column_sort_tristate(column, &search_list_sort);

	search_gui_synchronize_list(gtk_tree_view_get_model(
		GTK_TREE_VIEW(column->tree_view)));
}

static void
cell_renderer(GtkTreeViewColumn *column, GtkCellRenderer *cell,
	GtkTreeModel *model, GtkTreeIter *iter, gpointer udata)
{
	const struct result_data *data;
    const struct results_set *rs;
	const gchar *text;
	enum c_sr_columns id;

	if (!gtk_tree_view_column_get_visible(column))
		return;

	text = NULL;	/* default to nothing */
	id = GPOINTER_TO_UINT(udata);
	data = get_result_data(model, iter);
    rs = data->record->results_set;

	switch (id) {
	case c_sr_filename:
		text = data->record->utf8_name;
		break;
	case c_sr_ext:
		text = data->record->ext;
		break;
	case c_sr_mime:
		text = mime_type_to_string(mime_type_from_extension(data->record->ext));
		break;
	case c_sr_vendor:
		if (!(ST_LOCAL & rs->status))
			text = vendor_code_get_name(rs->vendor);
		break;
	case c_sr_info:
		text = data->record->info;
		break;
	case c_sr_size:
		text = compact_size(data->record->size, show_metric_units());
		break;
	case c_sr_count:
		text = data->children ? uint32_to_string(1 + data->children) : NULL;
		break;
	case c_sr_loc:
		if (ISO3166_INVALID != rs->country)
			text = iso3166_country_cc(rs->country);
		break;
	case c_sr_charset:
		if (!(ST_LOCAL & rs->status))
			text = data->record->charset;
		break;
	case c_sr_route:
		text = search_gui_get_route(rs);
		break;
	case c_sr_protocol:
		if (!((ST_LOCAL | ST_BROWSE) & rs->status))
			text = ST_UDP & rs->status ?
				(ST_SR_UDP & rs->status ? N_("UDP (semi-reliable)") : "UDP")
				: "TCP";
		break;
	case c_sr_hops:
		if (!((ST_LOCAL | ST_BROWSE) & rs->status))
			text = uint32_to_string(rs->hops);
		break;
	case c_sr_ttl:
		if (!((ST_LOCAL | ST_BROWSE) & rs->status))
			text = uint32_to_string(rs->ttl);
		break;
	case c_sr_spam:
		if (SR_SPAM & data->record->flags) {
			text = "S";	/* Spam */
		} else if (ST_SPAM & rs->status) {
			text = "maybe";	/* maybe spam */
		}
		break;
	case c_sr_owned:
		if (SR_OWNED & data->record->flags) {
			text = _("owned");
		} else if (SR_PARTIAL & data->record->flags) {
			text = _("partial");
		} else if (SR_SHARED & data->record->flags) {
			text = _("shared");
		}
		break;
	case c_sr_hostile:
		if (ST_HOSTILE & rs->status) {
			text = "H";
		}
		break;
	case c_sr_sha1:
		if (data->record->sha1) {
			text = sha1_base32(data->record->sha1);
		}
		break;
	case c_sr_ctime:
		if ((time_t) -1 != data->record->create_time) {
			text = timestamp_to_string(data->record->create_time);
		}
		break;
	case c_sr_num:
		g_assert_not_reached();
		break;
	}
	g_object_set(cell,
		"text", text,
		"foreground-gdk", gui_color_get(data->color),
		"background-gdk", gui_color_get(GUI_COLOR_BACKGROUND),
		NULL_PTR);
}

static GtkCellRenderer *
create_cell_renderer(gfloat xalign)
{
	GtkCellRenderer *renderer;

	renderer = gtk_cell_renderer_text_new();
	gtk_cell_renderer_text_set_fixed_height_from_font(
		GTK_CELL_RENDERER_TEXT(renderer), TRUE);
	g_object_set(renderer,
		"mode",		GTK_CELL_RENDERER_MODE_INERT,
		"xalign",	xalign,
		"ypad",		(guint) GUI_CELL_RENDERER_YPAD,
		NULL_PTR);

	return renderer;
}

static GtkTreeViewColumn *
add_column(
	GtkTreeView *tv,
	const gchar *name,
	gint id,
	gfloat xalign,
	GtkTreeCellDataFunc cell_data_func,
	gint fg_col,
	gint bg_col)
{
    GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;

	renderer = create_cell_renderer(xalign);
	g_object_set(G_OBJECT(renderer),
		"foreground-set",	TRUE,
		"background-set",	TRUE,
		NULL_PTR);

	if (cell_data_func) {
		column =
			gtk_tree_view_column_new_with_attributes(name, renderer, NULL_PTR);
		gtk_tree_view_column_set_cell_data_func(column, renderer,
			cell_data_func, GUINT_TO_POINTER(id), NULL);
	} else {
		column = gtk_tree_view_column_new_with_attributes(name, renderer,
					"text", id, NULL_PTR);
	}

	if (fg_col >= 0)
		gtk_tree_view_column_add_attribute(column, renderer,
			"foreground-gdk", fg_col);
	if (bg_col >= 0)
		gtk_tree_view_column_add_attribute(column, renderer,
			"background-gdk", bg_col);

	g_object_set(column,
		"fixed-width", 100,
		"min-width", 1,
		"reorderable", FALSE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		NULL_PTR);

    gtk_tree_view_append_column(tv, column);
	gui_column_map(column, tv);		/* Capture resize events */

	return column;
}

static struct result_data *
find_parent(search_t *search, const struct result_data *rd)
{
	struct result_data *parent;

	/* NOTE: rd->record is not checked due to find_parent2() */
	parent = htable_lookup(search->parents, rd);
	if (parent) {
		record_check(parent->record);
	}
	return parent;
}

static struct result_data *
find_parent2(search_t *search, const struct sha1 *sha1, filesize_t filesize)
{
	struct result_data key;
	record_t rc;

	g_return_val_if_fail(sha1, NULL);

	rc.sha1 = sha1;
	rc.size = filesize;
	key.record = &rc;
  	return find_parent(search, &key);
}

static void
result_data_free(search_t *search, struct result_data *rd)
{
	record_check(rd->record);

	g_assert(hset_contains(search->dups, rd->record));
	hset_remove(search->dups, rd->record);
	search_gui_unref_record(rd->record);

	search_gui_unref_record(rd->record);
	/*
	 * rd->record may point to freed memory now if this was the last reference
	 */

	WFREE(rd);
}

static gboolean
prepare_remove_record(GtkTreeModel *model, GtkTreePath *unused_path,
	GtkTreeIter *iter, gpointer udata)
{
	struct result_data *rd;
	record_t *rc;
	search_t *search;

	(void) unused_path;

	search = udata;
	rd = get_result_data(model, iter);
	rc = rd->record;

	if (rc->sha1) {
		struct result_data *parent;

		parent = find_parent(search, rd);
		if (rd == parent) {
			htable_remove(search->parents, rd);
		} else if (parent) {
			parent->children--;
			search_gui_set_data(model, parent);
		}
	}
	result_data_free(search, rd);
	return FALSE;
}

static void
search_gui_clear_queue(search_t *search)
{
	struct result_data *rd;

	while (NULL != (rd = slist_shift(search->queue))) {
		result_data_free(search, rd);
	}
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

static void
search_gui_clear_tree(search_t *search)
{
	GtkTreeModel *model;
	bool stopped;

	stopped = search_gui_start_massive_update(search);

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(search->tree));
	gtk_tree_model_foreach(model, prepare_remove_record, search);
	gtk_tree_store_clear(GTK_TREE_STORE(model));

	if (stopped)
		search_gui_end_massive_update(search);
}

/**
 * Clear all results from search.
 */
void
search_gui_clear_search(search_t *search)
{
	g_assert(search);
	g_assert(search->dups);

	search_gui_clear_tree(search);
	search_gui_clear_queue(search);
	g_assert(0 == hset_count(search->dups));
	g_assert(0 == htable_count(search->parents));
}

static gboolean
search_gui_is_sorted(struct search *search)
{
	GtkTreeModel *model;
	GtkTreeSortable *sortable;

	g_return_val_if_fail(search, FALSE);

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(search->tree));
	sortable = GTK_TREE_SORTABLE(model);
	return gtk_tree_sortable_get_sort_column_id(sortable, NULL, NULL);
}

static void
search_gui_disable_sort(struct search *search)
{
	if (search && search->sort) {
#if GTK_CHECK_VERSION(2,6,0)
		GtkTreeModel *model;
		GtkTreeSortable *sortable;

		model = gtk_tree_view_get_model(GTK_TREE_VIEW(search->tree));
		sortable = GTK_TREE_SORTABLE(model);
		if (gtk_tree_sortable_get_sort_column_id(sortable, NULL, NULL)) {
			gtk_tree_sortable_set_sort_column_id(sortable,
				GTK_TREE_SORTABLE_UNSORTED_SORT_COLUMN_ID, GTK_SORT_DESCENDING);
		}
#endif /* Gtk+ >= 2.6.0 */
	}
}

static void
search_gui_enable_sort(struct search *search)
{
	g_return_if_fail(search);

	if (
		search->sort &&
		SORT_NONE != search->sorting.s_order &&
		UNSIGNED(search->sorting.s_column) < SEARCH_RESULTS_VISIBLE_COLUMNS
	) {
		GtkTreeModel *model;
		GtkSortType order;

		model = gtk_tree_view_get_model(GTK_TREE_VIEW(search->tree));
		order = SORT_ASC == search->sorting.s_order
					? GTK_SORT_ASCENDING
					: GTK_SORT_DESCENDING;
		gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(model),
			search->sorting.s_column, order);
	} else {
		search_gui_disable_sort(search);
	}
}

/**
 * Enforce a tri-state sorting.
 */
static void
on_tree_view_search_results_click_column(GtkTreeViewColumn *column,
	void *udata)
{
	struct search *search = udata;

	if (NULL == search)
		return;				/* The default treeview is empty */

	column_sort_tristate(column, &search->sorting);
}

char *
search_gui_get_local_file_url(GtkWidget *widget)
{
	const struct result_data *data;
	const char *pathname;
	GtkTreeModel *model;
   	GtkTreeIter iter;

	g_return_val_if_fail(widget, NULL);
	if (!drag_get_iter(GTK_TREE_VIEW(widget), &model, &iter))
		return NULL;

	data = get_result_data(model, &iter);
	if (!(ST_LOCAL & data->record->results_set->status))
		return NULL;

	pathname = data->record->tag;
	if (NULL == pathname)
		return NULL;

	return url_from_absolute_path(pathname);
}

guint
search_gui_file_hash(gconstpointer key)
{
	const struct result_data *rd = key;
	const record_t *rc = rd->record;
	guint hash;

	hash = rc->size;
	hash ^= rc->size >> 31;
	hash ^= rc->sha1 ? sha1_hash(rc->sha1) : 0;
	return hash;
}

gint
search_gui_file_eq(gconstpointer p, gconstpointer q)
{
	const struct result_data *rd_a = p, *rd_b = q;
	const record_t *a = rd_a->record, *b = rd_b->record;

	return a->sha1 == b->sha1 && a->size == b->size;
}

void
search_gui_init_tree(search_t *sch)
{
	GtkListStore *model;
	GtkTreeIter iter;

	g_assert(sch);

	g_assert(NULL == sch->parents);
	sch->parents = htable_create_any(search_gui_file_hash, NULL,
		search_gui_file_eq);

	g_assert(NULL == sch->queue);
	sch->queue = slist_new();

	/* Add the search to the TreeView in pane on the left */
	model = GTK_LIST_STORE(gtk_tree_view_get_model(tree_view_search));
	gtk_list_store_append(model, &iter);
	gtk_list_store_set(model, &iter,
		c_sl_name, search_gui_query(sch),
		c_sl_hit, 0,
		c_sl_new, 0,
		c_sl_sch, sch,
		c_sl_fg, NULL,
		c_sl_bg, NULL,
		(-1));
}

static inline int
search_gui_cmp_strings(const char *a, const char *b)
{
	if (a && b) {
		return a == b ? 0 :
			GUI_PROPERTY(search_sort_casesense) ? strcmp(a, b) :
			ascii_strcasecmp(a, b);
	} else {
		return a ? 1 : (b ? -1 : 0);
	}
}

#define SEARCH_GUI_CMP(a, b, c) CMP(((a)->c), ((b)->c))

static int
search_gui_cmp_size(const struct result_data *a, const struct result_data *b)
{
	return SEARCH_GUI_CMP(a, b, record->size);
}

static int
search_gui_cmp_count(const struct result_data *a, const struct result_data *b)
{
	return SEARCH_GUI_CMP(a, b, children);
}

static int
search_gui_cmp_filename(const struct result_data *a,
	const struct result_data *b)
{
	return search_gui_cmp_strings(a->record->utf8_name, b->record->utf8_name);
}

static int
search_gui_cmp_sha1(const struct result_data *a, const struct result_data *b)
{
	return search_gui_cmp_sha1s(a->record->sha1, b->record->sha1);
}

static int
search_gui_cmp_ctime(const struct result_data *a, const struct result_data *b)
{
	return delta_time(a->record->create_time, b->record->create_time);
}

static int
search_gui_cmp_charset(const struct result_data *a, const struct result_data *b)
{
	return search_gui_cmp_strings(a->record->charset, b->record->charset);
}

static int
search_gui_cmp_ext(const struct result_data *a, const struct result_data *b)
{
	return search_gui_cmp_strings(a->record->ext, b->record->ext);
}

static int
search_gui_cmp_mime(const struct result_data *a, const struct result_data *b)
{
	enum mime_type mt_a, mt_b;

	mt_a = mime_type_from_extension(a->record->ext);
	mt_b = mime_type_from_extension(b->record->ext);
	return CMP(mt_a, mt_b);
}

static int
search_gui_cmp_country(const struct result_data *a, const struct result_data *b)
{
	return SEARCH_GUI_CMP(a, b, record->results_set->country);
}

static int
search_gui_cmp_vendor(const struct result_data *a, const struct result_data *b)
{
	return SEARCH_GUI_CMP(a, b, record->results_set->vendor);
}

static int
search_gui_cmp_info(const struct result_data *a, const struct result_data *b)
{
	return search_gui_cmp_strings(a->record->info, b->record->info);
}

static int
search_gui_cmp_route(const struct result_data *a, const struct result_data *b)
{

	return host_addr_cmp(a->record->results_set->last_hop,
				b->record->results_set->last_hop);
}

static int
search_gui_cmp_hops(const struct result_data *a, const struct result_data *b)
{
	return SEARCH_GUI_CMP(a, b, record->results_set->hops);
}

static int
search_gui_cmp_ttl(const struct result_data *a, const struct result_data *b)
{
	return SEARCH_GUI_CMP(a, b, record->results_set->ttl);
}

static int
search_gui_cmp_protocol(const struct result_data *a,
	const struct result_data *b)
{
	return SEARCH_GUI_CMP(a, b, record->results_set->status & ST_UDP);
}

static int
search_gui_cmp_owned(const struct result_data *a, const struct result_data *b)
{
	const guint32 mask = SR_OWNED | SR_SHARED;
	return SEARCH_GUI_CMP(a, b, record->flags & mask);
}

static int
search_gui_cmp_hostile(const struct result_data *a, const struct result_data *b)
{
	return SEARCH_GUI_CMP(a, b, record->results_set->status & ST_HOSTILE);
}

static int
search_gui_cmp_spam(const struct result_data *a, const struct result_data *b)
{
	int ret = SEARCH_GUI_CMP(a, b, record->flags & SR_SPAM);
	return ret
		? ret
		: SEARCH_GUI_CMP(a, b, record->results_set->status & ST_SPAM);
}

#undef SEARCH_GUI_CMP

static int
search_gui_cmp(GtkTreeModel *model, GtkTreeIter *iter1, GtkTreeIter *iter2,
	void *user_data)
{
	const struct result_data *a, *b;
	enum c_sr_columns column;
	int ret = 0;

	column = GPOINTER_TO_UINT(user_data);
	a = get_result_data(model, iter1);
	b = get_result_data(model, iter2);
	switch (column) {
	case c_sr_filename: ret = search_gui_cmp_filename(a, b); break;
	case c_sr_ext:		ret = search_gui_cmp_ext(a, b); break;
	case c_sr_mime:		ret = search_gui_cmp_mime(a, b); break;
	case c_sr_vendor:	ret = search_gui_cmp_vendor(a, b); break;
	case c_sr_info:		ret = search_gui_cmp_info(a, b); break;
	case c_sr_size:		ret = search_gui_cmp_size(a, b); break;
	case c_sr_count:	ret = search_gui_cmp_count(a, b); break;
	case c_sr_loc:		ret = search_gui_cmp_country(a, b); break;
	case c_sr_charset:	ret = search_gui_cmp_charset(a, b); break;
	case c_sr_route:	ret = search_gui_cmp_route(a, b); break;
	case c_sr_protocol:	ret = search_gui_cmp_protocol(a, b); break;
	case c_sr_hops:		ret = search_gui_cmp_hops(a, b); break;
	case c_sr_ttl:		ret = search_gui_cmp_ttl(a, b); break;
	case c_sr_spam:		ret = search_gui_cmp_spam(a, b); break;
	case c_sr_owned:	ret = search_gui_cmp_owned(a, b); break;
	case c_sr_hostile:	ret = search_gui_cmp_hostile(a, b); break;
	case c_sr_sha1:		ret = search_gui_cmp_sha1(a, b); break;
	case c_sr_ctime:	ret = search_gui_cmp_ctime(a, b); break;
	case c_sr_num: 		g_assert_not_reached(); break;
	}
	/* Use address to stabilize sorting */
	return ret ? ret : CMP(pointer_to_ulong(a), pointer_to_ulong(b));
}

void
search_gui_add_record(search_t *sch, record_t *rc, enum gui_color color)
{
	static const struct result_data zero_data;
	struct result_data *data;

	record_check(rc);

	WALLOC(data);
	*data = zero_data;
	data->color = color;
	data->record = rc;
	data->sh = sch->search_handle;
	search_gui_ref_record(rc);

	slist_append(sch->queue, data);
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
		const search_t *s = l->data;
		if (tv == GTK_TREE_VIEW(s->tree)) {
			sch = l->data;
			break;
		}
	}
	g_return_val_if_fail(NULL != sch, NULL);

	model = GTK_TREE_MODEL(gtk_tree_view_get_model(tv));
	if (gtk_tree_model_get_iter(model, &iter, path)) {
		data = get_result_data(model, &iter);
		return data->record;
	} else {
		return NULL;
	}
}

static void
download_selected_file(GtkTreeModel *model, GtkTreeIter *iter, GSList **sl)
{
	struct result_data *rd;

	g_assert(model != NULL);
	g_assert(iter != NULL);

	if (sl) {
		*sl = g_slist_prepend(*sl, w_tree_iter_copy(iter));
	}

	rd = get_result_data(model, iter);
	search_gui_download(rd->record, rd->sh);

	if (SR_DOWNLOADED & rd->record->flags) {
		rd->color = GUI_COLOR_DOWNLOADING;
		search_gui_data_changed(model, rd);
	}
}

static void
remove_selected_file(void *iter_ptr, void *search_ptr)
{
	GtkTreeModel *model;
	GtkTreeIter *iter;
	GtkTreeIter child;
	struct result_data *rd;
	struct search *search;
	record_t *rc;

	search = search_ptr;
	iter = iter_ptr;
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(search->tree));

	g_assert(search->items > 0);
	search->items--;

	rd = get_result_data(model, iter);
	rc = rd->record;

	/* First get the record, it must be unreferenced at the end */
	g_assert(rc->refcount > 1);

	if (gtk_tree_model_iter_nth_child(model, &child, iter, 0)) {
		struct result_data *child_data, tmp;
		guint children;

		child_data = get_result_data(model, &child);

		/*
		 * Copy the contents of the first child's row into the parent's row
		 */

		children = rd->children;
		tmp = *rd;
		*rd = *child_data;
		*child_data = tmp;

		rd->iter = *iter;
		rd->children = children;

		/* And remove the child's row */
		iter = &child;
	} else {
		/*
		 * The row has no children, it's either a child or a top-level node
		 * without children.
		 */
	}
	prepare_remove_record(model, NULL, iter, search);
	gtk_tree_store_remove(GTK_TREE_STORE(model), iter);
	w_tree_iter_free(iter_ptr);
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

void
search_gui_download_files(struct search *search)
{
	GSList *sl = NULL;
	struct selection_ctx ctx;
    gboolean clear;

	g_return_if_fail(search);

	/* FIXME: This has to be GUI (not a core) property! */
    gnet_prop_get_boolean_val(PROP_SEARCH_REMOVE_DOWNLOADED, &clear);

	ctx.tv = GTK_TREE_VIEW(search->tree);
	ctx.iters = clear ? &sl : NULL;
	gtk_tree_selection_selected_foreach(gtk_tree_view_get_selection(ctx.tv),
		download_selected_all_files, &ctx);

	if (sl) {
		g_slist_foreach(sl, remove_selected_file, search);
    	g_slist_free(sl);
	}
}

void
search_gui_discard_files(struct search *search)
{
	GSList *sl = NULL;
	struct selection_ctx ctx;

	g_return_if_fail(search);

	ctx.tv = GTK_TREE_VIEW(search->tree);
	ctx.iters = &sl;
	gtk_tree_selection_selected_foreach(gtk_tree_view_get_selection(ctx.tv),
		collect_all_iters, &ctx);

	if (sl) {
		g_slist_foreach(sl, remove_selected_file, search);
    	g_slist_free(sl);
	}
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
	guint i;

	STATIC_ASSERT(SEARCH_LIST_VISIBLE_COLUMNS == N_ITEMS(columns));

	gui_parent_widths_saveto(tv, PROP_SEARCH_LIST_COL_WIDTHS);

	for (i = 0; i < N_ITEMS(columns); i++) {
		GtkTreeViewColumn *column;

		column = add_column(tv, _(columns[i].title), columns[i].id,
					columns[i].align, NULL, c_sl_fg, c_sl_bg);
		gtk_tree_view_column_set_sort_column_id(column, columns[i].id);

		column_sort_tristate_register(column,
			on_search_list_column_clicked, NULL);
	}
	tree_view_restore_widths(tv, PROP_SEARCH_LIST_COL_WIDTHS);
}

static void
add_results_column(GtkTreeView *tv, const gchar *name, gint id, gfloat xalign)
{
    GtkTreeViewColumn *column;

	column = add_column(tv, name, id, xalign, cell_renderer, -1, -1);
   	gtk_tree_view_column_set_sort_column_id(column, id);
}

static void
search_details_treeview_init(void)
{
	static const struct {
		const gchar *title;
		gfloat xalign;
		gboolean editable;
	} tab[] = {
		{ "Item",	1.0, FALSE },
		{ "Value",	0.0, TRUE },
	};
	GtkTreeView *tv;
	GtkTreeModel *model;
	guint i;

	tv = GTK_TREE_VIEW(gui_main_window_lookup("treeview_search_details"));
	g_return_if_fail(tv);

	model = GTK_TREE_MODEL(
				gtk_list_store_new(N_ITEMS(tab),
				G_TYPE_STRING, G_TYPE_STRING));

	gtk_tree_view_set_model(tv, model);
	g_object_unref(model);

	for (i = 0; i < N_ITEMS(tab); i++) {
    	GtkTreeViewColumn *column;
		GtkCellRenderer *renderer;

		renderer = create_cell_renderer(tab[i].xalign);
		g_object_set(G_OBJECT(renderer),
			"editable", tab[i].editable,
			NULL_PTR);
		column = gtk_tree_view_column_new_with_attributes(tab[i].title,
					renderer, "text", i, NULL_PTR);
		g_object_set(column,
			"min-width", 1,
			"resizable", TRUE,
			"sizing", (0 == i)
						? GTK_TREE_VIEW_COLUMN_AUTOSIZE
						: GTK_TREE_VIEW_COLUMN_FIXED,
			NULL_PTR);
    	gtk_tree_view_append_column(tv, column);
	}

	gui_signal_connect(tv,
		"key-press-event", on_search_details_key_press_event, NULL);
	drag_attach_text(GTK_WIDGET(tv), search_gui_details_get_text);
}

static GtkTreeModel *
create_searches_model(void)
{
	static GType columns[c_sl_num];
	GtkListStore *store;
	guint i;

	STATIC_ASSERT(c_sl_num == N_ITEMS(columns));
#define SET(c, x) case (c): columns[i] = (x); break
	for (i = 0; i < N_ITEMS(columns); i++) {
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

	store = gtk_list_store_newv(N_ITEMS(columns), columns);
	return GTK_TREE_MODEL(store);
}

static void
search_list_tree_view_init(void)
{
	GtkTreeView *tv;

    tv = GTK_TREE_VIEW(gui_main_window_lookup("tree_view_search"));
    tree_view_search = tv;

	gtk_tree_view_set_reorderable(tv, TRUE);
	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(tv),
		GTK_SELECTION_MULTIPLE);
	gtk_tree_view_set_model(tv, create_searches_model());
	add_list_columns(tv);

	widget_add_popup_menu(GTK_WIDGET(tv),
		search_gui_get_search_list_popup_menu);
	gui_signal_connect(tv,
		"button-release-event", on_search_list_button_release_event, NULL);
	gui_signal_connect(tv,
		"key-release-event", on_search_list_key_release_event, NULL);
	gui_signal_connect_after(gtk_tree_view_get_model(tv),
		"row-deleted", on_search_list_row_deleted, NULL);
}

/***
 *** Public functions
 ***/

void
search_gui_init(void)
{
	gtk_rc_parse_string(
		"style \"treeview\" { GtkTreeView::allow-rules = 0 }\n"
		"class \"GtkTreeView\" style \"treeview\"\n"
	);
	search_list_tree_view_init();
	search_details_treeview_init();
	search_gui_common_init();
}

void
search_gui_shutdown(void)
{
	search_gui_common_shutdown();
}

/**
 * Remove the search from the gui and update all widget accordingly.
 */
void
search_gui_remove_search(search_t *search)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	bool stopped;

	g_return_if_fail(search);

	stopped = search_gui_start_massive_update(search);

	if (search_gui_get_current_search() == search) {
		GtkTreeView *tv = GTK_TREE_VIEW(search->tree);

		tree_view_save_visibility(tv, PROP_SEARCH_RESULTS_COL_VISIBLE);
		tree_view_motion_clear_callback(&tvm_search);
	}
	g_assert(0 == slist_length(search->queue));
	slist_free(&search->queue);

	model = gtk_tree_view_get_model(tree_view_search);
	if (tree_find_iter_by_data(model, c_sl_sch, search, &iter)) {
   		gtk_list_store_remove(GTK_LIST_STORE(model), &iter);
	}

	if (stopped)
		search_gui_end_massive_update(search);
}

void
search_gui_hide_search(struct search *search)
{
	GtkTreeView *tv;

	g_return_if_fail(search);

	tv = GTK_TREE_VIEW(search->tree);
	tree_view_save_visibility(tv, PROP_SEARCH_RESULTS_COL_VISIBLE);
	tree_view_motion_clear_callback(&tvm_search);
}

void
search_gui_show_search(struct search *search)
{
	GtkTreeView *tv;

	g_return_if_fail(search);

	tv = GTK_TREE_VIEW(search->tree);
	tree_view_restore_visibility(tv, PROP_SEARCH_RESULTS_COL_VISIBLE);
	tree_view_restore_widths(tv, PROP_SEARCH_RESULTS_COL_WIDTHS);
	tvm_search = tree_view_motion_set_callback(tv,
			search_update_tooltip, 400);

	if (!search->sort) {
		int i;

		/*
		 * The signal handler for "clicked" must only be installed once,
		 * not each time the treeview is made visible.
		 */
		search->sort = TRUE;
		for (i = 0; i < c_sr_num; i++) {
			GtkTreeViewColumn *column;

			column = gtk_tree_view_get_column(tv, i);
			gtk_tree_view_column_set_sort_column_id(column, i);
			gtk_tree_sortable_set_sort_func(
				GTK_TREE_SORTABLE(gtk_tree_view_get_model(tv)), i,
				search_gui_cmp, uint_to_pointer(i), NULL);

			column_sort_tristate_register(column,
				on_tree_view_search_results_click_column, search);
		}
	}
}

static GtkTreeModel *
create_results_model(void)
{
	GtkTreeStore *store;

	store = gtk_tree_store_new(1, G_TYPE_POINTER);
	return GTK_TREE_MODEL(store);
}

static void
add_results_columns(GtkTreeView *tv)
{
	guint i;

	for (i = 0; i < c_sr_num; i++) {
		add_results_column(tv, search_gui_column_title(i), i,
			search_gui_column_justify_right(i) ? 1.0 : 0.0);
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
			HFREE_NULL(last_key);
		}

		ret = regcomp(&re, key, REG_EXTENDED | REG_NOSUB | REG_ICASE);
		g_return_val_if_fail(0 == ret, !found);

		last_key = h_strdup(key);
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

void
search_gui_update_list_label(const struct search *search)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkTreeView *tv;
	GtkStyle *style;
	GdkColor *fg, *bg;
	bool downloading;

	if (NULL == search)
		return;

	tv = GTK_TREE_VIEW(tree_view_search);
	model = gtk_tree_view_get_model(tv);
	if (!tree_find_iter_by_data(model, c_sl_sch, search, &iter))
		return;

	style = gtk_widget_get_style(GTK_WIDGET(tv));
	downloading = 0 != search_gui_download_count(search);

	if (search_gui_is_enabled(search)) {
		if (search->unseen_items > 0) {
			fg = downloading ? gui_color_get(GUI_COLOR_DOWNLOADING) :
					&style->fg[GTK_STATE_ACTIVE];
			bg = &style->bg[GTK_STATE_ACTIVE];
		} else {
			fg = downloading ? gui_color_get(GUI_COLOR_DOWNLOADING) : NULL;
			bg = NULL;
		}
	} else {
		fg = downloading ? gui_color_get(GUI_COLOR_DOWNLOADING) :
				&style->fg[GTK_STATE_INSENSITIVE];
		bg = &style->bg[GTK_STATE_INSENSITIVE];
	}

	gtk_list_store_set(GTK_LIST_STORE(model), &iter,
			c_sl_hit, search->items,
			c_sl_new, search->unseen_items,
			c_sl_fg, fg,
			c_sl_bg, bg,
			(-1));
}

/**
 * Expand all nodes in tree for current search.
 */
void
search_gui_expand_all(struct search *search)
{
	if (search) {
		gtk_tree_view_expand_all(GTK_TREE_VIEW(search->tree));
	}
}

/**
 * Collapse all nodes in tree for current search.
 */
void
search_gui_collapse_all(struct search *search)
{
	if (search) {
		gtk_tree_view_collapse_all(GTK_TREE_VIEW(search->tree));
	}
}

bool
search_gui_start_massive_update(struct search *search)
{
	GtkTreeModel *model;

	g_return_val_if_fail(search, FALSE);

	if (search->frozen)
		return FALSE;

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(search->tree));
	g_object_freeze_notify(G_OBJECT(search->tree));
	g_object_freeze_notify(G_OBJECT(model));
	search_gui_disable_sort(search);
	search->frozen = TRUE;

	return TRUE;
}

void
search_gui_end_massive_update(struct search *search)
{
	GtkTreeModel *model;

	g_return_if_fail(search);
	g_return_if_fail(search->frozen);

	search->frozen = FALSE;
	model = gtk_tree_view_get_model(GTK_TREE_VIEW(search->tree));
	g_object_thaw_notify(G_OBJECT(model));
	g_object_thaw_notify(G_OBJECT(search->tree));
	search_gui_enable_sort(search);
}

/**
 * Create a new GtkTreeView for search results.
 */
GtkWidget *
search_gui_create_tree(void)
{
	GtkTreeModel *model = create_results_model();
	GtkTreeSelection *selection;
	GtkTreeView	*tv;

	tv = GTK_TREE_VIEW(gtk_tree_view_new_with_model(model));
	g_object_unref(model);

	selection = gtk_tree_view_get_selection(tv);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_MULTIPLE);
	gtk_tree_view_set_headers_clickable(tv, TRUE);
	gtk_tree_view_set_headers_visible(tv, TRUE);
	gtk_tree_view_set_enable_search(tv, TRUE);
	gtk_tree_view_set_search_column(tv, 0);
	gtk_tree_view_set_rules_hint(tv, TRUE);
	gtk_tree_view_set_search_equal_func(tv, search_by_regex, NULL, NULL);
	tree_view_set_fixed_height_mode(tv, TRUE);

	gui_parent_widths_saveto(tv, PROP_SEARCH_RESULTS_COL_WIDTHS);

      /* add columns to the tree view */
	add_results_columns(tv);

	tree_view_restore_visibility(tv, PROP_SEARCH_RESULTS_COL_VISIBLE);
	tree_view_restore_widths(tv, PROP_SEARCH_RESULTS_COL_WIDTHS);

	gui_signal_connect(tv,
		"cursor-changed", on_tree_view_search_results_select_row, tv);
    gui_signal_connect(tv, "leave-notify-event", on_leave_notify, NULL);

	return GTK_WIDGET(tv);
}

static void
search_gui_get_selected_searches_helper(GtkTreeModel *model,
	GtkTreePath *unused_path, GtkTreeIter *iter, gpointer data)
{
	gpointer p = NULL;

	(void) unused_path;
	g_assert(data);

	gtk_tree_model_get(model, iter, c_sl_sch, &p, (-1));
	if (p) {
		GSList **sl_ptr = data;
		*sl_ptr = g_slist_prepend(*sl_ptr, p);
	}
}

GSList *
search_gui_get_selected_searches(void)
{
	GSList *sl = NULL;
	GtkTreeView *tv;

    tv = GTK_TREE_VIEW(gui_main_window_lookup("tree_view_search"));
	gtk_tree_selection_selected_foreach(gtk_tree_view_get_selection(tv),
		search_gui_get_selected_searches_helper, &sl);
	return sl;
}

gboolean
search_gui_has_selected_item(search_t *search)
{
	GtkTreePath *path = NULL;
	gboolean ret = FALSE;

	g_return_val_if_fail(search, FALSE);

	gtk_tree_view_get_cursor(GTK_TREE_VIEW(search->tree), &path, NULL);
	if (path) {
		ret = TRUE;
		gtk_tree_path_free(path);
	}
	return ret;
}

void
search_gui_search_list_clicked(void)
{
	GtkTreeView *tv = GTK_TREE_VIEW(tree_view_search);
	GtkTreePath *path = NULL;

	gtk_tree_view_get_cursor(tv, &path, NULL);
	if (path) {
		GtkTreeModel *model;
		GtkTreeIter iter;

		model = gtk_tree_view_get_model(tv);
		if (gtk_tree_model_get_iter(model, &iter, path)) {
			gpointer p = NULL;
			gtk_tree_model_get(model, &iter, c_sl_sch, &p, (-1));
			if (p) {
				search_t *search = p;
				search_gui_set_current_search(search);
			}
		}
		gtk_tree_path_free(path);
	}
}

record_t *
search_gui_record_get_parent(search_t *search, record_t *record)
{
	struct result_data *parent;

	g_return_val_if_fail(search, NULL);
	g_return_val_if_fail(record, NULL);
	record_check(record);

	parent = find_parent2(search, record->sha1, record->size);
	return parent ? parent->record : NULL;
}

GSList *
search_gui_record_get_children(search_t *search, record_t *record)
{
	struct result_data *parent;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GSList *children;

	g_return_val_if_fail(search, NULL);
	g_return_val_if_fail(record, NULL);
	record_check(record);

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(search->tree));
	g_return_val_if_fail(model, NULL);

	children = NULL;
	parent = find_parent2(search, record->sha1, record->size);

	if (
		parent->record == record &&
		gtk_tree_model_iter_children(model, &iter, &parent->iter)
	) {
		do {
			children = g_slist_prepend(children,
							search_gui_get_record(model, &iter));
		} while (gtk_tree_model_iter_next(model, &iter));
	}
	return g_slist_reverse(children);
}

static void
search_gui_flush_queue_data(search_t *search, GtkTreeModel *model,
	struct result_data *rd)
{
	GtkTreeIter *parent_iter;
	record_t *rc;

	rc = rd->record;
	record_check(rc);

	if (rc->sha1) {
		struct result_data *parent;

		parent = find_parent(search, rd);
		parent_iter = parent ? &parent->iter : NULL;
		if (parent) {
			record_check(parent->record);
			parent->children++;
			search_gui_data_changed(model, parent);
		} else {
			htable_insert(search->parents, rd, rd);
		}
	} else {
		parent_iter = NULL;
	}

	gtk_tree_store_append(GTK_TREE_STORE(model), &rd->iter, parent_iter);
	search_gui_set_data(model, rd);
}

static void
search_gui_flush_queue(search_t *search)
{
	g_return_if_fail(search);
	g_return_if_fail(search->tree);

	if (slist_length(search->queue) > 0) {
		GtkTreeModel *model;
		guint max_items;
		struct result_data *data;
		bool stopped;

		stopped = search_gui_start_massive_update(search);

		model = gtk_tree_view_get_model(GTK_TREE_VIEW(search->tree));
		max_items = search_gui_is_sorted(search) ? 100 : 500;

		while (max_items-- > 0 && NULL != (data = slist_shift(search->queue))) {
			search_gui_flush_queue_data(search, model, data);
		}

		if (stopped)
			search_gui_end_massive_update(search);
	}
}

void
search_gui_flush_queues(void)
{
	const GList *iter;

	iter = search_gui_get_searches();
	for (/* NOTHING*/; NULL != iter; iter = g_list_next(iter)) {
		search_gui_flush_queue(iter->data);
	}
}

unsigned
search_gui_queue_length(const struct search *search)
{
	g_return_val_if_fail(search, 0);
	g_return_val_if_fail(search->queue, 0);

	return slist_length(search->queue);
}

/* -*- mode: cc-mode; tab-width:4; -*- */
/* vi: set ts=4 sw=4 cindent: */
