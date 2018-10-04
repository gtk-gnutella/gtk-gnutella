/*
 * Copyright (c) 2001-2003, Richard Eckart
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
 * Management of the GTK2 "Uploads" pane.
 *
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "gtk/gui.h"

#include "gtk/uploads.h"
#include "gtk/uploads_common.h"
#include "gtk/columns.h"
#include "gtk/misc.h"
#include "gtk/settings.h"

#include "column_sort.h"

#include "if/gui_property.h"
#include "if/bridge/ui2c.h"

#include "lib/atoms.h"
#include "lib/cstr.h"
#include "lib/host_addr.h"
#include "lib/htable.h"
#include "lib/iso3166.h"
#include "lib/misc.h"
#include "lib/str.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

static gboolean uploads_remove_lock;
static gboolean uploads_shutting_down;

static GtkTreeView *treeview_uploads;
static GtkListStore *store_uploads;
static GtkWidget *button_uploads_clear_completed;

/** hash table for fast handle -> GtkTreeIter mapping */
static htable_t *upload_handles;
/** list of all *removed* uploads; contains the handles */
static GSList *sl_removed_uploads;

#if GTK_CHECK_VERSION(2,6,0)
static struct sorting_context uploads_sort;
#endif	/* GTK+ >= 2.6.0 */

static void uploads_gui_update_upload_info(const gnet_upload_info_t *u);
static void uploads_gui_add_upload(gnet_upload_info_t *u);

static const char * const column_titles[UPLOADS_GUI_VISIBLE_COLUMNS] = {
	N_("Filename"),
	N_("Host"),
	N_("Country"),
	N_("Size"),
	N_("Range"),
	N_("User-Agent"),
	N_("Progress"),
	N_("Status")
};

typedef struct remove_row_ctx {
	gboolean force;			/**< If false, rows will only be removed, if
							 **  their `entry_removal_timeout' has expired. */
	time_t now; 			/**< Current time, used to decide whether row
							 **  should be finally removed. */
	GSList *sl_remaining;	/**< Contains row data for not yet removed rows. */
} remove_row_ctx_t;


/**
 * Tries to fetch upload_row_data associated with the given upload handle.
 *
 * @return a pointer the upload_row_data.
 */
static inline upload_row_data_t *
find_upload(gnet_upload_t u)
{
	upload_row_data_t *rd;
	void *key;
	bool found;

	found = htable_lookup_extended(upload_handles, uint_to_pointer(u),
				NULL, &key);
	g_assert(found);
	rd = key;

	g_assert(NULL != rd);
	g_assert(rd->valid);
	g_assert(rd->handle == u);

	return rd;
}

/***
 *** Callbacks
 ***/

static gboolean
on_button_press_event(GtkWidget *unused_widget, GdkEventButton *event,
		gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;

	if (3 == event->button) {
        /* Right click section (popup menu) */
		gtk_menu_popup(GTK_MENU(gui_popup_uploads()), NULL, NULL, NULL, NULL,
			event->button, event->time);
		return TRUE;
    }

	return FALSE;
}

/**
 * Callback: called when an upload is removed from the backend.
 *
 * Either immediately clears the upload from the frontend or just
 * set the upload_row_info->valid to FALSE, so we don't accidentally
 * try to use the handle to communicate with the backend.
 */
static void
upload_removed(gnet_upload_t uh, const gchar *reason)
{
    upload_row_data_t *rd;

    /* Invalidate row and remove it from the GUI if autoclear is on */
	rd = find_upload(uh);
	g_assert(NULL != rd);
	rd->valid = FALSE;
	gtk_widget_set_sensitive(button_uploads_clear_completed, TRUE);
	if (reason != NULL)
		gtk_list_store_set(store_uploads, &rd->iter, c_ul_status, reason, (-1));
	sl_removed_uploads = g_slist_prepend(sl_removed_uploads, rd);
	htable_remove(upload_handles, uint_to_pointer(uh));
	/* NB: rd MUST NOT be freed yet because it contains the GtkTreeIter! */
}



/**
 * Callback: called when an upload is added from the backend.
 *
 * Adds the upload to the gui.
 */
static void
upload_added(gnet_upload_t n)
{
    gnet_upload_info_t *info;

    info = guc_upload_get_info(n);
    uploads_gui_add_upload(info);
    guc_upload_free_info(info);
}

/**
 * Fetch the GUI row data associated with upload handle.
 */
upload_row_data_t *
uploads_gui_get_row_data(gnet_upload_t uhandle)
{
	return find_upload(uhandle);
}

/**
 * Callback: called when upload information was changed by the backend.
 * This updates the upload information in the gui.
 */
static void
upload_info_changed(gnet_upload_t u)
{
    gnet_upload_info_t *info;

    info = guc_upload_get_info(u);
    uploads_gui_update_upload_info(info);
    guc_upload_free_info(info);
}

#define COMPARE_FUNC(field) \
static gint CAT2(compare_,field)( \
	GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer user_data) \
{ \
	const upload_row_data_t *rd_a = NULL; \
	const upload_row_data_t *rd_b = NULL; \
	(void) user_data; \
	gtk_tree_model_get(model, a, c_ul_data, &rd_a, (-1)); \
	gtk_tree_model_get(model, b, c_ul_data, &rd_b, (-1)); \
	{

#define COMPARE_FUNC_END } }

COMPARE_FUNC(hosts)
	return host_addr_cmp(rd_a->addr, rd_b->addr);
COMPARE_FUNC_END

COMPARE_FUNC(sizes)
	return CMP(rd_b->size, rd_a->size);
COMPARE_FUNC_END

COMPARE_FUNC(ranges)
	filesize_t u = rd_a->range_end - rd_a->range_start;
	filesize_t v = rd_b->range_end - rd_b->range_start;
	gint s = CMP(v, u);
	return 0 != s ? s : CMP(rd_a->range_start, rd_b->range_start);
COMPARE_FUNC_END

/***
 *** Private functions
 ***/

static void
uploads_gui_update_upload_info(const gnet_upload_info_t *u)
{
	GdkColor *color = NULL;
    upload_row_data_t *rd = NULL;
	gnet_upload_status_t status;
	size_t range_len;
	gint progress;

	rd = find_upload(u->upload_handle);
	g_assert(NULL != rd);

	rd->last_update = tm_time();
	rd->send_date = u->start_date;	/* Updated by "core" when header sent back */

	if (
		!host_addr_equiv(u->addr, rd->addr) ||
		!host_addr_equiv(u->gnet_addr, rd->gnet_addr) ||
		u->gnet_port != rd->gnet_port
	) {
		rd->addr = u->addr;
		rd->gnet_addr = u->gnet_addr;
		rd->gnet_port = u->gnet_port;

		gtk_list_store_set(store_uploads, &rd->iter,
			c_ul_host, uploads_gui_host_string(u), (-1));
	}

	if (u->range_start != rd->range_start || u->range_end != rd->range_end) {
		static char str[256];

		rd->range_start  = u->range_start;
		rd->range_end  = u->range_end;

		if (u->range_start == 0 && u->range_end == 0)
			cstr_lcpy(ARYLEN(str), "...");
		else {
			range_len = str_bprintf(ARYLEN(str), "%s%s",
				short_size(u->range_end - u->range_start + 1,
					show_metric_units()),
				u->partial ? _(" (partial)") : "");

			if ((guint) range_len < sizeof str) {
				if (u->range_start)
					range_len += str_bprintf(ARYPOSLEN(str, range_len),
						" @ %s", short_size(u->range_start, show_metric_units()));
				g_assert((guint) range_len < sizeof str);
			}
		}

		gtk_list_store_set(store_uploads, &rd->iter, c_ul_range, str, (-1));
	}

	if (u->file_size != rd->size) {
		rd->size = u->file_size;
		gtk_list_store_set(store_uploads, &rd->iter,
			c_ul_size, short_size(rd->size, show_metric_units()),
			(-1));
	}

	/* Exploit that u->name is an atom! */
	if (u->name != rd->name) {
		atom_str_free_null(&rd->name);
		rd->name = u->name ? atom_str_get(u->name) : NULL;
		gtk_list_store_set(store_uploads, &rd->iter,
			c_ul_filename, rd->name,
			(-1));
	}

	/* Exploit that u->user_agent is an atom! */
	if (u->user_agent != rd->user_agent) {
		atom_str_free_null(&rd->user_agent);
		rd->user_agent = u->user_agent ? atom_str_get(u->user_agent) : NULL;
		gtk_list_store_set(store_uploads, &rd->iter,
			c_ul_agent, rd->user_agent,
			(-1));
	}

	if (u->country != rd->country) {
		rd->country = u->country;
		gtk_list_store_set(store_uploads, &rd->iter,
			c_ul_loc, iso3166_country_cc(rd->country),
			(-1));
	}

	guc_upload_get_status(u->upload_handle, &status);
	rd->status = status.status;

	progress = 100.0 * uploads_gui_progress(&status, rd);
	gtk_list_store_set(store_uploads, &rd->iter,
		c_ul_progress, CLAMP(progress, 0, 100),
		c_ul_status, uploads_gui_status_str(&status, rd),
		(-1));

	if (u->push) {
	    color = &(gtk_widget_get_style(GTK_WIDGET(treeview_uploads))
		      ->fg[GTK_STATE_INSENSITIVE]);
	    gtk_list_store_set(store_uploads, &rd->iter, c_ul_fg, color, (-1));
	}
}

/**
 * Adds the given upload to the gui.
 */
void
uploads_gui_add_upload(gnet_upload_info_t *u)
{
	gint range_len, progress;
	const gchar *titles[UPLOADS_GUI_VISIBLE_COLUMNS];
    upload_row_data_t *rd;
	gnet_upload_status_t status;
	static gchar size_tmp[256];

	ZERO(&titles);

	WALLOC0(rd);
    rd->handle      = u->upload_handle;
    rd->range_start = u->range_start;
    rd->range_end   = u->range_end;
	rd->size		= u->file_size;
    rd->start_date  = u->start_date;
	rd->addr		= u->addr;
	rd->name		= NULL != u->name ? atom_str_get(u->name) : NULL;
	rd->country	    = u->country;
	rd->user_agent	= NULL != u->user_agent
						? atom_str_get(u->user_agent) : NULL;
	rd->push		= u->push;
	rd->valid		= TRUE;
    rd->gnet_addr   = u->gnet_addr;
    rd->gnet_port   = u->gnet_port;

	guc_upload_get_status(u->upload_handle, &status);
    rd->status = status.status;

    if (u->range_start == 0 && u->range_end == 0)
        titles[c_ul_range] =  "...";
    else {
		static gchar range_tmp[256];	/* MUST be static! */

        range_len = str_bprintf(ARYLEN(range_tmp), "%s%s",
            short_size(u->range_end - u->range_start + 1,
				show_metric_units()),
			u->partial ? _(" (partial)") : "");

        if (u->range_start)
            range_len += str_bprintf(ARYPOSLEN(range_tmp, range_len),
                " @ %s", short_size(u->range_start, show_metric_units()));

        g_assert((guint) range_len < sizeof range_tmp);

        titles[c_ul_range] = range_tmp;
    }

	cstr_bcpy(ARYLEN(size_tmp), short_size(u->file_size, show_metric_units()));
    titles[c_ul_size] = size_tmp;

   	titles[c_ul_agent] = u->user_agent ? u->user_agent : "...";
	titles[c_ul_loc] = iso3166_country_cc(u->country);
	titles[c_ul_filename] = u->name ? u->name : "...";
	titles[c_ul_host] = uploads_gui_host_string(u);
	titles[c_ul_status] = uploads_gui_status_str(&status, rd);

	progress = 100.0 * uploads_gui_progress(&status, rd);
    gtk_list_store_append(store_uploads, &rd->iter);
    gtk_list_store_set(store_uploads, &rd->iter,
		c_ul_size, titles[c_ul_size],
		c_ul_range, titles[c_ul_range],
		c_ul_filename, titles[c_ul_filename],
		c_ul_host, titles[c_ul_host],
		c_ul_loc, titles[c_ul_loc],
		c_ul_agent, titles[c_ul_agent],
		c_ul_progress, CLAMP(progress, 0, 100),
		c_ul_status, titles[c_ul_status],
		c_ul_fg, NULL,
		c_ul_data, rd,
		(-1));
	htable_insert(upload_handles, uint_to_pointer(rd->handle), rd);
}

static GtkTreeViewColumn *
add_column(gint column_id, GtkTreeIterCompareFunc sortfunc, GtkType column_type)
{
	GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;
	gint xpad;

	g_assert(column_id >= 0 && (guint) column_id < UPLOADS_GUI_VISIBLE_COLUMNS);
	g_assert(NULL != treeview_uploads);
	g_assert(NULL != store_uploads);

	if (column_type == GTK_TYPE_CELL_RENDERER_PROGRESS) {
		xpad = 0;
		renderer = gtk_cell_renderer_progress_new();
		column = gtk_tree_view_column_new_with_attributes(
					_(column_titles[column_id]), renderer,
					"value", column_id,
					NULL);
	} else { /* if (column_type == GTK_TYPE_CELL_RENDERER_TEXT) { */
		xpad = GUI_CELL_RENDERER_XPAD;
		renderer = gtk_cell_renderer_text_new();
		gtk_cell_renderer_text_set_fixed_height_from_font(
			GTK_CELL_RENDERER_TEXT(renderer), 1);
		g_object_set(renderer,
			"foreground-set", TRUE,
			NULL_PTR);
		column = gtk_tree_view_column_new_with_attributes(
					_(column_titles[column_id]), renderer,
					"foreground-gdk", c_ul_fg,
					"text", column_id,
					NULL_PTR);
	}

	g_object_set(renderer,
		"xalign", (gfloat) 0.0,
		"xpad", xpad,
		"ypad", GUI_CELL_RENDERER_YPAD,
		NULL_PTR);

	g_object_set(G_OBJECT(column),
		"fixed-width", 1,
		"min-width", 1,
		"reorderable", TRUE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		NULL_PTR);

	gtk_tree_view_column_set_sort_column_id(column, column_id);
	gtk_tree_view_append_column(treeview_uploads, column);

	if (NULL != sortfunc)
		gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(store_uploads),
			column_id, sortfunc, GINT_TO_POINTER(column_id), NULL);

	return column;
}

static GtkListStore *
create_uploads_model(void)
{
	static GType columns[c_ul_num];
	GtkListStore *store;
	guint i;

	STATIC_ASSERT(c_ul_num == N_ITEMS(columns));
#define SET(c, x) case (c): columns[i] = (x); break
	for (i = 0; i < N_ITEMS(columns); i++) {
		switch (i) {
		SET(c_ul_filename, G_TYPE_STRING);
		SET(c_ul_host, G_TYPE_STRING);
		SET(c_ul_loc, G_TYPE_STRING);
		SET(c_ul_size, G_TYPE_STRING);
		SET(c_ul_range, G_TYPE_STRING);
		SET(c_ul_agent, G_TYPE_STRING);
		SET(c_ul_progress, G_TYPE_INT);
		SET(c_ul_status, G_TYPE_STRING);
		SET(c_ul_fg, GDK_TYPE_COLOR);
		SET(c_ul_data, G_TYPE_POINTER);
		default:
			g_assert_not_reached();
		}
	}
#undef SET

	store = gtk_list_store_newv(N_ITEMS(columns), columns);
	return GTK_LIST_STORE(store);
}

static inline void
free_row_data(upload_row_data_t *rd)
{
	atom_str_free_null(&rd->user_agent);
	atom_str_free_null(&rd->name);
	WFREE(rd);
}

static inline void
free_handle(const void *key, void *value, void *user_data)
{
	(void) key;
	(void) user_data;

	free_row_data(value);
}

static inline void
remove_row(upload_row_data_t *rd, remove_row_ctx_t *ctx)
{
	g_assert(NULL != rd);
	if (ctx->force || upload_should_remove(ctx->now, rd)) {
    	gtk_list_store_remove(store_uploads, &rd->iter);
		free_row_data(rd);
	} else
		ctx->sl_remaining = g_slist_prepend(ctx->sl_remaining, rd);
}

static inline void
update_row(const void *key, void *value, void *unused_udata)
{
	time_t now;
	upload_row_data_t *rd = value;
	gnet_upload_status_t status;
	guint progress;

	(void) unused_udata;
	g_assert(NULL != rd);
	g_assert(pointer_to_uint(key) == rd->handle);

	now = tm_time();
	if (delta_time(now, rd->last_update) < 2)
		return;

	rd->last_update = now;
	guc_upload_get_status(rd->handle, &status);
	progress = 100.0 * uploads_gui_progress(&status, rd);
	progress = MIN(progress, 100);
	gtk_list_store_set(store_uploads, &rd->iter,
		c_ul_progress, progress,
		c_ul_status, uploads_gui_status_str(&status, rd),
		(-1));
}

/**
 * Update all the uploads at the same time.
 */
static void
uploads_gui_update_display(time_t now)
{
   	static gboolean locked = FALSE;
	remove_row_ctx_t ctx;

	ctx.force = FALSE;
	ctx.now = now;
	ctx.sl_remaining = NULL;

	g_return_if_fail(!locked);
	locked = TRUE;

	g_object_freeze_notify(G_OBJECT(treeview_uploads));
	/* Remove all rows with `removed' uploads. */
	G_SLIST_FOREACH_WITH_DATA(sl_removed_uploads, remove_row, &ctx);
	g_slist_free(sl_removed_uploads);
	sl_removed_uploads = ctx.sl_remaining;

	/* Update the status column for all active uploads. */
	htable_foreach(upload_handles, update_row, NULL);
	g_object_thaw_notify(G_OBJECT(treeview_uploads));

	gtk_widget_set_sensitive(button_uploads_clear_completed,
		NULL != sl_removed_uploads);

	locked = FALSE;
}

static void
uploads_gui_timer(time_t now)
{
	if (uploads_gui_update_required(now)) {
		uploads_gui_update_display(now);
	}
}

static gboolean
uploads_clear_helper(gpointer user_data)
{
	guint counter = 0;
    GSList *sl, *sl_remaining = NULL;
	remove_row_ctx_t ctx = { TRUE, 0, NULL };

	(void) user_data;

	if (uploads_shutting_down)
		return FALSE; /* Finished. */

	g_object_freeze_notify(G_OBJECT(treeview_uploads));
	/* Remove all rows with `removed' uploads. */

	G_SLIST_FOREACH_WITH_DATA(sl_removed_uploads, remove_row, &ctx);
	g_slist_free(sl_removed_uploads);
	sl_removed_uploads = ctx.sl_remaining;

    for (sl = sl_removed_uploads; sl; sl = g_slist_next(sl_removed_uploads)) {
		remove_row((upload_row_data_t *) sl->data, &ctx);
		/* Interrupt and come back later to prevent GUI stalling. */
		if (0 == (++counter & 0x7f)) {
			/* Remember which elements haven't been traversed yet. */
			sl_remaining = g_slist_remove_link(sl, sl);
			break;
		}
    }
	g_object_thaw_notify(G_OBJECT(treeview_uploads));

	/* The elements' data has been freed or is now referenced
	 * by ctx->remaining. */
	g_slist_free(sl_removed_uploads);
	sl_removed_uploads = g_slist_concat(ctx.sl_remaining, sl_remaining);

    if (NULL == sl_removed_uploads) {
		gtk_widget_set_sensitive(button_uploads_clear_completed, FALSE);
    	uploads_remove_lock = FALSE;
    	return FALSE; /* Finished. */
    }

    return TRUE; /* More rows to remove. */
}

void
uploads_gui_clear_completed(void)
{
	if (!uploads_remove_lock) {
		uploads_remove_lock = TRUE;
		gtk_timeout_add(100, uploads_clear_helper, store_uploads);
	}
}

/**
 * Enforce a tri-state sorting.
 */
static void
on_uploads_treeview_column_clicked(GtkTreeViewColumn *column, void *udata)
{
	(void) udata;

	column_sort_tristate(column, &uploads_sort);
}

void
uploads_gui_init(void)
{
	static const struct {
		gint id;
		GtkTreeIterCompareFunc sortfunc;
	} cols[] = {
		{ c_ul_filename, 	NULL },
		{ c_ul_host, 		compare_hosts },
		{ c_ul_loc, 		NULL },
		{ c_ul_size, 		compare_sizes },
		{ c_ul_range, 		compare_ranges },
		{ c_ul_agent, 		NULL },
		{ c_ul_progress, 	NULL },
		{ c_ul_status, 		NULL },
	};
	size_t i;

	STATIC_ASSERT(N_ITEMS(cols) == UPLOADS_GUI_VISIBLE_COLUMNS);
	store_uploads = create_uploads_model();

	button_uploads_clear_completed =
		gui_main_window_lookup("button_uploads_clear_completed");
	treeview_uploads =
		GTK_TREE_VIEW(gui_main_window_lookup("treeview_uploads"));
	gtk_tree_view_set_model(treeview_uploads, GTK_TREE_MODEL(store_uploads));
	tree_view_set_fixed_height_mode(treeview_uploads, TRUE);

	gui_parent_widths_saveto(treeview_uploads, PROP_UPLOADS_COL_WIDTHS);

	for (i = 0; i < N_ITEMS(cols); i++) {
		GtkTreeViewColumn *column;

		column = add_column(cols[i].id, cols[i].sortfunc,
			c_ul_progress == cols[i].id
				? GTK_TYPE_CELL_RENDERER_PROGRESS
				: GTK_TYPE_CELL_RENDERER_TEXT);

		column_sort_tristate_register(column,
			on_uploads_treeview_column_clicked, NULL);

		gui_column_map(column, treeview_uploads);	/* Capture resize events */

	}
	tree_view_restore_widths(treeview_uploads, PROP_UPLOADS_COL_WIDTHS);
	tree_view_restore_visibility(treeview_uploads, PROP_UPLOADS_COL_VISIBLE);

	upload_handles = htable_create(HASH_KEY_SELF, 0);

    guc_upload_add_upload_added_listener(upload_added);
    guc_upload_add_upload_removed_listener(upload_removed);
    guc_upload_add_upload_info_changed_listener(upload_info_changed);

	gui_signal_connect(treeview_uploads,
		"button_press_event", on_button_press_event, NULL);

	main_gui_add_timer(uploads_gui_timer);
}

/**
 * Unregister callbacks in the backend and clean up.
 */
void
uploads_gui_shutdown(void)
{
	uploads_shutting_down = TRUE;

	tree_view_save_visibility(treeview_uploads, PROP_UPLOADS_COL_VISIBLE);

    guc_upload_remove_upload_added_listener(upload_added);
    guc_upload_remove_upload_removed_listener(upload_removed);
    guc_upload_remove_upload_info_changed_listener(upload_info_changed);

	gtk_list_store_clear(store_uploads);

	htable_foreach(upload_handles, free_handle, NULL);
	htable_free_null(&upload_handles);
	G_SLIST_FOREACH(sl_removed_uploads, free_row_data);
	gm_slist_free_null(&sl_removed_uploads);
}

/* vi: set ts=4 sw=4 cindent: */
