/*
 * $Id$
 *
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

#include "gui.h"
#include "interface-glade2.h"
#include "uploads_gui.h"
#include "uploads_gui_common.h"

RCSID("$Id$");

#define IO_STALLED		60		/* If nothing exchanged after that many secs */
#define REMOVE_DELAY    5       /* delay before outdated info is removed */

static gboolean uploads_remove_lock = FALSE;
static gboolean uploads_shutting_down = FALSE;

static GtkTreeView *treeview_uploads = NULL;
static GtkListStore *store_uploads = NULL;
static GtkWidget *button_uploads_clear_completed = NULL;

/* hash table for fast handle -> GtkTreeIter mapping */
static GHashTable *upload_handles = NULL;
/* list of all *active* uploads; contains the handles */
static GList *list_uploads = NULL;
/* list of all *removed* uploads; contains the handles */
static GSList *sl_removed_uploads = NULL;

static inline upload_row_data_t *find_upload(gnet_upload_t u);

static void uploads_gui_update_upload_info(const gnet_upload_info_t *u);
static void uploads_gui_add_upload(gnet_upload_info_t *u);


static const char *column_titles[UPLOADS_GUI_VISIBLE_COLUMNS] = {
	N_("Filename"),
	N_("Host"),
	N_("Size"),
	N_("Range"),
	N_("User-Agent"),
	N_("Status")
};

typedef struct remove_row_ctx {
	gboolean force;			/* If false, rows will only be removed, if 
							 * their `REMOVE_DELAY' has expired. */
	time_t now; 			/* Current time, used to decide whether row
							 * should be finally removed. */
	GSList *sl_remaining;	/* Contains row data for not yet removed rows. */	
} remove_row_ctx_t;


/***
 *** Callbacks
 ***/

/*
 * upload_removed:
 *
 * Callback: called when an upload is removed from the backend.
 *
 * Either immediately clears the upload from the frontend or just
 * set the upload_row_info->valid to FALSE, so we don't accidentally
 * try to use the handle to communicate with the backend.
 */
static void upload_removed(
    gnet_upload_t uh, const gchar *reason, guint32 running, guint32 registered)
{
    upload_row_data_t *rd = NULL;
	
    /* Invalidate row and remove it from the GUI if autoclear is on */
	rd = find_upload(uh);
	g_assert(NULL != rd);
	rd->valid = FALSE;
	gtk_widget_set_sensitive(button_uploads_clear_completed, TRUE);
	if (reason != NULL)
		gtk_list_store_set(store_uploads, &rd->iter, c_ul_status, reason, (-1));
	sl_removed_uploads = g_slist_prepend(sl_removed_uploads, rd);
	g_hash_table_remove(upload_handles, GUINT_TO_POINTER(uh));
	list_uploads = g_list_remove(list_uploads, rd);
	/* NB: rd MUST NOT be freed yet because it contains the GtkTreeIter! */
}



/*
 * upload_added:
 *
 * Callback: called when an upload is added from the backend.
 *
 * Adds the upload to the gui.
 */
static void upload_added(
    gnet_upload_t n, guint32 running, guint32 registered)
{
    gnet_upload_info_t *info;

    info = upload_get_info(n);
    uploads_gui_add_upload(info);
    upload_free_info(info);
}


/*
 * upload_info_changed:
 *
 * Callback: called when upload information was changed by the backend.
 *
 * This updates the upload information in the gui. 
 */
static void upload_info_changed(gnet_upload_t u, 
    guint32 running, guint32 registered)
{
    gnet_upload_info_t *info;
    
    info = upload_get_info(u);
    uploads_gui_update_upload_info(info);
    upload_free_info(info);
}


#define COMPARE_FUNC(field, code) \
static gint compare_ ##field## _func( \
	GtkTreeModel *model, GtkTreeIter *a, GtkTreeIter *b, gpointer user_data) \
{ \
	const upload_row_data_t *rd_a = NULL; \
	const upload_row_data_t *rd_b = NULL; \
	\
	gtk_tree_model_get(model, a, c_ul_data, &rd_a, (-1)); \
	gtk_tree_model_get(model, b, c_ul_data, &rd_b, (-1)); \
	code \
} \

COMPARE_FUNC(hosts, {
	guint32 ip_a = GUINT32_FROM_LE(rd_a->ip);
	guint32 ip_b = GUINT32_FROM_LE(rd_b->ip);
	return SIGN(ip_a, ip_b);
});

COMPARE_FUNC(sizes, {
	return SIGN(rd_a->size, rd_b->size);
});

COMPARE_FUNC(ranges, {
	guint32 u = rd_a->range_end - rd_a->range_start;
	guint32 v = rd_b->range_end - rd_b->range_start;
	gint s = SIGN(u, v); 
	return 0 != s ? s : SIGN(rd_a->range_start, rd_b->range_start);
});


/***
 *** Private functions
 ***/

/*
 * find_upload:
 *
 * Tries to fetch upload_row_data associated with the given upload handle.
 * Returns a pointer the upload_row_data.
 */
static inline upload_row_data_t *find_upload(gnet_upload_t u)
{
	union {
		upload_row_data_t *rd; 
		gpointer ptr;
	} key;
	gboolean found;

	key.rd = NULL;
	found = g_hash_table_lookup_extended(upload_handles, GUINT_TO_POINTER(u),
				NULL, &key.ptr);
	g_assert(found);

	g_assert(NULL != key.rd);
	g_assert(key.rd->valid);
	g_assert(key.rd->handle == u);

	return key.rd;
}

static void uploads_gui_update_upload_info(const gnet_upload_info_t *u)
{
	GdkColor *color = NULL;
    upload_row_data_t *rd = NULL;
	gnet_upload_status_t status;
	gint range_len;

	rd = find_upload(u->upload_handle);
	g_assert(NULL != rd);
 
	rd->last_update  = time(NULL);	

	if (u->ip != rd->ip) {
		rd->ip = u->ip;
		gtk_list_store_set(store_uploads, &rd->iter,
			c_ul_host, ip_to_gchar(rd->ip), (-1));
	}

	if (u->range_start != rd->range_start || u->range_end != rd->range_end) {
		static gchar str[256];

		rd->range_start  = u->range_start;
		rd->range_end  = u->range_end;

		if (u->range_start == 0 && u->range_end == 0)
			g_strlcpy(str, "...", sizeof(str));
		else {
			range_len = g_strlcpy(str,
							compact_size(u->range_end - u->range_start + 1),
							sizeof(str));

			if (range_len < sizeof(str)) {
				if (u->range_start)
					range_len += gm_snprintf(&str[range_len],
									sizeof(str)-range_len,
									" @ %s", compact_size(u->range_start));
				g_assert(range_len < sizeof(str));
			}
		}

		gtk_list_store_set(store_uploads, &rd->iter, c_ul_range, str, (-1));
	}

	if (u->file_size != rd->size) {
		rd->size = u->file_size;
		gtk_list_store_set(store_uploads, &rd->iter,
			c_ul_size, short_size(rd->size), (-1));
	}

	/* Exploit that u->name is an atom! */ 
	if (u->name != rd->name) {
		g_assert(NULL != u->name);
		if (NULL != rd->name)
			atom_str_free(rd->name);
		rd->name = atom_str_get(u->name);
		gtk_list_store_set(store_uploads, &rd->iter,
			c_ul_filename, lazy_locale_to_utf8(rd->name, 0),
			(-1));
	}

	/* Exploit that u->user_agent is an atom! */ 
	if (u->user_agent != rd->user_agent) {
		g_assert(NULL != u->user_agent);
		if (NULL != rd->user_agent)
			atom_str_free(rd->user_agent);
		rd->user_agent = atom_str_get(u->user_agent);
		gtk_list_store_set(store_uploads, &rd->iter,
			c_ul_agent, lazy_locale_to_utf8(rd->user_agent, 0),
			(-1));
	}

	upload_get_status(u->upload_handle, &status);
	rd->status = status.status;

	gtk_list_store_set(store_uploads, &rd->iter,
		c_ul_status, uploads_gui_status_str(&status, rd), (-1));

	if (u->push != rd->push) {
		rd->push = u->push;
 		color = rd->push ? &(gtk_widget_get_style(GTK_WIDGET(treeview_uploads))
			->fg[GTK_STATE_INSENSITIVE]) : NULL;
		gtk_list_store_set(store_uploads, &rd->iter, c_ul_fg, color, (-1));
	}
}



/*
 * uploads_gui_add_upload:
 *
 * Adds the given upload to the gui.
 */
void uploads_gui_add_upload(gnet_upload_info_t *u)
{
	gint range_len;
	const gchar *titles[UPLOADS_GUI_VISIBLE_COLUMNS];
    upload_row_data_t *rd = walloc(sizeof(*rd));
	gnet_upload_status_t status;
	static gchar size_tmp[256];

	memset(titles, 0, sizeof(titles));

    rd->handle      = u->upload_handle;
    rd->range_start = u->range_start;
    rd->range_end   = u->range_end;
	rd->size		= u->file_size;
    rd->start_date  = u->start_date;
	rd->ip			= u->ip;
	rd->name		= NULL != u->name ? atom_str_get(u->name) : NULL;
	rd->user_agent	= NULL != u->user_agent
						? atom_str_get(u->user_agent) : NULL;
	rd->push		= u->push;
	rd->valid		= TRUE;

	upload_get_status(u->upload_handle, &status);
    rd->status = status.status;

    if (u->range_start == 0 && u->range_end == 0)
        titles[c_ul_range] =  "...";
    else {
		static gchar range_tmp[256];	/* MUST be static! */

        range_len = gm_snprintf(range_tmp, sizeof(range_tmp), "%s",
            compact_size(u->range_end - u->range_start + 1));

        if (u->range_start)
            range_len += gm_snprintf(
                &range_tmp[range_len], sizeof(range_tmp)-range_len,
                " @ %s", compact_size(u->range_start));
    
        g_assert(range_len < sizeof(range_tmp));

        titles[c_ul_range] = range_tmp;
    }

	g_strlcpy(size_tmp, short_size(u->file_size), sizeof(size_tmp)); 
    titles[c_ul_size] = size_tmp;

	if (NULL != u->user_agent) {
		static gchar str[256];	/* MUST be static! */
		gchar *agent;

		agent = lazy_locale_to_utf8(u->user_agent, 0);
		if (u->user_agent != agent) {
			g_strlcpy(str, agent, sizeof(str));
			agent = str;
		}
    	titles[c_ul_agent] = agent;
	} else
		titles[c_ul_agent] = "...";

	titles[c_ul_filename] = NULL != u->name
								? lazy_locale_to_utf8(u->name, 0) : "...";
	titles[c_ul_host]     = ip_to_gchar(u->ip);
	titles[c_ul_status] = uploads_gui_status_str(&status, rd);

    gtk_list_store_append(store_uploads, &rd->iter);
    gtk_list_store_set(store_uploads, &rd->iter,
		c_ul_size, titles[c_ul_size],
		c_ul_range, titles[c_ul_range],
		c_ul_filename, titles[c_ul_filename],
		c_ul_host, titles[c_ul_host],
		c_ul_agent, titles[c_ul_agent],
		c_ul_status, titles[c_ul_status],
		c_ul_fg, NULL,
		c_ul_data, rd,
		(-1));
	g_hash_table_insert(upload_handles, GUINT_TO_POINTER(rd->handle), rd);
	list_uploads = g_list_prepend(list_uploads, rd);
}

static void add_column(gint column_id, GtkTreeIterCompareFunc sortfunc)
{
	GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;
	guint32 width;

	g_assert(column_id >= 0 && column_id < UPLOADS_GUI_VISIBLE_COLUMNS);
	g_assert(NULL != treeview_uploads);
	g_assert(NULL != store_uploads);

	gui_prop_get_guint32(PROP_UPLOADS_COL_WIDTHS, &width, column_id, 1);
	renderer = gtk_cell_renderer_text_new();
	gtk_cell_renderer_text_set_fixed_height_from_font(
		GTK_CELL_RENDERER_TEXT(renderer), 1);
	g_object_set(renderer,
		"xalign", (gfloat) 0.0,
		"ypad", GUI_CELL_RENDERER_YPAD,
		NULL);
	column = gtk_tree_view_column_new_with_attributes(
		column_titles[column_id], renderer, "text", column_id, NULL);
	g_object_set(G_OBJECT(column),
		"min-width", 1,
		"fixed-width", MAX(1, width),
		"reorderable", TRUE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		NULL);
	gtk_tree_view_column_set_sort_column_id(column, column_id);
	gtk_tree_view_append_column(treeview_uploads, column);

	if (NULL != sortfunc)
		gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(store_uploads),
			column_id, sortfunc, GINT_TO_POINTER(column_id), NULL);
}

/***
 *** Public functions
 ***/

void uploads_gui_early_init(void)
{
    popup_uploads = create_popup_uploads();
}

void uploads_gui_init(void)
{
	GtkTreeView *treeview;

	button_uploads_clear_completed = lookup_widget(main_window,
		"button_uploads_clear_completed");
	treeview_uploads = treeview =
		GTK_TREE_VIEW(lookup_widget(main_window, "treeview_uploads"));
	store_uploads = gtk_list_store_new(c_ul_num,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		GDK_TYPE_COLOR,
		G_TYPE_POINTER);
	gtk_tree_view_set_model(treeview, GTK_TREE_MODEL(store_uploads));

	add_column(c_ul_filename, NULL);
	add_column(c_ul_host, compare_hosts_func);
	add_column(c_ul_size, compare_sizes_func);
	add_column(c_ul_range, compare_ranges_func);
	add_column(c_ul_agent, NULL);
	add_column(c_ul_status, NULL);

	upload_handles = g_hash_table_new(NULL, NULL);

    upload_add_upload_added_listener(upload_added);
    upload_add_upload_removed_listener(upload_removed);
    upload_add_upload_info_changed_listener(upload_info_changed);
}

static inline void free_row_data(upload_row_data_t *rd, gpointer user_data)
{
	if (NULL != rd->user_agent) {
		atom_str_free(rd->user_agent);
		rd->user_agent = NULL;
	}
	if (NULL != rd->name) {
		atom_str_free(rd->name);
		rd->user_agent = NULL;
	}
	wfree(rd, sizeof(*rd));
}

static inline void remove_row(upload_row_data_t *rd, remove_row_ctx_t *ctx)
{
	g_assert(NULL != rd);
	if (ctx->force || upload_should_remove(ctx->now, rd)) {
    	gtk_list_store_remove(store_uploads, &rd->iter);
		free_row_data(rd, NULL);
	} else
		ctx->sl_remaining = g_slist_prepend(ctx->sl_remaining, rd);
}

static inline void update_row(
	upload_row_data_t *rd, const time_t *now)
{
	gnet_upload_status_t status;

	g_assert(NULL != rd);
	if (*now > rd->last_update + 1) {
		rd->last_update = *now;
		upload_get_status(rd->handle, &status);
		gtk_list_store_set(store_uploads, &rd->iter,
			c_ul_status, uploads_gui_status_str(&status, rd), (-1));
	}
}

/*
 * uploads_gui_update_display
 *
 * Update all the uploads at the same time.
 */
void uploads_gui_update_display(time_t now)
{
    static time_t last_update = 0;
    static gboolean locked = FALSE;
	remove_row_ctx_t ctx = { FALSE, now, NULL };

    if (last_update == now)
        return;
    last_update = now;

    g_return_if_fail(!locked);
    locked = TRUE;

	/* Remove all rows with `removed' uploads. */
	G_SLIST_FOREACH(sl_removed_uploads, (GFunc) remove_row, &ctx);
	g_slist_free(sl_removed_uploads);
	sl_removed_uploads = ctx.sl_remaining;

	/* Update the status column for all active uploads. */ 
	G_LIST_FOREACH(list_uploads, (GFunc) update_row, &now);
       
	if (NULL == sl_removed_uploads)
		gtk_widget_set_sensitive(button_uploads_clear_completed, FALSE);

    locked = FALSE;
}

static gboolean uploads_clear_helper(gpointer user_data)
{
	guint counter = 0;
    GSList *sl, *sl_remaining = NULL;
	remove_row_ctx_t ctx = { TRUE, 0, NULL };

	if (uploads_shutting_down)
		return FALSE; /* Finished. */

	/* Remove all rows with `removed' uploads. */

	G_SLIST_FOREACH(sl_removed_uploads, (GFunc) remove_row, &ctx);
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

void uploads_gui_clear_completed(void)
{
	if (!uploads_remove_lock) {
		uploads_remove_lock = TRUE;
		gtk_timeout_add(100, uploads_clear_helper, store_uploads); 
	}
}

/*
 * uploads_gui_shutdown:
 *
 * Unregister callbacks in the backend and clean up.
 */
void uploads_gui_shutdown(void) 
{
	uploads_shutting_down = TRUE;
	
	tree_view_save_widths(treeview_uploads, PROP_UPLOADS_COL_WIDTHS);

    upload_remove_upload_added_listener(upload_added);
    upload_remove_upload_removed_listener(upload_removed);
    upload_remove_upload_info_changed_listener(upload_info_changed);

	gtk_list_store_clear(store_uploads);

	g_hash_table_destroy(upload_handles);
	upload_handles = NULL;
	G_LIST_FOREACH(list_uploads, (GFunc) free_row_data, NULL);
	g_list_free(list_uploads);
	list_uploads = NULL;
	G_SLIST_FOREACH(sl_removed_uploads, (GFunc) free_row_data, NULL);
	g_slist_free(sl_removed_uploads);
	sl_removed_uploads = NULL;
}

