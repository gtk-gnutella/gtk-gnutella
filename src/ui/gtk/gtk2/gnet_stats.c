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

#include "gtk/gui.h"

#include "gtk/gnet_stats.h"
#include "gtk/notebooks.h"
#include "gtk/misc.h"
#include "gtk/settings.h"

#include "if/gui_property.h"
#include "if/gui_property_priv.h"
#include "if/core/gnutella.h"
#include "if/bridge/ui2c.h"

#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/tm.h"

#include "lib/override.h"		/* Must be the last header included */

static GtkTreeView *treeview_gnet_stats_messages;
static GtkTreeView *treeview_gnet_stats_drop_reasons;
static GtkTreeView *treeview_gnet_stats_flowc;
static GtkTreeView *treeview_gnet_stats_recv;
static GtkTreeView *treeview_gnet_stats_general;
static GtkTreeView *treeview_gnet_stats_horizon;
static GtkNotebook *notebook_gnet_stats;

static const gchar * const msg_stats_label[] = {
	N_("Type"),
	N_("Received"),
	N_("Expired"),
	N_("Dropped"),
	N_("Queued"),
	N_("Relayed"),
	N_("Gen. queued"),
	N_("Gen. sent")
};

enum gnet_stats_nb_page {
	GNET_STATS_NB_PAGE_STATS,
	GNET_STATS_NB_PAGE_MESSAGES,
	GNET_STATS_NB_PAGE_FLOWC,
	GNET_STATS_NB_PAGE_RECV,
	GNET_STATS_NB_PAGE_HORIZON,

	NUM_GNET_STATS_NB_PAGES
};

static void gnet_stats_update_drop_reasons(const gnet_stats_t *);

/***
 *** Private functions
 ***/

void
hide_column_by_title(GtkTreeView *treeview, const gchar *header_title,
	gboolean hidden)
{
	GList *list, *l;
	const gchar *title;

	g_assert(NULL != header_title);
	list = gtk_tree_view_get_columns(treeview);
	g_assert(NULL != list);

	for (l = list; NULL != l; l = g_list_next(l))
		if (NULL != l->data) {
			gtk_object_get(GTK_OBJECT(l->data), "title", &title, NULL);
			if (NULL != title && !strcmp(header_title, title)) {
				gtk_tree_view_column_set_visible(GTK_TREE_VIEW_COLUMN(l->data),
					!hidden);
				break;
			}
		}

	g_list_free(list);
}

static gchar *
pkt_stat_str(gchar *dst, size_t size, const guint64 *val_tbl,
	gint type, gboolean perc)
{
	if (0 == val_tbl[type])
		g_strlcpy(dst, "-", size);
	else {
		if (!perc)
			uint64_to_string_buf(val_tbl[type], dst, size);
		else
			str_bprintf(dst, size, "%.2f%%",
			    (gfloat) val_tbl[type] / val_tbl[MSG_TOTAL] * 100.0);
	}

	return dst;
}


static const gchar *
byte_stat_str(gchar *dst, gulong n, const guint64 *val_tbl,
	gint type, gboolean perc)
{
	if (0 == val_tbl[type])
		g_strlcpy(dst, "-", n);
	else if (!perc)
		g_strlcpy(dst, compact_size(val_tbl[type], show_metric_units()), n);
	else
		str_bprintf(dst, n, "%.2f%%",
		    (gfloat) val_tbl[type] / val_tbl[MSG_TOTAL] * 100.0);

	return dst;
}

static void
drop_stat_str(gchar *dst, size_t size, const gnet_stats_t *stats, gint reason,
	gint selected_type)
{
	if (stats->drop_reason[reason][selected_type] == 0)
		g_strlcpy(dst, "-", size);
	else
		uint64_to_string_buf(stats->drop_reason[reason][selected_type],
			dst, size);
}

static inline void
general_stat_str(gchar *dst, size_t size, const gnet_stats_t *stats, gint type)
{
	gnet_stats_gui_general_to_string_buf(dst, size, stats, type);
}

static void
add_column(GtkTreeView *treeview, gint column_id, gint width, gfloat xalign,
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
		NULL_PTR);
	column = gtk_tree_view_column_new_with_attributes(label, renderer,
		"text", column_id,
		NULL);
	g_object_set(column,
		"fixed-width", MAX(1, width),
		"min-width", 1,
		"reorderable", TRUE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		NULL_PTR);
	gtk_tree_view_append_column(treeview, column);
}

static void
gnet_stats_update_general(const gnet_stats_t *stats)
{
	static uint64 general[GNR_TYPE_COUNT];
	GtkListStore *store;
	GtkTreeIter iter;
	gint n;

	store = GTK_LIST_STORE(gtk_tree_view_get_model(
				treeview_gnet_stats_general));
	if (!gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter))
		return;

	for (n = 0; n < GNR_TYPE_COUNT; n++) {
		gchar buf[UINT64_DEC_BUFLEN];

		if (stats->general[n] != general[n]) {
			general[n] = stats->general[n];
			general_stat_str(buf, sizeof buf, stats, n);
			gtk_list_store_set(store, &iter, 1, buf, (-1));
		}

		if (!gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter))
			break;
	}
}

static void
gnet_stats_update_drop_reasons(const gnet_stats_t *stats)
{
	static uint64 drop_reason[MSG_DROP_REASON_COUNT][MSG_TYPE_COUNT];
	GtkListStore *store;
	GtkTreeIter iter;
	gint n;
	guint i = GUI_PROPERTY(gnet_stats_drop_reasons_type);

	store = GTK_LIST_STORE(gtk_tree_view_get_model(
				treeview_gnet_stats_drop_reasons));
	if (!gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter))
		return;

	for (n = 0; n < MSG_DROP_REASON_COUNT; n++) {
		gchar buf[UINT64_DEC_BUFLEN];

		if (stats->drop_reason[n][i] != drop_reason[n][i]) {
			drop_reason[n][i] = stats->drop_reason[n][i];
			drop_stat_str(buf, sizeof buf, stats, n, i);
			gtk_list_store_set(store, &iter, 1, buf, (-1));
		}

		if (!gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter))
			break;
	}
}

static void
gnet_stats_update_messages(const gnet_stats_t *stats)
{
	static char str[num_c_gs][UINT64_DEC_BUFLEN];
	static const size_t len = sizeof(str[0]);
	GtkTreeView *treeview = treeview_gnet_stats_messages;
	GtkListStore *store;
	GtkTreeIter iter;
	gboolean perc = FALSE;
	gboolean bytes = FALSE;
	gint n;

	STATIC_ASSERT(num_c_gs == N_ITEMS(msg_stats_label));

	gui_prop_get_boolean_val(PROP_GNET_STATS_PERC, &perc);
	gui_prop_get_boolean_val(PROP_GNET_STATS_BYTES, &bytes);

	store = GTK_LIST_STORE(gtk_tree_view_get_model(treeview));
	if (!gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter))
		return;

	for (n = 0; n < msg_type_str_size(); n++) {
		if (!bytes) {
			gtk_list_store_set(store, &iter,
				c_gs_received,	 pkt_stat_str(str[c_gs_received],
									len, stats->pkg.received, n, perc),
				c_gs_expired,	 pkt_stat_str(str[c_gs_expired],
									len, stats->pkg.expired, n, perc),
				c_gs_dropped,	 pkt_stat_str(str[c_gs_dropped],
									len, stats->pkg.dropped, n, perc),
				c_gs_queued,	 pkt_stat_str(str[c_gs_queued],
									len, stats->pkg.queued, n, perc),
				c_gs_relayed,	 pkt_stat_str(str[c_gs_relayed],
									len, stats->pkg.relayed, n, perc),
				c_gs_gen_queued, pkt_stat_str(str[c_gs_gen_queued],
									len, stats->pkg.gen_queued, n, perc),
				c_gs_generated,  pkt_stat_str(str[c_gs_generated],
									len, stats->pkg.generated, n, perc),
				(-1));
		} else { /* byte mode */
			gtk_list_store_set(store, &iter,
				c_gs_received,	 byte_stat_str(str[c_gs_received],
									len, stats->byte.received, n, perc),
				c_gs_expired,	 byte_stat_str(str[c_gs_expired],
									len, stats->byte.expired, n, perc),
				c_gs_dropped,	 byte_stat_str(str[c_gs_dropped],
									len, stats->byte.dropped, n, perc),
				c_gs_queued,	 byte_stat_str(str[c_gs_queued],
									len, stats->byte.queued, n, perc),
				c_gs_relayed,	 byte_stat_str(str[c_gs_relayed],
									len, stats->byte.relayed, n, perc),
				c_gs_gen_queued, byte_stat_str(str[c_gs_gen_queued],
									len, stats->byte.gen_queued, n, perc),
				c_gs_generated,  byte_stat_str(str[c_gs_generated],
									len, stats->byte.generated, n, perc),
				(-1));
		}
		if (!gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter))
			break;
	}
}

static void
gnet_stats_update_flowc(const gnet_stats_t *stats)
{
	/* FIXME: Implement this.  */
	(void) stats;
}

static void
gnet_stats_update_recv(const gnet_stats_t *stats)
{
	/* FIXME: Implement this. */
	(void) stats;
}

static void
gnet_stats_update_horizon(time_t now)
{
	static time_t last_horizon_update;
	GtkTreeView *treeview = treeview_gnet_stats_horizon;
	GtkListStore *store;
	GtkTreeIter iter;
	gint i;
	gint global_table_size;

	/*
	 * Update horizon statistics table, but only if the values have changed.
	 *      -- TNT 09/06/2004
	 *
	 * Changed this check to update the table every 2 seconds, because not
	 * only the HSEP table but also the PONG-based library sizes of direct
	 * non-HSEP neighbors may have changed.
	 *      -- TNT 14/06/2004
	 */

    if (delta_time(now, last_horizon_update) < 2)
		return;

	store = GTK_LIST_STORE(gtk_tree_view_get_model(treeview));
	if (!gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter))
		return;

	global_table_size = guc_hsep_get_table_size();
	/* Skip the first element */
	for (i = 1; i < global_table_size; i++) {
		gtk_list_store_set(store, &iter,
			c_horizon_nodes, horizon_stat_str(i, c_horizon_nodes),
		    c_horizon_files, horizon_stat_str(i, c_horizon_files),
		    c_horizon_size,	 horizon_stat_str(i, c_horizon_size),
			(-1));
		if (!gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter))
			break;
	}

	last_horizon_update = now;
}

static void
gnet_stats_gui_horizon_init(void)
{
	static const gchar * const titles[num_c_horizon] = {
		N_("Hops"),
		N_("Nodes"),
		N_("Files"),
		N_("Size")
	};
	GType types[] = {
		G_TYPE_INT,		/* Hops */
		G_TYPE_STRING,	/* Nodes */
		G_TYPE_STRING,	/* Files */
		G_TYPE_STRING	/* Size */
	};
	GtkTreeView *treeview;
	GtkTreeModel *model;
	guint32 width[num_c_horizon];
	c_horizon_t n;

	STATIC_ASSERT(num_c_horizon == N_ITEMS(types));
	model = GTK_TREE_MODEL(gtk_list_store_newv(N_ITEMS(types), types));
	treeview = treeview_gnet_stats_horizon = GTK_TREE_VIEW(
	    gui_main_window_lookup("treeview_gnet_stats_horizon"));

	gui_prop_get_guint32(PROP_GNET_STATS_HORIZON_COL_WIDTHS,
		width, 0, N_ITEMS(width));
	for (n = 0; n < N_ITEMS(width); n++) {
		GtkTreeIter iter;
		gint i;

		for (i = 0; n == c_horizon_hops && i < HSEP_N_MAX; i++) {
			gtk_list_store_append(GTK_LIST_STORE(model), &iter);
			gtk_list_store_set(GTK_LIST_STORE(model), &iter,
				c_horizon_hops, i + 1,
				c_horizon_nodes, "-",
				c_horizon_files, "-",
				c_horizon_size, "-",
				(-1));
		}
		add_column(treeview, n, width[n], (gfloat) (n != 0), _(titles[n]));
	}
	gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);
	tree_view_set_fixed_height_mode(treeview, TRUE);
}

static void
gnet_stats_gui_flowc_init(void)
{
	GtkTreeView *treeview;
	GtkTreeModel *model;
	GType types[] = {
		G_TYPE_STRING,	/* Type */
		G_TYPE_STRING,	/* 0 */
		G_TYPE_STRING,	/* 1 */
		G_TYPE_STRING,	/* 2 */
		G_TYPE_STRING,	/* 3 */
		G_TYPE_STRING,	/* 4 */
		G_TYPE_STRING,	/* 5 */
		G_TYPE_STRING,	/* 6 */
		G_TYPE_STRING,	/* 7 */
		G_TYPE_STRING	/* 8+ */
	};
	guint32 width[STATS_FLOWC_COLUMNS];
	guint n;

	STATIC_ASSERT(STATS_FLOWC_COLUMNS == N_ITEMS(types));
	model = GTK_TREE_MODEL(gtk_list_store_newv(N_ITEMS(types), types));

	treeview = treeview_gnet_stats_flowc = GTK_TREE_VIEW(
	    gui_main_window_lookup("treeview_gnet_stats_flowc"));

	for (n = 0; (gint) n < msg_type_str_size(); n++) {
		GtkTreeIter iter;
		gint i;

		gtk_list_store_append(GTK_LIST_STORE(model), &iter);
		for (i = 0; i < STATS_FLOWC_COLUMNS; i++)
			gtk_list_store_set(GTK_LIST_STORE(model), &iter,
				i, i == 0 ? msg_type_str(n) : "-",
				(-1));
	}

	gui_prop_get_guint32(PROP_GNET_STATS_FC_COL_WIDTHS,
		width, 0, STATS_FLOWC_COLUMNS);
	for (n = 0; n < N_ITEMS(width); n++) {
		gchar buf[16];

		str_bprintf(buf, sizeof(buf), "%d%c", n - 1,
				n + 1 < STATS_FLOWC_COLUMNS ? '\0' : '+');
		add_column(treeview, n, width[n], (gfloat) (n != 0),
			n == 0 ? _("Type") : buf);
	}
	gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);
	tree_view_set_fixed_height_mode(treeview, TRUE);
}

static void
gnet_stats_gui_drop_reasons_init(void)
{
	GtkTreeView *treeview;
	GtkTreeModel *model;
	GType types[] = {
		G_TYPE_STRING,
		G_TYPE_STRING
	};
	guint32 width[N_ITEMS(types)];
	guint n;

	STATIC_ASSERT(2 == N_ITEMS(types));
	model = GTK_TREE_MODEL(gtk_list_store_newv(N_ITEMS(types), types));

	treeview = treeview_gnet_stats_drop_reasons = GTK_TREE_VIEW(
	    gui_main_window_lookup("treeview_gnet_stats_drop_reasons"));
	gui_prop_get_guint32(PROP_GNET_STATS_DROP_REASONS_COL_WIDTHS,
		width, 0, N_ITEMS(width));

	for (n = 0; n < N_ITEMS(types); n++) {
		GtkTreeIter iter;
		gint i;

		for (i = 0; n == 0 && i < MSG_DROP_REASON_COUNT; i++) {
			gtk_list_store_append(GTK_LIST_STORE(model), &iter);
			gtk_list_store_set(GTK_LIST_STORE(model), &iter,
				0, msg_drop_str(i), 1, "-", (-1));
		}

		add_column(treeview, n, width[n], (gfloat) (n != 0),
			n == 0 ? _("Reason") : _("Count"));
	}
	gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);
	tree_view_set_fixed_height_mode(treeview, TRUE);
}

static void
gnet_stats_gui_general_init(void)
{
	GtkTreeView *treeview;
	GtkTreeModel *model;
	GType types[] = {
		G_TYPE_STRING,
		G_TYPE_STRING
	};
	guint32 width[N_ITEMS(types)];
	guint n;

	STATIC_ASSERT(2 == N_ITEMS(types));
	model = GTK_TREE_MODEL(gtk_list_store_newv(N_ITEMS(types), types));

	treeview = treeview_gnet_stats_general = GTK_TREE_VIEW(
	    gui_main_window_lookup("treeview_gnet_stats_general"));
	gui_prop_get_guint32(PROP_GNET_STATS_GENERAL_COL_WIDTHS,
		width, 0, N_ITEMS(width));

	for (n = 0; n < N_ITEMS(types); n++) {
		GtkTreeIter iter;
		gint i;

		for (i = 0; n == 0 && i < GNR_TYPE_COUNT; i++) {
			gtk_list_store_append(GTK_LIST_STORE(model), &iter);
			gtk_list_store_set(GTK_LIST_STORE(model), &iter,
				0, general_type_str(i), 1, "-", (-1));
		}
		add_column(treeview, n, width[n], (gfloat) (n != 0),
			n == 0 ? _("Type") : _("Count"));
	}
	gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);
	tree_view_set_fixed_height_mode(treeview, TRUE);
}

static void
gnet_stats_gui_messages_init(void)
{
	GtkTreeView *treeview;
	GtkTreeModel *model;
	GType types[] = {
		G_TYPE_STRING,	/* c_gs_type */
		G_TYPE_STRING,	/* c_gs_received */
		G_TYPE_STRING,	/* c_gs_expired */
		G_TYPE_STRING,	/* c_gs_dropped */
		G_TYPE_STRING,	/* c_gs_queued */
		G_TYPE_STRING,	/* c_gs_relayed */
		G_TYPE_STRING,	/* c_gs_gen_queued */
		G_TYPE_STRING	/* c_gs_generated */
	};
	guint32 width[N_ITEMS(types)];
	guint n;

	STATIC_ASSERT(num_c_gs == N_ITEMS(msg_stats_label));
	STATIC_ASSERT(num_c_gs == N_ITEMS(types));
	model = GTK_TREE_MODEL(gtk_list_store_newv(N_ITEMS(types), types));

	treeview = treeview_gnet_stats_messages = GTK_TREE_VIEW(
	    gui_main_window_lookup("treeview_gnet_stats_messages"));

	for (n = 0; (gint) n < msg_type_str_size(); n++) {
		GtkTreeIter iter;
		gint i;

		gtk_list_store_append(GTK_LIST_STORE(model), &iter);
		for (i = 0; (guint) i < N_ITEMS(msg_stats_label); i++) {
			gtk_list_store_set(GTK_LIST_STORE(model), &iter,
				i, i == 0 ? msg_type_str(n) : "-",
				(-1));
		}
	}

	gui_prop_get_guint32(PROP_GNET_STATS_MSG_COL_WIDTHS,
		width, 0, N_ITEMS(width));

	for (n = 0; (guint) n < N_ITEMS(msg_stats_label); n++) {
		add_column(treeview, n, width[n], (gfloat) (n != 0),
			_(msg_stats_label[n]));
	}

	gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);
	tree_view_set_fixed_height_mode(treeview, TRUE);
}

static void
gnet_stats_gui_recv_init(void)
{
	GtkTreeView *treeview;
	GtkTreeModel *model;
	GType types[] = {
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING,
		G_TYPE_STRING
	};
	guint32 width[N_ITEMS(types)];
	guint n;

	STATIC_ASSERT(STATS_RECV_COLUMNS == N_ITEMS(types));
	STATIC_ASSERT(STATS_RECV_COLUMNS == N_ITEMS(width));
	model = GTK_TREE_MODEL(gtk_list_store_newv(N_ITEMS(types), types));

	treeview = treeview_gnet_stats_recv = GTK_TREE_VIEW(
	    gui_main_window_lookup("treeview_gnet_stats_recv"));
	gui_prop_get_guint32(PROP_GNET_STATS_RECV_COL_WIDTHS,
		width, 0, N_ITEMS(width));

	for (n = 0; n < N_ITEMS(width); n++) {
		gchar buf[16];

		str_bprintf(buf, sizeof(buf), "%d%c", n - 1,
				n + 1 < STATS_RECV_COLUMNS ? '\0' : '+');
		add_column(treeview, n, width[n], (gfloat) (n != 0),
			n == 0 ? _("Type") : buf);
	}

	for (n = 0; (gint) n < msg_type_str_size(); n++) {
		GtkTreeIter iter;
		gint i;

		gtk_list_store_append(GTK_LIST_STORE(model), &iter);
		for (i = 0; i < STATS_RECV_COLUMNS; i++) {
			gtk_list_store_set(GTK_LIST_STORE(model), &iter,
				i, i == 0 ? msg_type_str(n) : "-",
				(-1));
		}
	}

	gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);
}

/***
 *** Public functions
 ***/

void
gnet_stats_gui_init(void)
{
	notebook_gnet_stats = GTK_NOTEBOOK(
							gui_main_window_lookup("gnet_stats_notebook"));

	/*
	 * Initialize stats tables.
	 */

	gnet_stats_gui_drop_reasons_init();
	gnet_stats_gui_horizon_init();
	gnet_stats_gui_flowc_init();
	gnet_stats_gui_general_init();
	gnet_stats_gui_messages_init();
	gnet_stats_gui_recv_init();

	guc_hsep_add_global_table_listener(
		(callback_fn_t) gnet_stats_gui_horizon_update, FREQ_UPDATES, 0);

	main_gui_add_timer(gnet_stats_gui_timer);
}

void
gnet_stats_gui_shutdown(void)
{
	static const struct {
		property_t prop;
		GtkTreeView **tv;
	} widths[] = {
		{ 	PROP_GNET_STATS_GENERAL_COL_WIDTHS,
				&treeview_gnet_stats_general },
		{ 	PROP_GNET_STATS_DROP_REASONS_COL_WIDTHS,
				&treeview_gnet_stats_drop_reasons },
		{ 	PROP_GNET_STATS_MSG_COL_WIDTHS,
				&treeview_gnet_stats_messages },
		{ 	PROP_GNET_STATS_FC_COL_WIDTHS,
				&treeview_gnet_stats_flowc },
		{ 	PROP_GNET_STATS_RECV_COL_WIDTHS,
				&treeview_gnet_stats_recv },
		{ 	PROP_GNET_STATS_HORIZON_COL_WIDTHS,
				&treeview_gnet_stats_horizon },
	};
	size_t i;

	guc_hsep_remove_global_table_listener(
	    (callback_fn_t) gnet_stats_gui_horizon_update);

	for (i = 0; i < N_ITEMS(widths); i++) {
		tree_view_save_widths(*widths[i].tv, widths[i].prop);
	}
}

void
gnet_stats_gui_update_display(time_t now)
{
	static gnet_stats_t stats;
	gint current_page;

	guc_gnet_stats_get(&stats);

	current_page = gtk_notebook_get_current_page(notebook_gnet_stats);
	switch ((enum gnet_stats_nb_page) current_page) {
	case GNET_STATS_NB_PAGE_STATS:
		gnet_stats_update_general(&stats);
		gnet_stats_update_drop_reasons(&stats);
		break;
	case GNET_STATS_NB_PAGE_HORIZON:
		gnet_stats_update_horizon(now);
		break;
	case GNET_STATS_NB_PAGE_MESSAGES:
		switch (GUI_PROPERTY(gnet_stats_source)) {
		case GNET_STATS_FULL:
			break;
		case GNET_STATS_TCP_ONLY:
			guc_gnet_stats_tcp_get(&stats);
			break;
		case GNET_STATS_UDP_ONLY:
			guc_gnet_stats_udp_get(&stats);
			break;
		default:
			g_assert_not_reached();
		}
		gnet_stats_update_messages(&stats);
		break;
	case GNET_STATS_NB_PAGE_FLOWC:
		gnet_stats_update_flowc(&stats);
		break;
	case GNET_STATS_NB_PAGE_RECV:
		gnet_stats_update_recv(&stats);
		break;
	case NUM_GNET_STATS_NB_PAGES:
		break;
	}
}

/* vi: set ts=4 sw=4 cindent: */
