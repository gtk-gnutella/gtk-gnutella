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

#include "common.h"

#ifdef USE_GTK2

#include "gnet_stats_gui.h"
#include "gnutella.h" /* for sizeof(struct gnutella_header) */
#include "hsep.h"
#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

static GtkTreeView *treeview_gnet_stats_messages = NULL;
static GtkTreeView *treeview_gnet_stats_drop_reasons = NULL;
static GtkTreeView *treeview_gnet_stats_flowc = NULL;
static GtkTreeView *treeview_gnet_stats_recv = NULL;
static GtkTreeView *treeview_gnet_stats_general = NULL;
static GtkTreeView *treeview_gnet_stats_horizon = NULL;
static GtkNotebook *notebook_main = NULL;
static GtkNotebook *notebook_gnet_stats = NULL;

static const gchar *msg_stats_label[] = {
	N_("Type"),
	N_("Received"),
	N_("Expired"),
	N_("Dropped"),
	N_("Relayed"),
	N_("Generated")
};

enum {
	GNET_STATS_NB_PAGE_MESSAGES,
	GNET_STATS_NB_PAGE_FLOWC,
	GNET_STATS_NB_PAGE_RECV,

	GNET_STATS_NP_PAGE_NUMBER
};

static void hide_column_by_title(GtkTreeView *, const gchar *, gboolean);
static void gnet_stats_update_drop_reasons(const gnet_stats_t *);


/***
 *** Callbacks
 ***/

static gint gnet_stats_drop_reasons_type = MSG_TOTAL;

static void on_gnet_stats_type_selected(GtkItem *i, gpointer data)
{
	static gnet_stats_t stats;

	gnet_stats_drop_reasons_type = GPOINTER_TO_INT(data);
	gnet_stats_get(&stats);
	gnet_stats_update_drop_reasons(&stats);
}

/***
 *** Private functions
 ***/

static void hide_column_by_title(
	GtkTreeView *treeview, const gchar *header_title, gboolean hidden)
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

static gchar *pkt_stat_str(
	gchar *strbuf, gulong n, const guint64 *val_tbl, gint type, gboolean perc)
{
    if (val_tbl[type] == 0)
		g_strlcpy(strbuf, "-", n);
    else {
		if (!perc)
        	gm_snprintf(strbuf, n, "%llu", val_tbl[type]);
    	else
        	gm_snprintf(strbuf, n, "%.2f%%", 
            	(gfloat) val_tbl[type] / val_tbl[MSG_TOTAL] * 100.0);
	}

    return strbuf;
}


static const gchar *byte_stat_str(
	gchar *strbuf, gulong n, const guint64 *val_tbl, gint type, gboolean perc)
{
    if (val_tbl[type] == 0)
		g_strlcpy(strbuf, "-", n);
    else if (!perc)
        g_strlcpy(strbuf, compact_size64(val_tbl[type]), n);
    else
        gm_snprintf(strbuf, n, "%.2f%%", 
            (gfloat) val_tbl[type] / val_tbl[MSG_TOTAL] * 100.0);

	return strbuf;
}

static const gchar *drop_stat_str(
	gchar *str,
	gulong n,
	const gnet_stats_t *stats,
	gint reason,
	gint selected_type)
{
    guint32 total = stats->pkg.dropped[MSG_TOTAL];

    if (stats->drop_reason[reason][selected_type] == 0)
		g_strlcpy(str, "-", n);
    else if (gnet_stats_drop_perc)
        gm_snprintf(str, n, "%.2f%%", 
            (gfloat) stats->drop_reason[reason][selected_type] / total * 100);
    else
        gm_snprintf(str, n, "%llu", stats->drop_reason[reason][selected_type]);

    return str;
}

static const gchar *general_stat_str(
	gchar *str, gulong n, const gnet_stats_t *stats, gint type)
{
    if (stats->general[type] == 0)
        g_strlcpy(str, "-", n);
    else if (type == GNR_QUERY_COMPACT_SIZE)
        g_strlcpy(str, compact_size64(stats->general[type]), n);
    else
        gm_snprintf(str, n, "%" G_GUINT64_FORMAT, stats->general[type]);

	return str;
}

static const gchar *type_stat_str(
	gchar *strbuf,
	gulong n,
	gulong value,
	gulong total,
	gboolean perc,
	gboolean bytes)
{
	if (value == 0 || total == 0)
		g_strlcpy(strbuf, "-", n);
	else if (perc)
		gm_snprintf(strbuf, n, "%.2f%%", (gfloat) value / total * 100.0);
	else {
		if (bytes)
			g_strlcpy(strbuf, compact_size(value), n);
		else
       		gm_snprintf(strbuf, n, "%lu", (gulong) value);
	}

    return strbuf;
}

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
	column = gtk_tree_view_column_new_with_attributes(label, renderer,
		"text", column_id,
		NULL);
	g_object_set(column,
		"fixed-width", MAX(1, width),
		"min-width", 1,
		"reorderable", TRUE,
		"resizable", TRUE,
		"sizing", GTK_TREE_VIEW_COLUMN_FIXED,
		NULL);
	gtk_tree_view_append_column(treeview, column);
}

static void gnet_stats_update_general(const gnet_stats_t *stats)
{
	static gchar str[32];
    GtkTreeView *treeview = treeview_gnet_stats_general;
    GtkListStore *store;
    GtkTreeIter iter;
    gint n;

	store = GTK_LIST_STORE(gtk_tree_view_get_model(treeview));
	gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);

	for (n = 0; n < GNR_TYPE_COUNT; n++) {
		general_stat_str(str, sizeof(str), stats, n);
		gtk_list_store_set(store, &iter, 1, str, (-1));
		gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
	}
}

static void gnet_stats_update_drop_reasons(
	const gnet_stats_t *stats)
{
	static gchar str[32];
    GtkTreeView *treeview = treeview_gnet_stats_drop_reasons;
    GtkListStore *store;
    GtkTreeIter iter;
    gint n;

	store = GTK_LIST_STORE(gtk_tree_view_get_model(treeview));
	gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);

	for (n = 0; n < MSG_DROP_REASON_COUNT; n++) {
		drop_stat_str(str, sizeof(str), stats, n, gnet_stats_drop_reasons_type);
		gtk_list_store_set(store, &iter, 1, str, (-1));
		gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
	}
}

static void gnet_stats_update_messages(const gnet_stats_t *stats)
{
	static char str[num_c_gs][32];
	static const size_t len = sizeof(str[0]);
    GtkTreeView *treeview = treeview_gnet_stats_messages;
    GtkListStore *store;
    GtkTreeIter iter;
	gboolean perc = FALSE;
	gboolean bytes = FALSE;
    c_gs_t n;

	gui_prop_get_boolean_val(PROP_GNET_STATS_PERC, &perc);
	gui_prop_get_boolean_val(PROP_GNET_STATS_BYTES, &bytes);

	store = GTK_LIST_STORE(gtk_tree_view_get_model(treeview));
	gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);

    for (n = 0; n < num_c_gs; n ++) {
		if (!bytes) {
			gtk_list_store_set(store, &iter,
				c_gs_received,	pkt_stat_str(str[c_gs_received],
									len, stats->pkg.received, n, perc), 
				c_gs_generated, pkt_stat_str(str[c_gs_generated],
									len, stats->pkg.generated, n, perc),
				c_gs_dropped,	pkt_stat_str(str[c_gs_dropped],
									len, stats->pkg.dropped, n, perc),
				c_gs_expired,	pkt_stat_str(str[c_gs_expired],
									len, stats->pkg.expired, n, perc),
				c_gs_relayed,	pkt_stat_str(str[c_gs_relayed],
									len, stats->pkg.relayed, n, perc),
				(-1));
		} else { /* byte mode */
			gtk_list_store_set(store, &iter,
				c_gs_received,	byte_stat_str(str[c_gs_received],
									len, stats->byte.received, n, perc),
				c_gs_generated, byte_stat_str(str[c_gs_generated],
									len, stats->byte.generated, n, perc),
				c_gs_dropped,	byte_stat_str(str[c_gs_dropped],
									len, stats->byte.dropped, n, perc),
				c_gs_expired,	byte_stat_str(str[c_gs_expired],
									len, stats->byte.expired, n, perc),
				c_gs_relayed,	byte_stat_str(str[c_gs_relayed],
									len, stats->byte.relayed, n, perc),
				(-1));
    	}
		gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
	}

}

static void gnet_stats_update_types(
	const gnet_stats_t *stats,
	GtkTreeView *treeview,
	gint columns,
	const guint64 (*byte_counters)[MSG_TYPE_COUNT],
	const guint64 (*pkg_counters)[MSG_TYPE_COUNT])
{
	static gchar str[MSG_TYPE_COUNT][32];
    GtkListStore *store;
    GtkTreeIter iter;
	gboolean perc = FALSE;
	gboolean bytes = FALSE;
	gboolean with_headers = FALSE;
    gint n;

	gui_prop_get_boolean_val(PROP_GNET_STATS_PERC, &perc);
	gui_prop_get_boolean_val(PROP_GNET_STATS_BYTES, &bytes);
	gui_prop_get_boolean_val(PROP_GNET_STATS_WITH_HEADERS, &with_headers);

	store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(treeview)));
	gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);

	for (n = 0; n < MSG_TYPE_COUNT; n++) {
		gint i;

		if (!bytes)
			for (i = 0; i < columns; i++)
				type_stat_str(str[i], sizeof(str[0]),
					(gulong) pkg_counters[i][n],
					(gulong) pkg_counters[i][MSG_TOTAL],
					perc, FALSE);
		else
			for (i = 0; i < columns; i++) {
				gulong	value;
				gulong	total;
		
				value = byte_counters[i][n];
				total = byte_counters[i][MSG_TOTAL];
				if (with_headers) {
					value += pkg_counters[i][n]
						* sizeof(struct gnutella_header);
					total += pkg_counters[i][MSG_TOTAL]
						* sizeof(struct gnutella_header);
				}
				type_stat_str(str[i], sizeof(str[0]), value, total, perc, TRUE);
			}

		gtk_list_store_set(store, &iter,
			1, str[0], 2, str[1], 3, str[2], 4, str[3], 5, str[4],
			6, str[5], 7, str[6], 8, str[7], 9, str[8], (-1));
		gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
	}

}

static void gnet_stats_update_flowc(const gnet_stats_t *stats)
{
	const guint64 (*byte_counters)[MSG_TYPE_COUNT];
	const guint64 (*pkg_counters)[MSG_TYPE_COUNT];
	GtkTreeView *treeview = treeview_gnet_stats_flowc;
	gboolean hops = FALSE;

	gui_prop_get_boolean_val(PROP_GNET_STATS_HOPS, &hops);
	if (hops) {
		pkg_counters = stats->pkg.flowc_hops;
		byte_counters = stats->byte.flowc_hops;
	} else {
		pkg_counters = stats->pkg.flowc_ttl;
		byte_counters = stats->byte.flowc_ttl;
	}
	hide_column_by_title(treeview, "0", !hops);
	gnet_stats_update_types(stats, treeview, STATS_FLOWC_COLUMNS,
		byte_counters, pkg_counters);
}

static void gnet_stats_update_recv(const gnet_stats_t *stats)
{
	const guint64 (*byte_counters)[MSG_TYPE_COUNT];
	const guint64 (*pkg_counters)[MSG_TYPE_COUNT];
	GtkTreeView *treeview = treeview_gnet_stats_recv;
	gboolean hops = FALSE;
	
	gui_prop_get_boolean_val(PROP_GNET_STATS_HOPS, &hops);
	if (hops) {
		pkg_counters = stats->pkg.received_hops;
		byte_counters = stats->byte.received_hops;
	} else {
		pkg_counters = stats->pkg.received_ttl;
		byte_counters = stats->byte.received_ttl;
	}
	hide_column_by_title(treeview, "0", !hops);
	gnet_stats_update_types(stats, treeview, STATS_FLOWC_COLUMNS,
		byte_counters, pkg_counters);
}

static void gnet_stats_update_horizon(void)
{
    GtkTreeView *treeview = treeview_gnet_stats_horizon;
    GtkListStore *store;
    GtkTreeIter iter;
    gint n;
	hsep_triple hsep_table[HSEP_N_MAX + 1];

	hsep_get_global_table(hsep_table, G_N_ELEMENTS(hsep_table));

	store = GTK_LIST_STORE(gtk_tree_view_get_model(treeview));
	gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);

	/* Skip the first element */
	for (n = 1; n < G_N_ELEMENTS(hsep_table); n++) {
		gtk_list_store_set(store, &iter,
			c_horizon_nodes, horizon_stat_str(hsep_table, n, c_horizon_nodes),
		    c_horizon_files, horizon_stat_str(hsep_table, n, c_horizon_files),
		    c_horizon_size,	 horizon_stat_str(hsep_table, n, c_horizon_size),
			(-1));
		gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
	}
}

static void gnet_stats_gui_horizon_init(void)
{
	static const gchar * const titles[num_c_horizon] = {
		N_("Hops"),
		N_("Nodes"),
		N_("Files"),
		N_("Size")
	};
    GtkTreeView *treeview;
    GtkTreeModel *model;
	guint32 *width;
	c_horizon_t n;

    treeview = treeview_gnet_stats_horizon = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_horizon"));
	model = GTK_TREE_MODEL(
		gtk_list_store_new(num_c_horizon,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING));

	width = gui_prop_get_guint32(
				PROP_GNET_STATS_HORIZON_COL_WIDTHS, NULL, 0, 0);
	for (n = 0; n < num_c_horizon; n++) {
		GtkTreeIter iter;
		gint i;

		for (i = 0; n == c_horizon_hops && i < HSEP_N_MAX; i++) {
			gtk_list_store_append(GTK_LIST_STORE(model), &iter);
			gtk_list_store_set(GTK_LIST_STORE(model), &iter,
				c_horizon_hops, horizon_stat_str(NULL, i + 1, 0),
				c_horizon_nodes, "-",
				c_horizon_files, "-",
				c_horizon_size, "-",
				(-1));
		}
		add_column(treeview, n, width[n], (gfloat) (n != 0), titles[n]);
	}
	G_FREE_NULL(width);
    gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);
}

static void gnet_stats_gui_flowc_init(void)
{
    GtkTreeView *treeview;
    GtkTreeModel *model;
	guint32 *width;
	guint n;

    treeview = treeview_gnet_stats_flowc = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_flowc"));
	model = GTK_TREE_MODEL(
		gtk_list_store_new(STATS_FLOWC_COLUMNS,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING));

	for (n = 0; n < msg_type_str_size(); n++) {
		GtkTreeIter iter;
		gint i;

		gtk_list_store_append(GTK_LIST_STORE(model), &iter);
		for (i = 0; i < STATS_FLOWC_COLUMNS; i++)
			gtk_list_store_set(GTK_LIST_STORE(model), &iter,
				i, i == 0 ? msg_type_str(n) : "-",
				(-1));
	}

	width = gui_prop_get_guint32(PROP_GNET_STATS_FC_COL_WIDTHS, NULL, 0, 0);
	for (n = 0; n < STATS_FLOWC_COLUMNS; n++) {
    	gchar buf[16];

		gm_snprintf(buf, sizeof(buf), "%d%c", n - 1,
				n + 1 < STATS_FLOWC_COLUMNS ? '\0' : '+');
		add_column(treeview, n, width[n], (gfloat) (n != 0),
			n == 0 ? "Type" : buf);
	}
	G_FREE_NULL(width);
    gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);
}

static void gnet_stats_gui_drop_reasons_init(void)
{
    GtkTreeView *treeview;
    GtkTreeModel *model;
	guint32 *width;
	guint n;

    treeview = treeview_gnet_stats_drop_reasons = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_drop_reasons"));
	model = GTK_TREE_MODEL(gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_STRING));

	width = gui_prop_get_guint32(
				PROP_GNET_STATS_DROP_REASONS_COL_WIDTHS, NULL, 0, 0);
	for (n = 0; n < 2; n++) {
		GtkTreeIter iter;
		gint i;

		for (i = 0; n == 0 && i < MSG_DROP_REASON_COUNT; i++) {
			gtk_list_store_append(GTK_LIST_STORE(model), &iter);
			gtk_list_store_set(GTK_LIST_STORE(model), &iter,
				0, msg_drop_str(i), 1, "-", (-1));
		}

		add_column(treeview, n, width[n], (gfloat) (n != 0),
			n == 0 ? N_("Type") : N_("Count"));
	}
	G_FREE_NULL(width);
    gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);
}

static void gnet_stats_gui_general_init(void)
{
    GtkTreeView *treeview;
    GtkTreeModel *model;
	guint32 *width;
	guint n;

    treeview = treeview_gnet_stats_general = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_general"));
	model = GTK_TREE_MODEL(
		gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_STRING));

	width = gui_prop_get_guint32(
				PROP_GNET_STATS_GENERAL_COL_WIDTHS, NULL, 0, 0);
	for (n = 0; n < 2; n++) {
		GtkTreeIter iter;
		gint i;

		for (i = 0; n == 0 && i < GNR_TYPE_COUNT; i++) {
			gtk_list_store_append(GTK_LIST_STORE(model), &iter);
			gtk_list_store_set(GTK_LIST_STORE(model), &iter,
				0, general_type_str(i), 1, "-", (-1));
		}
		add_column(treeview, n, width[n], (gfloat) (n != 0),
			n == 0 ? N_("Type") : N_("Count"));
	}
	G_FREE_NULL(width);
    gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);
}

static void gnet_stats_gui_messages_init(void)
{
    GtkTreeView *treeview;
    GtkTreeModel *model;
	guint32 *width;
	guint n;

    treeview = treeview_gnet_stats_messages = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_messages"));
	model = GTK_TREE_MODEL(gtk_list_store_new(G_N_ELEMENTS(msg_stats_label),
							G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
							G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING));

	for (n = 0; n < msg_type_str_size(); n++) {
		GtkTreeIter iter;
		gint i;

		gtk_list_store_append(GTK_LIST_STORE(model), &iter);
		for (i = 0; i < G_N_ELEMENTS(msg_stats_label); i++) {
			gtk_list_store_set(GTK_LIST_STORE(model), &iter,
				i, i == 0 ? msg_type_str(n) : "-",
				(-1));
		}
	}

	width = gui_prop_get_guint32(
				PROP_GNET_STATS_MSG_COL_WIDTHS, NULL, 0, 0);
	for (n = 0; (guint) n < G_N_ELEMENTS(msg_stats_label); n++)
		add_column(treeview, n, width[n], (gfloat) (n != 0),
			msg_stats_label[n]);
	G_FREE_NULL(width);

    gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);
}

static void gnet_stats_gui_recv_init(void)
{
    GtkTreeView *treeview;
    GtkTreeModel *model;
	guint32 *width;
	guint n;

    treeview = treeview_gnet_stats_recv = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_recv"));
	model = GTK_TREE_MODEL(
		gtk_list_store_new(STATS_RECV_COLUMNS,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING));

	width = gui_prop_get_guint32(PROP_GNET_STATS_RECV_COL_WIDTHS, NULL, 0, 0);
	for (n = 0; n < STATS_FLOWC_COLUMNS; n++) {
    	gchar buf[16];

		gm_snprintf(buf, sizeof(buf), "%d%c", n - 1,
				n + 1 < STATS_RECV_COLUMNS ? '\0' : '+');
		add_column(treeview, n, width[n], (gfloat) (n != 0),
			n == 0 ? N_("Type") : buf);
	}
	G_FREE_NULL(width);

	for (n = 0; n < msg_type_str_size(); n++) {
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

static void gnet_stats_gui_type_menu_init(void)
{
	GtkOptionMenu *option_menu;
	GtkWidget *menu;
	guint n;

	option_menu = GTK_OPTION_MENU(
		lookup_widget(main_window, "option_menu_gnet_stats_type"));
	menu = gtk_menu_new();

	for (n = 0; n < msg_type_str_size(); n++) {
		GtkWidget *menu_item;

		menu_item = gtk_menu_item_new_with_label(msg_type_str(n));
		gtk_menu_shell_append(GTK_MENU_SHELL(menu), menu_item);
		g_signal_connect(
			GTK_OBJECT(menu_item), "activate",
			G_CALLBACK(on_gnet_stats_type_selected),
			GINT_TO_POINTER(n));
	}
	gtk_option_menu_set_menu(option_menu, menu);
	gtk_option_menu_set_history(option_menu, MSG_TOTAL);
	gtk_widget_show_all(GTK_WIDGET(option_menu));
}


/***
 *** Public functions
 ***/

void gnet_stats_gui_init(void)
{
	notebook_main = GTK_NOTEBOOK(
		lookup_widget(main_window, "notebook_main"));
	notebook_gnet_stats = GTK_NOTEBOOK(
		lookup_widget(main_window, "gnet_stats_notebook"));

    /*
     * Initialize stats tables.
     */

	gnet_stats_gui_drop_reasons_init();
	gnet_stats_gui_horizon_init();
	gnet_stats_gui_flowc_init();
	gnet_stats_gui_general_init();
	gnet_stats_gui_messages_init();
	gnet_stats_gui_recv_init();
	gnet_stats_gui_type_menu_init();
}

void gnet_stats_gui_shutdown(void)
{
    tree_view_save_widths(treeview_gnet_stats_general,
		PROP_GNET_STATS_GENERAL_COL_WIDTHS);
    tree_view_save_widths(treeview_gnet_stats_drop_reasons,
		PROP_GNET_STATS_DROP_REASONS_COL_WIDTHS);
    tree_view_save_widths(treeview_gnet_stats_messages,
		PROP_GNET_STATS_MSG_COL_WIDTHS);
    tree_view_save_widths(treeview_gnet_stats_flowc,
		PROP_GNET_STATS_FC_COL_WIDTHS);
    tree_view_save_widths(treeview_gnet_stats_recv,
		PROP_GNET_STATS_RECV_COL_WIDTHS);
    tree_view_save_widths(treeview_gnet_stats_horizon,
		PROP_GNET_STATS_HORIZON_COL_WIDTHS);
}

void gnet_stats_gui_update(time_t now)
{
    static gnet_stats_t stats;
	static gboolean locked = FALSE;
	static time_t last_update = 0;
    gint current_page;

	if (last_update == now || locked)
		return;
	last_update = now;
	locked = TRUE;
	
    current_page = gtk_notebook_get_current_page(notebook_main);
    if (current_page != nb_main_page_gnet_stats)
		goto cleanup;

    gnet_stats_get(&stats);

    current_page = gtk_notebook_get_current_page(notebook_gnet_stats);

	gnet_stats_update_general(&stats);
	gnet_stats_update_drop_reasons(&stats);
	gnet_stats_update_horizon();

	switch (current_page) {
	case GNET_STATS_NB_PAGE_MESSAGES:
		gnet_stats_update_messages(&stats);
		break;
	case GNET_STATS_NB_PAGE_FLOWC:
		gnet_stats_update_flowc(&stats);
		break;
	case GNET_STATS_NB_PAGE_RECV:
		gnet_stats_update_recv(&stats);
		break;
	default:
		g_assert_not_reached();
	}

cleanup:
	locked = FALSE;
}

/* vi: set ts=4: */
#endif	/* USE_GTK2 */
