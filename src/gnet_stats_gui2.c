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

#include "config.h"

#ifdef USE_GTK2

#include "gnet_stats_gui.h"
#include "gnutella.h" /* for sizeof(struct gnutella_header) */

RCSID("$Id$");

static GtkTreeView *treeview_gnet_stats_messages = NULL;
static GtkTreeView *treeview_gnet_stats_drop_reasons = NULL;
static GtkTreeView *treeview_gnet_stats_flowc = NULL;
static GtkTreeView *treeview_gnet_stats_recv = NULL;
static GtkTreeView *treeview_gnet_stats_general = NULL;
static GtkNotebook *notebook_main = NULL;
static GtkNotebook *notebook_gnet_stats = NULL;

static const gchar *msg_stats_label[] = {
	"Type",
	"Received",
	"Expired",
	"Dropped",
	"Relayed",
	"Generated"
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
	gchar *strbuf, gulong n, const guint32 *val_tbl, gint type, gboolean perc)
{
    if (val_tbl[type] == 0)
		g_strlcpy(strbuf, "-", n);
    else {
		if (!perc)
        	gm_snprintf(strbuf, n, "%lu", (gulong) val_tbl[type]);
    	else
        	gm_snprintf(strbuf, n, "%.2f%%", 
            	(gfloat) val_tbl[type] / val_tbl[MSG_TOTAL] * 100.0);
	}

    return strbuf;
}


static const gchar *byte_stat_str(
	gchar *strbuf, gulong n, const guint32 *val_tbl, gint type, gboolean perc)
{
    if (val_tbl[type] == 0)
		g_strlcpy(strbuf, "-", n);
    else if (!perc)
        g_strlcpy(strbuf, compact_size(val_tbl[type]), n);
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
        gm_snprintf(str, n, "%u", stats->drop_reason[reason][selected_type]);

    return str;
}

static const gchar *general_stat_str(
	gchar *str, gulong n, const gnet_stats_t *stats, gint type)
{
    if (stats->general[type] == 0)
        g_strlcpy(str, "-", n);
    else if (type == GNR_QUERY_COMPACT_SIZE)
        g_strlcpy(str, compact_size(stats->general[type]), n);
    else
        gm_snprintf(str, n, "%u", stats->general[type]);

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
    GtkTreeView *treeview = treeview_gnet_stats_general;
    GtkListStore *store;
    GtkTreeIter iter;
    gint n;
	static gchar str[32];

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
    GtkTreeView *treeview = treeview_gnet_stats_drop_reasons;
    GtkListStore *store;
    GtkTreeIter iter;
    gint n;
	static gchar str[32];

	store = GTK_LIST_STORE(gtk_tree_view_get_model(treeview));
	gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);

	for (n = 0; n < MSG_DROP_REASON_COUNT; n++) {
		drop_stat_str(str, sizeof(str), stats, n,
			gnet_stats_drop_reasons_type);
		gtk_list_store_set(store, &iter, 1, str, (-1));
		gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
	}

}

static void gnet_stats_update_messages(const gnet_stats_t *stats)
{
    GtkTreeView *treeview = treeview_gnet_stats_messages;
    GtkListStore *store;
    GtkTreeIter iter;
    gint n;
	gboolean perc = FALSE;
	gboolean bytes = FALSE;
	static char str[5][32];
	const size_t len = sizeof(str[0]);

	gui_prop_get_boolean_val(PROP_GNET_STATS_PERC, &perc);
	gui_prop_get_boolean_val(PROP_GNET_STATS_BYTES, &bytes);

	store = GTK_LIST_STORE(gtk_tree_view_get_model(treeview));
	gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);

    for (n = 0; n < MSG_TYPE_COUNT; n ++) {
		if (!bytes) {
			gtk_list_store_set(store, &iter,
				c_gs_received,
				pkt_stat_str(str[0], len, stats->pkg.received, n, perc), 
				c_gs_generated,
				pkt_stat_str(str[1], len, stats->pkg.generated, n, perc),
				c_gs_dropped,
				pkt_stat_str(str[2], len, stats->pkg.dropped, n, perc),
				c_gs_expired,
				pkt_stat_str(str[3], len, stats->pkg.expired, n, perc),
				c_gs_relayed,
				pkt_stat_str(str[4], len, stats->pkg.relayed, n, perc),
				(-1));
		} else { /* byte mode */
			gtk_list_store_set(store, &iter,
				c_gs_received,
				byte_stat_str(str[0], len, stats->byte.received, n, perc),
				c_gs_generated,
				byte_stat_str(str[1], len, stats->byte.generated, n, perc),
				c_gs_dropped,
				byte_stat_str(str[2], len, stats->byte.dropped, n, perc),
				c_gs_expired,
				byte_stat_str(str[3], len, stats->byte.expired, n, perc),
				c_gs_relayed,
				byte_stat_str(str[4], len, stats->byte.relayed, n, perc),
				(-1));
    	}
		gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
	}

}

static void gnet_stats_update_types(
	const gnet_stats_t *stats,
	GtkTreeView *treeview,
	gint columns,
	const guint32 (*byte_counters)[MSG_TYPE_COUNT],
	const guint32 (*pkg_counters)[MSG_TYPE_COUNT])
{
    GtkListStore *store;
    GtkTreeIter iter;
    gint n;
	gboolean perc = FALSE;
	gboolean bytes = FALSE;
	gboolean with_headers = FALSE;
	static gchar str[MSG_TYPE_COUNT][32];

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
#if 0		
		g_message("%-12s %-4s %-4s %-4s %-4s %-4s %-4s %-4s",
			msg_type_str[n],
			str[0], str[1], str[2], str[3], str[4], str[5], str[6]);
#endif
		gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
	}

#if 0 
	g_message(" ");
#endif
}

static void gnet_stats_update_flowc(const gnet_stats_t *stats)
{
	const guint32 (*byte_counters)[MSG_TYPE_COUNT];
	const guint32 (*pkg_counters)[MSG_TYPE_COUNT];
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
	const guint32 (*byte_counters)[MSG_TYPE_COUNT];
	const guint32 (*pkg_counters)[MSG_TYPE_COUNT];
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

/***
 *** Public functions
 ***/

void gnet_stats_gui_init(void)
{
    GtkTreeView *treeview;
    GtkTreeModel *model;
	GtkOptionMenu *option_menu;
	GtkWidget *menu;
    gint n;
	guint32 *width;

	notebook_main = GTK_NOTEBOOK(
		lookup_widget(main_window, "notebook_main"));
	notebook_gnet_stats = GTK_NOTEBOOK(
		lookup_widget(main_window, "gnet_stats_notebook"));
    treeview = treeview_gnet_stats_messages = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_messages"));
	model = GTK_TREE_MODEL(gtk_list_store_new(6,
							G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
							G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING));

	for (n = 0; n < G_N_ELEMENTS(msg_type_str); n++) {
		GtkTreeIter iter;
		gint i;

		gtk_list_store_append(GTK_LIST_STORE(model), &iter);
			for (i = 0; i < 6; i++)
				gtk_list_store_set(GTK_LIST_STORE(model), &iter, i,
					i == 0 ? msg_type_str[n] : "-", (-1));
	}

	width = gui_prop_get_guint32(
				PROP_GNET_STATS_MSG_COL_WIDTHS, NULL, 0, 0);
	for (n = 0; n < G_N_ELEMENTS(msg_stats_label); n++)
		add_column(treeview, n, width[n], (gfloat) (n != 0),
			msg_stats_label[n]);
	G_FREE_NULL(width);

    gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);

    treeview = treeview_gnet_stats_flowc = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_flowc"));
	model = GTK_TREE_MODEL(
		gtk_list_store_new(STATS_FLOWC_COLUMNS,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING));

	width = gui_prop_get_guint32(
				PROP_GNET_STATS_FC_COL_WIDTHS, NULL, 0, 0);
	for (n = 0; n < STATS_FLOWC_COLUMNS; n++) {
    	gchar buf[16];

		gm_snprintf(buf, sizeof(buf), "%d%c", n - 1,
				n + 1 < STATS_FLOWC_COLUMNS ? '\0' : '+');
		add_column(treeview, n, width[n], (gfloat) (n != 0),
			n == 0 ? "Type" : buf);
	}
	G_FREE_NULL(width);

	for (n = 0; n < G_N_ELEMENTS(msg_type_str); n++) {
		GtkTreeIter iter;
		gint i;

		gtk_list_store_append(GTK_LIST_STORE(model), &iter);
		for (i = 0; i < STATS_FLOWC_COLUMNS; i++)
			gtk_list_store_set(GTK_LIST_STORE(model), &iter, i,
				i == 0 ? msg_type_str[n] : "-", (-1));
	}

    gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);

    /*
     * Initialize stats tables.
     */

	option_menu = GTK_OPTION_MENU(
		lookup_widget(main_window, "option_menu_gnet_stats_type"));
	menu = gtk_menu_new();

	for (n = 0; n < G_N_ELEMENTS(msg_type_str); n ++) {
		GtkWidget *menu_item;

		menu_item = gtk_menu_item_new_with_label(_(msg_type_str[n]));
		gtk_menu_shell_append(GTK_MENU_SHELL(menu), menu_item);
		g_signal_connect(
			GTK_OBJECT(menu_item), "activate",
			G_CALLBACK(on_gnet_stats_type_selected),
			GINT_TO_POINTER(n));
	}
	gtk_option_menu_set_menu(option_menu, menu);
	gtk_option_menu_set_history(option_menu, MSG_TOTAL);
	gtk_widget_show_all(GTK_WIDGET(option_menu));


	/* ----------------------------------------- */

    treeview = treeview_gnet_stats_drop_reasons = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_drop_reasons"));
	model = GTK_TREE_MODEL(
		gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_STRING));

	width = gui_prop_get_guint32(
				PROP_GNET_STATS_DROP_REASONS_COL_WIDTHS, NULL, 0, 0);
	for (n = 0; n < 2; n++) {
		GtkTreeIter iter;
		gint i;

		for (i = 0; n == 0 && i < MSG_DROP_REASON_COUNT; i++) {
			gtk_list_store_append(GTK_LIST_STORE(model), &iter);
			gtk_list_store_set(GTK_LIST_STORE(model), &iter,
				0, msg_drop_str[i], 1, "-", (-1));
		}

		add_column(treeview, n, width[n], (gfloat) n != 0,
			n == 0 ? "Type" : "Count");
	}
	G_FREE_NULL(width);

    gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);

	/* ----------------------------------------- */

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
				0, general_type_str[i], 1, "-", (-1));
		}
		add_column(treeview, n, width[n], (gfloat) n != 0,
			n == 0 ? "Type" : "Count");
	}
	G_FREE_NULL(width);

    gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);

	/* ----------------------------------------- */

    treeview = treeview_gnet_stats_recv = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_recv"));
	model = GTK_TREE_MODEL(
		gtk_list_store_new(STATS_RECV_COLUMNS,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING));

	width = gui_prop_get_guint32(
				PROP_GNET_STATS_RECV_COL_WIDTHS, NULL, 0, 0);
	for (n = 0; n < STATS_FLOWC_COLUMNS; n++) {
    	gchar buf[16];

		gm_snprintf(buf, sizeof(buf), "%d%c", n - 1,
				n + 1 < STATS_RECV_COLUMNS ? '\0' : '+');
		add_column(treeview, n, width[n], (gfloat) (n != 0),
			n == 0 ? "Type" : buf);
	}
	G_FREE_NULL(width);

	for (n = 0; n < G_N_ELEMENTS(msg_type_str); n++) {
		GtkTreeIter iter;
		gint i;

		gtk_list_store_append(GTK_LIST_STORE(model), &iter);
		for (i = 0; i < STATS_RECV_COLUMNS; i++)
			gtk_list_store_set(GTK_LIST_STORE(model), &iter, i,
				i == 0 ? msg_type_str[n] : "-", (-1));
	}

    gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);
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
}

void gnet_stats_gui_update(time_t now)
{
    static gnet_stats_t stats;
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;
	static time_t last_update = 0;
    gint current_page;

	if (last_update == now || !g_static_mutex_trylock(&mutex))
		return;
	last_update = now;
	
    current_page = gtk_notebook_get_current_page(notebook_main);
    if (current_page != nb_main_page_gnet_stats)
		goto cleanup;

    gnet_stats_get(&stats);

    current_page = gtk_notebook_get_current_page(notebook_gnet_stats);

	gnet_stats_update_general(&stats);
	gnet_stats_update_drop_reasons(&stats);

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
	g_static_mutex_unlock(&mutex);
}

#endif	/* USE_GTK2 */
