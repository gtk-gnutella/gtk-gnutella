/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Richard Eckart
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

#include <ctype.h> /* for isdigit() */
#include "gnet_stats_gui2.h"
#include "gnutella.h" /* for sizeof(struct gnutella_header) */

gchar *msg_type_str[MSG_TYPE_COUNT] = {
    "Unknown",
    "Ping",
    "Pong",
    "Bye",
    "QRP",
    "Vendor Spec.",
    "Vendor Std.",
    "Push",
    "Query",
    "Query Hit",
    "Total"
};

gchar *msg_drop_str[MSG_DROP_REASON_COUNT] = {
    "Bad size",
    "Too small",
    "Too large",
	"Way too large",
    "Unknown message type",
    "Message sent with TTL = 0",
    "Max TTL exceeded",
    "Ping throttle",
	"Unusable Pong",
    "Hard TTL limit reached",
    "Max hop count reached",
    "Unrequested reply",
    "Route lost",
    "No route",
    "Duplicate message",
    "Message to banned GUID",
    "Node shutting down",
    "Flow control",
    "Query text had no trailing NUL",
    "Query text too short",
    "Query had unnecessary overhead",
    "Malformed SHA1 Query",
    "Malformed UTF-8 Query",
    "Malformed Query Hit",
    "Query hit had bad SHA1"
};

gchar *general_type_str[GNR_TYPE_COUNT] = {
    "Routing errors",
    "Searches to local DB",
    "Hits on local DB",
    "Compacted queries",
    "Bytes saved by compacting",
    "UTF8 queries",
    "SHA1 queries"
};

gchar *msg_stats_label[] = {
	"Type",
	"Received",
	"Expired",
	"Dropped",
	"Relayed",
	"Generated"
};

static guint gnet_stats_mode = 0;

#define MODE_FC_ABSOLUTE	0x01
#define MODE_FC_HEADERS		0x02
#define MODE_FC_PACKETS		0x04
#define MODE_FC_TTL			0x08

#define MODE_RECV_ABSOLUTE	0x10
#define MODE_RECV_HEADERS	0x20
#define MODE_RECV_PACKETS	0x40
#define MODE_RECV_TTL		0x80

#define MODE_MSGS_ABSOLUTE	0x100
#define MODE_MSGS_PACKETS	0x200
 
enum {
	GNET_STATS_NB_PAGE_GENERAL,
	GNET_STATS_NB_PAGE_DROP_REASONS,
	GNET_STATS_NB_PAGE_MESSAGES,
	GNET_STATS_NB_PAGE_FLOWC,
	GNET_STATS_NB_PAGE_RECV,

	GNET_STATS_NP_PAGE_NUMBER
};

static gint selected_type = MSG_TOTAL;

static void column_set_hidden(GtkTreeView *, const gchar *, gboolean);


/***
 *** Callbacks
 ***/

static void on_gnet_stats_column_resized(
	GtkTreeViewColumn *column, gpointer data)
{
	const gchar *widget_name;
	const gchar *title;
	guint32 width;
	gint property;
	gint column_id;
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;

	if (!g_static_mutex_trylock(&mutex))
		return;

	widget_name = gtk_widget_get_name(column->tree_view);
	title = gtk_tree_view_column_get_title(column);
 	width = gtk_tree_view_column_get_width(column);

#if 0
	g_message("%s: widget=\"%s\" title=\"%s\", width=%u",
		__FUNCTION__, widget_name, title, width);
#endif

	if (!(strcmp(title, "Type")))
		column_id = 0;
	else if (!(strcmp(title, "Count")))
		column_id = 1;
	else if (!(strcmp(title, "Received")))
		column_id = 1;
	else if (!(strcmp(title, "Expired")))
		column_id = 2;
	else if (!(strcmp(title, "Dropped")))
		column_id = 3;
	else if (!(strcmp(title, "Relayed")))
		column_id = 4;
	else if (!(strcmp(title, "Generated")))
		column_id = 5;
	else if (isdigit((guchar) title[0])) {
		column_id = (title[0] - '0') + 1;
		g_assert(column_id >= 1 && column_id <= 9);
	}
	else {
		column_id = -1;
		g_assert_not_reached();
	}

    if (!strcmp(widget_name, "treeview_gnet_stats_general"))
		property = PROP_GNET_STATS_GENERAL_COL_WIDTHS;
    else if (!strcmp(widget_name, "treeview_gnet_stats_drop_reasons"))
		property = PROP_GNET_STATS_DROP_REASONS_COL_WIDTHS;
    else if (!strcmp(widget_name, "treeview_gnet_stats_messages"))
		property = PROP_GNET_STATS_MSG_COL_WIDTHS;
    else if (!strcmp(widget_name, "treeview_gnet_stats_flowc"))
		property = PROP_GNET_STATS_FC_COL_WIDTHS;
    else if (!strcmp(widget_name, "treeview_gnet_stats_recv"))
		property = PROP_GNET_STATS_RECV_COL_WIDTHS;
	else {
		property = -1;
		g_assert_not_reached();
	}

	gui_prop_set_guint32(property, &width, column_id, 1);
	g_static_mutex_unlock(&mutex);
}

static void on_gnet_stats_type_selected(GtkItem *i, gpointer data)
{
    selected_type = GPOINTER_TO_INT(data);
    gnet_stats_gui_update();
}

#define GNET_STATS_BUTTON_TOGGLED(a, b)										 \
static void on_gnet_stats_##a##_toggled(									 \
	GtkWidget *widget, gpointer data)										 \
{																			 \
	gboolean value;															 \
																			 \
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))			 \
		gnet_stats_mode |= (b);												 \
	else																	 \
	 	gnet_stats_mode &= ~(b);											 \
	value = FALSE != (gnet_stats_mode & (b));								 \
	gui_prop_set_boolean(PROP_GNET_STATS_##b, &value, 0, 1);	 			 \
	gnet_stats_gui_update();												 \
}

GNET_STATS_BUTTON_TOGGLED(msgs_packets, MODE_MSGS_PACKETS)
GNET_STATS_BUTTON_TOGGLED(msgs_absolute, MODE_MSGS_ABSOLUTE)
GNET_STATS_BUTTON_TOGGLED(fc_absolute, MODE_FC_ABSOLUTE)
GNET_STATS_BUTTON_TOGGLED(fc_headers, MODE_FC_HEADERS)
GNET_STATS_BUTTON_TOGGLED(fc_packets, MODE_FC_PACKETS)
GNET_STATS_BUTTON_TOGGLED(recv_absolute, MODE_RECV_ABSOLUTE)
GNET_STATS_BUTTON_TOGGLED(recv_headers, MODE_RECV_HEADERS)
GNET_STATS_BUTTON_TOGGLED(recv_packets, MODE_RECV_PACKETS)

static void on_gnet_stats_fc_ttl_toggled(GtkWidget *widget, gpointer data)
{
	gboolean value;
	/* Hide column for TTL=0 */
	
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
		gnet_stats_mode |= MODE_FC_TTL;										
	else
		gnet_stats_mode &= ~MODE_FC_TTL;										
	column_set_hidden(
		GTK_TREE_VIEW(lookup_widget(main_window, "treeview_gnet_stats_flowc")),
		"0", gnet_stats_mode & MODE_FC_TTL);
	value = FALSE != (gnet_stats_mode & MODE_FC_TTL);
	gui_prop_set_boolean(PROP_GNET_STATS_MODE_FC_TTL, &value, 0, 1);
	gnet_stats_gui_update();
}

static void on_gnet_stats_recv_ttl_toggled(GtkWidget *widget, gpointer data)
{
	gboolean value;
	/* Hide column for TTL=0 */
	
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget)))
		gnet_stats_mode |= MODE_RECV_TTL;
	else
		gnet_stats_mode &= ~MODE_RECV_TTL;
	column_set_hidden(
		GTK_TREE_VIEW(lookup_widget(main_window, "treeview_gnet_stats_recv")),
		"0", gnet_stats_mode & MODE_RECV_TTL);
	value = FALSE != (gnet_stats_mode & MODE_RECV_TTL);
	gui_prop_set_boolean(PROP_GNET_STATS_MODE_RECV_TTL, &value, 0, 1);
    gnet_stats_gui_update();
}

/***
 *** Private functions
 ***/

static void column_set_hidden(
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
	gchar *strbuf, gulong n, const guint32 *val_tbl, gint type)
{
    if (val_tbl[type] == 0)
		g_strlcpy(strbuf, "-", n);
    else if (gnet_stats_mode & MODE_MSGS_ABSOLUTE)
        g_snprintf(strbuf, n, "%u", val_tbl[type]);
    else
        g_snprintf(strbuf, n, "%.2f%%", 
            (gfloat) val_tbl[type] / val_tbl[MSG_TOTAL] * 100.0);

    return strbuf;
}


const gchar *byte_stat_str(
	gchar *strbuf, gulong n, const guint32 *val_tbl, gint type)
{
    if (val_tbl[type] == 0)
		g_strlcpy(strbuf, "-", n);
    else if (gnet_stats_mode & MODE_MSGS_ABSOLUTE)
        g_strlcpy(strbuf, compact_size(val_tbl[type]), n);
    else
        g_snprintf(strbuf, n, "%.2f%%", 
            (gfloat) val_tbl[type] / val_tbl[MSG_TOTAL] * 100.0);

	return strbuf;
}

const gchar *drop_stat_str(
	gchar *str, gulong n, const gnet_stats_t *stats, gint reason)
{
    guint32 total = stats->pkg.dropped[MSG_TOTAL];

    if (stats->drop_reason[reason][selected_type] == 0)
		g_strlcpy(str, "-", n);
    else if (gnet_stats_drop_perc)
        g_snprintf(str, n, "%.2f%%", 
            (gfloat)stats->drop_reason[reason][selected_type]/total*100);
    else
        g_snprintf(str, n, "%u", stats->drop_reason[reason][selected_type]);

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
        g_snprintf(str, n, "%u", stats->general[type]);

	return str;
}

static const gchar *type_stat_str(
	gchar *strbuf,
	gulong n,
	gulong value,
	gulong total,
	gboolean absolute,
	gboolean packets)
{
	if (value == 0 || total == 0) {
		g_strlcpy(strbuf, "-", n);
	} else if (absolute) {
		if (packets)
       		g_snprintf(strbuf, n, "%lu", (gulong) value);
		else
			g_strlcpy(strbuf, compact_size(value), n);
	} else 
		g_snprintf(strbuf, n, "%.2f%%", (gfloat) value/total*100.0);

    return strbuf;
}

static void add_column(
	GtkTreeView *treeview, gint column_id, const gchar *label)
{
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;

	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes(
					label, renderer, "text", column_id, NULL);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_GROW_ONLY);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_reorderable(column, TRUE);
	gtk_tree_view_append_column(treeview, column);
	g_object_notify(G_OBJECT(column), "width");
	g_signal_connect(G_OBJECT(column), "notify::width",
		G_CALLBACK(on_gnet_stats_column_resized), NULL);
}

static void gnet_stats_update_general(const gnet_stats_t *stats)
{
    GtkTreeView *treeview;
    GtkListStore *store;
    GtkTreeIter iter;
    gint n;
	static gchar str[32];

    treeview = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_general"));
	store = GTK_LIST_STORE(gtk_tree_view_get_model(treeview));
	gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);

	for (n = 0; n < GNR_TYPE_COUNT; n++) {
		general_stat_str(str, sizeof(str), stats, n++);
		gtk_list_store_set(store, &iter, 1, str, -1);
		gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
	}
}

static void gnet_stats_update_drop_reasons(const gnet_stats_t *stats)
{
    GtkTreeView *treeview;
    GtkListStore *store;
    GtkTreeIter iter;
    gint n;
	static gchar str[32];

    treeview = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_drop_reasons"));
	store = GTK_LIST_STORE(gtk_tree_view_get_model(treeview));
	gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);

	for (n = 0; n < MSG_DROP_REASON_COUNT; n++) {
		drop_stat_str(str, sizeof(str), stats, n++);
		gtk_list_store_set(store, &iter, 1, str, -1);
		gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
	}

}

static void gnet_stats_update_messages(const gnet_stats_t *stats)
{
    GtkTreeView *treeview;
    GtkListStore *store;
    GtkTreeIter iter;
    gint n;
	static char str[5][32];

    treeview = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_messages"));
	store = GTK_LIST_STORE(gtk_tree_view_get_model(treeview));
	gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);

    for (n = 0; n < MSG_TYPE_COUNT; n ++) {
		if (gnet_stats_mode & MODE_MSGS_PACKETS) {
			gtk_list_store_set(store, &iter,
				c_gs_received,
				pkt_stat_str(str[0], sizeof(str[0]), stats->pkg.received, n), 
				c_gs_generated,
				pkt_stat_str(str[1], sizeof(str[0]), stats->pkg.generated, n),
				c_gs_dropped,
				pkt_stat_str(str[2], sizeof(str[0]), stats->pkg.dropped, n),
				c_gs_expired,
				pkt_stat_str(str[3], sizeof(str[0]), stats->pkg.expired, n),
				c_gs_relayed,
				pkt_stat_str(str[4], sizeof(str[0]), stats->pkg.relayed, n),
				-1);
		} else { /* byte mode */
			gtk_list_store_set(store, &iter,
				c_gs_received,
				byte_stat_str(str[0], sizeof(str[0]), stats->byte.received, n),
				c_gs_generated,
				byte_stat_str(str[1], sizeof(str[0]), stats->byte.generated, n),
				c_gs_dropped,
				byte_stat_str(str[2], sizeof(str[0]), stats->byte.dropped, n),
				c_gs_expired,
				byte_stat_str(str[3], sizeof(str[0]), stats->byte.expired, n),
				c_gs_relayed,
				byte_stat_str(str[4], sizeof(str[0]), stats->byte.relayed, n),
				-1);
    	}
		gtk_tree_model_iter_next(GTK_TREE_MODEL(store), &iter);
	}

}

static void gnet_stats_update_types(
	const gnet_stats_t *stats,
	const gchar *treeview_name,
	gboolean absolute,
	gboolean packets,
	gboolean with_headers,
	gint columns,
	const guint32 (*byte_counters)[MSG_TYPE_COUNT],
	const guint32 (*pkg_counters)[MSG_TYPE_COUNT])
{
    GtkTreeView *treeview;
    GtkListStore *store;
    GtkTreeIter iter;
    gint n;
	static gchar str[MSG_TYPE_COUNT][32];

    treeview = GTK_TREE_VIEW(lookup_widget(main_window, treeview_name));
	store = GTK_LIST_STORE(gtk_tree_view_get_model(treeview));
	gtk_tree_model_get_iter_first(GTK_TREE_MODEL(store), &iter);


	for (n = 0; n < MSG_TYPE_COUNT; n++) {
		gint i;

		if (packets)
			for (i = 0; i < columns; i++)
				type_stat_str(str[i], sizeof(str[0]),
					(gulong) pkg_counters[i][n],
					(gulong) pkg_counters[i][MSG_TOTAL],
					absolute, packets);
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
				type_stat_str(str[i], sizeof(str[0]),
					value, total, absolute, packets);
			}

		gtk_list_store_set(store, &iter,
			1, str[0], 2, str[1], 3, str[2], 4, str[3], 5, str[4],
			6, str[5], 7, str[6], 8, str[7], 9, str[8], -1);
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

	if (gnet_stats_mode & MODE_FC_TTL) {
		pkg_counters = stats->pkg.flowc_ttl;
		byte_counters = stats->byte.flowc_ttl;
	} else {
		pkg_counters = stats->pkg.flowc_hops;
		byte_counters = stats->byte.flowc_hops;
	}
	gnet_stats_update_types(stats,
		"treeview_gnet_stats_flowc",
		gnet_stats_mode & MODE_FC_ABSOLUTE,
		gnet_stats_mode & MODE_FC_PACKETS,
		gnet_stats_mode & MODE_FC_HEADERS,
		STATS_FLOWC_COLUMNS,
		byte_counters,
		pkg_counters);
}

static void gnet_stats_update_recv(const gnet_stats_t *stats)
{
	const guint32 (*byte_counters)[MSG_TYPE_COUNT];
	const guint32 (*pkg_counters)[MSG_TYPE_COUNT];

	if (gnet_stats_mode & MODE_RECV_TTL) {
		pkg_counters = stats->pkg.received_ttl;
		byte_counters = stats->byte.received_ttl;
	} else {
		pkg_counters = stats->pkg.received_hops;
		byte_counters = stats->byte.received_hops;
	}
	gnet_stats_update_types(stats,
		"treeview_gnet_stats_recv",
		gnet_stats_mode & MODE_RECV_ABSOLUTE,
		gnet_stats_mode & MODE_RECV_PACKETS,
		gnet_stats_mode & MODE_RECV_HEADERS,
		STATS_RECV_COLUMNS,
		byte_counters,
		pkg_counters);
}

/***
 *** Public functions
 ***/

void gnet_stats_gui_init(void)
{
    GtkTreeView *treeview;
    GtkTreeModel *model;
    GtkCombo *combo;
    gint n;

    treeview = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_messages"));
	model = GTK_TREE_MODEL(gtk_list_store_new(6,
							G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
							G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING));

	for (n = 0; n < MSG_TYPE_COUNT; n++) {
		GtkTreeIter iter;
		gint i;

		gtk_list_store_append(GTK_LIST_STORE(model), &iter);
			for (i = 0; i < 6; i++)
				gtk_list_store_set(GTK_LIST_STORE(model), &iter, i,
					i == 0 ? msg_type_str[n] : "-", -1);
	}

	for (n = 0; n < G_N_ELEMENTS(msg_stats_label); n++)
		add_column(treeview, n, msg_stats_label[n]);

    gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);

    treeview = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_flowc"));
	model = GTK_TREE_MODEL(
		gtk_list_store_new(STATS_FLOWC_COLUMNS,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING));

	for (n = 0; n < STATS_FLOWC_COLUMNS; n++) {
    	gchar buf[16];

		g_snprintf(buf, sizeof(buf), "%d%c", n-1,
				(n+1) < STATS_FLOWC_COLUMNS ? '\0' : '+');
		add_column(treeview, n, n == 0 ? "Type" : buf);
	}

	for (n = 0; n < MSG_TYPE_COUNT; n++) {
		GtkTreeIter iter;
		gint i;

		gtk_list_store_append(GTK_LIST_STORE(model), &iter);
			for (i = 0; i < STATS_FLOWC_COLUMNS; i++)
				gtk_list_store_set(GTK_LIST_STORE(model), &iter, i,
					i == 0 ? msg_type_str[n] : "-", -1);
	}

    gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);

    /*
     * Initialize stats tables.
     */

    combo = GTK_COMBO(
        lookup_widget(main_window, "combo_gnet_stats_type"));

    for (n = 0; n < MSG_TYPE_COUNT; n ++) {
        GtkWidget *list_item;
        GList *l;

        list_item = gtk_list_item_new_with_label(msg_type_str[n]);
        gtk_widget_show(list_item);

        g_signal_connect(
            GTK_OBJECT(list_item), "select",
            G_CALLBACK(on_gnet_stats_type_selected),
            GINT_TO_POINTER(n));

        l = g_list_prepend(NULL, (gpointer) list_item);
        gtk_list_append_items(GTK_LIST(GTK_COMBO(combo)->list), l);

        if (n == MSG_TOTAL)
            gtk_list_select_child(GTK_LIST(GTK_COMBO(combo)->list), list_item);
    }


	/* ----------------------------------------- */

    treeview = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_drop_reasons"));
	model = GTK_TREE_MODEL(
		gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_STRING));

	for (n = 0; n < 2; n++) {
		GtkTreeIter iter;
		gint i;

		for (i = 0; n == 0 && i < MSG_DROP_REASON_COUNT; i++) {
			gtk_list_store_append(GTK_LIST_STORE(model), &iter);
			gtk_list_store_set(GTK_LIST_STORE(model), &iter,
				0, msg_drop_str[i], 1, "-", -1);
		}

		add_column(treeview, n, n == 0 ? "Type" : "Count");
	}

    gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);

	/* ----------------------------------------- */

    treeview = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_general"));
	model = GTK_TREE_MODEL(
		gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_STRING));

	for (n = 0; n < 2; n++) {
		GtkTreeIter iter;
		gint i;

		for (i = 0; n == 0 && i < GNR_TYPE_COUNT; i++) {
			gtk_list_store_append(GTK_LIST_STORE(model), &iter);
			gtk_list_store_set(GTK_LIST_STORE(model), &iter,
				0, general_type_str[i], 1, "-", -1);
		}
		add_column(treeview, n, n == 0 ? "Type" : "Count");
	}

    gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);

	/* ----------------------------------------- */

    treeview = GTK_TREE_VIEW(
        lookup_widget(main_window, "treeview_gnet_stats_recv"));
	model = GTK_TREE_MODEL(
		gtk_list_store_new(STATS_RECV_COLUMNS,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING));

	for (n = 0; n < STATS_FLOWC_COLUMNS; n++) {
    	gchar buf[16];

		g_snprintf(buf, sizeof(buf), "%d%c", n-1,
				(n+1) < STATS_RECV_COLUMNS ? '\0' : '+');
		add_column(treeview, n, n == 0 ? "Type" : buf);
	}

	for (n = 0; n < MSG_TYPE_COUNT; n++) {
		GtkTreeIter iter;
		gint i;

		gtk_list_store_append(GTK_LIST_STORE(model), &iter);
			for (i = 0; i < STATS_RECV_COLUMNS; i++)
				gtk_list_store_set(GTK_LIST_STORE(model), &iter, i,
					i == 0 ? msg_type_str[n] : "-", -1);
	}

    gtk_tree_view_set_model(treeview, model);
	g_object_unref(model);

	/* Install signal handlers for view selection buttons */

	g_signal_connect(GTK_CHECK_BUTTON(
		lookup_widget(main_window, "checkbutton_gnet_stats_fc_headers")),
		"toggled", G_CALLBACK(on_gnet_stats_fc_headers_toggled), NULL);
	g_signal_connect(GTK_RADIO_BUTTON(
		lookup_widget(main_window, "radio_gnet_stats_fc_absolute")),
		"toggled", G_CALLBACK(on_gnet_stats_fc_absolute_toggled), NULL);
	g_signal_connect(GTK_RADIO_BUTTON(
		lookup_widget(main_window, "radio_gnet_stats_fc_packets")),
		"toggled", G_CALLBACK(on_gnet_stats_fc_packets_toggled), NULL);
	g_signal_connect(
		GTK_RADIO_BUTTON(lookup_widget(main_window, "radio_gnet_stats_fc_ttl")),
		"toggled", G_CALLBACK(on_gnet_stats_fc_ttl_toggled), NULL);

	g_signal_connect(GTK_RADIO_BUTTON(
		lookup_widget(main_window, "radio_gnet_stats_msgs_absolute")),
		"toggled", G_CALLBACK(on_gnet_stats_msgs_absolute_toggled), NULL);
	g_signal_connect(GTK_RADIO_BUTTON(
		lookup_widget(main_window, "radio_gnet_stats_msgs_packets")),
		"toggled", G_CALLBACK(on_gnet_stats_msgs_packets_toggled), NULL);

	g_signal_connect(GTK_CHECK_BUTTON(
		lookup_widget(main_window, "checkbutton_gnet_stats_recv_headers")),
		"toggled", G_CALLBACK(on_gnet_stats_recv_headers_toggled), NULL);
	g_signal_connect(GTK_RADIO_BUTTON(
		lookup_widget(main_window, "radio_gnet_stats_recv_absolute")),
		"toggled", G_CALLBACK(on_gnet_stats_recv_absolute_toggled), NULL);
	g_signal_connect(GTK_RADIO_BUTTON(
		lookup_widget(main_window, "radio_gnet_stats_recv_packets")),
		"toggled", G_CALLBACK(on_gnet_stats_recv_packets_toggled), NULL);
	g_signal_connect(GTK_RADIO_BUTTON(
		lookup_widget(main_window, "radio_gnet_stats_recv_ttl")),
		"toggled", G_CALLBACK(on_gnet_stats_recv_ttl_toggled), NULL);
}


void gnet_stats_gui_update(void)
{
    gnet_stats_t stats;
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;
    gint current_page;

	if (!g_static_mutex_trylock(&mutex))
		return;
	
    current_page = gtk_notebook_get_current_page(
        GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main")));
    if (current_page != nb_main_page_gnet_stats)
		goto cleanup;

    gnet_stats_get(&stats);

    current_page = gtk_notebook_get_current_page(
        GTK_NOTEBOOK(lookup_widget(main_window, "gnet_stats_notebook")));

	switch (current_page) {
		case GNET_STATS_NB_PAGE_GENERAL:
			gnet_stats_update_general(&stats);
			break;
		case GNET_STATS_NB_PAGE_DROP_REASONS:
			gnet_stats_update_drop_reasons(&stats);
			break;
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
