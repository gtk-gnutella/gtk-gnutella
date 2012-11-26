/*
 * Copyright (c) 2001-2003, Raphael Manfredi & Richard Eckart
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
 * General GUI functions and stuff which doesn't fit in anywhere else.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "gui.h"

#include "gtk-shared/callbacks.h"

#include "gtk/misc.h"

#include "settings.h"

#include "if/gnet_property.h"
#include "if/gui_property.h"
#include "if/gui_property_priv.h"

#include "if/core/net_stats.h"
#include "if/bridge/ui2c.h"

#include "lib/ascii.h"
#include "lib/parse.h"
#include "lib/str.h"
#include "lib/stringify.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * Implementation
 */

void
gui_update_files_scanned(void)
{
    static GtkLabel *label_files_scanned = NULL;
	gulong n = guc_shared_files_scanned();

	if (label_files_scanned == NULL)
		label_files_scanned =
			GTK_LABEL(gui_dlg_prefs_lookup("label_files_scanned"));

	gtk_label_printf(label_files_scanned,
		NG_("%lu file shared (%s)", "%lu files shared (%s)", n),
		n, short_kb_size(guc_shared_kbytes_scanned(), show_metric_units()));
}

void
gui_allow_rescan_dir(gboolean flag)
{
	gtk_widget_set_sensitive
        (gui_dlg_prefs_lookup("button_config_rescan_dir"), flag);
}

/**
 * Update some general information displayed in the gui.
 */
void
gui_general_timer(time_t now)
{
	static GtkLabel *label;
	const gchar *uptime;
	time_t start;

	if (label == NULL) {
		label = GTK_LABEL(gui_main_window_lookup("label_statusbar_uptime"));
	}
	gnet_prop_get_timestamp_val(PROP_START_STAMP, &start);
	uptime = short_uptime(delta_time(now, start));

#ifdef USE_GTK2
	{
		gchar buf[128];

		str_bprintf(buf, sizeof buf, "<tt>%s</tt>", uptime);
		gtk_label_set_use_markup(label, TRUE);
		gtk_label_set_markup(label, buf);
	}
#else

	gtk_label_set_text(label, uptime);
#endif /* USE_GTK2 */
}

static void
update_stat(guint32 *max, GtkProgressBar *pg,
    gnet_bw_stats_t *stats, gboolean avg_mode, gboolean inout)
{
    gfloat frac = 0;
    guint32 high_limit;
    guint32 current;
	guint32 max_bw = *max;
	gchar buf[128];

    current = avg_mode ? stats->average : stats->current;
    if (max_bw < current)
        max_bw = *max = current;
	else {
		guint32 new_max = stats->average + (stats->average >> 1);	/* 1.5 */
		if (max_bw > new_max)
			max_bw = *max = new_max;
	}

    high_limit = MAX(
        stats->enabled ? stats->limit : max_bw,
        current);
    frac = (high_limit == 0) ? 0 : (gfloat) current / high_limit;

	str_bprintf(buf, sizeof buf, "%s %s %s",
        short_rate(current, show_metric_units()),
        inout ? _("in") : _("out"),
        avg_mode ? _("(avg)") : "");
	gtk_progress_bar_set_text(pg, buf);
    gtk_progress_bar_set_fraction(pg, frac);
}

/**
 * Sum `dest' and `other', putting results in `dest'.
 */
static void
gnet_bw_stats_sum(gnet_bw_stats_t *dest, gnet_bw_stats_t *other)
{
	dest->current += other->current;
	dest->average += other->average;
	dest->limit += other->limit;
}

/* FIXME: stats that are turned off need not be calculated! */
void
gui_update_traffic_stats(void)
{
    static guint32 http_in_max = 0;
    static guint32 http_out_max = 0;
    static guint32 gnet_in_max = 0;
    static guint32 gnet_out_max = 0;
    static guint32 leaf_in_max = 0;
    static guint32 leaf_out_max = 0;
    static guint32 dht_in_max = 0;
    static guint32 dht_out_max = 0;
    gnet_bw_stats_t s;
    gnet_bw_stats_t s2;
    static GtkProgressBar *pg_http_in = NULL;
    static GtkProgressBar *pg_http_out = NULL;
    static GtkProgressBar *pg_gnet_in = NULL;
    static GtkProgressBar *pg_gnet_out = NULL;
    static GtkProgressBar *pg_leaf_in = NULL;
    static GtkProgressBar *pg_leaf_out = NULL;
    static GtkProgressBar *pg_dht_in = NULL;
    static GtkProgressBar *pg_dht_out = NULL;

	if (pg_http_in == NULL) {
		pg_http_in = GTK_PROGRESS_BAR(
			gui_main_window_lookup("progressbar_bws_in"));
		pg_http_out = GTK_PROGRESS_BAR
			(gui_main_window_lookup("progressbar_bws_out"));
		pg_gnet_in = GTK_PROGRESS_BAR
			(gui_main_window_lookup("progressbar_bws_gin"));
		pg_gnet_out = GTK_PROGRESS_BAR
			(gui_main_window_lookup("progressbar_bws_gout"));
		pg_leaf_in = GTK_PROGRESS_BAR
			(gui_main_window_lookup("progressbar_bws_lin"));
		pg_leaf_out = GTK_PROGRESS_BAR
			(gui_main_window_lookup("progressbar_bws_lout"));
		pg_dht_in = GTK_PROGRESS_BAR
			(gui_main_window_lookup("progressbar_bws_dht_in"));
		pg_dht_out = GTK_PROGRESS_BAR
			(gui_main_window_lookup("progressbar_bws_dht_out"));
	}

  	/*
	 * Since gtk_progress does not give us enough control over the format
     * of the displayed values, we have regenerate the value string on each
     * update.
	 *      --BLUE, 21/04/2002
	 */

   	/*
	 * If the bandwidth usage peaks above the maximum, then GTK will not
	 * update the progress bar, so we have to cheat and limit the value
	 * displayed.
	 *		--RAM, 16/04/2002
	 */

    guc_gnet_get_bw_stats(BW_HTTP_IN, &s);
    update_stat(&http_in_max, pg_http_in, &s,
		GUI_PROPERTY(progressbar_bws_in_avg), 1);

    guc_gnet_get_bw_stats(BW_HTTP_OUT, &s);
    update_stat(&http_out_max, pg_http_out, &s,
		GUI_PROPERTY(progressbar_bws_out_avg), 0);

    guc_gnet_get_bw_stats(BW_GNET_IN, &s);
    guc_gnet_get_bw_stats(BW_GNET_UDP_IN, &s2);
	gnet_bw_stats_sum(&s, &s2);
    update_stat(&gnet_in_max, pg_gnet_in, &s,
		GUI_PROPERTY(progressbar_bws_gin_avg), 1);

    guc_gnet_get_bw_stats(BW_GNET_OUT, &s);
    guc_gnet_get_bw_stats(BW_GNET_UDP_OUT, &s2);
	gnet_bw_stats_sum(&s, &s2);
    update_stat(&gnet_out_max, pg_gnet_out, &s,
		GUI_PROPERTY(progressbar_bws_gout_avg), 0);

    guc_gnet_get_bw_stats(BW_LEAF_IN, &s);
    update_stat(&leaf_in_max, pg_leaf_in, &s,
		GUI_PROPERTY(progressbar_bws_glin_avg), 1);

    guc_gnet_get_bw_stats(BW_LEAF_OUT, &s);
    update_stat(&leaf_out_max, pg_leaf_out, &s,
		GUI_PROPERTY(progressbar_bws_glout_avg), 0);

    guc_gnet_get_bw_stats(BW_DHT_IN, &s);
    update_stat(&dht_in_max, pg_dht_in, &s,
		GUI_PROPERTY(progressbar_bws_dht_in_avg), 1);

    guc_gnet_get_bw_stats(BW_DHT_OUT, &s);
    update_stat(&dht_out_max, pg_dht_out, &s,
		GUI_PROPERTY(progressbar_bws_dht_out_avg), 0);
}

/**
 * Utility routine to dynamically resize a widget after some items it holds
 * were hidden, so that the GTK layer can remove any uncessary hole that
 * would remain.
 */
void
gui_shrink_widget_named(const char *name)
{
#ifdef USE_GTK1
	GtkWidget *w = gui_main_window_lookup(name);

	if (w == NULL)
		return;

	gtk_widget_hide(w);
	gtk_widget_show(w);
#else	/* !USE_GTK1 */
	(void) name;
#endif	/* USE_GTK1 */
}

void
gui_update_stats_frames(void)
{
    static GtkWidget *frame_bws_inout = NULL;
    static GtkWidget *frame_bws_ginout = NULL;
    static GtkWidget *frame_bws_glinout = NULL;
    static GtkWidget *frame_bws_dht_inout = NULL;
    guint32 peermode;
	gboolean hidden = FALSE;

	if (frame_bws_inout == NULL) {
		frame_bws_inout = gui_main_window_lookup("frame_bws_inout");
		frame_bws_ginout = gui_main_window_lookup("frame_bws_ginout");
		frame_bws_glinout = gui_main_window_lookup("frame_bws_glinout");
		frame_bws_dht_inout = gui_main_window_lookup("frame_bws_dht_inout");
	}

   	gnet_prop_get_guint32_val(PROP_CURRENT_PEERMODE, &peermode);

    if (
		GUI_PROPERTY(progressbar_bws_in_visible) ||
		GUI_PROPERTY(progressbar_bws_out_visible)
	) {
        gtk_widget_show(frame_bws_inout);
    } else {
        gtk_widget_hide(frame_bws_inout);
		hidden = TRUE;
	}

    if (
		GUI_PROPERTY(progressbar_bws_gin_visible) ||
		GUI_PROPERTY(progressbar_bws_gout_visible)
	) {
        gtk_widget_show(frame_bws_ginout);
    } else {
        gtk_widget_hide(frame_bws_ginout);
		hidden = TRUE;
	}

    if (
		(
			GUI_PROPERTY(progressbar_bws_glin_visible) ||
			GUI_PROPERTY(progressbar_bws_glout_visible)
		) &&
        (peermode == NODE_P_ULTRA || !GUI_PROPERTY(autohide_bws_gleaf))
	) {
        gtk_widget_show(frame_bws_glinout);
    } else {
        gtk_widget_hide(frame_bws_glinout);
		hidden = TRUE;
	}

    if (
		(
			GUI_PROPERTY(progressbar_bws_dht_in_visible) ||
			GUI_PROPERTY(progressbar_bws_dht_out_visible)
		) &&
        (guc_dht_enabled() || !GUI_PROPERTY(autohide_bws_dht))
	) {
        gtk_widget_show(frame_bws_dht_inout);
    } else {
        gtk_widget_hide(frame_bws_dht_inout);
		hidden = TRUE;
	}

	if (hidden)
		gui_shrink_widget_named("vbox_sidebar_stats");
}

/**
 * If the given coordinates are not reasonable, they're appropriately
 * adjusted.
 *
 * @param	coord must point to an array of 4 guint32 values
 *			which describe an position an size [x, y, width, height].
 */
void
gui_fix_coords(guint32 *coord)
{
	gint x, y, w, h;
	gint screen_w, screen_h;

	g_return_if_fail(coord);

	screen_w = gdk_screen_width();
	screen_h = gdk_screen_height();
	if (GUI_PROPERTY(gui_debug))
		g_debug("screen: %dx%d", screen_w, screen_h);

	x = coord[0];
	y = coord[1];
	w = coord[2];
	h = coord[3];
	if (GUI_PROPERTY(gui_debug))
		g_debug("before: %dx%d+%d+%d", w, h, x, y);

	if (w < 200)
		w = MAX(screen_w / 2, 200);
	if (w > (screen_w / 10) * 15)
		w = screen_w;
	if (h < 200)
		h = MAX(screen_h / 2, 200);
	if (h > (screen_h / 10) * 15)
		h = screen_h;
	if (x > screen_w - 32 || x + w < 32)
		x = 0;
	if (y > screen_h - 32 || y + h < 32)
		y = 0;

	coord[0] = x;
	coord[1] = y;
	coord[2] = w;
	coord[3] = h;
	if (GUI_PROPERTY(gui_debug))
		g_debug("after: %dx%d+%d+%d", w, h, x, y);
}

/**
 * Parses an geometry string of the form [WIDTHxHEIGHT][+X+Y]. If the string
 * is not parsable a failure occurs. In case of failure, the coord[] array
 * is not touched. The coord[] array should be initialized with default
 * values before calling this function because the coordinates and the
 * dimensions are both optional and are not touched if omitted.
 *
 * @param spec  The string holding the geometry specification.
 * @param coord An array of four 32-bit integers representing
 *              x, y, width, height.
 * @return 0 on success, -1 on failure.
 */
gint
gui_parse_geometry_spec(const gchar *spec, guint32 coord[4])
{
	const gchar *endptr, *s;
	guint32 x, y, w, h;
	gint error;
	gboolean sign;

	g_return_val_if_fail(spec, -1);
	g_return_val_if_fail(coord, -1);

	x = coord[0];
	y = coord[1];
	w = coord[2];
	h = coord[3];

	s = spec;

	if (is_ascii_digit(s[0])) {
		w = parse_uint32(s, &endptr, 10, &error);
		if (error || 'x' != endptr[0]) {
			return -1;
		}

		s = &endptr[1];
		h = parse_uint32(s, &endptr, 10, &error);
		if (error) {
			return -1;
		}
		s = endptr;
	}

	switch (s[0]) {
	case '-':
		sign = -1;
		break;
	case '+':
		sign = 1;
		break;
	case '\0':
		goto done;
	default:
		return -1;
	}
	s++;

	x = parse_uint32(s, &endptr, 10, &error);
	if (error) {
		return -1;
	}
	s = endptr;
	if (sign < 0) {
		x = gdk_screen_width() - 1 - x - w;
	}

	switch (s[0]) {
	case '-':
		sign = -1;
		break;
	case '+':
		sign = 1;
		break;
	default:
		return -1;
	}
	s++;

	y = parse_uint32(s, &endptr, 10, &error);
	if (error) {
		return -1;
	}
	if (sign < 0) {
		y = gdk_screen_height() - 1 - y - h;
	}

done:
	coord[0] = x;
	coord[1] = y;
	coord[2] = w;
	coord[3] = h;
	return 0;
}

#if !GTK_CHECK_VERSION(2,0,0)
static void
gtk_window_get_position(GtkWindow *widget, int *x, int *y)
{
	g_assert(widget);
	gdk_window_get_root_origin(GTK_WIDGET(widget)->window, x, y);
}

static void
gtk_window_get_size(GtkWindow *widget, int *width, int *height)
{
	g_assert(widget);
	gdk_window_get_size(GTK_WIDGET(widget)->window, width, height);
}

static void
gtk_window_move(GtkWindow *widget, int x, int y)
{
	g_return_if_fail(widget);
	gdk_window_move(GTK_WIDGET(widget)->window, x, y);
}
#endif	/* Gtk+ < 2.x */

static void
gui_window_move_resize(GtkWidget *widget, int x, int y, int width, int height)
{
	g_return_if_fail(widget);
#if GTK_CHECK_VERSION(2,0,0)
	gtk_window_move(GTK_WINDOW(widget), x, y);
	gtk_window_resize(GTK_WINDOW(widget), width, height);
#else
	gdk_window_move_resize(GTK_WIDGET(widget)->window, x, y, width, height);
#endif	/* Gtk+ 2.x */
}


static void
anti_window_shift_hack(GtkWidget *widget, int x, int y, int width, int height)
{
	int ax, ay, dx, dy;
	
	/* First, move the window to the supposed location. Next make the
	 * window visible by gtk_window_get_position()... */

	gui_window_move_resize(widget, x, y, width, height);

	ax = x;
	ay = y;
	gtk_window_get_position(GTK_WINDOW(widget), &ax, &ay);

	/*
	 * (At least) FVWM2 doesn't take the window decoration into account
	 * when handling positions requests. Readjust the window position
	 * if we detect that the window manager added an offset.
	 */

	dx = ax - x;
	dy = ay - y;
	if (0 == dx && 0 == dy)
		return;

	if (abs(dx) > 64 || abs(dy) > 64)
		return;
	
	g_debug("anti_window_shift_hack: "
		"x=%d, y=%d, ax=%d, ay=%d , dx=%d, dy=%d",
			x, y, ax, ay, dx, dy);

	gtk_window_move(GTK_WINDOW(widget), x - dx, y - dy);
	gtk_window_get_position(GTK_WINDOW(widget), &ax, &ay);
	if (ax == x && ay == y)
		return;
		
	g_debug("anti_window_shift_hack failed: ax=%d, ay=%d", ax, ay);
}

void
gui_restore_window(GtkWidget *widget, property_t prop)
{
    guint32 coord[4] = { 0, 0, 0, 0 };
	int x, y, width, height;

    gui_prop_get_guint32(prop, coord, 0, G_N_ELEMENTS(coord));
	gui_fix_coords(coord);
	x = coord[0];
	y = coord[1];
	width = coord[2];
	height = coord[3];

    /*
     * We need to tell Gtk the size of the window, otherwise we'll get
     * strange side effects when the window is shown (like implicitly
     * resized widgets).
     *      -- Richard, 8/9/2002
     */

    gtk_window_set_default_size(GTK_WINDOW(widget), width, height);
    if (width != 0 && height != 0) {
		anti_window_shift_hack(widget, x, y, width, height);
	}

}

void
gui_save_window(GtkWidget *widget, property_t prop)
{
    guint32 coord[4] = { 0, 0, 0, 0};
	int x, y, w, h;

	gtk_window_get_position(GTK_WINDOW(widget), &x, &y);
	gtk_window_get_size(GTK_WINDOW(widget), &w, &h);
	coord[0] = x;
	coord[1] = y;
	coord[2] = w;
	coord[3] = h;
    gui_prop_set_guint32(prop, coord, 0, G_N_ELEMENTS(coord));
}

#ifdef USE_GTK2
/**
 * The following handles UI joining since the glade code is now
 * splitted into several files. Prevents huge UI creation functions
 * and allows GTK2 compilation on some platforms.
 *
 * @author ko (junkpile@free.fr)
 * @date 2003-02-08
 *
 */
typedef struct steal_dict_params {
	GtkWidget *target;
	GtkWidget *source;
} steal_dict_params_t;

/**
 * Transfers the widget dictionary for specified widget
 * from specified window to the main window.
 * If the widget is a container, recursively calls
 * itself on each child.
 *
 */
static void
gui_steal_widget_dict_recursive(GtkWidget *widget, gpointer user_data)
{
	const gchar *name;
	steal_dict_params_t *params = user_data;

	g_return_if_fail(widget);
	g_return_if_fail(user_data);

	name = gtk_widget_get_name(widget);
	if (name != NULL) {
		gpointer data = g_object_steal_data(G_OBJECT(params->source), name);
		if (data != NULL)
			g_object_set_data_full(G_OBJECT(params->target), name,
				data, (GDestroyNotify) gtk_widget_unref);
	}

	if (GTK_IS_CONTAINER(widget))
		gtk_container_foreach(GTK_CONTAINER(widget),
			gui_steal_widget_dict_recursive, user_data);
}

/**
 * Reparents children of specified window into a new notebook tab.
 * Also transfers the widget dictionary to specified toplevel
 * window so lookup_widget() is not broken afterwards.
 *
 * @author ko (junkpile@free.fr)
 * @date 2003-02-08
 */
void
gui_merge_window_as_tab(GtkWidget *toplvl,
	GtkWidget *notebook, GtkWidget *window)
{
	const gchar *title;
	steal_dict_params_t params;
	GList *children = NULL;

	params.target = toplvl;
	params.source = window;

	/*
	 * First recursively steal widget dictionary.
	 */
	gtk_container_foreach(GTK_CONTAINER(window),
		gui_steal_widget_dict_recursive, &params);

	/*
	 * Then reparent the first child of the window,
	 * using the window title as the new tab title.
	 */
	title = gtk_window_get_title(GTK_WINDOW(window));
	children = GLISTTRACK(gtk_container_get_children(GTK_CONTAINER(window)));

	if (children != NULL) {
		GtkWidget *child = GTK_WIDGET(children->data);
		if (child) {
			gtk_widget_reparent(child, notebook);
			gtk_notebook_set_tab_label_text(GTK_NOTEBOOK(notebook),
				child, title);
		}
		g_list_free(children);
	}
}

struct find_iter_by_data_context {
	GtkTreeIter iter;		/**< The iter to initialize */
	gconstpointer data;		/**< The data pointer to look for */
	guint column;			/**< The column to check for data */
	gboolean found;			/**< Set to TRUE when data was found */
};

static gboolean
tree_find_iter_by_data_helper(GtkTreeModel *model, GtkTreePath *unused_path,
	GtkTreeIter *iter, gpointer ctx_ptr)
{
	struct find_iter_by_data_context *ctx = ctx_ptr;
	static const GValue zero_value;
	GValue value = zero_value;

	(void) unused_path;

   	gtk_tree_model_get_value(model, iter, ctx->column, &value);
	g_assert(G_TYPE_POINTER == G_VALUE_TYPE(&value));

	if (g_value_peek_pointer(&value) == ctx->data) {
		ctx->iter = *iter;
		ctx->found = TRUE;
		return TRUE;	/* stop traversal */
	}
		
	return FALSE; /* continue traversal */
}

gboolean 
tree_find_iter_by_data(GtkTreeModel *model,
	guint column, gconstpointer data, GtkTreeIter *iter)
{
	struct find_iter_by_data_context ctx;

	ctx.data = data;
	ctx.found = FALSE;
	ctx.column = column;
	gtk_tree_model_foreach(model, tree_find_iter_by_data_helper, &ctx);

	if (ctx.found && iter)
		*iter = ctx.iter;

	return ctx.found;
}

#endif	/* USE_GTK2 */

void
paned_save_position(GtkPaned *paned, property_t prop)
{
	guint32 pos;
	
	g_return_if_fail(paned);

	pos = gtk_paned_get_position(paned);
	gui_prop_set_guint32_val(prop, pos);
}

void
paned_restore_position(GtkPaned *paned, property_t prop)
{
	guint32 pos;
	
	g_return_if_fail(paned);

	gui_prop_get_guint32_val(prop, &pos);
	gtk_paned_set_position(paned, pos);
}

#ifdef USE_GTK2
void
tree_view_save_widths(GtkTreeView *treeview, property_t prop)
{
	gint i;

	g_return_if_fail(treeview);

	for (i = 0; i < INT_MAX; i++) {
		GtkTreeViewColumn *c;
		guint32 width;

		c = gtk_tree_view_get_column(treeview, i);
		if (!c)
			break;

		width = gtk_tree_view_column_get_width(c);
		if ((gint) width > 0)
			gui_prop_set_guint32(prop, &width, i, 1);
	}
}

void
tree_view_restore_widths(GtkTreeView *treeview, property_t prop)
{
	gint i;

	g_return_if_fail(treeview);

	for (i = 0; i < INT_MAX; i++) {
		GtkTreeViewColumn *c;
		guint32 width;

		c = gtk_tree_view_get_column(treeview, i);
		if (!c)
			break;
		gui_prop_get_guint32(prop, &width, i, 1);
		g_object_set(G_OBJECT(c),
			"fixed-width", MAX(1, (gint32) width),
			(void *) 0);
	}
}

void
tree_view_save_visibility(GtkTreeView *treeview, property_t prop)
{
	guint i;

	g_return_if_fail(treeview);

	for (i = 0; i < INT_MAX; i++) {
		GtkTreeViewColumn *c;
		gboolean val;

		c = gtk_tree_view_get_column(treeview, i);
		if (!c)
			break;
		val = gtk_tree_view_column_get_visible(c);
		gui_prop_set_boolean(prop, &val, i, 1);
	}
}

void
tree_view_restore_visibility(GtkTreeView *treeview, property_t prop)
{
	guint i;

	g_return_if_fail(treeview);

	for (i = 0; i < INT_MAX; i++) {
		GtkTreeViewColumn *c;
		gboolean val;

		c = gtk_tree_view_get_column(treeview, i);
		if (!c)
			break;
		gui_prop_get_boolean(prop, &val, i, 1);
		gtk_tree_view_column_set_visible(c, val);
	}
}
#endif /* USE_GTK2 */

#ifdef USE_GTK1
/**
 * Save widths of columns in given property which must by a boolean array
 * property with at least as many elements as there are columns.
 */
void
clist_save_widths(GtkCList *clist, property_t prop)
{
	gint i;

	g_return_if_fail(clist);

    for (i = 0; i < clist->columns; i++) {
		guint32 width = clist->column[i].width;
		gui_prop_set_guint32(prop, &width, i, 1);
	}
}

/**
 * Restore widths of columns from given property which must by a boolean
 * array property with at least as many elements as there are columns.
 */
void
clist_restore_widths(GtkCList *clist, property_t prop)
{
	gint i;

	g_return_if_fail(clist);

    for (i = 0; i < clist->columns; i++) {
		guint32 width;

		gui_prop_get_guint32(prop, &width, i, 1);
    	gtk_clist_set_column_width(clist, i, width);
	}
}
/**
 * Save visibility of columns in given property which must by a boolean array
 * property with at least as many elements as there are columns.
 */
void
clist_save_visibility(GtkCList *clist, property_t prop)
{
	gint i;

	g_return_if_fail(clist);

    for (i = 0; i < clist->columns; i++) {
		gboolean val = clist->column[i].visible;
		gui_prop_set_boolean(prop, &val, i, 1);
	}
}

/**
 * Restore visibility of columns from given property which must by a boolean
 * array property with at least as many elements as there are columns.
 */
void
clist_restore_visibility(GtkCList *clist, property_t prop)
{
	gint i;

	g_return_if_fail(clist);

    for (i = 0; i < clist->columns; i++) {
		gboolean val;

		gui_prop_get_boolean(prop, &val, i, 1);
    	gtk_clist_set_column_visibility(clist, i, val);
	}
}
#endif /* USE_GTK1 */

static gboolean
show_popup_menu(widget_popup_menu_cb handler)
{
	GtkMenu *menu;

	g_return_val_if_fail(handler, FALSE);

	menu = (*handler)();
	if (menu) {
		int button;
		
		/*
		 * NOTE: Use 0 as button here even though 3 was probably pressed
		 * (right-click) because under Gtk+ 1.2 the popup will otherwise
		 * immediately disappear on button release if we use 3. Button 1
		 * does not work well for Gtk+ 2.x, thus use 0 then.
		 */
		button = GTK_CHECK_VERSION(2,0,0) ? 0 : 1;
		gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL,
			button, gtk_get_current_event_time());
		return TRUE;
	} else {
		return FALSE;
	}
}

static inline widget_popup_menu_cb
cast_to_widget_popup_menu_cb(const void *p)
{
	return (widget_popup_menu_cb) cast_pointer_to_func(p);
}

#if GTK_CHECK_VERSION(2,0,0)
static gboolean
on_popup_menu(GtkWidget *unused_widget, void *user_data)
{
	(void) unused_widget;
	return show_popup_menu(cast_to_widget_popup_menu_cb(user_data));
}
#endif	/* Gtk+ >= 2.0*/

static gboolean
on_key_press_event(GtkWidget *unused_widget,
	GdkEventKey *event, void *user_data)
{
	(void) unused_widget;

	switch (event->keyval) {
	unsigned modifier;
	case GDK_F10:
	case 0x1008FE0A:	/* Shift+F10 under Xnest */
		modifier = gtk_accelerator_get_default_mod_mask() & event->state;
		if (GDK_SHIFT_MASK == modifier) {
			return show_popup_menu(cast_to_widget_popup_menu_cb(user_data));
		}
		break;
	}
	return FALSE;
}

static gboolean
on_button_press_event(GtkWidget *unused_widget,
	GdkEventButton *event, void *user_data)
{
	(void) unused_widget;

	if (
		GDK_BUTTON_PRESS == event->type &&
		3 == event->button &&
		0 == (gtk_accelerator_get_default_mod_mask() & event->state)
	) {
		return show_popup_menu(cast_to_widget_popup_menu_cb(user_data));
	}
	return FALSE;
}

/**
 * "handler" will be called whenever a popup menu is requested for "widget".
 */
void
widget_add_popup_menu(GtkWidget *widget, widget_popup_menu_cb handler)
{
	void *data = func_to_pointer(handler);

	g_return_if_fail(widget);
	g_return_if_fail(handler);

	GTK_WIDGET_SET_FLAGS(widget, GTK_CAN_FOCUS);
	GTK_WIDGET_SET_FLAGS(widget, GTK_CAN_DEFAULT);
#if GTK_CHECK_VERSION(2,0,0)
	gui_signal_connect(widget, "popup-menu", on_popup_menu, data);
#endif	/* Gtk+ >= 2.0*/

	gui_signal_connect(widget, "key-press-event", on_key_press_event, data);
	gui_signal_connect(widget, "button-press-event", on_button_press_event,
		data);
}

/* vi: set ts=4 sw=4 cindent: */
