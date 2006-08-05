/*
 * $Id$
 *
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

RCSID("$Id$")

#include "gtk-shared/callbacks.h"

#include "nodes.h"
#include "downloads.h"
#include "settings.h"
#include "search.h"
#include "gtk-missing.h"

#include "if/gnet_property.h"
#include "if/gui_property.h"
#include "if/gui_property_priv.h"

#include "if/core/net_stats.h"
#include "if/bridge/ui2c.h"

#include "lib/glib-missing.h"
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
			GTK_LABEL(lookup_widget(dlg_prefs, "label_files_scanned"));

	gtk_label_printf(label_files_scanned,
		NG_("%lu file shared (%s)", "%lu files shared (%s)", n),
		n, short_kb_size(guc_shared_kbytes_scanned(), show_metric_units()));
}

void
gui_allow_rescan_dir(gboolean flag)
{
	gtk_widget_set_sensitive
        (lookup_widget(dlg_prefs, "button_config_rescan_dir"), flag);
}

/**
 * Update some general information displayed in the gui.
 */
void
gui_general_timer(time_t now)
{
	static GtkLabel *label = NULL;
	const gchar *uptime;
	time_t start;

	if (label == NULL)
		label = GTK_LABEL(lookup_widget(main_window, "label_statusbar_uptime"));

	gnet_prop_get_timestamp_val(PROP_START_STAMP, &start);
	uptime = short_uptime(delta_time(now, start));

#ifdef USE_GTK2
	{
		gchar buf[128];

		gm_snprintf(buf, sizeof buf, "<tt> %s </tt>", uptime);
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

	gm_snprintf(buf, sizeof buf, "%s %s %s",
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
    gnet_bw_stats_t s;
    gnet_bw_stats_t s2;
    static GtkProgressBar *pg_http_in = NULL;
    static GtkProgressBar *pg_http_out = NULL;
    static GtkProgressBar *pg_gnet_in = NULL;
    static GtkProgressBar *pg_gnet_out = NULL;
    static GtkProgressBar *pg_leaf_in = NULL;
    static GtkProgressBar *pg_leaf_out = NULL;

	if (pg_http_in == NULL) {
		pg_http_in = GTK_PROGRESS_BAR(
			lookup_widget(main_window, "progressbar_bws_in"));
		pg_http_out = GTK_PROGRESS_BAR
			(lookup_widget(main_window, "progressbar_bws_out"));
		pg_gnet_in = GTK_PROGRESS_BAR
			(lookup_widget(main_window, "progressbar_bws_gin"));
		pg_gnet_out = GTK_PROGRESS_BAR
			(lookup_widget(main_window, "progressbar_bws_gout"));
		pg_leaf_in = GTK_PROGRESS_BAR
			(lookup_widget(main_window, "progressbar_bws_lin"));
		pg_leaf_out = GTK_PROGRESS_BAR
			(lookup_widget(main_window, "progressbar_bws_lout"));
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
    update_stat(&http_in_max, pg_http_in, &s, progressbar_bws_in_avg, 1);
    guc_gnet_get_bw_stats(BW_HTTP_OUT, &s);
    update_stat(&http_out_max, pg_http_out, &s, progressbar_bws_out_avg, 0);
    guc_gnet_get_bw_stats(BW_GNET_IN, &s);
    guc_gnet_get_bw_stats(BW_GNET_UDP_IN, &s2);
	gnet_bw_stats_sum(&s, &s2);
    update_stat(&gnet_in_max, pg_gnet_in, &s, progressbar_bws_gin_avg, 1);
    guc_gnet_get_bw_stats(BW_GNET_OUT, &s);
    guc_gnet_get_bw_stats(BW_GNET_UDP_OUT, &s2);
	gnet_bw_stats_sum(&s, &s2);
    update_stat(&gnet_out_max, pg_gnet_out, &s, progressbar_bws_gout_avg, 0);
    guc_gnet_get_bw_stats(BW_LEAF_IN, &s);
    update_stat(&leaf_in_max, pg_leaf_in, &s, progressbar_bws_glin_avg, 1);
    guc_gnet_get_bw_stats(BW_LEAF_OUT, &s);
    update_stat(&leaf_out_max, pg_leaf_out, &s, progressbar_bws_glout_avg, 0);
}

void
gui_update_stats_frames(void)
{
    static GtkWidget *frame_bws_inout = NULL;
    static GtkWidget *frame_bws_ginout = NULL;
    static GtkWidget *frame_bws_glinout = NULL;
    guint32 peermode;

	if (frame_bws_inout == NULL) {
		frame_bws_inout = lookup_widget(main_window, "frame_bws_inout");
		frame_bws_ginout = lookup_widget(main_window, "frame_bws_ginout");
		frame_bws_glinout = lookup_widget(main_window, "frame_bws_glinout");
	}

   	gnet_prop_get_guint32_val(PROP_CURRENT_PEERMODE, &peermode);

    if (progressbar_bws_in_visible || progressbar_bws_out_visible)
        gtk_widget_show(frame_bws_inout);
    else
        gtk_widget_hide(frame_bws_inout);

    if (progressbar_bws_gin_visible || progressbar_bws_gout_visible)
        gtk_widget_show(frame_bws_ginout);
    else
        gtk_widget_hide(frame_bws_ginout);

    if (
		(progressbar_bws_glin_visible || progressbar_bws_glout_visible) &&
        (peermode == NODE_P_ULTRA || !autohide_bws_gleaf)
	)
        gtk_widget_show(frame_bws_glinout);
    else
        gtk_widget_hide(frame_bws_glinout);
}

/**
 * Tells if two hit records have the same filename.
 */
gint
gui_record_name_eq(gconstpointer rec1, gconstpointer rec2)
{
    gint result;

    result = strcmp(((const record_t *) rec1)->name,
       ((const record_t *) rec2)->name);

	if (gui_debug > 4)
    	g_message("[%s] == [%s] -> %d\n", ((const record_t *) rec1)->name,
			((const record_t *) rec2)->name, result);

    return result;
}

/**
 * Tells if two hit records have the same SHA1.
 */
gint
gui_record_sha1_eq(gconstpointer rec1, gconstpointer rec2)
{
    const gchar *s1 = ((const record_t *) rec1)->sha1;
    const gchar *s2 = ((const record_t *) rec2)->sha1;

    if (s1 == s2)
        return 0;

    if (s1 == NULL || s2 == NULL)
		return 1;

    return memcmp(s1, s2, SHA1_RAW_SIZE);
}

/**
 * Tells if two hit records come from the same host.
 */
gint
gui_record_host_eq(gconstpointer rec1, gconstpointer rec2)
{
	const record_t *r1 = rec1, *r2 = rec2;
    return !host_addr_equal(r1->results_set->addr, r2->results_set->addr);
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
gint
gui_record_sha1_or_name_eq(gconstpointer rec1, gconstpointer rec2)
{
    if (((const record_t *) rec1)->sha1 || ((const record_t *) rec2)->sha1)
        return gui_record_sha1_eq(rec1, rec2);
    else
        return gui_record_name_eq(rec1, rec2);
}

/**
 * If the given coordinates are not reasonable, they're appriopriately
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

	g_assert(coord != NULL);

	screen_w = gdk_screen_width();
	screen_h = gdk_screen_height();
	if (gui_debug)
		g_message("screen: %dx%d", screen_w, screen_h);

	x = coord[0];
	y = coord[1];
	w = coord[2];
	h = coord[3];
	if (gui_debug)
		g_message("before: %dx%d+%d+%d", w, h, x, y);

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
	if (gui_debug)
		g_message("after: %dx%d+%d+%d", w, h, x, y);
}

void
gui_restore_window(GtkWidget *widget, property_t prop)
{
    guint32 coord[4] = { 0, 0, 0, 0 };

    gui_prop_get_guint32(prop, coord, 0, G_N_ELEMENTS(coord));
	gui_fix_coords(coord);

    /*
     * We need to tell Gtk the size of the window, otherwise we'll get
     * strange side effects when the window is shown (like implicitly
     * resized widgets).
     *      -- Richard, 8/9/2002
     */

    gtk_window_set_default_size(GTK_WINDOW(widget), coord[2], coord[3]);


#ifdef USE_GTK2
    if (coord[2] != 0 && coord[3] != 0) {
		gint x, y, dx, dy;
		gint i;

		/* First, move the window to the supposed location. Next make the
		 * window visible by gtk_window_get_position()... */

       	gtk_window_move(GTK_WINDOW(widget), coord[0], coord[1]);

		/* The first call to gtk_window_get_position() makes the window
		 * visible but x and y are always set to zero. The second call
		 * yields the *real* values.
		 *
		 * Must wait some time between subsequent calls, and if we get both
		 * x and y set to 0, assume we did not correctly compute the position
		 * and leave it unaltered..
		 */

		for (i = 0; i < 2; i++) {
#ifdef HAS_USLEEP
			usleep(20000);
#endif
			gtk_window_get_position(GTK_WINDOW(widget), &x, &y);
			if (x || y)
				break;
		}

		gtk_window_resize(GTK_WINDOW(widget), coord[2], coord[3]);

		/*
		 * (At least) FVWM2 doesn't take the window decoration into account
		 * when handling positions requests. Readjust the window position
		 * if we detect that the window manager added an offset.
		 */

		dx = (gint) coord[0] - x;
		dy = (gint) coord[1] - y;
		if ((x || y) && (dx || dy))
        	gtk_window_move(GTK_WINDOW(widget), coord[0] + dx, coord[1] + dy);
	}
#else	/* !USE_GTK2 */
    if (coord[2] != 0 && coord[3] != 0) {
        gdk_window_move_resize(widget->window,
			coord[0], coord[1], coord[2], coord[3]);

		/* This causes a wandering window -- make it optional */
		{
			gint x, y, dx, dy;
			gint i;

			/* (At least) FVWM2 doesn't take the window decoration into account
			 * when handling positions requests. Readjust the window position
			 * if we detect that the window manager added an offset.
			 */

			for (i = 0; i < 2; i++) {
#ifdef HAS_USLEEP
				usleep(20000);
#endif
				gdk_window_get_root_origin(widget->window, &x, &y);
				if (x || y)
					break;
			}
			dx = (gint) coord[0] - x;
			dy = (gint) coord[1] - y;
			if ((x || y) && (dx || dy))
				gdk_window_move(widget->window, coord[0] + dx, coord[1] + dy);
		}
	}
#endif /* USE_GTK2 */
}

void
gui_save_window(GtkWidget *widget, property_t prop)
{
    guint32 coord[4] = { 0, 0, 0, 0};
	gint x, y, w, h;

#ifdef USE_GTK1
	gdk_window_get_root_origin(widget->window, &x, &y);
	gdk_window_get_size(widget->window, &w, &h);
#else	/* !USE_GTK1 */
	gtk_window_get_position(GTK_WINDOW(widget), &x, &y);
	gtk_window_get_size(GTK_WINDOW(widget), &w, &h);
#endif /* USE_GTK1 */
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
	steal_dict_params_t *params = (steal_dict_params_t *) user_data;

	g_assert(widget != NULL);
	g_assert(user_data != NULL);

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
	children = gtk_container_get_children(GTK_CONTAINER(window));

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
	
	g_assert(paned);

	pos = gtk_paned_get_position(paned);
	gui_prop_set_guint32_val(prop, pos);
}

void
paned_restore_position(GtkPaned *paned, property_t prop)
{
	guint32 pos;
	
	g_assert(paned);

	gui_prop_get_guint32_val(prop, &pos);
	gtk_paned_set_position(paned, pos);
}

#ifdef USE_GTK2
void
tree_view_save_widths(GtkTreeView *treeview, property_t prop)
{
	gint i;

	g_assert(treeview);
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

	g_assert(treeview);
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

	g_assert(treeview);
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

	g_assert(treeview);
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
 * Save visibility of columns in given property which must by a boolean array
 * property with at least as many elements as there are columns.
 */
void
gtk_clist_save_visibility(GtkCList *clist, property_t prop)
{
	gint i;
	gboolean val;

	g_assert(clist);

    for (i = 0; i < clist->columns; i++) {
		val = clist->column[i].visible;
		gui_prop_set_boolean(prop, &val, i, 1);
	}
}

/**
 * Restore visibility of columns from given property which must by a boolean
 * array property with at least as many elements as there are columns.
 */
void
gtk_clist_restore_visibility(GtkCList *clist, property_t prop)
{
	gint i;
	gboolean val;

	g_assert(clist);

    for (i = 0; i < clist->columns; i++) {
		gui_prop_get_boolean(prop, &val, i, 1);
    	gtk_clist_set_column_visibility(clist, i, val);
	}
}
#endif /* USE_GTK1 */

/* vi: set ts=4 sw=4 cindent: */
