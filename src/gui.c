/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi & Richard Eckart
 *
 * GUI functions.
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
#include "callbacks.h"

#include "search_gui.h"
#include "filter_gui.h"
#include "nodes_gui.h"
#include "downloads_gui.h"
#include "uploads_gui.h"
#include "statusbar_gui.h"
#include "settings_gui.h"
#include "search_stats_gui.h"

#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

static gchar gui_tmp[4096];

/*
 * Implementation
 */

void gui_update_all() 
{
	gui_update_files_scanned();
    gui_update_stats_frames();

    {
        guint32 coord[4] = {0, 0, 0, 0};

        gui_prop_get_guint32(PROP_WINDOW_COORDS, coord, 0, 4);

        if (coord[0] && coord[1]) {
            gtk_widget_set_uposition(main_window, coord[0], coord[1]);
            gtk_window_set_default_size
                (GTK_WINDOW(main_window), coord[2], coord[3]);
        }
    }
}

void gui_update_files_scanned(void)
{
    GtkLabel *label_files_scanned =
        GTK_LABEL(lookup_widget(main_window, "label_files_scanned"));

	gm_snprintf(gui_tmp, sizeof(gui_tmp),
		(files_scanned == 1) ?
			_("%u file shared (%s)") :_("%u files shared (%s)"),
		files_scanned,
		short_kb_size(kbytes_scanned));
	gtk_label_set(label_files_scanned, gui_tmp);
}

void gui_allow_rescan_dir(gboolean flag)
{
	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_config_rescan_dir"), flag);
}

void gui_update_global(void)
{
	time_t now = time((time_t *) NULL);	
	guint32 start_stamp;

	gnet_prop_get_guint32_val(PROP_START_STAMP, &start_stamp);

    gtk_label_set_text(
        GTK_LABEL(lookup_widget(main_window, "label_statusbar_uptime")),
        short_uptime(difftime(now, start_stamp)));

    /*
     * Update the different parts of the GUI.
     */
    gnet_stats_gui_update(now);
    search_stats_gui_update(now);
    nodes_gui_update_nodes_display(now);
    uploads_gui_update_display(now);
    statusbar_gui_clear_timeouts(now);
    search_gui_flush(now);
}

static void update_stat(guint32 *max, GtkProgressBar *pg, 
    gnet_bw_stats_t *stats, gboolean avg_mode, gboolean inout)
{
    gfloat frac = 0;
    guint32 high_limit;
    guint32 current;
    
    current = avg_mode ? stats->average : stats->current;
    if (*max < current)
        *max = current;

    high_limit = MAX(
        stats->enabled ? stats->limit : *max,
        current);
    frac = (high_limit == 0) ? 0 : (gfloat) current / high_limit;

	gm_snprintf(gui_tmp, sizeof(gui_tmp), "%s/s %s %s", 
        compact_size(current), 
        inout ? _("in") : _("out"),
        avg_mode ? _("(avg)") : "");
	gtk_progress_bar_set_text(pg, gui_tmp);
    gtk_progress_bar_set_fraction(pg, frac);
}

/* FIXME: stats that are turned off need not be calculated! */
void gui_update_traffic_stats() {
    static guint32 http_in_max = 0;
    static guint32 http_out_max = 0;
    static guint32 gnet_in_max = 0;
    static guint32 gnet_out_max = 0;
    static guint32 leaf_in_max = 0;
    static guint32 leaf_out_max = 0;
    gnet_bw_stats_t s;

    GtkProgressBar *pg_http_in = GTK_PROGRESS_BAR
        (lookup_widget(main_window, "progressbar_bws_in"));
    GtkProgressBar *pg_http_out = GTK_PROGRESS_BAR
        (lookup_widget(main_window, "progressbar_bws_out"));
    GtkProgressBar *pg_gnet_in = GTK_PROGRESS_BAR
        (lookup_widget(main_window, "progressbar_bws_gin"));
    GtkProgressBar *pg_gnet_out = GTK_PROGRESS_BAR
        (lookup_widget(main_window, "progressbar_bws_gout"));
    GtkProgressBar *pg_leaf_in = GTK_PROGRESS_BAR
        (lookup_widget(main_window, "progressbar_bws_lin"));
    GtkProgressBar *pg_leaf_out = GTK_PROGRESS_BAR
        (lookup_widget(main_window, "progressbar_bws_lout"));

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

    gnet_get_bw_stats(BW_HTTP_IN,&s);
    update_stat(&http_in_max, pg_http_in, &s, progressbar_bws_in_avg, 1);
    gnet_get_bw_stats(BW_HTTP_OUT, &s);
    update_stat(&http_out_max, pg_http_out, &s, progressbar_bws_out_avg, 0);
    gnet_get_bw_stats(BW_GNET_IN, &s);
    update_stat(&gnet_in_max, pg_gnet_in, &s, progressbar_bws_gin_avg, 1);
    gnet_get_bw_stats(BW_GNET_OUT, &s);
    update_stat(&gnet_out_max, pg_gnet_out, &s, progressbar_bws_gout_avg, 0);
    gnet_get_bw_stats(BW_LEAF_IN, &s);
    update_stat(&leaf_in_max, pg_leaf_in, &s, progressbar_bws_glin_avg, 1);
    gnet_get_bw_stats(BW_LEAF_OUT, &s);
    update_stat(&leaf_out_max, pg_leaf_out, &s, progressbar_bws_glout_avg, 0);
}

void gui_update_stats_frames(void)
{
    GtkWidget *frame_bws_inout = 
        lookup_widget(main_window, "frame_bws_inout");
    GtkWidget *frame_bws_ginout = 
        lookup_widget(main_window, "frame_bws_ginout");
    GtkWidget *frame_bws_glinout = 
        lookup_widget(main_window, "frame_bws_glinout");
#ifdef USE_GTK1
    GtkWidget *handlebox_traffic = 
        lookup_widget(main_window, "handlebox_traffic");
#endif
    guint32 peermode;
    
   	gnet_prop_get_guint32_val(PROP_CURRENT_PEERMODE, &peermode);

    if (progressbar_bws_in_visible || progressbar_bws_out_visible) {
        gtk_widget_show(frame_bws_inout);
    } else {
        gtk_widget_hide(frame_bws_inout);
    }

    if (progressbar_bws_gin_visible || progressbar_bws_gout_visible) {
        gtk_widget_show(frame_bws_ginout);
    } else {
        gtk_widget_hide(frame_bws_ginout);
    }

    if ((progressbar_bws_glin_visible || progressbar_bws_glout_visible) &&
        (peermode == 2 || !autohide_bws_gleaf)) {
        gtk_widget_show(frame_bws_glinout);
    } else {
        gtk_widget_hide(frame_bws_glinout);
    }

#ifdef USE_GTK1
    gtk_widget_hide(handlebox_traffic);
    gtk_widget_show(handlebox_traffic);
#endif
}

/*
 * search_gui_add_targetted_search:
 *
 * Creates a new search based on the filename found and adds a filter
 * to it based on the sha1 hash if it has one or the exact filename if
 * it hasn't.
 * (patch by Andrew Meredith <andrew@anvil.org>)
 */
void gui_add_targetted_search(record_t *rec, filter_t *noneed)
{
    search_t *new_search;
    rule_t *rule;

    g_assert(rec != NULL);
    g_assert(rec->name != NULL);

    /* create new search item with search string set to filename */
    search_gui_new_search(rec->name, 0, &new_search);
    g_assert(new_search != NULL);

    if (rec->sha1) {
        rule = filter_new_sha1_rule(rec->sha1, rec->name,
            filter_get_download_target(), RULE_FLAG_ACTIVE);
    } else {
        rule = filter_new_text_rule(rec->name, RULE_TEXT_EXACT, TRUE,
            filter_get_download_target(), RULE_FLAG_ACTIVE);
    }
    g_assert(rule != NULL);

    filter_append_rule(new_search->filter, rule);
}


/*
 * Tells if two hit records have the same filename.
 */
gint gui_record_name_eq(gconstpointer rec1, gconstpointer rec2)
{
    gint result;

    result = 0 == strcmp(((const record_t *) rec1)->name,
       ((const record_t *) rec2)->name);

	if (common_dbg > 4)
    	g_message("[%s] == [%s] -> %d\n", ((const record_t *) rec1)->name,
			((const record_t *) rec2)->name, result);

    return result;
}

/*
 * Tells if two hit records have the same SHA1.
 */
gint gui_record_sha1_eq(gconstpointer rec1, gconstpointer rec2)
{
    const gchar *s1 = ((const record_t *) rec1)->sha1;
    const gchar *s2 = ((const record_t *) rec2)->sha1;

    if (s1 == s2)
        return 0;

    if (s1 == NULL || s2 == NULL)
               return 1;

    return memcmp(s1, s2, SHA1_RAW_SIZE);
}

/*
 * Tells if two hit records come from the same host.
 */
gint gui_record_host_eq(gconstpointer rec1, gconstpointer rec2)
{
    return ((const record_t *) rec1)->results_set->ip
       == ((const record_t *) rec2)->results_set->ip
       ? 0 : 1;
}

/*
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
gint gui_record_sha1_or_name_eq(gconstpointer rec1, gconstpointer rec2)
{
    if (((const record_t *) rec1)->sha1 || ((const record_t *) rec2)->sha1)
        return gui_record_sha1_eq(rec1, rec2);
    else
        return gui_record_name_eq(rec1, rec2);
}

#ifdef USE_GTK2
/*
 * The following handles UI joining since the glade code is now
 * splitted into several files. Prevents huge UI creation functions
 * and allows GTK2 compilation on some platforms.
 *
 * 2003-02-08 ko [junkpile@free.fr]
 *
 */
typedef struct steal_dict_params {
	GtkWidget *target;
	GtkWidget *source;
} steal_dict_params_t;

/*
 * gui_steal_widget_dict_recursive:
 *
 * Transfers the widget dictionary for specified widget
 * from specified window to the main window.
 * If the widget is a container, recursively calls
 * itself on each child.
 *
 */
static void gui_steal_widget_dict_recursive(
	GtkWidget *widget, gpointer user_data)
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

/*
 * gui_merge_window_as_tab:
 *
 * 2003-02-08 ko [junkpile@free.fr]
 *
 * Reparents children of specified window into a new notebook tab.
 * Also transfers the widget dictionary to specified toplevel
 * window so lookup_widget() is not broken afterwards.
 * 
 */
void gui_merge_window_as_tab(GtkWidget *toplvl, GtkWidget *notebook,
							 GtkWidget *window)
{
	const gchar *title;
	GList *children = NULL;
	steal_dict_params_t params = {
		toplvl, window
	};

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
#endif	/* USE_GTK2 */

