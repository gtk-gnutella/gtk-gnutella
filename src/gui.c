/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi & Richard Eckart
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

	gm_snprintf(gui_tmp, sizeof(gui_tmp), "%u file%s shared (%s)",
		files_scanned, files_scanned == 1 ? "" : "s",
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

    gtk_label_printf(
        GTK_LABEL(lookup_widget(main_window, "label_statusbar_uptime")),
        "Uptime: %s", short_uptime((guint32) difftime(now, start_stamp)));

    /*
     * Update the different parts of the GUI.
     */
    gnet_stats_gui_update();
    search_stats_gui_update(now);
    nodes_gui_update_nodes_display(now);
    uploads_gui_update_display(now);
    statusbar_gui_clear_timeouts(now);
}

// FIXME: stats that are turned off need not be calculated!
void gui_update_traffic_stats() {
    static guint32 bw_http_in_max = 0;
    static guint32 bw_http_out_max = 0;
    static guint32 bw_gnet_in_max = 0;
    static guint32 bw_gnet_out_max = 0;
    gfloat frac = 0;
    gnet_bw_stats_t stats;
    guint32 high_limit;
    guint32 current;

    GtkProgressBar *progressbar_bws_in = GTK_PROGRESS_BAR
        (lookup_widget(main_window, "progressbar_bws_in"));
    GtkProgressBar *progressbar_bws_out = GTK_PROGRESS_BAR
        (lookup_widget(main_window, "progressbar_bws_out"));
    GtkProgressBar *progressbar_bws_gin = GTK_PROGRESS_BAR
        (lookup_widget(main_window, "progressbar_bws_gin"));
    GtkProgressBar *progressbar_bws_gout = GTK_PROGRESS_BAR
        (lookup_widget(main_window, "progressbar_bws_gout"));

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

    gnet_get_bw_stats(&stats);

    current = progressbar_bws_in_avg ? stats.http_in_avg : stats.http_in;
    if (bw_http_in_max < current)
        bw_http_in_max = current;

    high_limit = MAX(
        stats.http_in_enabled ? stats.http_in_limit : bw_http_in_max,
        current);
    frac = (high_limit == 0) ? 0 : (gfloat) current / high_limit;

	gm_snprintf(gui_tmp, sizeof(gui_tmp), "%s/s in %s", 
        compact_size(current), progressbar_bws_in_avg ? "(avg)" : "");
	gtk_progress_bar_set_text(progressbar_bws_in, gui_tmp);
    gtk_progress_bar_set_fraction(progressbar_bws_in, frac);

    current = progressbar_bws_out_avg ? stats.http_out_avg : stats.http_out;
    if (bw_http_out_max < current)
        bw_http_out_max = current;

    high_limit = MAX(
        stats.http_out_enabled ? stats.http_out_limit : bw_http_out_max,
        current);
    frac = (high_limit == 0) ? 0 : (gfloat) current / high_limit;

	gm_snprintf(gui_tmp, sizeof(gui_tmp), "%s/s out %s",
        compact_size(current), progressbar_bws_out_avg ? "(avg)" : "");
	gtk_progress_bar_set_text(progressbar_bws_out, gui_tmp);
    gtk_progress_bar_set_fraction(progressbar_bws_out, frac);

    current = progressbar_bws_gin_avg ? stats.gnet_in_avg : stats.gnet_in;
    if (bw_gnet_in_max < current)
        bw_gnet_in_max = current;

    high_limit = MAX(
        stats.gnet_in_enabled ? stats.gnet_in_limit : bw_gnet_in_max,
        current);
    frac = (high_limit == 0) ? 0 : (gfloat) current / high_limit;

    gm_snprintf(gui_tmp, sizeof(gui_tmp), "%s/s in %s", 
        compact_size(current), progressbar_bws_gin_avg ? "(avg)" : "");
	gtk_progress_bar_set_text(progressbar_bws_gin, gui_tmp);
    gtk_progress_bar_set_fraction(progressbar_bws_gin, frac);


    current = progressbar_bws_gout_avg ? stats.gnet_out_avg : stats.gnet_out;
    if (bw_gnet_out_max < current)
        bw_gnet_out_max = current;

    high_limit = MAX(
        stats.gnet_out_enabled ? stats.gnet_out_limit : bw_gnet_out_max,
        current);
    frac = (high_limit == 0) ? 0 : (gfloat) current / high_limit;

	gm_snprintf(gui_tmp, sizeof(gui_tmp), "%s/s out %s", 
        compact_size(current), progressbar_bws_gout_avg ? "(avg)" : "");
	gtk_progress_bar_set_text(progressbar_bws_gout, gui_tmp);
    gtk_progress_bar_set_fraction(progressbar_bws_gout, frac);
}

void gui_update_stats_frames()
{
    GtkWidget *frame_bws_inout = 
        lookup_widget(main_window, "frame_bws_inout");
    GtkWidget *frame_bws_ginout = 
        lookup_widget(main_window, "frame_bws_ginout");


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

    result = g_str_equal(((const record_t *) rec1)->name,
       ((const record_t *) rec2)->name) ? 0 : 1;

    printf("[%s] == [%s] -> %d\n", ((const record_t *) rec1)->name,
       ((const record_t *) rec2)->name, result);

    return result;
}

/*
 * Tells if two hit records have the same SHA1.
 */
gint gui_record_sha1_eq(gconstpointer rec1, gconstpointer rec2)
{
    const guchar *s1 = ((const record_t *) rec1)->sha1;
    const guchar *s2 = ((const record_t *) rec2)->sha1;

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
