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
#include "search_gui.h"
#include "callbacks.h"
#include "nodes.h" // FIXME: remove this dependency

#include "filter_gui.h"
#include "nodes_gui.h"
#include "statusbar_gui.h"

#include <arpa/inet.h>
#include <math.h>

#include "statusbar_gui.h"
#include "settings_gui.h"

#define NO_FUNC

static gchar gui_tmp[4096];

#define IO_STALLED		60		/* If nothing exchanged after that many secs */

/*
 * Windows
 */
GtkWidget *main_window = NULL;
GtkWidget *shutdown_window = NULL;
GtkWidget *dlg_about = NULL;
GtkWidget *popup_downloads = NULL;
GtkWidget *popup_uploads = NULL;
GtkWidget *popup_search = NULL;
GtkWidget *popup_nodes = NULL;
GtkWidget *popup_monitor = NULL;
GtkWidget *popup_queue = NULL;

/*
 * Private functions
 */
static void gui_init_menu();

/*
 * Implementation
 */

void gui_init(void)
{
    statusbar_gui_init();

	/* popup menus */
	popup_nodes = create_popup_nodes();
	popup_search = create_popup_search();
	popup_monitor = create_popup_monitor();
	popup_uploads = create_popup_uploads();
	popup_downloads = create_popup_dl_active();
	popup_queue = create_popup_dl_queued();	

    gui_init_menu();

    /* about box */
#ifdef GTA_REVISION
	g_snprintf(gui_tmp, sizeof(gui_tmp), "gtk-gnutella %u.%u %s", GTA_VERSION,
			   GTA_SUBVERSION, GTA_REVISION);
#else
	g_snprintf(gui_tmp, sizeof(gui_tmp), "gtk-gnutella %u.%u", GTA_VERSION,
			   GTA_SUBVERSION);
#endif
    gtk_label_set_text
        (GTK_LABEL(lookup_widget(dlg_about, "label_about_title")), gui_tmp);

    /* search history combo stuff */
    gtk_combo_disable_activate
        (GTK_COMBO(lookup_widget(main_window, "combo_search")));

    /* copy url selection stuff */
    gtk_selection_add_target
        (popup_downloads, GDK_SELECTION_PRIMARY, GDK_SELECTION_TYPE_STRING, 1);
}

static void gui_init_menu() 
{
    gchar * title;
	gint optimal_width;
	GtkCTreeNode *parent_node = NULL;    
	GtkCTreeNode *last_node = NULL;
    GtkCTree *ctree_menu =
        GTK_CTREE(lookup_widget(main_window, "ctree_menu"));

     // gnutellaNet
    title = (gchar *) &"gnutellaNet";
    last_node = gtk_ctree_insert_node(
		ctree_menu, NULL, NULL, &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		ctree_menu, last_node, 
        (gpointer) nb_main_page_gnutellaNet);

    // Uploads
    title = (gchar *) &"Uploads";
    parent_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, &title,
        0, NULL, NULL, NULL, NULL, FALSE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), parent_node, 
        (gpointer) nb_main_page_uploads);

    // Uploads -> Stats
    title = (gchar *) &"Stats";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), parent_node, NULL, &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE);
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        (gpointer) nb_main_page_uploads_stats);

    // Downloads
    title = (gchar *) &"Downloads";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, &title,

        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        (gpointer) nb_main_page_downloads);

    // Search
    title = (gchar *) &"Search";
    parent_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, &title,
        0, NULL, NULL, NULL, NULL, FALSE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), parent_node, 
        (gpointer) nb_main_page_search);

    // Search -> Monitor
    title = (gchar *) &"Monitor";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), parent_node, NULL, &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        (gpointer) nb_main_page_monitor);

    // Search -> search stats
    title = (gchar *) &"Stats";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), parent_node, NULL, &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        (gpointer) nb_main_page_search_stats);

    // Config
    title = (gchar *) &"Config";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, (gchar **) &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        (gpointer) nb_main_page_config);

	gtk_clist_select_row(GTK_CLIST(ctree_menu), 0, 0);

    optimal_width =
		gtk_clist_optimal_column_width(GTK_CLIST(ctree_menu), 0);

#ifdef GTA_REVISION
	g_snprintf(gui_tmp, sizeof(gui_tmp), "gtk-gnutella %u.%u %s", GTA_VERSION,
			   GTA_SUBVERSION, GTA_REVISION);
#else
	g_snprintf(gui_tmp, sizeof(gui_tmp), "gtk-gnutella %u.%u", GTA_VERSION,
			   GTA_SUBVERSION);
#endif

	gtk_window_set_title(GTK_WINDOW(main_window), gui_tmp);
}

void gui_update_all() 
{
    guint32 proxy_protocol;

    gnet_prop_get_guint32(PROP_PROXY_PROTOCOL, &proxy_protocol, 0, 1);

    /* update gui setting from config variables */

    gui_update_guid();
    
    gui_update_c_gnutellanet();
	gui_update_c_uploads();
	gui_update_c_downloads(0, 0);
    
	gui_update_files_scanned();

	gui_update_scan_extensions();

    gui_update_config_netmasks();

	gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(main_window, "radio_config_http")),
        (proxy_protocol == 1) ? TRUE : FALSE);
	gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(main_window, "radio_config_socksv4")),
        (proxy_protocol == 4) ? TRUE : FALSE);
	gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON
            (lookup_widget(main_window, "radio_config_socksv5")),
		(proxy_protocol == 5) ? TRUE : FALSE);

    gtk_notebook_set_page(    
        GTK_NOTEBOOK(lookup_widget(main_window, "notebook_sidebar")),
        search_results_show_tabs ? 1 : 0);

    gtk_notebook_set_show_tabs(
        GTK_NOTEBOOK(lookup_widget(main_window, "notebook_search_results")),
        search_results_show_tabs);

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


void gui_update_c_gnutellanet(void)
{
    GtkProgressBar *pg = GTK_PROGRESS_BAR
        (lookup_widget(main_window, "progressbar_connections"));
	gint nodes = node_count();
	gint cnodes = connected_nodes();
    gfloat frac;
    
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u/%u gnutellaNet", cnodes, nodes);
    gtk_progress_bar_set_text(pg, gui_tmp);

    frac = MIN(cnodes, nodes) != 0 ? (float)MIN(cnodes, nodes) / nodes : 0;

    gtk_progress_bar_set_fraction(pg, frac);
}

void gui_update_c_uploads(void)
{
    GtkProgressBar *pg = GTK_PROGRESS_BAR
         (lookup_widget(main_window, "progressbar_uploads"));
	gint i = running_uploads;
	gint t = registered_uploads;
    gfloat frac;

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u/%u upload%s", i, t,
			   (i == 1 && t == 1) ? "" : "s");

    frac = MIN(i, t) != 0 ? (float)MIN(i, t) / t : 0;

    gtk_progress_bar_set_text(pg, gui_tmp);
    gtk_progress_bar_set_fraction(pg, frac);
}

void gui_update_c_downloads(gint c, gint ec)
{
    GtkProgressBar *pg = GTK_PROGRESS_BAR
        (lookup_widget(main_window, "progressbar_downloads"));
    gfloat frac;

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u/%u download%s", c, ec,
			   (c == 1 && ec == 1) ? "" : "s");
    
    frac = MIN(c, ec) != 0 ? (float)MIN(c, ec) / ec : 0;

    gtk_progress_bar_set_text(pg, gui_tmp);
    gtk_progress_bar_set_fraction(pg, frac);
}

void gui_update_files_scanned(void)
{
    GtkLabel *label_files_scanned =
        GTK_LABEL(lookup_widget(main_window, "label_files_scanned"));

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u file%s shared (%s)",
		files_scanned, files_scanned == 1 ? "" : "s",
		short_kb_size(kbytes_scanned));
	gtk_label_set(label_files_scanned, gui_tmp);
}

void gui_update_guid()
{
    gtk_entry_set_text(
        GTK_ENTRY(lookup_widget(main_window, "entry_nodes_guid")),
        guid_hex_str(guid));
}

void gui_update_queue_frozen()
{
    static gboolean msg_displayed = FALSE;
    static statusbar_msgid_t id = {0, 0};

    GtkWidget *togglebutton_queue_freeze;

    togglebutton_queue_freeze =
        lookup_widget(main_window, "togglebutton_queue_freeze");

    if (gui_debug >= 3)
	printf("frozen %i, msg %i\n", download_queue_is_frozen(),
	    msg_displayed);

    if (download_queue_is_frozen() > 0) {
		gtk_label_set_text(
            GTK_LABEL(GTK_BIN(togglebutton_queue_freeze)->child),
			"Thaw queue");
        if (!msg_displayed) {
            msg_displayed = TRUE;
          	id = statusbar_gui_message(0, "QUEUE FROZEN");
        }
    } else {
		gtk_label_set_text(
            GTK_LABEL(GTK_BIN(togglebutton_queue_freeze)->child),
			"Freeze queue");
        if (msg_displayed) {
            msg_displayed = FALSE;
            statusbar_gui_remove(id);
        }
	} 

    gtk_signal_handler_block_by_func(
        GTK_OBJECT(togglebutton_queue_freeze),
        GTK_SIGNAL_FUNC(on_togglebutton_queue_freeze_toggled),
        NULL);

    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(togglebutton_queue_freeze),
        download_queue_is_frozen() > 0);
    
    gtk_signal_handler_unblock_by_func(
        GTK_OBJECT(togglebutton_queue_freeze),
        GTK_SIGNAL_FUNC(on_togglebutton_queue_freeze_toggled),
        NULL);
}

/*
 * gui_update_config_netmasks
 *
 * Update the gui with info from the config file
 */
void gui_update_config_netmasks()
{
	gtk_toggle_button_set_active(
		GTK_TOGGLE_BUTTON
            (lookup_widget(main_window, "checkbutton_config_use_netmasks")), 
        use_netmasks);
    if (local_netmasks_string)
        gtk_entry_set_text(
            GTK_ENTRY(lookup_widget(main_window, "entry_config_netmasks")),
			local_netmasks_string);
}

void gui_update_scan_extensions(void)
{
	GSList *l;
    GtkEntry *entry_config_extensions;

    entry_config_extensions = GTK_ENTRY
        (lookup_widget(main_window, "entry_config_extensions"));

	g_free(scan_extensions);

	*gui_tmp = 0;

	for (l = extensions; l; l = l->next) {
		struct extension *e = (struct extension *) l->data;
		if (*gui_tmp)
			strcat(gui_tmp, ";");
		strcat(gui_tmp, (gchar *) e->str);
	}

	scan_extensions = g_strdup(gui_tmp);

	gtk_entry_set_text(entry_config_extensions, scan_extensions);
	gtk_entry_set_position(entry_config_extensions, 0);
}

void gui_allow_rescan_dir(gboolean flag)
{
	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_config_rescan_dir"), flag);
}

void gui_update_global(void)
{
	static gboolean startupset = FALSE;
	static time_t   startup;
   
	time_t now = time((time_t *) NULL);	

	if( !startupset ) {
		startup = time((time_t *) NULL);
		startupset = TRUE;
	}

    gtk_entry_printf(
        GTK_ENTRY(lookup_widget(main_window, "entry_global_messages")),
        "%u", global_messages);
    gtk_entry_printf(
        GTK_ENTRY(lookup_widget(main_window, "entry_global_searches")),
        "%u", global_searches);

    gtk_entry_printf(
        GTK_ENTRY(lookup_widget(main_window, "entry_routing_errors")),
        "%u", routing_errors);

    gtk_entry_printf(
        GTK_ENTRY(lookup_widget(main_window, "entry_dropped_messages")),
        "%u", dropped_messages);

    gtk_label_printf(
        GTK_LABEL(lookup_widget(main_window, "label_statusbar_uptime")),
        "Uptime: %s", short_uptime((guint32) difftime(now,startup)));

    /*
     * Update the different parts of the GUI.
     */
    nodes_gui_update_nodes_display(now);
    statusbar_gui_clear_timeouts(now);
}

void gui_update_traffic_stats() {
    static guint32 bw_http_in_max = 0;
    static guint32 bw_http_out_max = 0;
    static guint32 bw_gnet_in_max = 0;
    static guint32 bw_gnet_out_max = 0;
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

    current = progressbar_bws_in_avg ?
		bsched_avg_bps(bws.in) : bsched_bps(bws.in);

    if (bw_http_in_max < current)
        bw_http_in_max = current;

    high_limit = bws_in_enabled ? bws.in->bw_per_second : bw_http_in_max;

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s/s in %s", compact_size(current),
			   progressbar_bws_in_avg ? "(avg)" : "");
	gtk_progress_bar_set_text(progressbar_bws_in, gui_tmp);

    gtk_progress_configure(GTK_PROGRESS(progressbar_bws_in), 
    	MIN(current,bws.in->bw_per_second), 0, high_limit);


    current = progressbar_bws_out_avg ?
		bsched_avg_bps(bws.out) : bsched_bps(bws.out);

    if (bw_http_out_max < current)
        bw_http_out_max = current;

    high_limit = bws_out_enabled ? bws.out->bw_per_second : bw_http_out_max;

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s/s out %s", compact_size(current),
			   progressbar_bws_out_avg ? "(avg)" : "");
	gtk_progress_bar_set_text(progressbar_bws_out, gui_tmp);

	gtk_progress_configure(GTK_PROGRESS(progressbar_bws_out), 
    	MIN(current, bws.out->bw_per_second), 0, high_limit);


    current = progressbar_bws_gin_avg ?
		bsched_avg_bps(bws.gin) : bsched_bps(bws.gin);

    if (bw_gnet_in_max < current)
        bw_gnet_in_max = current;

    high_limit = bws_gin_enabled ? bws.gin->bw_per_second : bw_gnet_in_max;

    g_snprintf(gui_tmp, sizeof(gui_tmp), "%s/s in %s", 
			   compact_size(current), progressbar_bws_gin_avg ? "(avg)" : "");
	gtk_progress_set_format_string(GTK_PROGRESS(progressbar_bws_gin), gui_tmp);

 	gtk_progress_configure(GTK_PROGRESS(progressbar_bws_gin), 
    	MIN(current, bws.gin->bw_per_second), 0, high_limit);


    current = progressbar_bws_gout_avg ?
		bsched_avg_bps(bws.gout) : bsched_bps(bws.gout);

    if (bw_gnet_out_max < current)
        bw_gnet_out_max = current;

    high_limit = bws_gout_enabled ? bws.gout->bw_per_second : bw_gnet_out_max;

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s/s out %s", 
			   compact_size(current), progressbar_bws_gout_avg ? "(avg)" : "");
	gtk_progress_set_format_string(GTK_PROGRESS(progressbar_bws_gout), gui_tmp);

	gtk_progress_configure(GTK_PROGRESS(progressbar_bws_gout), 
    	MIN(current, bws.gout->bw_per_second), 0, high_limit);
}

void gui_update_download_abort_resume(void)
{
	struct download *d;
	GList *l;
    GtkCList *clist_downloads;
	gboolean abort  = FALSE;
    gboolean resume = FALSE;
    gboolean remove = FALSE;
    gboolean queue  = FALSE;
    gboolean abort_sha1 = FALSE;

    clist_downloads = GTK_CLIST(lookup_widget(main_window, "clist_downloads"));


	for (l = clist_downloads->selection; l; l = l->next) {
		d = (struct download *)
			gtk_clist_get_row_data(clist_downloads, (gint) l->data);

        if (!d) {
			g_warning
				("gui_update_download_abort_resume(): row %d has NULL data\n",
				 (gint) l->data);
			continue;
		}

        if (d->status != GTA_DL_COMPLETED)
            queue = TRUE;
    
        if (d->sha1 != NULL)
            abort_sha1 = TRUE;

		switch (d->status) {
		case GTA_DL_QUEUED:
			fprintf(stderr, "gui_update_download_abort_resume(): "
				"found queued download '%s' in active download list !\n",
				d->file_name);
			continue;
		case GTA_DL_CONNECTING:
		case GTA_DL_PUSH_SENT:
		case GTA_DL_FALLBACK:
		case GTA_DL_REQ_SENT:
		case GTA_DL_HEADERS:
		case GTA_DL_RECEIVING:
			abort = TRUE;
			break;
		case GTA_DL_ERROR:
		case GTA_DL_ABORTED:
			resume = TRUE;
            /* only check if file exists if really necessary */
            if (!remove && download_file_exists(d))
                remove = TRUE;
			break;
		case GTA_DL_TIMEOUT_WAIT:
			abort = resume = TRUE;
			break;
		}

		if (abort & resume & remove)
			break;
	}

	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_downloads_abort"), abort);
	gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_abort"), abort);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_abort_named"), abort);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_abort_host"), abort);
    gtk_widget_set_sensitive(
        lookup_widget(popup_downloads, "popup_downloads_abort_sha1"), 
        abort_sha1);
	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_downloads_resume"), resume);
	gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_resume"), resume);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_remove_file"), remove);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_queue"), queue);
}

void gui_update_upload(struct upload *u)
{
	gfloat rate = 1, pc = 0;
	guint32 tr = 0;
	gint row;
	gchar gui_tmp[256];
	guint32 requested = u->end - u->skip + 1;

	if (u->pos < u->skip)
		return;					/* Never wrote anything yet */

	if (!UPLOAD_IS_COMPLETE(u)) {
		gint slen;
		guint32 bps = 1;
		guint32 avg_bps = 1;

		/*
		 * position divided by 1 percentage point, found by dividing
		 * the total size by 100
		 */
		pc = (u->pos - u->skip) * 100.0 / requested;

		if (u->bio) {
			bps = bio_bps(u->bio);
			avg_bps = bio_avg_bps(u->bio);
		}

		if (avg_bps <= 10 && u->last_update != u->start_date)
			avg_bps = (u->pos - u->skip) / (u->last_update - u->start_date);
		if (avg_bps == 0)
			avg_bps++;

		rate = bps / 1024.0;

		/* Time Remaining at the current rate, in seconds  */
		tr = (u->end + 1 - u->pos) / avg_bps;

		slen = g_snprintf(gui_tmp, sizeof(gui_tmp), "%.02f%% ", pc);

		if (time((time_t *) 0) - u->last_update > IO_STALLED)
			slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				"(stalled) ");
		else
			slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				"(%.1f k/s) ", rate);

		g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
			"TR: %s", short_time(tr));
	} else {
		if (u->last_update != u->start_date) {
			guint32 spent = u->last_update - u->start_date;

			rate = (requested / 1024.0) / spent;
			g_snprintf(gui_tmp, sizeof(gui_tmp),
				"Completed (%.1f k/s) %s", rate, short_time(spent));
		} else
			g_snprintf(gui_tmp, sizeof(gui_tmp), "Completed (< 1s)");
	}

    {
        GtkCList *clist_uploads = GTK_CLIST
            (lookup_widget(main_window, "clist_uploads"));

        row = gtk_clist_find_row_from_data(clist_uploads, (gpointer) u);
        gtk_clist_set_text(clist_uploads, row, c_ul_status, gui_tmp);
    }
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

/* vi: set ts=4: */
