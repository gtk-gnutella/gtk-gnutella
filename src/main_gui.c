/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi & Richard Eckart
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

#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif

#include "gui.h"

#include "main_gui.h"
#include "nodes_gui.h"

#include "settings_gui.h"
#include "search_gui.h"
#include "monitor_gui.h"
#include "statusbar_gui.h"
#include "search_stats_gui.h"
#include "gnet_stats_gui.h"
#include "uploads_gui.h"
#include "upload_stats_gui.h"
#include "downloads_gui.h"
#include "version.h"

#include "filter_cb.h"

#include "filter.h"

#include "oldconfig.h"

#include "callbacks.h" // FIXME: remove this dependency (compare_ul_norm)

#include <pwd.h>

static gchar tmpstr[4096];

/***
 *** Windows
 ***/
GtkWidget *main_window = NULL;
GtkWidget *shutdown_window = NULL;
GtkWidget *dlg_about = NULL;
GtkWidget *dlg_quit = NULL;
GtkWidget *popup_downloads = NULL;
GtkWidget *popup_uploads = NULL;
GtkWidget *popup_search = NULL;
GtkWidget *popup_nodes = NULL;
GtkWidget *popup_monitor = NULL;
GtkWidget *popup_queue = NULL;


/***
 *** Private function
 ***/

/*
 * load_legacy_settings:
 *
 * If no configuration files are found for frontend and core, it tries
 * to read in the old config file.
 * FIXME: This should be removed as soon as possible, probably for 1.0.
 */
void load_legacy_settings(void)
{
    struct passwd *pwd = getpwuid(getuid());
    gchar *config_dir;
    gchar *home_dir;
    gchar tmp[2000] = "";
    gchar core_config_file[2000] = "";
    gchar gui_config_file[2000] = "";

    config_dir = g_strdup(getenv("GTK_GNUTELLA_DIR"));
    if (pwd && pwd->pw_dir)
		home_dir = g_strdup(pwd->pw_dir);
	else
		home_dir = g_strdup(getenv("HOME"));

    if (!home_dir)
		g_warning("can't find your home directory!");
 
    if (!config_dir) {
		if (home_dir) {
			g_snprintf(tmp, sizeof(tmp),
				"%s/.gtk-gnutella", home_dir);
			config_dir = g_strdup(tmp);
		} else
			g_warning("no home directory: can't check legacy configuration!");
	}

    g_snprintf(core_config_file, sizeof(core_config_file), 
        "%s/%s", config_dir, "config_gnet");
    g_snprintf(gui_config_file, sizeof(gui_config_file), 
        "%s/%s", config_dir, "config_gui");

    if (!file_exists(core_config_file) && !file_exists(gui_config_file)) {
        g_warning("No configuration found, trying legacy config file");
        config_init();
    }

    g_free(config_dir);
    g_free(home_dir);
}

static void gui_init_menu() 
{
    gchar * title;
	gint optimal_width;
	GtkCTreeNode *parent_node = NULL;    
	GtkCTreeNode *last_node = NULL;
    GtkCTree *ctree_menu =
        GTK_CTREE(lookup_widget(main_window, "ctree_menu"));

     // gNet
    title = (gchar *) &"gnutellaNet";
    parent_node = gtk_ctree_insert_node(
		ctree_menu, NULL, NULL, &title,
        0, NULL, NULL, NULL, NULL, FALSE, TRUE );
    gtk_ctree_node_set_row_data(
		ctree_menu, parent_node, 
        (gpointer) nb_main_page_gnet);

    // gNet -> Stats
    title = (gchar *) &"Stats";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), parent_node, NULL, &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE);
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        (gpointer) nb_main_page_gnet_stats);

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
	g_snprintf(tmpstr, sizeof(tmpstr),
		"gtk-gnutella %s %s", version_number, GTA_REVISION);
#else
	g_snprintf(tmpstr, sizeof(tmpstr), "gtk-gnutella %s", version_number);
#endif

	gtk_window_set_title(GTK_WINDOW(main_window), tmpstr);
}



/***
 *** Public functions
 ***/

/*
 * main_gui_early_init:
 *
 * Some setup of the gui side which I wanted out of main.c but must be done
 * before the backend can be initialized since the core code is not free of
 * GTK yet.
 *      -- Richard, 6/9/2002
 */
void main_gui_early_init(gint argc, gchar **argv)
{
	/* Glade inits */

	gtk_set_locale();

	gtk_init(&argc, &argv);

	add_pixmap_directory(PACKAGE_DATA_DIR "/pixmaps");
	add_pixmap_directory(PACKAGE_SOURCE_DIR "/pixmaps");

    main_window = create_main_window();
    shutdown_window = create_shutdown_window();
    dlg_about = create_dlg_about();
    dlg_quit = create_dlg_quit();

	/* popup menus */
	popup_search = create_popup_search();
	popup_monitor = create_popup_monitor();
	popup_downloads = create_popup_dl_active();
	popup_queue = create_popup_dl_queued();	

    nodes_gui_early_init();
    uploads_gui_early_init();
    statusbar_gui_init();

    gui_init_menu();

    /* about box */
#ifdef GTA_REVISION
	g_snprintf(tmpstr, sizeof(tmpstr),
		"gtk-gnutella %s %s", version_number, GTA_REVISION);
#else
	g_snprintf(tmpstr, sizeof(tmpstr), "gtk-gnutella %s", version_number);
#endif
    gtk_label_set_text
        (GTK_LABEL(lookup_widget(dlg_about, "label_about_title")), tmpstr);

    /* search history combo stuff */
    gtk_combo_disable_activate
        (GTK_COMBO(lookup_widget(main_window, "combo_search")));

    /* copy url selection stuff */
    gtk_selection_add_target
        (popup_downloads, GDK_SELECTION_PRIMARY, GDK_SELECTION_TYPE_STRING, 1);

}

void main_gui_init(void)
{
    gtk_clist_set_column_justification(
        GTK_CLIST(lookup_widget(main_window, "clist_search_stats")),
        c_st_period, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        GTK_CLIST(lookup_widget(main_window, "clist_search_stats")),
        c_st_total, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        GTK_CLIST(lookup_widget(main_window, "clist_downloads")),
        c_dl_size, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        GTK_CLIST(lookup_widget(main_window, "clist_downloads_queue")),
        c_queue_size, GTK_JUSTIFY_RIGHT);

    gtk_clist_column_titles_passive(
        GTK_CLIST(lookup_widget(main_window, "clist_search_stats")));
#ifndef USE_GTK2
    gtk_clist_column_titles_passive(
        GTK_CLIST(lookup_widget(main_window, "clist_search")));
#endif
	gtk_clist_column_titles_passive(
        GTK_CLIST(lookup_widget(main_window, "clist_downloads")));
#ifndef USE_GTK2
    gtk_clist_set_compare_func(
        GTK_CLIST(lookup_widget(main_window, "clist_ul_stats")), 
        compare_ul_norm);
#endif

    {
        GtkCList *clist = 
            GTK_CLIST(lookup_widget(main_window, "clist_downloads_queue"));

        gtk_clist_column_titles_passive(clist);
        gtk_clist_set_reorderable(clist, TRUE);
        gtk_clist_set_use_drag_icons(clist, FALSE);
    }  

    // FIXME: those gtk_widget_set_sensitive should become obsolete when
    // all property-change callbacks are set up properly
	gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_remove_file"), FALSE);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_copy_url"), FALSE);
	gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort"), FALSE); 
	gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort_named"), FALSE);
	gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort_host"), FALSE);
    gtk_widget_set_sensitive(
        lookup_widget(popup_downloads, "popup_downloads_push"),
    	!gtk_toggle_button_get_active(
            GTK_TOGGLE_BUTTON
                (lookup_widget(main_window, 
                               "checkbutton_downloads_never_push"))));

    nodes_gui_init();
    settings_gui_init();
    gnet_stats_gui_init();
    search_stats_gui_init();
    uploads_gui_init();
    gui_update_c_downloads(0,0); // FIXME: remove when downloads are overhauled
    /* Must come before search_init() so searches/filters can be loaded.*/
	filter_init(); 
    search_gui_init();
    filter_update_targets(); /* Make sure the default filters are ok */
    monitor_gui_init();

    load_legacy_settings();

   	gui_update_all();
}

void main_gui_run(void)
{
    guint32 coord[4] = { 0, 0, 0, 0 };

    gui_prop_get_guint32(PROP_WINDOW_COORDS, coord, 0, 4);

    gui_update_global();

    /*
     * We need to tell Gtk the size of the window, otherwise we'll get
     * strange side effects when the window is shown (like implicitly
     * resized widgets).
     *      -- Richard, 8/9/2002
     */
    if ((coord[2] != 0) && (coord[3] != 0))
        gtk_window_set_default_size(
            GTK_WINDOW(main_window), coord[2], coord[3]);

    gtk_widget_show(main_window);		/* Display the main window */

    if ((coord[2] != 0) && (coord[3] != 0))
        gdk_window_move_resize(main_window->window, 
	    coord[0], coord[1], coord[2], coord[3]);

    gtk_main();
}

void main_gui_shutdown(void)
{
    guint32 coord[4] = { 0, 0, 0, 0};

	gdk_window_get_root_origin(main_window->window, &coord[0], &coord[1]);
	gdk_window_get_size(main_window->window, &coord[2], &coord[3]);
    gui_prop_set_guint32(PROP_WINDOW_COORDS, coord, 0, 4);

    /*
     * Discard all changes and close the dialog.
     */
    filter_close_dialog(FALSE);
	gtk_widget_hide(main_window);

    search_stats_gui_shutdown();
    filter_cb_close();
    monitor_gui_shutdown();
    search_gui_shutdown(); /* must be done before filter_shutdown! */
	filter_shutdown();
    nodes_gui_shutdown();
    uploads_gui_shutdown();
    settings_gui_shutdown();
}

void main_gui_timer()
{
    gui_update_global();
    gui_update_traffic_stats();
    filter_timer(); /* Update the filter stats */
}

void main_gui_shutdown_tick(guint left)
{
    static gboolean notice_visible = FALSE;
	gchar tmp[256];

    GtkLabel *label_shutdown_count;
 
    if (!notice_visible) {
        gtk_widget_show(shutdown_window);
        notice_visible = TRUE;
    }

    label_shutdown_count = GTK_LABEL
        (lookup_widget(shutdown_window, "label_shutdown_count"));

	g_snprintf(tmp, sizeof(tmp), "%d seconds", left);

	gtk_label_set(label_shutdown_count,tmp);
    gtk_main_flush();
}
