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

#ifdef USE_GTK2
#include "interface-glade2.h"
#else
#include "interface-glade1.h"
#endif

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
#include "icon.h"

#include "filter_cb.h"
#include "filter.h"
#include "oldconfig.h"
#include "callbacks.h" /* FIXME: remove this dependency (compare_ul_norm) */

#include "fileinfo_gui.h"

#include <pwd.h>

RCSID("$Id$");

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
static void load_legacy_settings(void)
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
		g_warning(_("can't find your home directory!"));
 
    if (!config_dir) {
		if (home_dir) {
			gm_snprintf(tmp, sizeof(tmp),
				"%s/.gtk-gnutella", home_dir);
			config_dir = g_strdup(tmp);
		} else
			g_warning(_("no home directory: can't check legacy configuration!"));
	}

    gm_snprintf(core_config_file, sizeof(core_config_file), 
        "%s/%s", config_dir, "config_gnet");
    gm_snprintf(gui_config_file, sizeof(gui_config_file), 
        "%s/%s", config_dir, "config_gui");

    if (!file_exists(core_config_file) && !file_exists(gui_config_file)) {
        g_warning(_("No configuration found, trying legacy config file"));
        config_init();
    }

    g_free(config_dir);
    g_free(home_dir);
}

static void gui_init_window_title(void)
{
	gchar tmpstr[256];

	gm_snprintf(tmpstr, sizeof(tmpstr),
#ifdef GTA_REVISION
		"gtk-gnutella %s %s", version_number, GTA_REVISION
#else
		"gtk-gnutella %s", version_number
#endif
	);
	gtk_window_set_title(GTK_WINDOW(main_window), tmpstr);
}

#ifdef USE_GTK2

static gboolean gui_init_menu_helper(
	GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer data)
{
	guint32 expanded;
	gint id;
	
	gtk_tree_model_get(model, iter, 2, &id, -1);
	gui_prop_get_guint32(PROP_TREEMENU_NODES_EXPANDED, &expanded, id, 1);
	if (expanded)
		gtk_tree_view_expand_row(GTK_TREE_VIEW(data), path, FALSE);
	return FALSE;
}

static void gui_init_menu(void) 
{
	GtkTreeView	*treeview;
	GtkTreeIter	iter, parent;
	GtkTreeStore *store;
	GtkTreeViewColumn *column;
    GtkCellRenderer *renderer;

    renderer = gtk_cell_renderer_text_new();
    g_object_set(renderer, "ypad", GUI_CELL_RENDERER_YPAD, NULL);
	treeview = GTK_TREE_VIEW(lookup_widget(main_window, "treeview_menu"));
	store = gtk_tree_store_new(3,
		G_TYPE_STRING,	/* Label */
		G_TYPE_INT,		/* Notbook page */
		G_TYPE_INT);	/* Menu entry ID (persistent between releases) */

	gtk_tree_store_append(store, &parent, NULL);
	gtk_tree_store_set(store, &parent,
		0, _("gnutellaNet"), 1, nb_main_page_gnet, 2, TREEMENU_NODE_GNET, -1);
	gtk_tree_store_append(store, &iter, &parent);
	gtk_tree_store_set(store, &iter,
		0, _("Stats"), 1, nb_main_page_gnet_stats, 2, TREEMENU_NODE_GNET_STATS,
		-1);
	gtk_tree_store_append(store, &parent, NULL);
	gtk_tree_store_set(store, &parent,
		0, _("Uploads"), 1, nb_main_page_uploads, 2, TREEMENU_NODE_UL, -1);
	gtk_tree_store_append(store, &iter, &parent);
	gtk_tree_store_set(store, &iter,
		0, _("Stats"), 1, nb_main_page_uploads_stats, 2, TREEMENU_NODE_UL_STATS,
		-1);

	gtk_tree_store_append(store, &parent, NULL);
	gtk_tree_store_set(store, &parent,
		0, _("Downloads"), 1, nb_main_page_downloads, 2, TREEMENU_NODE_DL, -1);

	gtk_tree_store_append(store, &parent, NULL);
	gtk_tree_store_set(store, &parent,
		0, _("Search"), 1, nb_main_page_search, 2, TREEMENU_NODE_SEARCH, -1);
	gtk_tree_store_append(store, &iter, &parent);
	gtk_tree_store_set(store, &iter,
		0, _("Monitor"), 1, nb_main_page_monitor, 2, TREEMENU_NODE_SEARCH_MON, -1);
	gtk_tree_store_append(store, &iter, &parent);
	gtk_tree_store_set(store, &iter,
		0, _("Stats"), 1, nb_main_page_search_stats, 2, TREEMENU_NODE_SEARCH_STATS,
		-1);

	gtk_tree_store_append(store, &parent, NULL);
	gtk_tree_store_set(store, &parent,
		0, _("Config"), 1, nb_main_page_config_sel,
		2, TREEMENU_NODE_CFG_SEL, -1);
	gtk_tree_store_append(store, &iter, &parent);
	gtk_tree_store_set(store, &iter,
		0, _("Network"), 1, nb_main_page_config_net,
		2, TREEMENU_NODE_CFG_NET, -1);
	gtk_tree_store_append(store, &iter, &parent);
	gtk_tree_store_set(store, &iter,
		0, _("GnutellaNet"), 1, nb_main_page_config_gnet,
		2, TREEMENU_NODE_CFG_GNET, -1);
	gtk_tree_store_append(store, &iter, &parent);
	gtk_tree_store_set(store, &iter,
		0, _("Bandwidth"), 1, nb_main_page_config_bwc,
		2, TREEMENU_NODE_CFG_BWC, -1);
	gtk_tree_store_append(store, &iter, &parent);
	gtk_tree_store_set(store, &iter,
		0, _("Downloads"), 1, nb_main_page_config_dl,
		2, TREEMENU_NODE_CFG_DL, -1);
	gtk_tree_store_append(store, &iter, &parent);
	gtk_tree_store_set(store, &iter,
		0, _("Uploads"), 1, nb_main_page_config_ul,
		2, TREEMENU_NODE_CFG_UL, -1);
	gtk_tree_store_append(store, &iter, &parent);
	gtk_tree_store_set(store, &iter,
		0, _("User Interface"), 1, nb_main_page_config_ui,
		2, TREEMENU_NODE_CFG_UI, -1);
	gtk_tree_store_append(store, &iter, &parent);
	gtk_tree_store_set(store, &iter,
		0, _("Debugging"), 1, nb_main_page_config_dbg,
		2, TREEMENU_NODE_CFG_DBG, -1);

	gtk_tree_view_set_model(treeview, GTK_TREE_MODEL(store));

	column = gtk_tree_view_column_new_with_attributes(
		NULL, renderer, "text", 0, NULL);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_append_column(treeview, column);
	gtk_tree_view_columns_autosize(treeview);
	
	gtk_tree_model_foreach(GTK_TREE_MODEL(store),
		(gpointer) &gui_init_menu_helper, treeview);
	g_object_unref(store);

	g_signal_connect(G_OBJECT(treeview), "cursor-changed",
		G_CALLBACK(on_main_gui_treeview_menu_cursor_changed), NULL);
	g_signal_connect(G_OBJECT(treeview), "row-collapsed",
		G_CALLBACK(on_main_gui_treeview_menu_row_collapsed), NULL);
	g_signal_connect(G_OBJECT(treeview), "row-expanded",
		G_CALLBACK(on_main_gui_treeview_menu_row_expanded), NULL);
}

/*
 * gui_create_main_window:
 *
 * Handles main window UI joining.
 * Creates all dependent "tab" windows and merges them into
 * the main notebook.
 *
 */
static GtkWidget *gui_create_main_window(void)
{
	GtkWidget *window;
	GtkWidget *notebook;
	GtkWidget *tab_window[nb_main_page_num];
	gint i ;

	/*
	 * First create the main window without the tab contents.
	 */
	window = create_main_window();
	notebook = lookup_widget(window, "notebook_main");

	/*
	 * Then create all the tabs in their own window.
	 */
	tab_window[nb_main_page_gnet] = create_main_window_gnet_tab();
	tab_window[nb_main_page_uploads] = create_main_window_uploads_tab();
	tab_window[nb_main_page_uploads_stats] = create_main_window_upload_stats_tab();
	tab_window[nb_main_page_downloads] = create_main_window_downloads_tab();
	tab_window[nb_main_page_search] = create_main_window_search_tab();
	tab_window[nb_main_page_monitor] = create_main_window_monitor_tab();
	tab_window[nb_main_page_search_stats] = create_main_window_search_stats_tab();
	tab_window[nb_main_page_gnet_stats] = create_main_window_gnet_stats_tab();

	tab_window[nb_main_page_config_sel] = create_main_window_config_sel_tab();
	tab_window[nb_main_page_config_net] = create_main_window_config_net_tab();
	tab_window[nb_main_page_config_gnet] = create_main_window_config_gnet_tab();
	tab_window[nb_main_page_config_bwc] = create_main_window_config_bwc_tab();
	tab_window[nb_main_page_config_dl] = create_main_window_config_dl_tab();
	tab_window[nb_main_page_config_ul] = create_main_window_config_ul_tab();
	tab_window[nb_main_page_config_ui] = create_main_window_config_ui_tab();
	tab_window[nb_main_page_config_dbg] = create_main_window_config_dbg_tab();

	/*
	 * Merge the UI and destroy the source windows.
	 */
	for (i = 0; i < nb_main_page_num; i++) {
		GtkWidget *w = tab_window[i];
		gui_merge_window_as_tab(window, notebook, w);
		gtk_object_destroy(GTK_OBJECT(w));
	}

	/*
	 * Get rid of the first (dummy) notebook tab.
	 * (My glade seems to require a tab to be defined in the notebook
	 * as a placeholder, or it creates _two_ unlabeled tabs at runtime).
	 */
	gtk_container_remove(GTK_CONTAINER(notebook),
		gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook), 0));

	return window;
}

#else

#define gui_create_main_window() create_main_window()

static void gui_init_menu(void) 
{
	gchar *title;
	GtkCTreeNode *parent_node = NULL;    
	GtkCTreeNode *last_node = NULL;
    GtkCTree *ctree_menu =
        GTK_CTREE(lookup_widget(main_window, "ctree_menu"));

     /* gNet */
    title = (gchar *) &"gnutellaNet";
    parent_node = gtk_ctree_insert_node(
		ctree_menu, NULL, NULL, &title,
        0, NULL, NULL, NULL, NULL, FALSE, TRUE );
    gtk_ctree_node_set_row_data(
		ctree_menu, parent_node, 
        GINT_TO_POINTER(nb_main_page_gnet));

    /* gNet -> Stats */
    title = (gchar *) &"Stats";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), parent_node, NULL, &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE);
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        GINT_TO_POINTER(nb_main_page_gnet_stats));

    /* Uploads */
    title = (gchar *) &"Uploads";
    parent_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, &title,
        0, NULL, NULL, NULL, NULL, FALSE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), parent_node, 
        GINT_TO_POINTER(nb_main_page_uploads));

    /* Uploads -> Stats */
    title = (gchar *) &"Stats";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), parent_node, NULL, &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE);
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        GINT_TO_POINTER(nb_main_page_uploads_stats));

    /* Downloads */
    title = (gchar *) &"Downloads";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        GINT_TO_POINTER(nb_main_page_downloads));

    /* Search */
    title = (gchar *) &"Search";
    parent_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, &title,
        0, NULL, NULL, NULL, NULL, FALSE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), parent_node, 
        GINT_TO_POINTER(nb_main_page_search));

    /* Search -> Monitor */
    title = (gchar *) &"Monitor";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), parent_node, NULL, &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        GINT_TO_POINTER(nb_main_page_monitor));

    /* Search -> search stats */
    title = (gchar *) &"Stats";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), parent_node, NULL, &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        GINT_TO_POINTER(nb_main_page_search_stats));

    /* Config */
    title = (gchar *) &"Config";
    last_node = gtk_ctree_insert_node(
		GTK_CTREE(ctree_menu), NULL, NULL, &title,
        0, NULL, NULL, NULL, NULL, TRUE, TRUE );
    gtk_ctree_node_set_row_data(
		GTK_CTREE(ctree_menu), last_node, 
        GINT_TO_POINTER(nb_main_page_config));

	gtk_clist_select_row(GTK_CLIST(ctree_menu), 0, 0);
}
#endif /* USE_GTK2 */

static GtkWidget *gui_create_dlg_about(void)
{
    /* NB: These strings are ISO-8859-1 encoded. */
    static const char *contributors[] = {
        "Yann Grossel <olrick@users.sourceforge.net>",
        "Steven Wilcoxon <swilcoxon@users.sourceforge.net>",
        "Jason Lingohr <lingman@users.sourceforge.net>",
        "Brian St Pierre <bstpierre@users.sourceforge.net>",
        "Chuck Homic <homic@users.sourceforge.net>",
        "Ingo Saitz <salz@users.sourceforge.net>",
        "Ben Hochstedler <hochstrb@users.sourceforge.net>",
        "Daniel Walker <axiom@users.sourceforge.net>",
        "Paul Cassella <pwc@users.sourceforge.net>",
        "Jared Mauch <jaredmauch@users.sourceforge.net>",
        "Nate E <web1 (at) users dot sourceforge dot net>",
        "Rapha\353l Manfredi <Raphael_Manfredi@pobox.com>",
        "Kenn Brooks Hamm <khamm@andrew.cmu.edu>",
        "Mark Schreiber <mark7@andrew.cmu.edu>",
        "Sam Varshavchik <mrsam@courier-mta.com>",
        "Vladimir Klebanov <unny@rz.uni-karlsruhe.de>",
        "Roman Shterenzon <roman@xpert.com>",
        "Robert Bihlmeyer <robbe@orcus.priv.at>",
        "Noel T.Nunkovich <ntnunk@earthlink.net>",
        "Michael Tesch <tesch@users.sourceforge.net>",
        "Markus 'guruz' Goetz <guruz@guruz.info>",
        "Richard Eckart <wyldfire@users.sourceforge.net>",
        "Christophe Tronche <ch.tronche@computer.org>",
        "Alex Bennee <alex@bennee.com>",
        "Mike Perry <mikepery@fscked.org>",
        "Zygo Blaxell <zblaxell@feedme.hungrycats.org>",
        "Vidar Madsen <vidar@gimp.org>",
        "Christian Biere <christianbiere@gmx.de>",
        "ko <junkpile@free.fr>",
        "Jeroen Asselman <jeroen@asselman.com>",
        "T'aZ <tazdev@altern.org>",
        "Andrew Barnert <barnert@myrealbox.com>",
        "Michael Gray <mrgray01@louisville.edu>",
        "Nicol\341s Lichtmaier <nick@technisys.com.ar>",
        "Emile le Vivre <emile@struggle.ca>",
        "Angelo Cano <angelo_cano@fastmail.fm>",
        NULL
    };
    GtkWidget *dlg = create_dlg_about();
    guint i;
#ifdef USE_GTK2
    GtkTextBuffer *textbuf;

    textbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(
        lookup_widget(dlg, "textview_about_contributors")));
    
    for (i = 0; NULL != contributors[i]; i++) {
        static char s[256];

        gm_snprintf(s, sizeof(s), "%s%s", i > 0 ? "\n" : "", contributors[i]);
        gtk_text_buffer_insert_at_cursor(
            textbuf, convert_to_utf8(s, 0, "ISO-8859-1"), (-1));
    }
#else
    GtkText *text = GTK_TEXT(lookup_widget(dlg, "text_about_contributors"));

    for (i = 0; NULL != contributors[i]; i++) {
        if (i > 0)
            gtk_text_insert(text, NULL, NULL, NULL, "\n", (-1));
        gtk_text_insert(text, NULL, NULL, NULL, contributors[i], (-1));
    }
#endif

    gtk_label_set_text(
        GTK_LABEL(lookup_widget(dlg, "label_about_title")), 
        version_string);

    return dlg;
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
#ifdef USE_SOURCE_DIR_AS_FALLBACK
	add_pixmap_directory(PACKAGE_SOURCE_DIR "/pixmaps");
#endif

    main_window = gui_create_main_window();
    shutdown_window = create_shutdown_window();
    dlg_about = gui_create_dlg_about();
    dlg_quit = create_dlg_quit();

	/* popup menus */
	popup_search = create_popup_search();
	popup_monitor = create_popup_monitor();
	popup_downloads = create_popup_dl_active();
	popup_queue = create_popup_dl_queued();	

    nodes_gui_early_init();
    uploads_gui_early_init();
    statusbar_gui_init();

	gui_init_window_title();

    /* search history combo stuff */
    gtk_combo_disable_activate
        (GTK_COMBO(lookup_widget(main_window, "combo_search")));

    /* copy url selection stuff */
    gtk_selection_add_target
        (popup_downloads, GDK_SELECTION_PRIMARY, GDK_SELECTION_TYPE_STRING, 1);

}

void main_gui_init(void)
{	
#ifndef USE_GTK2
    gtk_clist_set_column_justification(
        GTK_CLIST(lookup_widget(main_window, "clist_search_stats")),
        c_st_period, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        GTK_CLIST(lookup_widget(main_window, "clist_search_stats")),
        c_st_total, GTK_JUSTIFY_RIGHT);
    gtk_clist_column_titles_passive(
        GTK_CLIST(lookup_widget(main_window, "clist_search_stats")));

    gtk_clist_column_titles_passive(
        GTK_CLIST(lookup_widget(main_window, "clist_search")));
    gtk_clist_set_compare_func(
        GTK_CLIST(lookup_widget(main_window, "clist_ul_stats")), 
        compare_ul_norm);
#endif
    gtk_clist_set_column_justification(
        GTK_CLIST(lookup_widget(main_window, "clist_downloads")),
        c_dl_size, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        GTK_CLIST(lookup_widget(main_window, "clist_downloads_queue")),
        c_queue_size, GTK_JUSTIFY_RIGHT);

	gtk_clist_column_titles_passive(
        GTK_CLIST(lookup_widget(main_window, "clist_downloads")));

    {
        GtkCList *clist = 
            GTK_CLIST(lookup_widget(main_window, "clist_downloads_queue"));

        gtk_clist_column_titles_passive(clist);
        gtk_clist_set_reorderable(clist, TRUE);
        gtk_clist_set_use_drag_icons(clist, FALSE);
    }  

    /* FIXME: those gtk_widget_set_sensitive should become obsolete when
     * all property-change callbacks are set up properly
     */
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
    settings_gui_init();
    fi_gui_init();
    nodes_gui_init();
    gui_init_menu();
    gnet_stats_gui_init();
    search_stats_gui_init();
    uploads_gui_init();
    upload_stats_gui_init();
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
    
    icon_init();

    if ((coord[2] != 0) && (coord[3] != 0))
        gdk_window_move_resize(main_window->window, 
	    coord[0], coord[1], coord[2], coord[3]);

    gtk_main();
}

void main_gui_shutdown(void)
{
    gint32 coord[4] = { 0, 0, 0, 0};
	
	icon_close();

	gdk_window_get_root_origin(main_window->window, &coord[0], &coord[1]);
	gdk_drawable_get_size(main_window->window, &coord[2], &coord[3]);
    gui_prop_set_guint32(PROP_WINDOW_COORDS, (guint32 *) coord, 0, 4);

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
    fi_gui_shutdown();
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

	gm_snprintf(tmp, sizeof(tmp), "%d seconds", left);

	gtk_label_set(label_shutdown_count,tmp);
    gtk_main_flush();
}

