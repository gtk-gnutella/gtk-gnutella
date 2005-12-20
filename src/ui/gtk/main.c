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
 * Main functions for GTK+ interface.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "gui.h"

RCSID("$Id$");

#ifdef I_PWD
#include <pwd.h>
#endif /* I_PWD */

#ifdef USE_GTK1
#include "gtk1/interface-glade.h"
#endif
#ifdef USE_GTK2
#include "gtk2/interface-glade.h"
#endif

#include "notebooks.h"
#include "main.h"
#include "misc.h"
#include "nodes.h"
#include "hcache.h"
#include "main_cb.h"
#include "settings.h"
#include "search.h"
#include "monitor.h"
#include "statusbar.h"
#include "search_stats.h"
#include "gnet_stats.h"
#include "uploads.h"
#include "upload_stats.h"
#include "downloads.h"
#include "icon.h"
#include "filter_cb.h"
#include "filter_core.h"
#include "upload_stats_cb.h" /* FIXME: remove dependency (compare_ul_norm) */
#include "fileinfo.h"
#include "visual_progress.h"

#include "gtk-missing.h"

#include "gtk/misc.h"

#include "if/bridge/ui2c.h"

#include "lib/file.h"
#include "lib/glib-missing.h"
#include "lib/tm.h"
#include "lib/utf8.h"
#include "lib/override.h"			/* Must be the last header included */

/***
 *** Windows
 ***/
GtkWidget *main_window = NULL;
GtkWidget *shutdown_window = NULL;
GtkWidget *dlg_about = NULL;
GtkWidget *dlg_faq = NULL;
GtkWidget *dlg_prefs = NULL;
GtkWidget *dlg_quit = NULL;
GtkWidget *popup_downloads = NULL;
GtkWidget *popup_uploads = NULL;
GtkWidget *popup_search = NULL;
GtkWidget *popup_search_list = NULL;
GtkWidget *popup_nodes = NULL;
GtkWidget *popup_monitor = NULL;
GtkWidget *popup_queue = NULL;

/***
 *** Private functions
 ***/

static void
gui_init_window_title(void)
{
	gchar title[256];

#ifdef GTA_REVISION
	gm_snprintf(title, sizeof(title), "gtk-gnutella %s %s",
		GTA_VERSION_NUMBER, GTA_REVISION);
#else
	gm_snprintf(title, sizeof(title), "gtk-gnutella %s", GTA_VERSION_NUMBER);
#endif

	gtk_window_set_title(GTK_WINDOW(main_window), title);
}

/**
 * The contents of the navigation tree menu in exact order.
 */
static const struct {
	const gint	depth;	/**< Depth in tree */
	const gchar *title; /**< Translatable title for the node */
	const gint	page;	/**< Page reference ("the target") for the node */
} menu[] = {
	{   0,	 N_("GnutellaNet"),		nb_main_page_gnet },
	{     1, N_("Stats"),			nb_main_page_gnet_stats },
	{     1, N_("Hostcache"),		nb_main_page_hostcache },
	{   0,	 N_("Uploads"),			nb_main_page_uploads },
	{     1, N_("History"), 		nb_main_page_uploads_stats },
	{   0,	 N_("Downloads"),		nb_main_page_dl_files },
	{     1, N_("Active"),			nb_main_page_dl_active },
	{     1, N_("Queue"),			nb_main_page_dl_queue },
	{   0,	 N_("Search"),			nb_main_page_search },
	{     1, N_("Monitor"),			nb_main_page_monitor },
	{     1, N_("Stats"),			nb_main_page_search_stats },
};


#ifdef USE_GTK2

static gboolean
gui_init_menu_helper(GtkTreeModel *model, GtkTreePath *path,
	GtkTreeIter *iter, gpointer data)
{
	guint32 expanded;
	gint id;

	gtk_tree_model_get(model, iter, 1, &id, (-1));
	gui_prop_get_guint32(PROP_TREEMENU_NODES_EXPANDED, &expanded, id, 1);
	if (expanded)
		gtk_tree_view_expand_row(GTK_TREE_VIEW(data), path, FALSE);
	return FALSE;
}

static void
gui_init_menu(void)
{
	static GType types[] = {
		G_TYPE_STRING,	/* Label */
		G_TYPE_POINTER,		/* Notebook page number (casted to a pointer)*/
	};
	GtkTreeView	*treeview;
	GtkTreeIter	parent, iter;
	GtkTreeStore *store;
	GtkTreeViewColumn *column;
    GtkCellRenderer *renderer;
	guint i;
	gint depth = -1;

	STATIC_ASSERT(G_N_ELEMENTS(types) == 2);

    renderer = gtk_cell_renderer_text_new();
    g_object_set(renderer, "ypad", GUI_CELL_RENDERER_YPAD, (void *) 0);
	treeview = GTK_TREE_VIEW(lookup_widget(main_window, "treeview_menu"));
	store = gtk_tree_store_newv(G_N_ELEMENTS(types), types);

	for (i = 0; i < G_N_ELEMENTS(menu); i++) {
		if (depth < menu[i].depth) {
			g_assert(menu[i].depth == depth + 1);
	
			parent = iter;
			depth = menu[i].depth;
		} else if (depth > menu[i].depth) {
			do {
				gboolean valid;
				
				valid = gtk_tree_model_iter_parent(GTK_TREE_MODEL(store),
							&parent, &iter);	
				g_assert(valid);
				iter = parent;
			} while (--depth > menu[i].depth);
			depth = menu[i].depth;
		}
		
		gtk_tree_store_append(store, &iter, depth > 0 ? &parent : NULL);
		gtk_tree_store_set(store, &iter,
				0, _(menu[i].title),
				1, GINT_TO_POINTER(menu[i].page),
				(-1));
	}

	gtk_tree_view_set_model(treeview, GTK_TREE_MODEL(store));

	column = gtk_tree_view_column_new_with_attributes(
				NULL, renderer, "text", 0, (void *) 0);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_append_column(treeview, column);
	gtk_tree_view_columns_autosize(treeview);

	gtk_tree_model_foreach(GTK_TREE_MODEL(store),
		gui_init_menu_helper, treeview);

	g_object_unref(store);

	g_signal_connect(G_OBJECT(treeview), "cursor-changed",
		G_CALLBACK(on_main_gui_treeview_menu_cursor_changed), NULL);
	g_signal_connect(G_OBJECT(treeview), "row-collapsed",
		G_CALLBACK(on_main_gui_treeview_menu_row_collapsed), NULL);
	g_signal_connect(G_OBJECT(treeview), "row-expanded",
		G_CALLBACK(on_main_gui_treeview_menu_row_expanded), NULL);
}

static void
gui_menu_shutdown(void)
{
	g_signal_handlers_disconnect_by_func(
		G_OBJECT(lookup_widget(main_window, "treeview_menu")),
		on_main_gui_treeview_menu_cursor_changed,
		NULL);
	g_signal_handlers_disconnect_by_func(
		G_OBJECT(lookup_widget(main_window, "treeview_menu")),
		on_main_gui_treeview_menu_row_collapsed,
		NULL);
	g_signal_handlers_disconnect_by_func(
		G_OBJECT(lookup_widget(main_window, "treeview_menu")),
		on_main_gui_treeview_menu_row_expanded,
		NULL);
}

/**
 * Handles main window UI joining.
 *
 * Creates all dependent "tab" windows and merges them into
 * the main notebook.
 */
static GtkWidget *
gui_create_main_window(void)
{
	GtkWidget *window;
	GtkWidget *notebook;
	GtkWidget *tab_window[nb_main_page_num];
	gint i;

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
	tab_window[nb_main_page_uploads_stats] =
		create_main_window_upload_stats_tab();

	tab_window[nb_main_page_dl_active] = create_main_window_dl_active_tab();
	tab_window[nb_main_page_dl_files] = create_main_window_dl_files_tab();
	tab_window[nb_main_page_dl_queue] = create_main_window_dl_queue_tab();

	tab_window[nb_main_page_search] = create_main_window_search_tab();
	tab_window[nb_main_page_monitor] = create_main_window_monitor_tab();
	tab_window[nb_main_page_search_stats] =
		create_main_window_search_stats_tab();
	tab_window[nb_main_page_gnet_stats] = create_main_window_gnet_stats_tab();
	tab_window[nb_main_page_hostcache] = create_main_window_hostcache_tab();

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

static void
gui_init_menu(void)
{
    GtkCTree *ctree_menu = GTK_CTREE(lookup_widget(main_window, "ctree_menu"));
	GtkCTreeNode *parent_node = NULL;
	guint i;

	for (i = 0; i < G_N_ELEMENTS(menu); i++) {
		GtkCTreeNode *node;
		const gchar *title[1];

		title[0] = _(menu[i].title);
    	node = gtk_ctree_insert_node(ctree_menu,
					menu[i].depth == 0 ? NULL : parent_node, NULL,
					(gchar **) title, /* Override const */
					0, NULL, NULL, NULL, NULL, FALSE, TRUE);
		if (i == 0 || menu[i].depth < menu[i - 1].depth)
			parent_node = node;

    	gtk_ctree_node_set_row_data(ctree_menu, node,
			GINT_TO_POINTER(menu[i].page));
	}

	gtk_clist_select_row(GTK_CLIST(ctree_menu), 0, 0);
}

static void
gui_menu_shutdown(void)
{
	/* NOTHING */
}
	
#endif /* USE_GTK2 */


static GtkWidget *
gui_create_dlg_prefs(void)
{
	GtkWidget *dialog;
#ifdef USE_GTK2
    GtkWidget *notebook;
    GtkWidget *tab_window[nb_prefs_num];
	gint i;
#endif

    dialog = create_dlg_prefs();
#ifdef USE_GTK2

    notebook = lookup_widget(dialog, "notebook_prefs");

    /*
     * Then create all the tabs in their own window.
     */
	tab_window[nb_prefs_net] = create_dlg_prefs_net_tab();
	tab_window[nb_prefs_gnet] = create_dlg_prefs_gnet_tab();
	tab_window[nb_prefs_bw] = create_dlg_prefs_bw_tab();
	tab_window[nb_prefs_dl] = create_dlg_prefs_dl_tab();
	tab_window[nb_prefs_ul] = create_dlg_prefs_ul_tab();
	tab_window[nb_prefs_ui] = create_dlg_prefs_ui_tab();
	tab_window[nb_prefs_dbg] = create_dlg_prefs_dbg_tab();

    /*
     * Merge the UI and destroy the source windows.
     */
    for (i = 0; i < nb_prefs_num; i++) {
        GtkWidget *w = tab_window[i];
        gui_merge_window_as_tab(dialog, notebook, w);
        gtk_object_destroy(GTK_OBJECT(w));
    }

    /*
     * Get rid of the first (dummy) notebook tab.
     */
    gtk_container_remove(GTK_CONTAINER(notebook),
        gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook), 0));
#endif /* USE_GTK2 */

	return dialog;
}

static void
text_widget_append(GtkWidget *widget, const gchar *line)
#ifdef USE_GTK2
{
	GtkTextBuffer *textbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(widget));

	gtk_text_buffer_insert_at_cursor(textbuf, line, (-1));
}
#else /* !USE_GTK2 */
{
	gtk_text_insert(GTK_TEXT(widget), NULL, NULL, NULL, line, (-1));
}
#endif /* USE_GTK2 */

static GtkWidget *
gui_create_dlg_about(void)
{
    /* NB: These strings are UTF-8 encoded. */
    static const char * const contributors[] = {
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
        "Rapha\303\253l Manfredi <Raphael_Manfredi@pobox.com>",
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
        "Nicol\303\241s Lichtmaier <nick@technisys.com.ar>",
        "Rafael R. Reilova <rreilova@magepr.net>",
        "Stephane Corbe <noubi@users.sourceforge.net>",
        "Emile le Vivre <emile@struggle.ca>",
        "Angelo Cano <angelo_cano@fastmail.fm>",
        "Thomas Schuerger <thomas@schuerger.com>",
        "Russell Francis <rf358197@ohio.edu>",
        "Richard Hyde <email@richardhyde.net>",
        "Thadeu Lima de Souza Cascardo <cascardo@dcc.ufmg.br>",
        "Paco Arjonilla <pacoarjonilla@yahoo.es>",
        "Clayton Rollins <clayton.rollins@asu.edu>",
        "Hans de Graaff <hans@degraaff.org>",
        "Globuz",
		"Daichi Kawahata <daichik@users.sourceforge.net>",
		"Dave Rutherford <polymath69@users.sourceforge.net>",
		"Ian Sheldon <shellgeekorguk@users.sourceforge.net>",
		"Bill Pringlemeir <bpringle@sympatico.ca>",
    };
 	GtkWidget *dlg = create_dlg_about();
	GtkWidget *text = lookup_widget(dlg, "textview_about_contributors");
    guint i;
	
    gtk_label_set_text(
        GTK_LABEL(lookup_widget(dlg, "label_about_title")),
        guc_version_get_version_string());

  	for (i = 0; i < G_N_ELEMENTS(contributors); i++) {
		if (i > 0)
			text_widget_append(GTK_WIDGET(text), "\n");
		text_widget_append(GTK_WIDGET(text), contributors[i]);
	}

	gtk_label_set_text(
		GTK_LABEL(lookup_widget(dlg, "label_about_translation")),
		/* TRANSLATORS: Translate this as "Translation provided by" or similar
   	   	   and append your name to the list. */
    	Q_("translation_credit|"));

    return dlg;
}

static GtkWidget *
gui_create_dlg_faq(void)
{
	static const gchar faq_file[] = "FAQ";
	static file_path_t fp[4];
    GtkWidget *dlg = create_dlg_faq();
	GtkWidget *text = lookup_widget(dlg, "textview_faq");
	const gchar *lang;
	guint i = 0;
	FILE *f;

	lang = locale_get_language();

	file_path_set(&fp[i++], make_pathname(PRIVLIB_EXP, lang), faq_file);
	file_path_set(&fp[i++], PRIVLIB_EXP G_DIR_SEPARATOR_S "en", faq_file);
	
#ifndef OFFICIAL_BUILD
	file_path_set(&fp[i++],
		make_pathname(PACKAGE_EXTRA_SOURCE_DIR, lang), faq_file);

	file_path_set(&fp[i++],
		PACKAGE_EXTRA_SOURCE_DIR G_DIR_SEPARATOR_S "en", faq_file);
#endif /* !OFFICIAL_BUILD */

	g_assert(i <= G_N_ELEMENTS(fp));

	f = file_config_open_read_norename("FAQ", fp, i);
	if (f) {
		gchar buf[4096];
		gboolean tag = FALSE;

		while (fgets(buf, sizeof buf, f)) {
			const gchar *s;
			gchar *p;

			if (!utf8_is_valid_string(buf)) {
				text_widget_append(GTK_WIDGET(text),
					_("\nThe FAQ document is damaged.\n"));
				break;
			}

			/* Strip HTML tags */
			for (s = buf, p = buf; *s != '\0'; s++) {
				if (tag) {
					if (*s == '>')
						tag = FALSE;
				} else if (*s != '<') {
					*p++ = *s;
				} else {
					tag = TRUE;
				}
			}
			*p = '\0';
			
			text_widget_append(GTK_WIDGET(text), lazy_utf8_to_ui_string(buf));
		}

		fclose(f);
	} else {
		static const gchar msg[] =
		N_(	"The FAQ document could not be loaded. Please read the online FAQ "
			"at http://gtk-gnutella.sourceforge.net/?page=faq instead.");
		text_widget_append(GTK_WIDGET(text), _(msg));
	}
    return dlg;
}

/**
 * Searches for the gktrc file to use. Order in which they are scanned:
 *
 *	- $HOME/.gtkrc
 *	- $HOME/.gtk/gtkrc
 *	- $HOME/.gtk1/gtkrc ($HOME/.gtk2/gtkrc if GTK2 interface is used)
 *	- $GTK_GNUTELLA_DIR/gtkrc
 *	- ./gtkrc
 *
 * Where the last one can overrule settings from earlier resource files.
 */
void
main_gui_gtkrc_init(void)
{
#ifdef USE_GTK2
    const gchar rcfn[] = "gtkrc-2.0";
    const gchar rchfn[] = ".gtkrc-2.0";
#else
    const gchar rcfn[] = "gtkrc";
    const gchar rchfn[] = ".gtkrc";
#endif
	gchar *userrc;

	/* parse gtkrc files (thx to the sylpheed-claws developers for the tip) */
	userrc = make_pathname(guc_settings_home_dir(), rchfn);
	gtk_rc_parse(userrc);
	G_FREE_NULL(userrc);

	userrc = g_strconcat(guc_settings_home_dir(),
		G_DIR_SEPARATOR_S, ".gtk", G_DIR_SEPARATOR_S, "gtkrc", (void *) 0);
	gtk_rc_parse(userrc);
	G_FREE_NULL(userrc);

#ifdef USE_GTK2
	userrc = g_strconcat(guc_settings_home_dir(),
		G_DIR_SEPARATOR_S, ".gtk2", G_DIR_SEPARATOR_S, "gtkrc", (void *) 0);
#else
	userrc = g_strconcat(guc_settings_home_dir(),
		G_DIR_SEPARATOR_S, ".gtk1", G_DIR_SEPARATOR_S, "gtkrc", (void *) 0);
#endif
	gtk_rc_parse(userrc);
	G_FREE_NULL(userrc);

	userrc = make_pathname(guc_settings_config_dir(), rcfn);
	gtk_rc_parse(userrc);
	G_FREE_NULL(userrc);

	gtk_rc_parse("." G_DIR_SEPARATOR_S "gtkrc");
}

/***
 *** Public functions
 ***/

/**
 * Some setup of the gui side which I wanted out of main.c but must be done
 * before the backend can be initialized since the core code is not free of
 * GTK yet.
 *      -- Richard, 6/9/2002
 */
void
main_gui_early_init(gint argc, gchar **argv)
{
	/* Glade inits */

	gtk_set_locale();
	gtk_init(&argc, &argv);

	add_pixmap_directory(PRIVLIB_EXP G_DIR_SEPARATOR_S "pixmaps");
#ifndef OFFICIAL_BUILD
	add_pixmap_directory(PACKAGE_SOURCE_DIR G_DIR_SEPARATOR_S "pixmaps");
#endif

    main_window = gui_create_main_window();
    shutdown_window = create_shutdown_window();
    dlg_about = gui_create_dlg_about();
    dlg_faq = gui_create_dlg_faq();
    dlg_prefs = gui_create_dlg_prefs();
    dlg_quit = create_dlg_quit();

	/* popup menus */
	popup_search = create_popup_search();
#ifdef USE_GTK2
	/* XXX: Create the equivalent popup for GTK+ 1.2 */
	popup_search_list = create_popup_search_list();
#endif /* USE_GTK2 */

	popup_monitor = create_popup_monitor();
	popup_downloads = create_popup_dl_active();
	popup_queue = create_popup_dl_queued();

    nodes_gui_early_init();
    uploads_gui_early_init();
    statusbar_gui_init();

	gui_init_window_title();

    /* search history combo stuff */
    gtk_combo_disable_activate(GTK_COMBO(
		lookup_widget(main_window, "combo_search")));

    /* copy url selection stuff */
    gtk_selection_add_target(popup_downloads,
		GDK_SELECTION_PRIMARY, GDK_SELECTION_TYPE_STRING, 1);
}

void
main_gui_init(void)
{
	main_gui_gtkrc_init();

#ifdef USE_GTK1
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
#endif /* USE_GTK1 */

#ifdef USE_GTK2
	GTK_WINDOW(main_window)->allow_shrink = TRUE;
#endif /* USE_GTK2 */

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
	downloads_gui_init();
    fi_gui_init();
    vp_gui_init();
    nodes_gui_init();
    gui_init_menu();
    hcache_gui_init();
    gnet_stats_gui_init();
    search_stats_gui_init();
    uploads_gui_init();
    upload_stats_gui_init();
    /* Must come before search_init() so searches/filters can be loaded.*/
	filter_init();
    search_gui_init();
    filter_update_targets(); /* Make sure the default filters are ok */
    monitor_gui_init();
	gui_update_files_scanned();
    gui_update_stats_frames();
}

void
main_gui_run(void)
{
	time_t now = tm_time_exact();

    gtk_widget_show(main_window);		/* Display the main window */
	gui_restore_window(main_window, PROP_WINDOW_COORDS);
 
    icon_init();
    main_gui_timer(now);

 	gtk_widget_fix_width(
        lookup_widget(main_window, "frame_statusbar_uptime"),
        lookup_widget(main_window, "label_statusbar_uptime"),
        8, 8);

#ifdef USE_GTK2
	g_signal_connect(GTK_OBJECT(lookup_widget(main_window, "notebook_main")),
		"switch-page", G_CALLBACK(on_notebook_main_switch_page), NULL);
#else
	gtk_signal_connect(GTK_OBJECT(lookup_widget(main_window, "notebook_main")),
		"switch-page", on_notebook_main_switch_page, NULL);
#endif /* USE_GTK2 */

	/*
	 * Make sure the application starts in the Gnet pane.
	 */

	gtk_notebook_set_page(
		GTK_NOTEBOOK(lookup_widget(main_window, "notebook_main")),
		nb_main_page_gnet);

#ifdef USE_GTK1
	{
		GtkCTree *ctree_menu =
			GTK_CTREE(lookup_widget(main_window, "ctree_menu"));
		GtkCTreeNode *node;

		node = gtk_ctree_find_by_row_data(ctree_menu,
			gtk_ctree_node_nth(ctree_menu, 0),
			GINT_TO_POINTER(nb_main_page_gnet));

		if (node != NULL)
			gtk_ctree_select(ctree_menu, node);
	}
#endif /* USE_GTK1 */

	settings_gui_restore_panes();
    gtk_main();
}

void
main_gui_shutdown(void)
{
	icon_close();

    /*
     * Discard all changes and close the dialog.
     */

    filter_close_dialog(FALSE);
	gtk_widget_hide(main_window);
	if (dlg_prefs)
		gtk_widget_hide(dlg_prefs);

	gui_menu_shutdown();
    search_stats_gui_shutdown();
    filter_cb_close();
    monitor_gui_shutdown();
    search_gui_flush(0);
    search_gui_shutdown(); /* must be done before filter_shutdown! */
 	downloads_gui_shutdown();
	filter_shutdown();
	vp_gui_shutdown();
    fi_gui_shutdown();
    nodes_gui_shutdown();
    uploads_gui_shutdown();
    upload_stats_gui_shutdown();
	gnet_stats_gui_shutdown();
    hcache_gui_shutdown();
}

void
main_gui_update_coords(void)
{
	gui_save_window(main_window, PROP_WINDOW_COORDS);
}

/**
 * Main gui timer. This is called once a second.
 */
void
main_gui_timer(time_t now)
{
	gboolean overloaded;

	gnet_prop_get_boolean_val(PROP_OVERLOADED_CPU, &overloaded);

    gui_general_timer(now);
    search_gui_flush(now);
    gui_update_traffic_stats();

	/*
	 * When the CPU is overloaded, non-essential GUI information is not
	 * updated every second.
	 */

	if (!overloaded) {
		hcache_gui_update(now);
		gnet_stats_gui_update(now);
		search_stats_gui_update(now);
		nodes_gui_update_nodes_display(now);
		downloads_gui_update_display(now);
		uploads_gui_update_display(now);
		fi_gui_update_display(now);
		statusbar_gui_clear_timeouts(now);
		filter_timer();				/* Update the filter stats */
	} else {
		static guint counter = 0;

		switch (counter) {
		case 0: hcache_gui_update(now);					break;
		case 1: gnet_stats_gui_update(now);				break;
		case 2: search_stats_gui_update(now);			break;
		case 3: nodes_gui_update_nodes_display(now);	break;
		case 4: uploads_gui_update_display(now);		break;
		case 5: fi_gui_update_display(now);				break;
		case 6: statusbar_gui_clear_timeouts(now);		break;
		case 7: filter_timer();							break;
		case 8: downloads_gui_update_display(now);		break;
		default:
			g_error("bad modulus computation (counter is %d)", counter);
			break;
		}
		counter = (counter + 1) % 9;
	}
}

void
main_gui_shutdown_tick(guint left)
{
    static gboolean notice_visible = FALSE;
    GtkLabel *label;

    if (!notice_visible) {
        gtk_widget_show(shutdown_window);
        notice_visible = TRUE;
    }

    label = GTK_LABEL(lookup_widget(shutdown_window, "label_shutdown_count"));
	gtk_label_printf(label, NG_("%d second", "%d seconds", left), left);
    gtk_main_flush();
}

/* vi: set ts=4 sw=4 cindent: */
