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

RCSID("$Id$")

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

#define WIDGET(name) \
static GtkWidget * name ## _protected_ ; \
 \
GtkWidget *gui_ ## name (void) \
{ \
	return name ## _protected_ ; \
} \
 \
static inline void \
gui_ ## name ## _set (GtkWidget *w) \
{ \
	name ## _protected_ = w; \
} \
 \
GtkWidget * \
gui_ ## name ## _lookup(const gchar *id) \
{ \
	return lookup_widget(name ## _protected_ , id); \
}

WIDGET(dlg_about)
WIDGET(dlg_faq)
WIDGET(dlg_prefs)
WIDGET(dlg_quit)
WIDGET(main_window)
WIDGET(popup_downloads)
WIDGET(popup_monitor)
WIDGET(popup_nodes)
WIDGET(popup_queue)
WIDGET(popup_search)
WIDGET(popup_search_list)
WIDGET(popup_uploads)
WIDGET(shutdown_window)
#undef WIDGET

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

	gtk_window_set_title(GTK_WINDOW(gui_main_window()), title);
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
#ifdef USE_GTK1
	{   0,	 N_("Downloads"),		nb_main_page_dl_files },
	{     1, N_("Active"),			nb_main_page_dl_active },
	{     1, N_("Queue"),			nb_main_page_dl_queue },
#endif /* USE_GTK1 */
#ifdef USE_GTK2
	{   0,	 N_("Downloads"),		nb_main_page_downloads },
#endif /* USE_GTK1 */
	{   0,	 N_("Search"),			nb_main_page_search },
	{     1, N_("Monitor"),			nb_main_page_monitor },
	{     1, N_("Stats"),			nb_main_page_search_stats },
};


#ifdef USE_GTK2

static gboolean
gui_init_menu_helper(GtkTreeModel *model, GtkTreePath *path,
	GtkTreeIter *iter, gpointer data)
{
	static const GValue zero_value;
	GValue value;
	guint32 expanded;
	gint id;

	value = zero_value;
	gtk_tree_model_get_value(model, iter, 1, &value);
	id = GPOINTER_TO_UINT(g_value_get_pointer(&value));
	
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
		G_TYPE_POINTER,	/* Notebook page number (casted to a pointer) */
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
	treeview = GTK_TREE_VIEW(gui_main_window_lookup("treeview_menu"));
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
				1, GUINT_TO_POINTER(menu[i].page),
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
		G_OBJECT(gui_main_window_lookup("treeview_menu")),
		on_main_gui_treeview_menu_cursor_changed,
		NULL);
	g_signal_handlers_disconnect_by_func(
		G_OBJECT(gui_main_window_lookup("treeview_menu")),
		on_main_gui_treeview_menu_row_collapsed,
		NULL);
	g_signal_handlers_disconnect_by_func(
		G_OBJECT(gui_main_window_lookup("treeview_menu")),
		on_main_gui_treeview_menu_row_expanded,
		NULL);
}

#else

static void
gui_init_menu(void)
{
    GtkCTree *ctree_menu = GTK_CTREE(gui_main_window_lookup("ctree_menu"));
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

/**
 * Handles main window UI joining.
 *
 * Creates all dependent "tab" windows and merges them into
 * the main notebook.
 */
static void
gui_init_main_window(void)
{
#ifdef USE_GTK2
	GtkWidget *notebook;
	GtkWidget *tab_window[nb_main_page_num];
	gint i;

	/*
	 * First create the main window without the tab contents.
	 */
	notebook = gui_main_window_lookup("notebook_main");

	/*
	 * Then create all the tabs in their own window.
	 */
	tab_window[nb_main_page_gnet] = create_main_window_gnet_tab();
	tab_window[nb_main_page_uploads] = create_main_window_uploads_tab();
	tab_window[nb_main_page_uploads_stats] =
		create_main_window_upload_stats_tab();

	tab_window[nb_main_page_downloads] = create_main_window_downloads_tab();

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
		gui_merge_window_as_tab(gui_main_window(), notebook, w);
		gtk_object_destroy(GTK_OBJECT(w));
	}

	/*
	 * Get rid of the first (dummy) notebook tab.
	 * (My glade seems to require a tab to be defined in the notebook
	 * as a placeholder, or it creates _two_ unlabeled tabs at runtime).
	 */
	gtk_container_remove(GTK_CONTAINER(notebook),
		gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook), 0));

#endif	/* USE_GTK2 */
}

static void 
gui_init_dlg_prefs(void)
{
#ifdef USE_GTK2
    GtkWidget *notebook;
    GtkWidget *tab_window[nb_prefs_num];
	gint i;

    notebook = gui_dlg_prefs_lookup("notebook_prefs");

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
        gui_merge_window_as_tab(gui_dlg_prefs(), notebook, w);
        gtk_object_destroy(GTK_OBJECT(w));
    }

    /*
     * Get rid of the first (dummy) notebook tab.
     */
    gtk_container_remove(GTK_CONTAINER(notebook),
        gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook), 0));

#endif	/* USE_GTK2 */
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

static void
gui_init_dlg_about(void)
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
		"Bouklis Panos <panos@echidna-band.com>",
		"Sulyok P\303\251ter <sp@elte.hu>",
		"Alexander N. S\303\270rnes <alex@thehandofagony.com>",
		"Vitaliy Buyar <vetal18@users.sourceforge.net>",
		"Wu Xiaoguang <wxgnj@yahoo.com.cn>",
		"Lorenzo Gaifas <lorenzo@artiemestieri.tn.it>",
		"FlashCode <flashcode@flashtux.org>",
		"U\304\237ur \303\207etin <ugur.jnmbk@gmail.com>",
		"Lloyd Bryant <lloydbaz@msn.com>",
    };
	GtkWidget *text;
    guint i;
	
	text = gui_dlg_about_lookup("textview_about_contributors");
    gtk_label_set_text(
        GTK_LABEL(gui_dlg_about_lookup("label_about_title")),
        guc_version_get_version_string());

  	for (i = 0; i < G_N_ELEMENTS(contributors); i++) {
		if (i > 0)
			text_widget_append(GTK_WIDGET(text), "\n");
		text_widget_append(GTK_WIDGET(text),
			lazy_utf8_to_ui_string(contributors[i]));
	}

	gtk_label_set_text(
		GTK_LABEL(gui_dlg_about_lookup("label_about_translation")),
		/* TRANSLATORS: Translate this as "Translation provided by" or similar
   	   	   and append your name to the list. */
    	Q_("translation_credit|"));
}

static void
gui_init_dlg_faq(void)
{
	static const gchar faq_file[] = "FAQ";
	static file_path_t fp[4];
	GtkWidget *text;
	const gchar *lang;
	guint i = 0;
	FILE *f;

	text = gui_dlg_faq_lookup("textview_faq");
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
			
			/* Convert entities */
			p = buf;
			for (s = buf; '\0' != *s; s++) {
				if ('&' == *s) {
					const gchar *endptr;
					guint32 uc;

					uc = html_decode_entity(s, &endptr);
					if ((guint32) -1 != uc) {
						guint n;

						n = utf8_encode_char(uc, p, (endptr - s) + 1);
						p += n;
						s = endptr;
						continue;
					}
				}
				*p++ = *s;
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

    gui_main_window_set(create_main_window());
	gui_init_main_window();

    gui_shutdown_window_set(create_shutdown_window());
    gui_dlg_quit_set(create_dlg_quit());
	
    gui_dlg_about_set(create_dlg_about());
	gui_init_dlg_about();

    gui_dlg_faq_set(create_dlg_faq());
    gui_init_dlg_faq();

    gui_dlg_prefs_set(create_dlg_prefs());
	gui_init_dlg_prefs();

	/* popup menus */
	gui_popup_search_set(create_popup_search());
#ifdef USE_GTK2
	gui_popup_downloads_set(create_popup_downloads());
	/* XXX: Create the equivalent popup for GTK+ 1.2 */
	gui_popup_search_list_set(create_popup_search_list());
#endif /* USE_GTK2 */
	
#ifdef USE_GTK1
	gui_popup_downloads_set(create_popup_dl_active());
	gui_popup_queue_set(create_popup_dl_queued());
#endif /* USE_GTK1 */

	gui_popup_monitor_set(create_popup_monitor());

	gui_popup_nodes_set(create_popup_nodes());
    nodes_gui_early_init();

    gui_popup_uploads_set(create_popup_uploads());
    uploads_gui_early_init();
    statusbar_gui_init();

	gui_init_window_title();

    /* search history combo stuff */
    gtk_combo_disable_activate(GTK_COMBO(
		gui_main_window_lookup("combo_search")));

    /* copy url selection stuff */
    gtk_selection_add_target(gui_popup_downloads(),
		GDK_SELECTION_PRIMARY, GDK_SELECTION_TYPE_STRING, 1);
}

void
main_gui_init(void)
{
	main_gui_gtkrc_init();

#ifdef USE_GTK1
    gtk_clist_set_column_justification(
        GTK_CLIST(gui_main_window_lookup("clist_search_stats")),
        c_st_period, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        GTK_CLIST(gui_main_window_lookup("clist_search_stats")),
        c_st_total, GTK_JUSTIFY_RIGHT);
    gtk_clist_column_titles_passive(
        GTK_CLIST(gui_main_window_lookup("clist_search_stats")));

    gtk_clist_column_titles_passive(
        GTK_CLIST(gui_main_window_lookup("clist_search")));
    gtk_clist_set_compare_func(
        GTK_CLIST(gui_main_window_lookup("clist_ul_stats")),
        compare_ul_norm);
#endif /* USE_GTK1 */

#ifdef USE_GTK2
	GTK_WINDOW(gui_main_window())->allow_shrink = TRUE;
#endif /* USE_GTK2 */

#ifdef USE_GTK1
    /* FIXME: those gtk_widget_set_sensitive should become obsolete when
     * all property-change callbacks are set up properly
     */
	gtk_widget_set_sensitive
        (gui_popup_downloads_lookup("popup_downloads_remove_file"), FALSE);
    gtk_widget_set_sensitive
        (gui_popup_downloads_lookup("popup_downloads_copy_url"), FALSE);
	gtk_widget_set_sensitive
        (gui_popup_queue_lookup("popup_queue_abort"), FALSE);
	gtk_widget_set_sensitive
        (gui_popup_queue_lookup("popup_queue_abort_named"), FALSE);
	gtk_widget_set_sensitive
        (gui_popup_queue_lookup("popup_queue_abort_host"), FALSE);
    gtk_widget_set_sensitive(
        gui_popup_downloads_lookup("popup_downloads_push"),
    	!gtk_toggle_button_get_active(
            GTK_TOGGLE_BUTTON
                (lookup_widget(gui_main_window(),
                               "checkbutton_downloads_never_push"))));
#endif /* USE_GTK1 */

    settings_gui_init();
    fi_gui_init();
	downloads_gui_init();
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
main_gui_run(const gchar *geometry_spec)
{
	time_t now = tm_time_exact();

    gtk_widget_show(gui_main_window());		/* Display the main window */

	if (geometry_spec) {
		guint32 coord[4] = { 0, 0, 0, 0 };

    	gui_prop_get_guint32(PROP_WINDOW_COORDS, coord, 0, G_N_ELEMENTS(coord));
		if (0 == gui_parse_geometry_spec(geometry_spec, coord)) {
    		gui_prop_set_guint32(PROP_WINDOW_COORDS,
				coord, 0, G_N_ELEMENTS(coord));
		}
	}
	gui_restore_window(gui_main_window(), PROP_WINDOW_COORDS);
 
    icon_init();
    main_gui_timer(now);

 	gtk_widget_fix_width(
        gui_main_window_lookup("frame_statusbar_uptime"),
        gui_main_window_lookup("label_statusbar_uptime"),
        8, 8);

#ifdef USE_GTK2
	g_signal_connect(GTK_OBJECT(gui_main_window_lookup("notebook_main")),
		"switch-page", G_CALLBACK(on_notebook_main_switch_page), NULL);
#else
	gtk_signal_connect(GTK_OBJECT(gui_main_window_lookup("notebook_main")),
		"switch-page", on_notebook_main_switch_page, NULL);
#endif /* USE_GTK2 */

	/*
	 * Make sure the application starts in the Gnet pane.
	 */

	gtk_notebook_set_page(
		GTK_NOTEBOOK(gui_main_window_lookup("notebook_main")),
		nb_main_page_gnet);

#ifdef USE_GTK1
	{
		GtkCTree *ctree_menu =
			GTK_CTREE(gui_main_window_lookup("ctree_menu"));
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
	gtk_widget_hide(gui_main_window());
	if (gui_dlg_prefs())
		gtk_widget_hide(gui_dlg_prefs());

	gui_menu_shutdown();
    search_stats_gui_shutdown();
    filter_cb_close();
    monitor_gui_shutdown();
    search_gui_flush(tm_time(), TRUE);
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
	gui_save_window(gui_main_window(), PROP_WINDOW_COORDS);
}

/**
 * Main gui timer. This is called once a second.
 */
void
main_gui_timer(time_t now)
{
	static const gint num_states = 10;
	gboolean overloaded;
	gint i;

	gnet_prop_get_boolean_val(PROP_OVERLOADED_CPU, &overloaded);

    gui_general_timer(now);
    gui_update_traffic_stats();

	/*
	 * When the CPU is overloaded, non-essential GUI information is not
	 * updated every second.
	 */

	for (i = 0; i < num_states; i++) {
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
		case 9: search_gui_flush(now, FALSE);			break;
		default:
			g_error("bad modulus computation (counter is %d)", counter);
			break;
		}
		counter = (counter + 1) % num_states;

		if (overloaded)
			break;
	}
}

void
main_gui_shutdown_tick(guint left)
{
    static gboolean notice_visible = FALSE;
    GtkLabel *label;

    if (!notice_visible) {
        gtk_widget_show(gui_shutdown_window());
        notice_visible = TRUE;
    }

    label = GTK_LABEL(gui_shutdown_window_lookup("label_shutdown_count"));
	gtk_label_printf(label, NG_("%d second", "%d seconds", left), left);
    gtk_main_flush();
}

/* vi: set ts=4 sw=4 cindent: */
