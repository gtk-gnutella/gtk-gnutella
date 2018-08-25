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
 * Main functions for GTK+ interface.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 */

#include "gui.h"

#ifdef I_PWD
#include <pwd.h>
#endif /* I_PWD */

#ifdef HAVE_GTKOSXAPPLICATION
#include <gtkmacintegration/gtkosxapplication.h>
#include "settings_cb.h"
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
#include "fileinfo.h"
#include "visual_progress.h"

#include "gtk/misc.h"

#include "if/bridge/ui2c.h"

#include "lib/crash.h"
#include "lib/entropy.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/hstrfn.h"
#include "lib/omalloc.h"
#include "lib/path.h"
#include "lib/product.h"
#include "lib/str.h"
#include "lib/tm.h"
#include "lib/utf8.h"

#include "lib/override.h"			/* Must be the last header included */

/***
 *** Windows
 ***/

/*
 * For each window xxx defined by glade through a create_xxx() call, we define
 * 3 routines and a private variable.
 *
 * Variable xxx_protected_ contains the output of create_xxx(), and is
 * initialized via a call to gui_xxx_set() done in main_gui_early_init().
 * This variable is accessed only through gui_xxx() calls, never directly.
 *
 * The gui_xxx_lookup() routine is used to invoke lookup_widget() on a
 * particular xxx window.
 *
 * gui_xxx()			public
 * gui_xxx_set()		private
 * gui_xxx_lookup()		public
 */

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
WIDGET(dlg_glossary)
WIDGET(dlg_ancient)
WIDGET(dlg_prefs)
WIDGET(dlg_quit)
WIDGET(main_window)
WIDGET(popup_downloads)
WIDGET(popup_monitor)
WIDGET(popup_nodes)
WIDGET(popup_search)
WIDGET(popup_search_list)
WIDGET(popup_sources)
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
	const char *revision = product_revision();

	if (revision[0] != '\0') {
		str_bprintf(title, sizeof(title), "gtk-gnutella %s %s",
			product_version(), revision);
	} else {
		str_bprintf(title, sizeof(title), "gtk-gnutella %s",
			product_version());
	}

	gtk_window_set_title(GTK_WINDOW(gui_main_window()), title);
}

static GSList *visibility_listeners[nb_main_page_num];
static GSList *main_visibility_listeners;
static int notebook_main_current_page;
static gboolean main_window_is_visible;

gboolean
main_gui_window_visible(void)
{
	return main_window_is_visible;
}

static void
main_gui_page_visibility_change(int page_num, gboolean visible)
{
	GSList *sl;

	g_return_if_fail(UNSIGNED(page_num) < nb_main_page_num);

	/*
	 * Process per-page visibility change handlers.
	 */

	GM_SLIST_FOREACH(visibility_listeners[page_num], sl) {
		main_gui_visibility_cb func = cast_pointer_to_func(sl->data);

		g_assert(func != NULL);
		(*func)(visible);
	}
}

static gboolean
on_main_gui_map_event(GtkWidget *unused_widget,
	GdkEvent *event, gpointer unused_udata)
{
	const gboolean was_visible = main_window_is_visible;

	(void) unused_widget;
	(void) unused_udata;

	entropy_harvest_single(PTRLEN(event));

	switch (event->type) {
	case GDK_MAP:
		main_window_is_visible = TRUE;
		break;

	case GDK_UNMAP:
		main_window_is_visible = FALSE;
		break;

#if GTK_CHECK_VERSION(2,0,0)
	case GDK_WINDOW_STATE:
		main_window_is_visible = !(event->window_state.new_window_state
				& (GDK_WINDOW_STATE_WITHDRAWN | GDK_WINDOW_STATE_ICONIFIED));
		break;
#endif	/* Gtk+ >= 2.0 */

	default:
		break;
	}
	if (was_visible != main_window_is_visible) {
		GSList *sl;

		/*
		 * Process global visibility change handlers.
		 */

		GM_SLIST_FOREACH(main_visibility_listeners, sl) {
			main_gui_visibility_cb func = cast_pointer_to_func(sl->data);

			g_assert(func != NULL);
			(*func)(main_window_is_visible);
		}

		main_gui_page_visibility_change(notebook_main_current_page,
			main_window_is_visible);
	}
	return FALSE;	/* propagate further */
}

static void
on_notebook_main_switch_page(GtkNotebook *unused_notebook,
	GtkNotebookPage *unused_page, int page_num, void *unused_udata)
{
	int old_page;

	(void) unused_notebook;
	(void) unused_page;
	(void) unused_udata;

	g_return_if_fail(UNSIGNED(page_num) < nb_main_page_num);

	entropy_harvest_single(VARLEN(page_num));

	old_page = notebook_main_current_page;
	notebook_main_current_page = page_num;

	gui_prop_set_guint32_val(PROP_MAIN_NOTEBOOK_TAB, page_num);

	if (main_window_is_visible) {
		main_gui_page_visibility_change(old_page, FALSE);
		main_gui_page_visibility_change(notebook_main_current_page, TRUE);
	}
}

void
main_gui_add_visibility_listener(main_gui_visibility_cb func)
{
	g_return_if_fail(func);

	main_visibility_listeners = g_slist_append(
			main_visibility_listeners, cast_func_to_pointer(func));
}

void
main_gui_remove_visibility_listener(main_gui_visibility_cb func)
{
	g_return_if_fail(func);

	main_visibility_listeners = g_slist_remove(
			main_visibility_listeners, cast_func_to_pointer(func));
}

void
main_gui_add_page_visibility_listener(main_gui_visibility_cb func,
	int page_num)
{
	g_return_if_fail(func);
	g_return_if_fail(UNSIGNED(page_num) < nb_main_page_num);

	visibility_listeners[page_num] = g_slist_append(
			visibility_listeners[page_num], cast_func_to_pointer(func));
}

void
main_gui_remove_page_visibility_listener(main_gui_visibility_cb func,
	int page_num)
{
	g_return_if_fail(func);
	g_return_if_fail(UNSIGNED(page_num) < nb_main_page_num);

	visibility_listeners[page_num] = g_slist_remove(
			visibility_listeners[page_num], cast_func_to_pointer(func));
}

int
main_gui_notebook_get_page(void)
{
	g_assert(UNSIGNED(notebook_main_current_page) < nb_main_page_num);
	return notebook_main_current_page;
}

void
main_gui_notebook_set_page(int page_num)
{
	g_return_if_fail(UNSIGNED(page_num) < nb_main_page_num);

	entropy_harvest_single(VARLEN(page_num));

	gtk_notebook_set_current_page(
		GTK_NOTEBOOK(gui_main_window_lookup("notebook_main")),
		page_num);
}

#ifdef USE_GTK2
static const gchar *
notebook_main_page_label(gint page)
{
	g_return_val_if_fail(UNSIGNED(page) < nb_main_page_num, NULL);
	switch (page) {
	case nb_main_page_network:			return _("Network");
	case nb_main_page_search:			return _("Searches");
	case nb_main_page_downloads:		return _("Downloads");
	case nb_main_page_uploads:			return _("Uploads");
	case nb_main_page_stats:			return _("Statistics");
	case nb_main_page_monitor:			return _("Search Monitor");
	case nb_main_page_uploads_stats:	return _("Upload History");
	case nb_main_page_hostcache:		return _("Hostcache");
	case nb_main_page_search_stats:		return _("Search Stats");
	}
	return NULL;
}
#endif	/* Gtk+ >= 2.0 */

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
	gtk_notebook_set_show_tabs(GTK_NOTEBOOK(notebook), TRUE);

	/*
	 * Then create all the tabs in their own window.
	 */
	tab_window[nb_main_page_network] = create_main_window_gnet_tab();
	tab_window[nb_main_page_uploads] = create_main_window_uploads_tab();
	tab_window[nb_main_page_uploads_stats] =
		create_main_window_upload_stats_tab();

	tab_window[nb_main_page_downloads] = create_main_window_downloads_tab();

	tab_window[nb_main_page_search] = create_main_window_search_tab();
	tab_window[nb_main_page_monitor] = create_main_window_monitor_tab();
	tab_window[nb_main_page_search_stats] =
		create_main_window_search_stats_tab();
	tab_window[nb_main_page_stats] = create_main_window_gnet_stats_tab();
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

	for (i = 0; i < nb_main_page_num; i++) {
		gtk_notebook_set_tab_label_text(GTK_NOTEBOOK(notebook),
			gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook), i),
			notebook_main_page_label(i));
	}

	gui_signal_connect(gui_main_window(), "window-state-event",
		on_main_gui_map_event, NULL);

#endif	/* USE_GTK2 */

	gui_signal_connect(gui_main_window(), "map-event",
		on_main_gui_map_event, NULL);
	gui_signal_connect(gui_main_window(), "unmap-event",
		on_main_gui_map_event, NULL);
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
		"Yann Grossel <olrick\100users.sourceforge.net>",
		"Steven Wilcoxon <swilcoxon\100users.sourceforge.net>",
		"Jason Lingohr <lingman\100users.sourceforge.net>",
		"Brian St Pierre <bstpierre\100users.sourceforge.net>",
		"Chuck Homic <homic\100users.sourceforge.net>",
		"Ingo Saitz <salz\100users.sourceforge.net>",
		"Ben Hochstedler <hochstrb\100users.sourceforge.net>",
		"Daniel Walker <axiom\100users.sourceforge.net>",
		"Paul Cassella <pwc\100users.sourceforge.net>",
		"Jared Mauch <jaredmauch\100users.sourceforge.net>",
		"Nate E <web1 (at) users dot sourceforge dot net>",
		"Rapha\303\253l Manfredi <Raphael_Manfredi\100pobox.com>",
		"Kenn Brooks Hamm <khamm\100andrew.cmu.edu>",
		"Mark Schreiber <mark7\100andrew.cmu.edu>",
		"Sam Varshavchik <mrsam\100courier-mta.com>",
		"Vladimir Klebanov <unny\100rz.uni-karlsruhe.de>",
		"Roman Shterenzon <roman\100xpert.com>",
		"Robert Bihlmeyer <robbe\100orcus.priv.at>",
		"Noel T.Nunkovich <ntnunk\100earthlink.net>",
		"Michael Tesch <tesch\100users.sourceforge.net>",
		"Markus 'guruz' Goetz <guruz\100guruz.info>",
		"Richard Eckart <wyldfire\100users.sourceforge.net>",
		"Christophe Tronche <ch.tronche\100computer.org>",
		"Alex Bennee <alex\100bennee.com>",
		"Mike Perry <mikepery\100fscked.org>",
		"Zygo Blaxell <zblaxell\100feedme.hungrycats.org>",
		"Vidar Madsen <vidar\100gimp.org>",
		"Christian Biere <christianbiere\100gmx.de>",
		"ko <junkpile\100free.fr>",
		"Jeroen Asselman <jeroen\100asselman.com>",
		"T'aZ <tazdev\100altern.org>",
		"Andrew Barnert <barnert\100myrealbox.com>",
		"Michael Gray <mrgray01\100louisville.edu>",
		"Nicol\303\241s Lichtmaier <nick\100technisys.com.ar>",
		"Rafael R. Reilova <rreilova\100magepr.net>",
		"Stephane Corbe <noubi\100users.sourceforge.net>",
		"Emile le Vivre <emile\100struggle.ca>",
		"Angelo Cano <angelo_cano\100fastmail.fm>",
		"Thomas Schuerger <thomas\100schuerger.com>",
		"Russell Francis <rf358197\100ohio.edu>",
		"Richard Hyde <email\100richardhyde.net>",
		"Thadeu Lima de Souza Cascardo <cascardo\100dcc.ufmg.br>",
		"Paco Arjonilla <pacoarjonilla\100yahoo.es>",
		"Clayton Rollins <clayton.rollins\100asu.edu>",
		"Hans de Graaff <hans\100degraaff.org>",
		"Globuz",
		"Daichi Kawahata <daichik\100users.sourceforge.net>",
		"Dave Rutherford <polymath69\100users.sourceforge.net>",
		"Ian Sheldon <shellgeekorguk\100users.sourceforge.net>",
		"Bill Pringlemeir <bpringle\100sympatico.ca>",
		"Bouklis Panos <panos\100echidna-band.com>",
		"Sulyok P\303\251ter <sp\100elte.hu>",
		"Alexander N. S\303\270rnes <alex\100thehandofagony.com>",
		"Vitaliy Buyar <vetal18\100users.sourceforge.net>",
		"Wu Xiaoguang <wxgnj\100yahoo.com.cn>",
		"Lorenzo Gaifas <lorenzo\100artiemestieri.tn.it>",
		"FlashCode <flashcode\100flashtux.org>",
		"U\304\237ur \303\207etin <ugur.jnmbk\100gmail.com>",
		"Lloyd Bryant <lloydbaz\100msn.com>",
		"Martijn van Oosterhout <kleptog\100svana.org>",
		"Jochen Kemnade <jochenkemnade\100web.de>",
		"Larry Nieves <lanieves\100gmail.com>",
    };
	GtkWidget *text;
    guint i;

	text = gui_dlg_about_lookup("textview_about_contributors");
    gtk_label_set_text(
        GTK_LABEL(gui_dlg_about_lookup("label_about_title")),
        guc_version_get_version_string());

  	for (i = 0; i < N_ITEMS(contributors); i++) {
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

/**
 * Searches for the gktrc file to use. Order in which they are scanned:
 *
 *	- $HOME/.gtkrc
 *	- $HOME/.gtk/gtkrc
 *	- $HOME/.gtk1/gtkrc ($HOME/.gtk2/gtkrc if GTK2 interface is used)
 *	- $GTK_GNUTELLA_DIR/gtkrc
 *
 * Where the last one can overrule settings from earlier resource files.
 */
static void
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
	HFREE_NULL(userrc);

	userrc = h_strconcat(guc_settings_home_dir(),
		G_DIR_SEPARATOR_S, ".gtk", G_DIR_SEPARATOR_S, "gtkrc", NULL_PTR);
	gtk_rc_parse(userrc);
	HFREE_NULL(userrc);

#ifdef USE_GTK2
	userrc = h_strconcat(guc_settings_home_dir(),
		G_DIR_SEPARATOR_S, ".gtk2", G_DIR_SEPARATOR_S, "gtkrc", NULL_PTR);
#else
	userrc = h_strconcat(guc_settings_home_dir(),
		G_DIR_SEPARATOR_S, ".gtk1", G_DIR_SEPARATOR_S, "gtkrc", NULL_PTR);
#endif
	gtk_rc_parse(userrc);
	HFREE_NULL(userrc);

	userrc = make_pathname(guc_settings_config_dir(), rcfn);
	gtk_rc_parse(userrc);
	HFREE_NULL(userrc);
}

/***
 *** Public functions
 ***/

void
main_gui_show_prefences(void)
{
	g_return_if_fail(gui_dlg_prefs());

    gtk_widget_show(gui_dlg_prefs());
	gui_restore_window(gui_dlg_prefs(), PROP_PREFS_DLG_COORDS);
	gdk_window_raise(gui_dlg_prefs()->window);
}

#ifdef HAVE_GTKOSXAPPLICATION
void main_gui_init_osx()
{
	GError *err = NULL;
	GtkosxApplication *theApp = g_object_new(GTKOSX_TYPE_APPLICATION, NULL);
	GtkUIManager *mgr = gtk_ui_manager_new();
	GtkWidget *item;
	GtkWidget *sep;
	GtkWidget *menubar;

	g_signal_connect(theApp, "NSApplicationBlockTermination",
					 G_CALLBACK(on_button_quit_clicked), NULL);
	g_signal_connect(theApp, "NSApplicationDidBecomeActive",
					 G_CALLBACK(on_NSApplicationDidBecomeActive), NULL);
	g_signal_connect(theApp, "NSApplicationOpenFile",
					 G_CALLBACK(on_NSApplicationOpenFile), NULL);

	gtk_ui_manager_add_ui_from_string(mgr,
		"<ui>"
		"<menubar name='MenuBar'>"
		"<menu name='File' action='FileAction'>"
		"  <menuitem action='CloseWindow'/>"
		"  <menuitem name='Preferences' action='PreferencesAction'/>"
		"  <menuitem name='Quit' action='QuitAction'/>"
		"</menu>"
		"<menu name='View' action='ViewAction'>"
		"  <menuitem action='menu_searchbar_visible'/>"
		"  <menuitem action='menu_sidebar_visible'/>"
		"  <menuitem action='menu_menubar_visible'/>"
		"  <menuitem action='menu_statusbar_visible'/>"
		"  <separator/>"
		"  <menu action='connection_counters1'>"
		"    <menuitem action='menu_downloads_visible'/>"
		"    <menuitem action='menu_uploads_visible'/>"
		"    <menuitem action='menu_connections_visible'/>"
		"  </menu>"

		"  <menu action='menu_http_stats_visible'>"
		"    <menuitem action='menu_bws_in_visible'/>"
		"    <menuitem action='menu_bws_out_visible'/>"
		"  </menu>"

		"  <menu action='menu_gnet_stats_visible'>"
		"    <menuitem action='menu_bws_gin_visible'/>"
		"    <menuitem action='menu_bws_gout_visible'/>"
		"  </menu>"

		"  <menu action='menu_gnet_leaf_stats_visible'>"
		"    <menuitem action='menu_autohide_bws_gleaf'/>"
		"    <menuitem action='menu_bws_glin_visible'/>"
		"    <menuitem action='menu_bws_glout_visible'/>"
		"  </menu>"

		"  <menu action='menu_dht_traffic_stats_visible'>"
		"    <menuitem action='menu_autohide_bws_dht'/>"
		"    <menuitem action='menu_bws_dht_in_visible'/>"
		"    <menuitem action='menu_bws_dht_out_visible'/>"
		"  </menu>"
		"</menu>"
		"<menu name='Help' action='HelpAction'>"
		"  <menuitem action='FAQAction'/>"
		"  <menuitem name='About' action='AboutAction'/>"
		"</menu>"
		"</menubar>"
		"</ui>",
		-1, &err);


	if (err != NULL) {
		g_error("%s", err->message);
	}
	static GtkActionEntry entries[] = {
		{ "FileAction", NULL, "_File", NULL, NULL, NULL },
		{ "PreferencesAction", GTK_STOCK_PREFERENCES, "Preferences",
			NULL, "Set Viewing Preferences",
			G_CALLBACK(on_menu_prefs_activate) },

		{ "CloseWindow", NULL, "Close window",
			"<meta>W", NULL,
			G_CALLBACK(on_main_window_delete_event_hide) },

		{ "QuitAction", GTK_STOCK_QUIT, "_Quit",
			"<control>q", "Quit Gtk-Gnutella",
			G_CALLBACK (on_button_quit_clicked) },

		{ "ViewAction", NULL, "View", NULL, NULL, NULL },

		{ "connection_counters1", NULL,
			"Connection counters", NULL, NULL, NULL },

		{ "menu_http_stats_visible", NULL,
			"_HTTP traffic stats", NULL, NULL, NULL },

		{ "menu_gnet_stats_visible", NULL,
			"Gnutella _traffic stats", NULL, NULL, NULL },

		{ "menu_gnet_leaf_stats_visible", NULL,
			"Gnutella _leaf traffic stats", NULL, NULL, NULL },

		{ "menu_dht_traffic_stats_visible", NULL,
			"DHT traffic stats", NULL, NULL, NULL },


		{ "HelpAction", NULL, "_Help", NULL, NULL, NULL },
		{ "FAQAction", NULL, "_FAQ",
			NULL, "Show Frequently Asked Questions",
			G_CALLBACK(on_menu_faq_activate) },
		{ "AboutAction", NULL,
			"_About Gtk-Gnutella", "<control>a", "About Gtk-Gnutella",
			G_CALLBACK(on_menu_about_activate) }
	};

	static const GtkToggleActionEntry toggle_entries[] = {
		{ "menu_searchbar_visible", NULL,
			"Show Search_bar", "F2", NULL,
			G_CALLBACK(on_menu_searchbar_visible_activate), TRUE },
		{ "menu_sidebar_visible", NULL,
			"Show _Sidebar", "F8", NULL,
			G_CALLBACK(on_menu_sidebar_visible_activate), TRUE },
		{ "menu_menubar_visible", NULL,
			"Show _Menubar", "F9", NULL,
			G_CALLBACK(on_menu_menubar_visible_activate), TRUE },
		{ "menu_statusbar_visible", NULL,
			"Show _Statusbar", NULL, NULL,
			G_CALLBACK(on_menu_statusbar_visible_activate), TRUE},

		{ "menu_downloads_visible", NULL,
			"Show _Downloads", NULL, NULL,
			G_CALLBACK(on_menu_downloads_visible_activate), TRUE },
		{ "menu_uploads_visible", NULL,
			"Show _Uploads", NULL, NULL,
			G_CALLBACK(on_menu_uploads_visible_activate), TRUE },
		{ "menu_connections_visible", NULL,
			"Show _Peers", NULL, NULL,
			G_CALLBACK(on_menu_connections_visible_activate), TRUE },


		{ "menu_bws_in_visible", NULL,
			"Show _inbound HTTP traffic", NULL, NULL,
			G_CALLBACK(on_menu_bws_in_visible_activate), TRUE },
		{ "menu_bws_out_visible", NULL,
			"Show _outbound HTTP traffic", NULL, NULL,
			G_CALLBACK(on_menu_bws_out_visible_activate), TRUE },

		{ "menu_bws_gin_visible", NULL,
			"Show _inbound Gnutella traffic" ,NULL, NULL,
			G_CALLBACK(on_menu_bws_gin_visible_activate), TRUE },
		{ "menu_bws_gout_visible", NULL,
			"Show _outbound Gnutella traffic",  NULL, NULL,
			G_CALLBACK(on_menu_bws_gout_visible_activate), TRUE },

		{ "menu_autohide_bws_gleaf", NULL,
			"_Auto-hide leaf traffic stats", NULL, NULL,
			G_CALLBACK(on_menu_autohide_bws_gleaf_activate), TRUE },
		{ "menu_bws_glin_visible", NULL,
			"Show _inbound leaf traffic", NULL, NULL,
			G_CALLBACK(on_menu_bws_glin_visible_activate), TRUE },
		{ "menu_bws_glout_visible", NULL,
			"Show _outbound leaf traffic", NULL, NULL,
			G_CALLBACK(on_menu_bws_glout_visible_activate), TRUE },

		{ "menu_autohide_bws_dht", NULL,
			"auto-hide DHT traffic stats", NULL,  NULL,
			G_CALLBACK(on_menu_autohide_bws_dht_activate), TRUE },
		{ "menu_bws_dht_in_visible", NULL,
			"Show inbound DHT traffic", NULL, NULL,
			G_CALLBACK(on_menu_bws_dht_in_visible_activate), TRUE },
		{ "menu_bws_dht_out_visible", NULL,
			"Show outbound DHT traffic", NULL, NULL,
			G_CALLBACK(on_menu_bws_dht_out_visible_activate), TRUE },

	};

	GtkActionGroup *actions = gtk_action_group_new ("Actions");
	gtk_action_group_add_actions (actions, entries,
								  N_ITEMS (entries), NULL);
	gtk_action_group_add_toggle_actions(actions, toggle_entries,
										N_ITEMS (toggle_entries), NULL);
	gtk_ui_manager_insert_action_group (mgr, actions, 0);

	menubar = gtk_ui_manager_get_widget(mgr, "/MenuBar");


	gtkosx_application_set_menu_bar(theApp, GTK_MENU_SHELL(menubar));
	gtkosx_application_set_use_quartz_accelerators(theApp, TRUE);


	item = gtk_ui_manager_get_widget(mgr, "/MenuBar/File/Quit");
	gtk_widget_hide(GTK_WIDGET(item));

	item = gtk_ui_manager_get_widget(mgr, "/MenuBar/View/menu_statusbar_visible");
	gtk_widget_hide(GTK_WIDGET(item));

	item = gtk_ui_manager_get_widget(mgr,"/MenuBar/Help/About");
	gtkosx_application_insert_app_menu_item  (theApp, item, 0);
	sep = gtk_separator_menu_item_new();
	g_object_ref(sep);
	gtkosx_application_insert_app_menu_item  (theApp, sep, 1);

	item = gtk_ui_manager_get_widget(mgr,"/MenuBar/File/Preferences");
	gtkosx_application_insert_app_menu_item  (theApp, item, 2);


	GtkWidget *dock_menu = gtk_menu_new();

	item = gtk_menu_item_new_with_label("Toon");
	g_signal_connect_data (item, "activate", G_CALLBACK (on_NSApplicationDidBecomeActive),0,0, 0);
	gtk_menu_append(dock_menu, item);

	gtkosx_application_set_dock_menu(theApp, GTK_MENU_SHELL(dock_menu));

	gtkosx_application_ready(theApp);
}
#endif

/**
 * Some setup of the gui side which I wanted out of main.c but must be done
 * before the backend can be initialized since the core code is not free of
 * GTK yet.
 *      -- Richard, 6/9/2002
 */
void
main_gui_early_init(gint argc, gchar **argv, gboolean disable_xshm)
{
	static const char pixmaps[] = "pixmaps";

	/* Glade inits */

	gtk_set_locale();
	gtk_init(&argc, &argv);

#ifdef HAVE_GTKOSXAPPLICATION
	main_gui_init_osx();
#endif

	if (disable_xshm)
		gdk_set_use_xshm(FALSE);

	add_pixmap_directory(native_path(PRIVLIB_EXP G_DIR_SEPARATOR_S "pixmaps"));

#ifndef OFFICIAL_BUILD
	add_pixmap_directory(
		native_path(PACKAGE_SOURCE_DIR G_DIR_SEPARATOR_S "pixmaps"));
#endif

	{
		const char *path = get_folder_path(PRIVLIB_PATH);

		if (path != NULL) {
			char *tmp = h_strconcat(path, G_DIR_SEPARATOR_S, pixmaps, NULL_PTR);
			add_pixmap_directory(native_path(tmp));
			HFREE_NULL(tmp);
		}
	}

#ifdef MINGW32
	add_pixmap_directory(mingw_filename_nearby(pixmaps));
#endif

    gui_main_window_set(create_main_window());
	gui_init_main_window();

    gui_shutdown_window_set(create_shutdown_window());
    gui_dlg_quit_set(create_dlg_quit());

    gui_dlg_about_set(create_dlg_about());
	gui_init_dlg_about();

    gui_dlg_faq_set(create_dlg_faq());
    gui_dlg_glossary_set(create_dlg_glossary());
    gui_dlg_ancient_set(create_dlg_ancient());

    gui_dlg_prefs_set(create_dlg_prefs());
	gui_init_dlg_prefs();

	/* popup menus */
	gui_popup_search_set(create_popup_search());
	gui_popup_search_list_set(create_popup_search_list());

	gui_popup_downloads_set(create_popup_downloads());
	gui_popup_sources_set(create_popup_sources());
	gui_popup_monitor_set(create_popup_monitor());

	gui_popup_nodes_set(create_popup_nodes());
    nodes_gui_early_init();

    gui_popup_uploads_set(create_popup_uploads());
    statusbar_gui_init();

	gui_init_window_title();

    /* search history combo stuff */
    gtk_combo_disable_activate(GTK_COMBO(
		gui_main_window_lookup("combo_search")));

	clipboard_attach(gui_main_window());
}

void
main_gui_exit(int n)
{
	exit_cleanup();
	gtk_exit(n);
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
#endif /* USE_GTK1 */

#ifdef USE_GTK2
	GTK_WINDOW(gui_main_window())->allow_shrink = TRUE;
#endif /* USE_GTK2 */

    settings_gui_init();
    fi_gui_init();
    vp_gui_init();
    nodes_gui_init();
    hcache_gui_init();
    gnet_stats_gui_init();
    search_stats_gui_init();
    uploads_gui_init();
	upload_stats_common_gui_init();
    upload_stats_gui_init();
    /* Must come before search_init() so searches/filters can be loaded.*/
	filter_init();
    search_gui_init();
	filter_init_presets();
    filter_update_targets(); /* Make sure the default filters are ok */
    monitor_gui_init();
	gui_update_files_scanned();
    gui_update_stats_frames();

#ifdef HAVE_GTKOSXAPPLICATION
	g_signal_handlers_disconnect_by_func((gpointer) gui_main_window(), G_CALLBACK (on_main_window_delete_event), NULL);

	g_signal_connect ((gpointer) gui_main_window(), "delete_event",
					  G_CALLBACK (on_main_window_delete_event_hide),
					  NULL);

	gui_prop_set_boolean_val(PROP_MENUBAR_VISIBLE, FALSE);
#endif
}

void
main_gui_run(const gchar *geometry_spec, const gboolean minimized)
{
	time_t now = tm_time_exact();

	/*
	 * With GTK2, we can iconify the window before its widget is initialized
	 * For GTK1, this will be a no-op but no need to #ifdef the code.
	 */

	if (minimized) {
		gtk_window_iconify(GTK_WINDOW(gui_main_window()));
	}

	gtk_widget_show_now(gui_main_window());		/* Display the main window */
	gtk_widget_map(gui_main_window());

	if (geometry_spec) {
		guint32 coord[4] = { 0, 0, 0, 0 };

    	gui_prop_get_guint32(PROP_WINDOW_COORDS, coord, 0, N_ITEMS(coord));
		if (0 == gui_parse_geometry_spec(geometry_spec, coord)) {
    		gui_prop_set_guint32(PROP_WINDOW_COORDS,
				coord, 0, N_ITEMS(coord));
		}
	}
	gui_restore_window(gui_main_window(), PROP_WINDOW_COORDS);

#ifdef USE_GTK1
	/*
	 * With GTK1, we need to iconify after the window is properly displayed.
	 * Users will see the window display briefly and then iconify itself, but
	 * this is inevitable, halas.
	 */
	if (minimized) {
		gtk_window_iconify(GTK_WINDOW(gui_main_window()));
	}
#endif

#ifndef HAVE_GTKOSXAPPLICATION
    icon_init();
#endif
    main_gui_timer(now);

 	gtk_widget_fix_width(
        gui_main_window_lookup("frame_statusbar_uptime"),
        gui_main_window_lookup("label_statusbar_uptime"),
        8, 8);

	/*
	 * Make sure the application starts in the Gnet pane by default, or
	 * whereever they had left it in the previous session if it restarted
	 * abnormally (after a crash).
	 */

	gui_signal_connect(GTK_NOTEBOOK(gui_main_window_lookup("notebook_main")),
		"switch-page", on_notebook_main_switch_page, NULL);

	{
		uint32 page = nb_main_page_network;
		bool clean_restart;

		gnet_prop_get_boolean_val(PROP_CLEAN_RESTART, &clean_restart);

		if (!clean_restart) {
			gui_prop_get_guint32_val(PROP_MAIN_NOTEBOOK_TAB, &page);

			if (page >= nb_main_page_num)
				page = nb_main_page_network;
		}

		main_gui_notebook_set_page(page);
	}

	settings_gui_restore_panes();
    gtk_main();
}

static slist_t *timers;

void
main_gui_add_timer(main_gui_timer_cb func)
{
	g_return_if_fail(func);

	if (NULL == timers) {
		timers = slist_new();
	}
	g_return_if_fail(!slist_contains_identical(timers, func));

	slist_append(timers, cast_func_to_pointer(func));
}

void
main_gui_remove_timer(main_gui_timer_cb func)
{
	g_return_if_fail(func);
	g_return_if_fail(timers);

	slist_remove(timers, cast_func_to_pointer(func));
}

/**
 * Main gui timer. This is called once a second.
 */
void
main_gui_timer(time_t now)
{
	gboolean overloaded;
	size_t length;

	gnet_prop_get_boolean_val(PROP_OVERLOADED_CPU, &overloaded);

    gui_general_timer(now);
    gui_update_traffic_stats();

	/*
	 * When the CPU is overloaded, non-essential GUI information is not
	 * updated every second.
	 */

	length = timers ? slist_length(timers) : 0;
	while (length-- > 0) {
		void *p;

		p = slist_shift(timers);
		if (p) {
			main_gui_timer_cb func;

			slist_append(timers, p);
			func = cast_pointer_to_func(p);
			(*func)(now);
		}
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

void
main_gui_shutdown(void)
{
	unsigned i;

	gui_save_window(gui_main_window(), PROP_WINDOW_COORDS);

	for (i = 0; i < N_ITEMS(visibility_listeners); i++) {
		gm_slist_free_null(&visibility_listeners[i]);
	}
	slist_free(&timers);

	icon_close();

    /*
     * Discard all changes and close the dialog.
     */

    filter_close_dialog(FALSE);
	gtk_widget_hide(gui_main_window());
	if (gui_dlg_prefs()) {
		gtk_widget_hide(gui_dlg_prefs());
	}
    search_stats_gui_shutdown();
    filter_cb_close();
    monitor_gui_shutdown();
    search_gui_shutdown(); /* must be done before filter_shutdown! */
	filter_shutdown();
	vp_gui_shutdown();
    fi_gui_shutdown();
    nodes_gui_shutdown();
    uploads_gui_shutdown();
    upload_stats_gui_shutdown();
    upload_stats_common_gui_shutdown();
	gnet_stats_gui_shutdown();
    hcache_gui_shutdown();
    statusbar_gui_shutdown();
}

/* vi: set ts=4 sw=4 cindent: */
