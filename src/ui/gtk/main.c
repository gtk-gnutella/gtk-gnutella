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

#include "gtk/misc.h"

#include "if/bridge/ui2c.h"

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

#ifdef GTA_REVISION
	gm_snprintf(title, sizeof(title), "gtk-gnutella %s %s",
		GTA_VERSION_NUMBER, GTA_REVISION);
#else
	gm_snprintf(title, sizeof(title), "gtk-gnutella %s", GTA_VERSION_NUMBER);
#endif

	gtk_window_set_title(GTK_WINDOW(gui_main_window()), title);
}

static gboolean main_window_is_visible = TRUE;

gboolean
main_gui_window_visible(void)
{
	return main_window_is_visible;
}

static gboolean
on_main_gui_map_event(GtkWidget *unused_widget,
	GdkEvent *event, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;

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
	return FALSE;	/* propagate further */
}

static int notebook_main_current_page;

static void
on_notebook_main_switch_page(GtkNotebook *unused_notebook,
	GtkNotebookPage *unused_page, int page_num, void *unused_udata)
{
	(void) unused_notebook;
	(void) unused_page;
	(void) unused_udata;

	g_return_if_fail(UNSIGNED(page_num) < nb_main_page_num);
	notebook_main_current_page = page_num;
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
		"Martijn van Oosterhout <kleptog@svana.org>",
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

/**
 * Some setup of the gui side which I wanted out of main.c but must be done
 * before the backend can be initialized since the core code is not free of
 * GTK yet.
 *      -- Richard, 6/9/2002
 */
void
main_gui_early_init(gint argc, gchar **argv, gboolean disable_xshm)
{
	/* Glade inits */

	gtk_set_locale();
	gtk_init(&argc, &argv);

	if (disable_xshm)
		gdk_set_use_xshm(FALSE);

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
    uploads_gui_early_init();
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
    gtk_clist_set_compare_func(
        GTK_CLIST(gui_main_window_lookup("clist_ul_stats")),
        compare_ul_norm);
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

	/*
	 * Make sure the application starts in the Gnet pane.
	 */

	gui_signal_connect(GTK_NOTEBOOK(gui_main_window_lookup("notebook_main")),
		"switch-page", on_notebook_main_switch_page, NULL);
	main_gui_notebook_set_page(nb_main_page_network);

	settings_gui_restore_panes();
    gtk_main();
}

void
main_gui_shutdown(void)
{
	gui_save_window(gui_main_window(), PROP_WINDOW_COORDS);
	icon_close();

    /*
     * Discard all changes and close the dialog.
     */

    filter_close_dialog(FALSE);
	gtk_widget_hide(gui_main_window());
	if (gui_dlg_prefs())
		gtk_widget_hide(gui_dlg_prefs());

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
	gnet_stats_gui_shutdown();
    hcache_gui_shutdown();
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
		case 8: search_gui_timer(now);					break;
		case 9: icon_timer();							break;
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
