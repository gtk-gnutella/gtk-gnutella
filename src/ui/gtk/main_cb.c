/*
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#include "gui.h"

#include "html_view.h"
#include "main.h"
#include "main_cb.h"
#include "misc.h"
#include "notebooks.h"
#include "settings.h"

#include "if/gui_property.h"
#include "if/bridge/ui2c.h"

#include "lib/crash.h"
#include "lib/file.h"
#include "lib/halloc.h"
#include "lib/omalloc.h"
#include "lib/utf8.h"

#include "lib/override.h"	/* Must be the last header included */

/***
 *** Private functions
 ***/

struct textview_info {
	const char *file;
	file_path_t fp[6];
	struct html_view *view;
	uint fp_cnt;
};

static struct textview_info faq_textview = {
	.file = "FAQ",
};

static struct textview_info glossary_textview = {
	.file = "glossary",
};

static void G_COLD
load_textview(GtkWidget *textview,
	struct textview_info *ti, const struct array dflt)
{
	const char *lang;
	uint i = 0;
	FILE *f;

	html_view_free(&ti->view);

	lang = locale_get_language();

	if (ti->fp_cnt != 0) {
		i = ti->fp_cnt;
	} else {
		const char *tmp;
		char *path;

		tmp = get_folder_path(PRIVLIB_PATH);

		if (tmp != NULL) {
			path = make_pathname(tmp, lang);
			file_path_set(&ti->fp[i++], ostrdup(path), ti->file);
			HFREE_NULL(path);
			path = make_pathname(tmp, "en");
			file_path_set(&ti->fp[i++], ostrdup(path), ti->file);
			HFREE_NULL(path);
		}

		path = make_pathname(PRIVLIB_EXP, lang);
		file_path_set(&ti->fp[i++], ostrdup(path), ti->file);
		HFREE_NULL(path);
		file_path_set(&ti->fp[i++],
			PRIVLIB_EXP G_DIR_SEPARATOR_S "en", ti->file);

#ifndef OFFICIAL_BUILD
		path = make_pathname(PACKAGE_EXTRA_SOURCE_DIR, lang);
		file_path_set(&ti->fp[i++], ostrdup(path), ti->file);
		HFREE_NULL(path);

		file_path_set(&ti->fp[i++],
			PACKAGE_EXTRA_SOURCE_DIR G_DIR_SEPARATOR_S "en", ti->file);
#endif /* !OFFICIAL_BUILD */

		ti->fp_cnt = i;
	}

	g_assert(i <= N_ITEMS(ti->fp));

	f = file_config_open_read_norename(ti->file, ti->fp, i);
	if (f != NULL) {
		ti->view = html_view_load_file(textview, fileno(f));
		fclose(f);
	} else {
		ti->view = html_view_load_memory(textview, dflt);
	}
}

static void G_COLD
load_faq(void)
{
	static const char msg[] =
		N_(
			"<html>"
			"<head>"
			"<title>Frequently Asked Questions</title>"
			"</head>"
			"<body>"
			"<p>"
			"The FAQ document could not be loaded. Please read the "
			"<a href=\"https://gtk-gnutella.sourceforge.io/?page=faq\">"
			"FAQ online</a> instead."
			"</p>"
			"</body>"
			"</html>"
		);

	load_textview(
		gui_dlg_faq_lookup("textview_faq"),
		&faq_textview,
		array_from_string(msg));
}

static void G_COLD
load_glossary(void)
{
	static const char msg[] =
		N_(
			"<html>"
			"<head>"
			"<title>Glossary</title>"
			"</head>"
			"<body>"
			"<p>"
			"The glossary document could not be loaded."
			"</p>"
			"</body>"
			"</html>"
		);

	load_textview(
		gui_dlg_glossary_lookup("textview_glossary"),
		&glossary_textview,
		array_from_string(msg));
}

static gboolean quitting;

static void
quit(gboolean force)
{
	gboolean confirm;

	/*
	 * Protect against multiple invocations, since we have many callbacks
	 * that can invoke this routine.  Once we decided to quit for good,
	 * any further invocation would fault on the GUI property access.
	 */

	if (quitting)
		return;

    gui_prop_get_boolean_val(PROP_CONFIRM_QUIT, &confirm);
    if (force || !confirm) {
		quitting = TRUE;
		crash_ctl(CRASH_FLAG_CLEAR, CRASH_F_RESTART);
       	guc_gtk_gnutella_exit(0);
	} else {
        gtk_widget_show(gui_dlg_quit());
    	gdk_window_raise(gui_dlg_quit()->window);
	}
}

/***
 *** Main window
 ***/

gboolean
on_main_window_delete_event(GtkWidget *unused_widget, GdkEvent *unused_event,
		gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;

	quit(FALSE);
	return TRUE;
}

void
on_button_quit_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

    quit(FALSE);
}


#ifdef HAVE_GTKOSXAPPLICATION
gboolean
on_main_window_delete_event_hide(GtkWidget *unused_widget, GdkEvent *unused_event,
							gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;

	gtk_widget_hide(gui_main_window());

	return TRUE;
}

gboolean
on_NSApplicationOpenFile(GtkosxApplication *app, gchar *path,
						 gpointer user_data)
{
	(void) app;
	(void) path;
	(void) user_data;

	gtk_widget_show(gui_main_window());

	return TRUE;
}

gboolean
on_NSApplicationDidBecomeActive(GtkosxApplication *app, gpointer user_data)
{
	(void) app;
	(void) user_data;

	if (!quitting)
		gtk_widget_show(gui_main_window());

	return TRUE;
}

#endif

/***
 *** Tray menu
 ***/

void
on_popup_tray_preferences_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	if (!quitting)
		main_gui_show_prefences();
}

void
on_popup_tray_quit_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

    quit(FALSE);
}

/***
 *** menu bar
 ***/

void
on_menu_about_activate(GtkMenuItem *unused_menuitem, gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	g_return_if_fail(gui_dlg_about());
    gtk_widget_show(gui_dlg_about());
	g_return_if_fail(gui_dlg_about()->window);
	gdk_window_raise(gui_dlg_about()->window);
}

void
on_menu_faq_activate(GtkMenuItem *unused_menuitem, gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	g_return_if_fail(gui_dlg_faq());
	load_faq();
    gtk_widget_show(gui_dlg_faq());
	g_return_if_fail(gui_dlg_faq()->window);
	gdk_window_raise(gui_dlg_faq()->window);
}

void
on_menu_glossary_activate(GtkMenuItem *unused_menuitem, gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	g_return_if_fail(gui_dlg_glossary());
	load_glossary();
    gtk_widget_show(gui_dlg_glossary());
	g_return_if_fail(gui_dlg_glossary()->window);
	gdk_window_raise(gui_dlg_glossary()->window);
}

void
on_menu_prefs_activate(GtkMenuItem *unused_menuitem, gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	main_gui_show_prefences();
}

void
on_menu_keyboard_shortcuts_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	g_carp("%s(): this is a stub", G_STRFUNC);
}



/***
 *** about dialog
 ***/

void
on_button_about_close_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	g_return_if_fail(gui_dlg_about());

    gtk_widget_hide(gui_dlg_about());
}

gboolean
on_dlg_about_delete_event(GtkWidget *unused_widget, GdkEvent *unused_event,
	gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;

	g_return_val_if_fail(gui_dlg_about(), TRUE);

	gtk_widget_hide(gui_dlg_about());
	return TRUE;
}

gboolean
on_dlg_ancient_delete_event(GtkWidget *unused_widget, GdkEvent *unused_event,
	gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;

	ancient_version_dialog_hide();
	return TRUE;
}

/***
 *** FAQ dialog
 ***/

gboolean
on_dlg_faq_delete_event(GtkWidget *unused_widget, GdkEvent *unused_event,
	gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;

	g_return_val_if_fail(gui_dlg_faq(), TRUE);

	html_view_free(&faq_textview.view);
	gtk_widget_hide(gui_dlg_faq());
	return TRUE;
}

/***
 *** Glossary dialog
 ***/

gboolean
on_dlg_glossary_delete_event(GtkWidget *unused_widget, GdkEvent *unused_event,
	gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;

	g_return_val_if_fail(gui_dlg_glossary(), TRUE);

	html_view_free(&glossary_textview.view);
	gtk_widget_hide(gui_dlg_glossary());
	return TRUE;
}

/***
 *** prefs dialog
 ***/

void
on_button_prefs_close_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	g_return_if_fail(gui_dlg_prefs());
	g_return_if_fail(GTK_WIDGET_REALIZED(gui_dlg_prefs()));
	g_return_if_fail(GTK_WIDGET_VISIBLE(gui_dlg_prefs()));

	gui_save_window(gui_dlg_prefs(), PROP_PREFS_DLG_COORDS);
    gtk_widget_hide(gui_dlg_prefs());
}

gboolean
on_dlg_prefs_delete_event(GtkWidget *unused_widget, GdkEvent *unused_event,
	gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;

	g_return_val_if_fail(gui_dlg_prefs(), TRUE);
	g_return_val_if_fail(GTK_WIDGET_REALIZED(gui_dlg_prefs()), TRUE);
	g_return_val_if_fail(GTK_WIDGET_VISIBLE(gui_dlg_prefs()), TRUE);

	gtk_widget_hide(gui_dlg_prefs());
	return TRUE;
}


/***
 *** Quit dialog
 ***/

void
on_button_really_quit_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;
	g_return_if_fail(gui_dlg_quit());

    gtk_widget_hide(gui_dlg_quit());
	quit(TRUE);
}

void
on_button_abort_quit_clicked(GtkButton *unused_button, gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;

	g_return_if_fail(gui_dlg_quit());

    gtk_widget_hide(gui_dlg_quit());
}

gboolean
on_dlg_quit_delete_event(GtkWidget *unused_widget, GdkEvent *unused_event,
	gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_event;
	(void) unused_udata;

	g_return_val_if_fail(gui_dlg_quit(), TRUE);
    gtk_widget_hide(gui_dlg_quit());
    return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
