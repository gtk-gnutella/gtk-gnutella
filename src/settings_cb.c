/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
 *
 * GUI stuff used by share.c
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

#include "adns.h"
#include "settings_cb.h"
#include "settings_gui.h"
#include "search_gui.h"

RCSID("$Id$");

/* 
 * Create a function for the focus out signal and make it call
 * the callback for the activate signal.
 */
#define FOCUS_TO_ACTIVATE(a)                                            \
    gboolean on_##a##_focus_out_event                                   \
        (GtkWidget *widget, GdkEventFocus *event, gpointer user_data)   \
    {                                                                   \
        on_##a##_activate(GTK_EDITABLE(widget), NULL);                  \
        return FALSE;                                                    \
    }

#define checkmenu_changed(pref,p, cb) do {                              \
        gboolean val = GTK_CHECK_MENU_ITEM(cb)->active;                 \
        pref##_prop_set_boolean(p, &val, 0, 1);                         \
    } while (0)

void on_spinbutton_search_reissue_timeout_changed
    (GtkEditable *editable, gpointer user_data)
{
    static gboolean lock = FALSE;
    search_t *current_search;
    guint32 timeout_real;
    guint32 timeout;

    if (lock)
        return;

    lock = TRUE;

    current_search = search_gui_get_current_search();

    if (!current_search || search_is_passive(current_search->search_handle)) {
        lock = FALSE;
        return;
    }

    timeout = gtk_spin_button_get_value(GTK_SPIN_BUTTON(editable));

    search_set_reissue_timeout(current_search->search_handle, timeout);
    timeout_real = search_get_reissue_timeout(current_search->search_handle);

    if (timeout != timeout_real)
        gtk_spin_button_set_value(GTK_SPIN_BUTTON(editable), timeout_real);

    lock = FALSE;
}

void on_spinbutton_minimum_speed_changed
    (GtkEditable *editable, gpointer user_data)
{
    search_t *current_search;

    current_search = search_gui_get_current_search();

    if (!current_search)
        return;

    search_set_minimum_speed(current_search->search_handle,
        gtk_spin_button_get_value(GTK_SPIN_BUTTON(editable)));
}

static void on_entry_config_proxy_ip_activate_helper(
	guint32 ip, gpointer user_data)
{
    gnet_prop_set_guint32_val(PROP_PROXY_IP, ip);
}

void on_entry_config_proxy_ip_activate
    (GtkEditable *editable, gpointer user_data)
{
   	gchar *e = g_strstrip(gtk_editable_get_chars(editable, 0, -1));

	adns_resolve(e, &on_entry_config_proxy_ip_activate_helper, NULL);
	g_free(e);
}
FOCUS_TO_ACTIVATE(entry_config_proxy_ip)

void on_entry_config_socks_username_activate
    (GtkEditable *editable, gpointer user_data)
{
   	gchar *e = g_strstrip(gtk_editable_get_chars(editable, 0, -1));

    gnet_prop_set_string(PROP_SOCKS_USER, e);
	
    g_free(e);
}
FOCUS_TO_ACTIVATE(entry_config_socks_username)

void on_entry_config_socks_password_activate
    (GtkEditable * editable, gpointer user_data)
{
   	gchar *e = g_strstrip(gtk_editable_get_chars(editable, 0, -1));

    gnet_prop_set_string(PROP_SOCKS_PASS, e);
	
    g_free(e);
}
FOCUS_TO_ACTIVATE(entry_config_socks_password)

void on_entry_config_extensions_activate(GtkEditable *editable, gpointer data)
{
    gchar *ext;

    ext = gtk_editable_get_chars(editable, 0, -1);

    gnet_prop_set_string(PROP_SCAN_EXTENSIONS, ext);

    g_free(ext);
}
FOCUS_TO_ACTIVATE(entry_config_extensions)

void on_entry_config_path_activate(GtkEditable *editable, gpointer user_data)
{
    gchar *path;

    path = gtk_editable_get_chars(editable, 0, -1);

    gnet_prop_set_string(PROP_SHARED_DIRS_PATHS, path);

    g_free(path);
}
FOCUS_TO_ACTIVATE(entry_config_path)

void on_entry_config_force_ip_activate
    (GtkEditable *editable, gpointer user_data)
{
   	gchar *e;
	guint32 ip;
	e = gtk_editable_get_chars(
        GTK_EDITABLE(lookup_widget(main_window, "entry_config_force_ip")), 
        0, -1);
	g_strstrip(e);
	ip = gchar_to_ip(e);
	gnet_prop_set_guint32_val(PROP_FORCED_LOCAL_IP, ip);
	g_free(e);
}
FOCUS_TO_ACTIVATE(entry_config_force_ip)

void on_entry_config_force_ip_changed
    (GtkEditable *editable,  gpointer user_data)
{
    gchar *e = gtk_editable_get_chars(editable, 0, -1);

	g_strstrip(e);

	gtk_widget_set_sensitive(
        lookup_widget(main_window, "checkbutton_config_force_ip"),
        is_string_ip(e));

	g_free(e);
}

void on_menu_toolbar_visible_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
	checkmenu_changed(gui, PROP_TOOLBAR_VISIBLE, menuitem);
}

void on_menu_statusbar_visible_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
	checkmenu_changed(gui, PROP_STATUSBAR_VISIBLE, menuitem);
}

void on_menu_downloads_visible_activate(GtkMenuItem * menuitem,
									 gpointer user_data)
{
	checkmenu_changed(gui, PROP_PROGRESSBAR_DOWNLOADS_VISIBLE, menuitem);
}

void on_menu_uploads_visible_activate(GtkMenuItem * menuitem,
								   gpointer user_data)
{
	checkmenu_changed(gui, PROP_PROGRESSBAR_UPLOADS_VISIBLE, menuitem);
}

void on_menu_connections_visible_activate(GtkMenuItem * menuitem,
									   gpointer user_data)
{
	checkmenu_changed(gui, PROP_PROGRESSBAR_CONNECTIONS_VISIBLE, menuitem);
}

void on_menu_bws_in_visible_activate(GtkMenuItem * menuitem,
								     gpointer user_data)
{
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_IN_VISIBLE, menuitem);
}

void on_menu_bws_out_visible_activate(GtkMenuItem * menuitem,
								      gpointer user_data)
{
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_OUT_VISIBLE, menuitem);
}

void on_menu_bws_gin_visible_activate(GtkMenuItem * menuitem,
						 		      gpointer user_data)
{
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_GIN_VISIBLE, menuitem);
}

void on_menu_bws_gout_visible_activate(GtkMenuItem * menuitem,
								       gpointer user_data)
{
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_GOUT_VISIBLE, menuitem);
}

void on_menu_bws_glin_visible_activate(GtkMenuItem * menuitem,
						 		      gpointer user_data)
{
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_GLIN_VISIBLE, menuitem);
}

void on_menu_bws_glout_visible_activate(GtkMenuItem * menuitem,
								       gpointer user_data)
{
	checkmenu_changed(gui, PROP_PROGRESSBAR_BWS_GLOUT_VISIBLE, menuitem);
}

void on_popup_search_toggle_tabs_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
    gboolean val;

    gui_prop_get_boolean(PROP_SEARCH_RESULTS_SHOW_TABS, &val, 0, 1);
    val = !val;
    gui_prop_set_boolean(PROP_SEARCH_RESULTS_SHOW_TABS, &val, 0, 1);
}

